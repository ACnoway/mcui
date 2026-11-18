//go:build linux

package xrayruntime

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

const maxArchiveSize = 512 << 20
const bootstrapConfig = "{}\n"

func extract(ctx context.Context, archive string, release Release, length int64, stage string) error {
	if length <= 0 || length > maxArchiveSize {
		return fmt.Errorf("invalid Xray artifact size")
	}
	// Use the same descriptor for digest verification and ZIP decoding.
	fd, err := unix.Open(archive, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "Xray archive")
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || stat.Uid != uint32(os.Geteuid()) || info.Size() != length {
		return fmt.Errorf("invalid Xray artifact file")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(contextReader{ctx, file}, length+1))
	if err != nil {
		return err
	}
	if written != length || fmt.Sprintf("%x", hash.Sum(nil)) != release.SHA256 {
		return fmt.Errorf("Xray artifact SHA-256 or length mismatch")
	}
	if err := boundZIPDirectory(file, length); err != nil {
		return err
	}
	reader, err := zip.NewReader(file, length)
	if err != nil {
		return err
	}
	if len(reader.File) < 3 || len(reader.File) > 5 {
		return fmt.Errorf("invalid Xray ZIP file count")
	}
	// The official Linux archive is flat. Only the executable and geodata
	// become runtime files. License and README entries are checked, then discarded.
	limits := map[string]uint64{
		"xray": 128 << 20, "geoip.dat": 128 << 20, "geosite.dat": 128 << 20,
		"LICENSE": 1 << 20, "README.md": 1 << 20,
	}
	seen := make(map[string]bool, len(reader.File))
	for _, entry := range reader.File {
		limit := limits[entry.Name]
		if limit == 0 || seen[entry.Name] || entry.UncompressedSize64 == 0 || entry.UncompressedSize64 > limit ||
			!entry.Mode().IsRegular() || entry.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
			entry.Flags&1 != 0 || (entry.Method != zip.Store && entry.Method != zip.Deflate) {
			return fmt.Errorf("invalid or duplicate Xray ZIP entry")
		}
		seen[entry.Name] = true
		if err := extractEntry(ctx, entry, stage); err != nil {
			return err
		}
	}
	if !seen["xray"] || !seen["geoip.dat"] || !seen["geosite.dat"] {
		return fmt.Errorf("Xray ZIP is missing a runtime file")
	}
	if err := validateExecutable(filepath.Join(stage, "xray")); err != nil {
		return err
	}
	return writeNew(filepath.Join(stage, "config.json"), []byte(bootstrapConfig), 0444)
}

// Require a bounded, single-disk ZIP32 directory before archive/zip allocates
// memory for entries. Official Linux archives do not need ZIP64 or ZIP comments.
func boundZIPDirectory(file *os.File, length int64) error {
	var end [22]byte
	if length < int64(len(end)) {
		return fmt.Errorf("Xray ZIP is truncated")
	}
	offset := length - int64(len(end))
	if _, err := file.ReadAt(end[:], offset); err != nil {
		return err
	}
	count := binary.LittleEndian.Uint16(end[10:12])
	size := int64(binary.LittleEndian.Uint32(end[12:16]))
	start := int64(binary.LittleEndian.Uint32(end[16:20]))
	if string(end[:4]) != "PK\x05\x06" || binary.LittleEndian.Uint32(end[4:8]) != 0 ||
		binary.LittleEndian.Uint16(end[8:10]) != count || count < 3 || count > 5 ||
		size < 46*int64(count) || size > 64<<10 || start <= 0 || start+size != offset ||
		binary.LittleEndian.Uint16(end[20:22]) != 0 {
		return fmt.Errorf("invalid Xray ZIP directory")
	}
	return nil
}

func extractEntry(ctx context.Context, entry *zip.File, stage string) error {
	reader, err := entry.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	var destination io.Writer = io.Discard
	var output *os.File
	if entry.Name == "xray" || entry.Name == "geoip.dat" || entry.Name == "geosite.dat" {
		mode := os.FileMode(0444)
		if entry.Name == "xray" {
			mode = 0555
		}
		output, err = os.OpenFile(filepath.Join(stage, entry.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer output.Close()
		if err := output.Chmod(mode); err != nil {
			return err
		}
		destination = output
	}
	limit := int64(entry.UncompressedSize64)
	written, err := io.Copy(destination, io.LimitReader(contextReader{ctx, reader}, limit+1))
	if err != nil {
		return err
	}
	if written != limit {
		return fmt.Errorf("Xray ZIP entry size mismatch")
	}
	if output != nil {
		return output.Sync()
	}
	return nil
}

func validateExecutable(path string) error {
	// Read only the fixed ELF header. The archive need not expose any ELF
	// sections to the privileged installer.
	header, err := os.Open(path)
	if err != nil {
		return err
	}
	defer header.Close()
	var data [64]byte
	if _, err := io.ReadFull(header, data[:]); err != nil {
		return err
	}
	var machine elf.Machine
	switch runtime.GOARCH {
	case "amd64":
		machine = elf.EM_X86_64
	case "arm64":
		machine = elf.EM_AARCH64
	default:
		return fmt.Errorf("unsupported Xray architecture")
	}
	objectType := elf.Type(binary.LittleEndian.Uint16(data[16:18]))
	if string(data[:4]) != elf.ELFMAG || elf.Class(data[4]) != elf.ELFCLASS64 ||
		elf.Data(data[5]) != elf.ELFDATA2LSB || elf.Version(data[6]) != elf.EV_CURRENT ||
		(objectType != elf.ET_EXEC && objectType != elf.ET_DYN) ||
		elf.Machine(binary.LittleEndian.Uint16(data[18:20])) != machine {
		return fmt.Errorf("Xray executable has the wrong ELF architecture")
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	io.Reader
}

func (reader contextReader) Read(buf []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.Reader.Read(buf)
}
