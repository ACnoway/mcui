//go:build linux

package xrayruntime

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/ACnoway/mcui/internal/checkedasset"
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
	if err := checkedasset.ZIP32Directory(file, length, 3, 5); err != nil {
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
	return checkedasset.LinuxExecutable(header, runtime.GOARCH)
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
