package checkedasset

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
)

// ZIP32Directory bounds entries before archive/zip allocates its directory.
func ZIP32Directory(file io.ReaderAt, length int64, minEntries, maxEntries uint16) error {
	var end [22]byte
	if length < int64(len(end)) {
		return errors.New("ZIP is truncated")
	}
	offset := length - int64(len(end))
	if _, err := file.ReadAt(end[:], offset); err != nil {
		return err
	}
	count := binary.LittleEndian.Uint16(end[10:12])
	size := int64(binary.LittleEndian.Uint32(end[12:16]))
	start := int64(binary.LittleEndian.Uint32(end[16:20]))
	if string(end[:4]) != "PK\x05\x06" || binary.LittleEndian.Uint32(end[4:8]) != 0 ||
		binary.LittleEndian.Uint16(end[8:10]) != count || count < minEntries || count > maxEntries ||
		size < 46*int64(count) || size > 64<<10 || start <= 0 || start+size != offset ||
		binary.LittleEndian.Uint16(end[20:22]) != 0 {
		return errors.New("invalid ZIP32 directory")
	}
	return nil
}

// LinuxExecutable validates the fixed ELF header without following offsets.
func LinuxExecutable(file io.ReaderAt, architecture string) error {
	var data [64]byte
	if _, err := file.ReadAt(data[:], 0); err != nil {
		return err
	}
	var machine elf.Machine
	switch architecture {
	case "amd64":
		machine = elf.EM_X86_64
	case "arm64":
		machine = elf.EM_AARCH64
	default:
		return errors.New("unsupported Linux executable architecture")
	}
	objectType := elf.Type(binary.LittleEndian.Uint16(data[16:18]))
	if string(data[:4]) != elf.ELFMAG || elf.Class(data[4]) != elf.ELFCLASS64 ||
		elf.Data(data[5]) != elf.ELFDATA2LSB || elf.Version(data[6]) != elf.EV_CURRENT ||
		(objectType != elf.ET_EXEC && objectType != elf.ET_DYN) ||
		elf.Machine(binary.LittleEndian.Uint16(data[18:20])) != machine {
		return errors.New("executable has the wrong ELF architecture or type")
	}
	return nil
}
