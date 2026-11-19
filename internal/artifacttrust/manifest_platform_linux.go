package artifacttrust

import (
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ACnoway/mcui/internal/security"
	"golang.org/x/sys/unix"
)

func lockManifestState(dir string) (func(), error) {
	parent, err := os.Lstat(dir)
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 ||
		parent.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("manifest state directory must be private and owned by the caller")
	}
	fd, err := unix.Open(filepath.Join(dir, ".lock"), unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	var status unix.Stat_t
	if err = unix.Fstat(fd, &status); err != nil || status.Mode&unix.S_IFMT != unix.S_IFREG ||
		status.Mode&0777 != 0600 || status.Uid != uint32(os.Geteuid()) {
		_ = unix.Close(fd)
		return nil, errors.New("invalid manifest lock")
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return func() { _ = unix.Close(fd) }, nil
}

func readProvisionedManifestKey(path string) (ed25519.PublicKey, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("release public key path must be absolute")
	}
	for parent := filepath.Dir(filepath.Clean(path)); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			return nil, errors.New("release public key must be under root-managed directories")
		}
		if parent == "/" {
			break
		}
	}
	fd, err := unix.Open(filepath.Clean(path), unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 ||
		info.Sys().(*syscall.Stat_t).Uid != 0 || info.Size() <= 0 || info.Size() > 4096 {
		return nil, errors.New("release public key must be a bounded, root-owned regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return nil, errors.New("could not read release public key")
	}
	return security.ParseEd25519PublicKey(raw)
}
