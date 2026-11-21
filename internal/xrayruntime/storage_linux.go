//go:build linux

package xrayruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var bundleFiles = map[string]os.FileMode{"xray": 0555, "geoip.dat": 0444, "geosite.dat": 0444, "config.json": 0444}

func openRuntime(dir string, svc service, initialize bool) (*Runtime, error) {
	runtime := &Runtime{dir: dir, service: svc}
	if err := ownDirectory(dir, 0755, initialize); err != nil {
		return nil, err
	}
	if err := ownDirectory(filepath.Join(dir, "control"), 0700, initialize); err != nil {
		return nil, err
	}
	if err := ownDirectory(filepath.Join(dir, "versions"), 0755, initialize); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, "control", "lock")
	fd, err := unix.Open(lockPath, unix.O_CREAT|unix.O_NOFOLLOW|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	runtime.lock = os.NewFile(uintptr(fd), lockPath)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		runtime.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("another Xray lifecycle operation is in progress")
		}
		return nil, err
	}
	_, err = runtime.readStatus()
	if initialize && errors.Is(err, os.ErrNotExist) {
		err = runtime.initializeState()
	}
	if err != nil {
		runtime.Close()
		return nil, fmt.Errorf("open Xray lifecycle state: %w", err)
	}
	return runtime, nil
}

func (r *Runtime) initializeState() error {
	for _, name := range []string{"current", "candidate"} {
		if _, err := os.Lstat(filepath.Join(r.dir, name)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("cannot initialize Xray state over an existing selection")
		}
	}
	entries, err := os.ReadDir(filepath.Join(r.dir, "versions"))
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("cannot initialize Xray state over existing bundles")
	}
	if err := syncDir(r.dir); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(r.dir)); err != nil {
		return err
	}
	return r.save(Status{Schema: 1})
}

func ownDirectory(path string, mode os.FileMode, create bool) error {
	if create {
		err := os.Mkdir(path, mode)
		if err == nil {
			if err = os.Chmod(path, mode); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode() != (os.ModeDir|mode) || !owned(info) {
		return fmt.Errorf("unexpected directory ownership, type or permissions: %s", path)
	}
	return nil
}

func owned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func readJSON(path string, mode os.FileMode, dest any) error {
	const limit = 4096
	file, err := checkedFile(path, mode, limit)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return err
	}
	if len(data) > limit {
		return errors.New("Xray runtime metadata too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing Xray runtime data")
	}
	return nil
}

func (r *Runtime) readStatus() (Status, error) {
	var state Status
	if err := readJSON(filepath.Join(r.dir, "control", "state.json"), 0600, &state); err != nil {
		return Status{}, err
	}
	current := state.Current
	if state.Schema != 1 || (current.Release != (Release{}) && !current.Release.valid()) ||
		(current.Release == (Release{}) && (current.Running || state.Previous != (Release{}))) ||
		(state.Previous != (Release{}) && (!state.Previous.valid() || state.Previous == current.Release)) {
		return Status{}, errors.New("invalid committed Xray state")
	}
	if state.Pending != nil {
		if err := validateTransition(current, *state.Pending); err != nil {
			return Status{}, err
		}
		if state.Pending.InstallHash != "" && (state.Pending.Action != Install || !validInstallHash(state.Pending.InstallHash)) {
			return Status{}, errors.New("invalid Xray install intent identity")
		}
	}
	if receipt := state.InstallReceipt; receipt != nil {
		if !validInstallHash(receipt.Hash) || !receipt.Release.valid() || (receipt.Outcome != "SUCCEEDED" && receipt.Outcome != "ROLLED_BACK") {
			return Status{}, errors.New("invalid Xray install receipt")
		}
	}
	return state, nil
}

func (r *Runtime) save(state Status) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	dir := filepath.Join(r.dir, "control")
	file, err := os.CreateTemp(dir, ".state-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := persist(file, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), filepath.Join(dir, "state.json")); err != nil {
		return err
	}
	return syncDir(dir)
}

func (r *Runtime) readPointer(name string) (string, error) {
	path := filepath.Join(r.dir, name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink == 0 || !owned(info) {
		return "", errors.New("invalid Xray selection pointer")
	}
	value, err := os.Readlink(path)
	if err != nil {
		return "", err
	}
	key, ok := strings.CutPrefix(value, "versions/")
	if !ok || !managedKey(key) {
		return "", errors.New("Xray selection pointer leaves managed storage")
	}
	return value, nil
}

func (r *Runtime) point(name string, release Release) error {
	current, err := r.readPointer(name)
	if err != nil {
		return err
	}
	target := release.link()
	if current == target {
		return nil
	}
	path := filepath.Join(r.dir, name)
	if target == "" {
		if err := os.Remove(path); err != nil {
			return err
		}
		return syncDir(r.dir)
	}
	temp := path + ".next"
	// A prior crash can leave the unpublished link. It lives in a root-owned
	// directory and removing it cannot follow the destination.
	if err := os.Remove(temp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Symlink(target, temp); err != nil {
		return err
	}
	defer os.Remove(temp)
	if err := os.Rename(temp, path); err != nil {
		return err
	}
	return syncDir(r.dir)
}

type bundleManifest struct {
	Release Release           `json:"release"`
	Files   map[string]string `json:"files"`
}

func (r *Runtime) stage(ctx context.Context, release Release, size int64, download func() (string, error)) error {
	destination := filepath.Join(r.dir, release.link())
	if _, err := os.Lstat(destination); err == nil {
		return r.verifyBundle(release)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	path, err := download()
	if err != nil {
		return err
	}
	dir := filepath.Dir(destination)
	temp, err := os.MkdirTemp(dir, ".stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	if err := extract(ctx, path, release, size, temp); err != nil {
		return err
	}
	digests, err := bundleDigests(temp)
	if err != nil {
		return err
	}
	data, err := json.Marshal(bundleManifest{Release: release, Files: digests})
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(temp, "manifest.json"), data, 0444); err != nil {
		return err
	}
	if err := os.Chmod(temp, 0555); err != nil {
		return err
	}
	if err := syncDir(temp); err != nil {
		return err
	}
	if err := os.Rename(temp, destination); err != nil {
		return err
	}
	return syncDir(dir)
}

func (r *Runtime) verifyBundle(release Release) error {
	if release == (Release{}) {
		return nil
	}
	if !release.valid() {
		return errors.New("invalid Xray release identity")
	}
	dir := filepath.Join(r.dir, release.link())
	if err := ownDirectory(dir, 0555, false); err != nil {
		return err
	}
	var manifest bundleManifest
	if err := readJSON(filepath.Join(dir, "manifest.json"), 0444, &manifest); err != nil {
		return err
	}
	if manifest.Release != release || len(manifest.Files) != len(bundleFiles) {
		return errors.New("Xray bundle identity mismatch")
	}
	digests, err := bundleDigests(dir)
	if err != nil {
		return err
	}
	for name, digest := range digests {
		if manifest.Files[name] != digest {
			return errors.New("Xray bundle file digest mismatch")
		}
	}
	return nil
}

func bundleDigests(dir string) (map[string]string, error) {
	digests := make(map[string]string, len(bundleFiles))
	for name, mode := range bundleFiles {
		file, err := checkedFile(filepath.Join(dir, name), mode, maxArchiveSize)
		if err != nil {
			return nil, err
		}
		hash := sha256.New()
		_, err = io.Copy(hash, io.LimitReader(file, maxArchiveSize+1))
		closeErr := file.Close()
		if err := errors.Join(err, closeErr); err != nil {
			return nil, err
		}
		digests[name] = fmt.Sprintf("%x", hash.Sum(nil))
	}
	if digests["config.json"] != fmt.Sprintf("%x", sha256.Sum256([]byte(bootstrapConfig))) {
		return nil, errors.New("unexpected Xray bootstrap configuration")
	}
	return digests, nil
}

func checkedFile(path string, mode os.FileMode, maxSize int64) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err == nil && (info.Mode() != mode || !owned(info) || info.Size() <= 0 || info.Size() > maxSize) {
		err = errors.New("unexpected Xray file ownership, size, type or permissions")
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func (r *Runtime) prune(state Status) error {
	dir := filepath.Join(r.dir, "versions")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	current, err := r.readPointer("current")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == state.Current.Release.key() || name == state.Previous.key() || filepath.Join("versions", name) == current {
			continue
		}
		if entry.IsDir() && (managedKey(name) || strings.HasPrefix(name, ".stage-")) {
			path := filepath.Join(dir, name)
			if err := os.Chmod(path, 0700); err != nil {
				return err
			}
			if err := os.RemoveAll(path); err != nil {
				return err
			}
		}
	}
	return syncDir(dir)
}

func managedKey(key string) bool {
	version, digest, ok := strings.Cut(key, "-")
	return ok && (Release{Version: version, SHA256: digest}).valid()
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	return persist(file, data, mode)
}

func persist(file *os.File, data []byte, mode os.FileMode) error {
	_, err := file.Write(data)
	if err == nil {
		err = file.Chmod(mode)
	}
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close())
}

func syncDir(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}
