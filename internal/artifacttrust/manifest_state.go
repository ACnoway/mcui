package artifacttrust

import (
	"crypto/ed25519"
	json "encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

const manifestStateName = "accepted.json"
const manifestSuspendedName = "recovery-required"

// InitializeManifestState installs a locally verified baseline. Reinitializing
// existing state can only keep the same bytes or advance the version.
func InitializeManifestState(dir string, raw, sig []byte, key ed25519.PublicKey, now time.Time) error {
	m, err := VerifyManifest(raw, sig, key, now)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(dir) {
		return errors.New("manifest state path must be absolute")
	}
	dir, err = preparePrivateDirectory(dir)
	if err != nil {
		return err
	}
	unlock, err := lockManifestState(dir)
	if err != nil {
		return err
	}
	defer unlock()
	next := stateOf(m, raw)
	current, err := readManifestState(dir)
	if errors.Is(err, errManifestNotInitialized) {
		err = writeManifestState(dir, next)
	} else if err == nil {
		err = advanceManifestState(dir, current, next)
	}
	if err != nil {
		return err
	}
	if err = os.Remove(filepath.Join(dir, manifestSuspendedName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = syncDirectory(dir); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(dir))
}

// SuspendManifestState blocks new changes after a restore until the operator
// has checked the current version and verified it with init-state.
func SuspendManifestState(dir string) error {
	if !filepath.IsAbs(dir) {
		return errors.New("manifest state path must be absolute")
	}
	unlock, err := lockManifestState(dir)
	if err != nil {
		return err
	}
	defer unlock()
	f, err := os.OpenFile(filepath.Join(dir, manifestSuspendedName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return syncDirectory(dir)
	}
	if err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func readManifestState(dir string) (manifestState, error) {
	var state manifestState
	path := filepath.Join(dir, manifestStateName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, errManifestNotInitialized
	}
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > 1024 {
		return state, errors.New("invalid manifest state file")
	}
	f, err := os.Open(path)
	if err != nil {
		return state, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return state, errors.New("manifest state file changed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil || len(raw) > 1024 || json.Unmarshal(raw, &state, json.RejectUnknownMembers(true)) != nil || !state.valid() {
		return manifestState{}, errors.New("invalid manifest state contents")
	}
	return state, nil
}

func advanceManifestState(dir string, current, next manifestState) error {
	if err := current.accepts(next); err != nil {
		return err
	}
	if next == current {
		return syncDirectory(dir)
	}
	return writeManifestState(dir, next)
}

func writeManifestState(dir string, next manifestState) error {
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".accepted-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, manifestStateName)); err != nil {
		return err
	}
	return syncDirectory(dir)
}
