//go:build linux

package runtimeupdate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ACnoway/mcui/internal/runtimehealth"
	"github.com/ACnoway/mcui/internal/security"
	"golang.org/x/sys/unix"
)

const agentBinary = "mcui-agent"
const helperBinary = "mcui-helper"
const maxBinary = 128 << 20
const maxArchive = 256 << 20

var binaries = [...]string{agentBinary, helperBinary}

type Pair struct {
	Version      string `json:"version"`
	AgentSHA256  string `json:"agent_sha256"`
	HelperSHA256 string `json:"helper_sha256"`
}

func (p Pair) Digest() string {
	hash := sha256.Sum256([]byte("MCUI-RUNTIME-PAIR-V1\n" + p.AgentSHA256 + p.HelperSHA256))
	return hex.EncodeToString(hash[:])
}

func (p Pair) valid() bool {
	return versionPattern.MatchString(p.Version) && digestPattern.MatchString(p.AgentSHA256) && digestPattern.MatchString(p.HelperSHA256)
}

type State struct {
	SchemaVersion    int    `json:"schema_version"`
	NodeID           string `json:"node_id"`
	Current          Pair   `json:"current"`
	Previous         *Pair  `json:"previous,omitempty"`
	Pending          *Pair  `json:"pending,omitempty"`
	Sequence         int64  `json:"sequence"`
	ManifestVersion  int64  `json:"manifest_version,omitempty"`
	ManifestSHA256   string `json:"manifest_sha256,omitempty"`
	ReleaseKey       []byte `json:"release_key"`
	AuthorizationKey []byte `json:"authorization_key"`
	LastResult       string `json:"last_result,omitempty"`
}

func (s State) valid() bool {
	validWatermark := s.Sequence == 0 && s.ManifestVersion == 0 && s.ManifestSHA256 == "" ||
		s.Sequence > 0 && s.Sequence <= maxSequence && s.ManifestVersion > 0 && s.ManifestVersion <= maxSequence &&
			digestPattern.MatchString(s.ManifestSHA256)
	return s.SchemaVersion == 1 && security.ValidNodeID(s.NodeID) && s.Current.valid() && validWatermark &&
		(s.Previous == nil || (s.Previous.valid() && s.Previous.Digest() != s.Current.Digest())) &&
		(s.Pending == nil || (s.Pending.valid() && s.Pending.Digest() != s.Current.Digest())) &&
		len(s.ReleaseKey) == ed25519.PublicKeySize && len(s.AuthorizationKey) == ed25519.PublicKeySize &&
		!ed25519.PublicKey(s.ReleaseKey).Equal(ed25519.PublicKey(s.AuthorizationKey))
}

func (m *Manager) Status() (State, error) {
	var state State
	raw, err := readTrusted(filepath.Join(m.dir, "state.json"), 8192)
	if err != nil {
		return state, err
	}
	if json.Unmarshal(raw, &state, json.RejectUnknownMembers(true)) != nil || !state.valid() {
		return State{}, errors.New("invalid runtime supervisor state")
	}
	return state, nil
}

func (m *Manager) save(state State) error {
	if !state.valid() {
		return errors.New("refusing to persist invalid runtime supervisor state")
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(m.dir, ".state-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := syncAndClose(f); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(m.dir, "state.json")); err != nil {
		return err
	}
	return syncDir(m.dir)
}

func (m *Manager) setTrial() error {
	f, err := os.OpenFile(filepath.Join(m.dir, runtimehealth.TrialFile), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0444); err != nil {
		f.Close()
		return err
	}
	if err := syncAndClose(f); err != nil {
		return err
	}
	return syncDir(m.dir)
}

func (m *Manager) clearTrial() error {
	if err := os.Remove(filepath.Join(m.dir, runtimehealth.TrialFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(m.dir)
}

func (m *Manager) point(pair Pair) error {
	if err := m.verifyPair(pair); err != nil {
		return err
	}
	current := filepath.Join(m.dir, "current")
	target := filepath.Join("releases", pair.Digest())
	existing, err := os.Readlink(current)
	if err == nil {
		if existing == target {
			return syncDir(m.dir)
		}
		if filepath.Dir(existing) != "releases" || !digestPattern.MatchString(filepath.Base(existing)) {
			return errors.New("invalid runtime selection link")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.MkdirTemp(m.dir, ".link-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	path := filepath.Join(tmp, "current")
	if err := os.Symlink(target, path); err != nil {
		return err
	}
	defer os.Remove(path)
	if err := os.Rename(path, current); err != nil {
		return err
	}
	return syncDir(m.dir)
}

func (m *Manager) verifyPair(pair Pair) error {
	dir := filepath.Join(m.dir, "releases", pair.Digest())
	if err := ownedDir(dir, 0555, false); err != nil {
		return err
	}
	for i, digest := range []string{pair.AgentSHA256, pair.HelperSHA256} {
		file, _, err := openTrusted(filepath.Join(dir, binaries[i]), maxBinary)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		hash := sha256.New()
		if err == nil && info.Mode().Perm() == 0555 {
			_, err = io.Copy(hash, io.LimitReader(file, maxBinary+1))
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil || hex.EncodeToString(hash.Sum(nil)) != digest {
			return fmt.Errorf("runtime release integrity check failed for %s", binaries[i])
		}
	}
	return nil
}

func ReadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := readTrusted(path, 4096)
	if err != nil {
		return nil, err
	}
	return security.ParseEd25519PublicKey(raw)
}

func ownedDir(path string, mode os.FileMode, create bool) error {
	if create {
		if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != mode || info.Sys().(*syscall.Stat_t).Uid != 0 {
		return fmt.Errorf("invalid root-owned directory %s", path)
	}
	return nil
}

func openTrusted(path string, limit int64) (*os.File, int64, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&(0022|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		info.Sys().(*syscall.Stat_t).Uid != 0 || info.Size() <= 0 || info.Size() > limit {
		f.Close()
		return nil, 0, fmt.Errorf("invalid trusted runtime file %s", path)
	}
	return f, info.Size(), nil
}

func readTrusted(path string, limit int64) ([]byte, error) {
	f, size, err := openTrusted(path, limit)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, size+1))
	if err != nil || int64(len(data)) != size {
		return nil, fmt.Errorf("trusted runtime file changed: %s", path)
	}
	return data, nil
}

func syncAndClose(f *os.File) error { return errors.Join(f.Sync(), f.Close()) }

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return syncAndClose(f)
}
