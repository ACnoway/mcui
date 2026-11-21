//go:build linux

package runtimeupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/runtimehealth"
	"github.com/ACnoway/mcui/internal/security"
	"golang.org/x/sys/unix"
)

type pairServices interface {
	Stop(context.Context) error
	Start(context.Context) error
	Healthy(context.Context) error
}

type Manager struct {
	dir      string
	lock     *os.File
	services pairServices
}

func Open(initialize bool) (*Manager, error) {
	return openManager(runtimehealth.StateDir, initialize, systemdPair{
		dir: runtimehealth.StateDir, agentUnit: "mcui-agent.service", helperUnit: "mcui-helper.service",
	})
}

func openManager(dir string, initialize bool, services pairServices) (*Manager, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(dir) || services == nil {
		return nil, errors.New("runtime supervisor requires local root")
	}
	if err := ownedDir(dir, 0755, initialize); err != nil {
		return nil, err
	}
	if err := ownedDir(filepath.Join(dir, "releases"), 0755, initialize); err != nil {
		return nil, err
	}
	if err := ownedDir(filepath.Join(dir, "incoming"), 0700, initialize); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(dir, "lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), "runtime update lock")
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("acquire runtime supervisor lock: %w", err)
	}
	return &Manager{dir: dir, lock: lock, services: services}, nil
}

func (m *Manager) Close() error { return m.lock.Close() }

// Bootstrap imports the currently installed pair. Its provenance is verified
// by the local administrator before the managed units are enabled.
func (m *Manager) Bootstrap(ctx context.Context, node, version string, releaseKey, authorizationKey ed25519.PublicKey) error {
	return m.bootstrap(ctx, node, version, releaseKey, authorizationKey, "/usr/local/bin")
}

func (m *Manager) bootstrap(ctx context.Context, node, version string, releaseKey, authorizationKey ed25519.PublicKey, source string) error {
	for _, name := range []string{"state.json", "current", runtimehealth.TrialFile} {
		if _, err := os.Lstat(filepath.Join(m.dir, name)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("runtime state already exists or requires local recovery")
		}
	}
	if !security.ValidNodeID(node) || !versionPattern.MatchString(version) || len(releaseKey) != ed25519.PublicKeySize ||
		len(authorizationKey) != ed25519.PublicKeySize || releaseKey.Equal(authorizationKey) {
		return errors.New("invalid runtime version or independent trust keys")
	}
	pair, err := m.stagePair(ctx, version, func(name string) (io.ReadCloser, int64, error) {
		file, size, err := openTrusted(filepath.Join(source, name), maxBinary)
		return file, size, err
	})
	if err != nil {
		return err
	}
	state := State{
		SchemaVersion: 1, NodeID: node, Current: pair, ReleaseKey: releaseKey,
		AuthorizationKey: authorizationKey, LastResult: "initialized",
	}
	if err := m.save(state); err != nil {
		return err
	}
	return m.point(pair)
}

func (m *Manager) Apply(ctx context.Context, clock func() (time.Time, error)) error {
	state, err := m.available()
	if err != nil {
		return err
	}
	auth, artifact, expiry, err := m.authorize(state, clock)
	if err != nil {
		return err
	}
	if err := m.services.Healthy(ctx); err != nil {
		return fmt.Errorf("last committed pair is not healthy: %w", err)
	}
	pair, err := m.stageArchive(ctx, artifact)
	if err != nil {
		return err
	}
	state.Sequence, state.ManifestVersion, state.ManifestSHA256 = auth.Sequence, auth.ManifestVersion, auth.ManifestSHA256
	return m.switchPair(ctx, state, pair, func() error {
		now, err := clock()
		if err != nil || now.Before(auth.NotBefore) || !now.Before(auth.ExpiresAt) || !now.Before(expiry) {
			return errors.New("runtime update authorization expired or clock changed before activation")
		}
		return nil
	})
}

func (m *Manager) authorize(state State, clock func() (time.Time, error)) (Authorization, artifacttrust.Artifact, time.Time, error) {
	var empty artifacttrust.Artifact
	now, err := clock()
	if err != nil {
		return Authorization{}, empty, time.Time{}, err
	}
	incoming := filepath.Join(m.dir, "incoming")
	raw, err := readTrusted(filepath.Join(incoming, "authorization.json"), MaxAuthorizationBytes)
	if err != nil {
		return Authorization{}, empty, time.Time{}, err
	}
	sig, err := readTrusted(filepath.Join(incoming, "authorization.json.sig"), ed25519.SignatureSize)
	if err != nil {
		return Authorization{}, empty, time.Time{}, err
	}
	auth, err := verifyAuthorization(raw, sig, state.AuthorizationKey, now)
	if err != nil {
		return Authorization{}, empty, time.Time{}, err
	}
	if auth.NodeID != state.NodeID || auth.CurrentPair != state.Current.Digest() || auth.Architecture != runtime.GOARCH ||
		auth.Sequence <= state.Sequence || auth.ManifestVersion < state.ManifestVersion ||
		auth.ManifestVersion == state.ManifestVersion && auth.ManifestSHA256 != state.ManifestSHA256 {
		return Authorization{}, empty, time.Time{}, errors.New("stale or mismatched runtime update authorization")
	}
	raw, err = readTrusted(filepath.Join(incoming, "manifest.json"), artifacttrust.MaxManifestBytes)
	if err != nil {
		return Authorization{}, empty, time.Time{}, err
	}
	sig, err = readTrusted(filepath.Join(incoming, "manifest.json.sig"), ed25519.SignatureSize)
	if err != nil {
		return Authorization{}, empty, time.Time{}, err
	}
	manifest, err := artifacttrust.VerifyManifest(raw, sig, state.ReleaseKey, now)
	if err != nil {
		return Authorization{}, empty, time.Time{}, err
	}
	if manifest.ManifestVersion != auth.ManifestVersion || fmt.Sprintf("%x", sha256.Sum256(raw)) != auth.ManifestSHA256 {
		return Authorization{}, empty, time.Time{}, errors.New("runtime manifest differs from the authorized manifest")
	}
	var target artifacttrust.Artifact
	for _, entry := range manifest.Artifacts {
		if entry.Component != "mcui-runtime" {
			return Authorization{}, empty, time.Time{}, errors.New("runtime signing stream must contain only runtime releases")
		}
		if entry.Architecture == auth.Architecture && entry.Version == auth.Version && entry.SHA256 == auth.SHA256 {
			target = entry
		}
	}
	if target.Component == "mcui-runtime" {
		return auth, target, manifest.ExpiresAt, nil
	}
	return Authorization{}, empty, time.Time{}, errors.New("authorized runtime pair is absent from the release manifest")
}

func (m *Manager) available() (State, error) {
	state, err := m.Status()
	if err != nil {
		return state, err
	}
	if state.Pending != nil {
		return State{}, errors.New("runtime transaction pending; run recovery before updating")
	}
	link, err := os.Readlink(filepath.Join(m.dir, "current"))
	if err != nil || link != filepath.Join("releases", state.Current.Digest()) {
		return State{}, errors.New("runtime selection differs from the supervisor state")
	}
	if err := m.verifyPair(state.Current); err != nil {
		return State{}, err
	}
	return state, nil
}

// Revert retries the previous committed pair under the same trial gate. It is
// a local root repair operation and retains the update and manifest watermarks.
func (m *Manager) Revert(ctx context.Context) error {
	state, err := m.available()
	if err != nil {
		return err
	}
	if state.Previous == nil {
		return errors.New("no previously committed runtime pair")
	}
	return m.switchPair(ctx, state, *state.Previous, nil)
}

func (m *Manager) switchPair(ctx context.Context, state State, pair Pair, authorize func() error) error {
	if pair.Digest() == state.Current.Digest() {
		return errors.New("the authorized pair is already active")
	}
	if err := m.verifyPair(pair); err != nil {
		return err
	}
	if authorize != nil {
		if err := authorize(); err != nil {
			return err
		}
	}
	if err := m.setTrial(); err != nil {
		return err
	}
	state.Pending, state.LastResult = &pair, "trial"
	if err := m.trial(ctx, state); err != nil {
		recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 100*time.Second)
		defer cancel()
		if recoverErr := m.Repair(recoveryCtx); recoverErr != nil {
			return errors.Join(err, fmt.Errorf("runtime pair recovery failed: %w", recoverErr))
		}
		return err
	}
	return nil
}

func (m *Manager) trial(ctx context.Context, state State) error {
	if err := m.save(state); err != nil {
		return err
	}
	if err := m.services.Stop(ctx); err != nil {
		return err
	}
	if err := m.point(*state.Pending); err != nil {
		return err
	}
	if err := m.services.Start(ctx); err != nil {
		return err
	}
	if err := m.services.Healthy(ctx); err != nil {
		return err
	}
	old := state.Current
	state.Current, state.Previous, state.Pending, state.LastResult = *state.Pending, &old, nil, "committed"
	if err := m.save(state); err != nil {
		return err
	}
	return m.clearTrial()
}

// BootRecover restores the durable committed pair before systemd starts either
// service. It must not wait on either of those services.
func (m *Manager) BootRecover() error {
	state, err := m.Status()
	if err != nil {
		return err
	}
	return m.restoreSelection(state)
}

// Repair is the systemd stop-post recovery as well as a local recovery command.
func (m *Manager) Repair(ctx context.Context) error {
	state, err := m.Status()
	if err != nil {
		return err
	}
	if state.Pending == nil {
		return m.restoreSelection(state)
	}
	if err := m.services.Stop(ctx); err != nil {
		return err
	}
	if err := m.restoreSelection(state); err != nil {
		return err
	}
	if err := m.services.Start(ctx); err != nil {
		return err
	}
	return m.services.Healthy(ctx)
}

func (m *Manager) restoreSelection(state State) error {
	if err := m.point(state.Current); err != nil {
		return err
	}
	if state.Pending != nil {
		state.Pending, state.LastResult = nil, "rolled_back"
		if err := m.save(state); err != nil {
			return err
		}
	}
	return m.clearTrial()
}
