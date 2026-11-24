//go:build linux

package runtimeupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
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
	return m.bootstrapPair(ctx, node, version, releaseKey, authorizationKey, source, false)
}

// BootstrapInstaller imports an audited pair from a verified installer archive.
// A retry may resume the exact initialized pair before any update has run.
func (m *Manager) BootstrapInstaller(ctx context.Context, node, version string, releaseKey, authorizationKey ed25519.PublicKey, source string) error {
	if !filepath.IsAbs(source) || filepath.Clean(source) != source {
		return errors.New("invalid installer source directory")
	}
	return m.bootstrapPair(ctx, node, version, releaseKey, authorizationKey, source, true)
}

func (m *Manager) bootstrapPair(ctx context.Context, node, version string, releaseKey, authorizationKey ed25519.PublicKey, source string, retry bool) error {
	if !security.ValidNodeID(node) || !versionPattern.MatchString(version) || len(releaseKey) != ed25519.PublicKeySize ||
		len(authorizationKey) != ed25519.PublicKeySize || releaseKey.Equal(authorizationKey) {
		return errors.New("invalid runtime version or independent trust keys")
	}
	if _, err := os.Lstat(filepath.Join(m.dir, runtimehealth.TrialFile)); !errors.Is(err, os.ErrNotExist) {
		return errors.New("runtime trial requires local recovery")
	}
	prior, err := m.Status()
	if errors.Is(err, os.ErrNotExist) {
		if _, linkErr := os.Lstat(filepath.Join(m.dir, "current")); !errors.Is(linkErr, os.ErrNotExist) {
			return errors.New("runtime selection without state requires local recovery")
		}
	} else if err != nil || !retry || prior.NodeID != node || prior.Current.Version != version || prior.LastResult != "initialized" ||
		prior.Sequence != 0 || prior.Pending != nil || prior.Previous != nil || prior.RemoteReceipt != nil ||
		!releaseKey.Equal(ed25519.PublicKey(prior.ReleaseKey)) || !authorizationKey.Equal(ed25519.PublicKey(prior.AuthorizationKey)) {
		return errors.New("runtime state already exists or requires local recovery")
	} else {
		link, err := os.Readlink(filepath.Join(m.dir, "current"))
		if (err == nil && link != filepath.Join("releases", prior.Current.Digest())) || (err != nil && !errors.Is(err, os.ErrNotExist)) {
			return errors.New("runtime selection differs from the initialized pair")
		}
		for index, digest := range []string{prior.Current.AgentSHA256, prior.Current.HelperSHA256} {
			file, _, err := openTrusted(filepath.Join(source, binaries[index]), maxBinary)
			if err != nil {
				return err
			}
			hash := sha256.New()
			_, err = io.Copy(hash, &contextReader{ctx, file})
			if err = errors.Join(err, file.Close()); err != nil {
				return err
			}
			if hex.EncodeToString(hash.Sum(nil)) != digest {
				return errors.New("installer binaries differ from the initialized runtime pair")
			}
		}
		if err := m.point(prior.Current); err != nil {
			return err
		}
		return syncDir(filepath.Dir(m.dir))
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
	if err := m.point(pair); err != nil {
		return err
	}
	return syncDir(filepath.Dir(m.dir))
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
	return m.activate(ctx, state, pair, auth, expiry, clock)
}

func (m *Manager) activate(ctx context.Context, state State, pair Pair, auth Authorization, expiry time.Time, clock func() (time.Time, error)) error {
	state.Sequence, state.ManifestVersion, state.ManifestSHA256 = auth.Sequence, auth.ManifestVersion, auth.ManifestSHA256
	return m.switchPair(ctx, state, pair, func() error {
		now, err := clock()
		if err != nil || !auth.MatchesTime(now, expiry) {
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
	manifest, err := readTrusted(filepath.Join(incoming, "manifest.json"), artifacttrust.MaxManifestBytes)
	if err != nil {
		return Authorization{}, empty, time.Time{}, err
	}
	manifestSig, err := readTrusted(filepath.Join(incoming, "manifest.json.sig"), ed25519.SignatureSize)
	if err != nil {
		return Authorization{}, empty, time.Time{}, err
	}
	proof := Package{Authorization: raw, AuthorizationSignature: sig, Manifest: manifest, ManifestSignature: manifestSig}
	auth, target, expiry, err := proof.Verify(state.ReleaseKey, state.AuthorizationKey)
	if err != nil {
		return Authorization{}, empty, time.Time{}, err
	}
	if !state.accepts(auth) || !auth.MatchesTime(now, expiry) {
		return Authorization{}, empty, time.Time{}, errors.New("stale, expired or mismatched runtime update authorization")
	}
	return auth, target, expiry, nil
}

func (s State) accepts(auth Authorization) bool {
	return auth.NodeID == s.NodeID && auth.CurrentPair == s.Current.Digest() && auth.Architecture == runtime.GOARCH &&
		auth.Sequence > s.Sequence && (auth.ManifestVersion > s.ManifestVersion ||
		auth.ManifestVersion == s.ManifestVersion && auth.ManifestSHA256 == s.ManifestSHA256)
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
	state.finishRemote(Committed)
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
	if state.Pending != nil {
		if err := m.releaseRecoverySpace(); err != nil {
			return err
		}
	}
	if err := m.point(state.Current); err != nil {
		return err
	}
	if state.Pending != nil {
		state.Pending, state.LastResult = nil, "rolled_back"
		state.finishRemote(RolledBack)
		if err := m.save(state); err != nil {
			return err
		}
	}
	return m.clearTrial()
}

func (s *State) finishRemote(result string) {
	if s.RemoteReceipt != nil && s.RemoteReceipt.Status == Delivered {
		s.RemoteReceipt.Status = result
		s.RemoteReceipt.CurrentPair = s.Current.Digest()
	}
}
