//go:build linux

package runtimeupdate

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/runtimehealth"
)

type testServices struct {
	dir       string
	ifStarted func(string) error
	running   bool
	calls     int
}

func (s *testServices) Stop(context.Context) error {
	s.calls++
	s.running = false
	return nil
}

func (s *testServices) Start(context.Context) error {
	s.calls++
	link, err := os.Readlink(filepath.Join(s.dir, "current"))
	if err == nil && s.ifStarted != nil {
		err = s.ifStarted(filepath.Base(link))
	}
	s.running = err == nil
	return err
}

func (s *testServices) Healthy(context.Context) error {
	if !s.running {
		return fmt.Errorf("test pair is not ready")
	}
	return nil
}

type updateFixture struct {
	manager  *Manager
	services *testServices
	release  ed25519.PrivateKey
	approve  ed25519.PrivateKey
	now      time.Time
}

func newUpdateFixture(t *testing.T) updateFixture {
	t.Helper()
	if os.Geteuid() != 0 || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("fixture requires a supported Linux root test environment")
	}
	dir := filepath.Join(t.TempDir(), "runtime")
	services := &testServices{dir: dir, running: true}
	manager, err := openManager(dir, true, services)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	release := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	approve := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	source := t.TempDir()
	for _, name := range binaries {
		writeTestFile(t, filepath.Join(source, name), executableFixture("old-"+name))
	}
	if err := manager.bootstrap(t.Context(), "node-test", "v1.0.0", release.Public().(ed25519.PublicKey), approve.Public().(ed25519.PublicKey), source); err != nil {
		t.Fatal(err)
	}
	return updateFixture{manager, services, release, approve, time.Unix(1_800_000_000, 0).UTC()}
}

func (f updateFixture) clock() (time.Time, error) { return f.now, nil }

func (f updateFixture) provision(t *testing.T, version string, sequence, manifestVersion int64) {
	t.Helper()
	state, err := f.manager.Status()
	if err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	for _, name := range binaries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(executableFixture(version + "-" + name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	artifactHash := fmt.Sprintf("%x", sha256.Sum256(data.Bytes()))
	filename := "mcui-runtime-linux-" + runtime.GOARCH + ".zip"
	manifest := artifacttrust.Manifest{SchemaVersion: 1, ManifestVersion: manifestVersion, ExpiresAt: f.now.Add(time.Hour), Artifacts: []artifacttrust.Artifact{{
		ArtifactID: "mcui-runtime-" + runtime.GOARCH + "-" + artifactHash, Component: "mcui-runtime", Version: version, OS: "linux",
		Architecture: runtime.GOARCH, Filename: filename, SourceID: "github:ACnoway/mcui", ArchiveFormat: "zip",
		BuildOptions: "mcui-build:" + strings.Repeat("a", 40), Length: int64(data.Len()), SHA256: artifactHash,
		ReviewID: "runtime-test", SignatureStatus: "not-applicable",
	}}}
	rawManifest := mustJSON(t, manifest)
	auth := Authorization{
		SchemaVersion: 1, StateProtocol: runtimehealth.Protocol, NodeID: state.NodeID, Sequence: sequence, CurrentPair: state.Current.Digest(),
		ManifestVersion: manifestVersion, ManifestSHA256: fmt.Sprintf("%x", sha256.Sum256(rawManifest)), Version: version,
		Architecture: runtime.GOARCH, SHA256: artifactHash, NotBefore: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Minute),
	}
	raw := mustJSON(t, auth)
	sig, err := SignAuthorization(raw, f.approve)
	if err != nil {
		t.Fatal(err)
	}
	incoming := filepath.Join(f.manager.dir, "incoming")
	for name, data := range map[string][]byte{
		filename: data.Bytes(), "manifest.json": rawManifest, "manifest.json.sig": ed25519.Sign(f.release, rawManifest),
		"authorization.json": raw, "authorization.json.sig": sig,
	} {
		writeTestFile(t, filepath.Join(incoming, name), data)
	}
}

func TestPairUpdateRollbackAndRevertRetainWatermarks(t *testing.T) {
	f := newUpdateFixture(t)
	requireStatus(t, f.manager, "v1.0.0", "initialized", 0, 0)
	f.provision(t, "v2.0.0", 1, 7)
	f.services.ifStarted = func(pair string) error {
		state, err := f.manager.Status()
		if err != nil {
			return err
		}
		if state.Pending != nil && pair == state.Pending.Digest() {
			if _, err := os.Stat(filepath.Join(f.manager.dir, runtimehealth.TrialFile)); err != nil {
				t.Fatal("candidate started without the trial gate")
			}
			return fmt.Errorf("candidate cannot start")
		}
		return nil
	}
	if err := f.manager.Apply(t.Context(), f.clock); err == nil {
		t.Fatal("failed candidate committed")
	}
	requireStatus(t, f.manager, "v1.0.0", "rolled_back", 1, 7)
	if !f.services.running {
		t.Fatal("rollback did not restart the previous pair")
	}
	before := f.services.calls
	if err := f.manager.Apply(t.Context(), f.clock); err == nil || f.services.calls != before {
		t.Fatal("replayed authorization affected services")
	}
	f.provision(t, "v2.0.0", 2, 6)
	if err := f.manager.Apply(t.Context(), f.clock); err == nil || f.services.calls != before {
		t.Fatal("an older manifest affected services")
	}
	f.provision(t, "v2.0.0", 2, 8)
	f.services.ifStarted = nil
	if err := f.manager.Apply(t.Context(), f.clock); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, f.manager, "v2.0.0", "committed", 2, 8)
	if err := f.manager.Revert(t.Context()); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, f.manager, "v1.0.0", "committed", 2, 8)
}

func TestBootRestoresCommittedPairWithoutStartingServices(t *testing.T) {
	f := newUpdateFixture(t)
	f.provision(t, "v2.0.0", 1, 7)
	state := requireStatus(t, f.manager, "v1.0.0", "initialized", 0, 0)
	auth, target, _, err := f.manager.authorize(state, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := f.manager.stageArchive(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.setTrial(); err != nil {
		t.Fatal(err)
	}
	state.Pending, state.Sequence, state.ManifestVersion, state.ManifestSHA256 = &candidate, auth.Sequence, auth.ManifestVersion, auth.ManifestSHA256
	if err := f.manager.save(state); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.point(candidate); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openManager(f.services.dir, false, f.services)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.BootRecover(); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, reopened, "v1.0.0", "rolled_back", 1, 7)
	if f.services.calls != 0 {
		t.Fatal("boot recovery called a dependent service")
	}
}

func TestUpdateRejectsWrongApprovalKeyAndCorruptArchive(t *testing.T) {
	f := newUpdateFixture(t)
	f.provision(t, "v2.0.0", 1, 7)
	incoming := filepath.Join(f.manager.dir, "incoming")
	raw, err := os.ReadFile(filepath.Join(incoming, "authorization.json"))
	if err != nil {
		t.Fatal(err)
	}
	bad, err := SignAuthorization(raw, f.release)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(incoming, "authorization.json.sig"), bad)
	if err := f.manager.Apply(t.Context(), f.clock); err == nil || f.services.calls != 0 {
		t.Fatal("release key was allowed to authorize an update")
	}
	f.provision(t, "v2.0.0", 1, 7)
	writeTestFile(t, filepath.Join(incoming, "mcui-runtime-linux-"+runtime.GOARCH+".zip"), []byte("corrupt"))
	if err := f.manager.Apply(t.Context(), f.clock); err == nil || f.services.calls != 0 {
		t.Fatal("corrupt archive changed services")
	}
	requireStatus(t, f.manager, "v1.0.0", "initialized", 0, 0)
}

func requireStatus(t *testing.T, m *Manager, version, result string, sequence, manifest int64) State {
	t.Helper()
	state, err := m.Status()
	if err != nil || state.Current.Version != version || state.LastResult != result || state.Pending != nil ||
		state.Sequence != sequence || state.ManifestVersion != manifest {
		t.Fatalf("state = %+v, %v", state, err)
	}
	link, err := os.Readlink(filepath.Join(m.dir, "current"))
	if err != nil || filepath.Base(link) != state.Current.Digest() {
		t.Fatalf("current link = %q, %v", link, err)
	}
	if _, err := os.Lstat(filepath.Join(m.dir, runtimehealth.TrialFile)); !os.IsNotExist(err) {
		t.Fatalf("trial marker remains: %v", err)
	}
	return state
}

func executableFixture(content string) []byte {
	data := make([]byte, 64)
	copy(data, elf.ELFMAG)
	data[4], data[5], data[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(data[16:18], uint16(elf.ET_EXEC))
	machine := elf.EM_X86_64
	if runtime.GOARCH == "arm64" {
		machine = elf.EM_AARCH64
	}
	binary.LittleEndian.PutUint16(data[18:20], uint16(machine))
	return append(data, []byte(content)...)
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
