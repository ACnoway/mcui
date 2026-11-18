//go:build linux

package xrayruntime

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestXrayArchiveRejectsInvalidInput(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("Xray release platform is unsupported")
	}
	for _, name := range []string{"valid", "wrong digest", "wrong length", "traversal", "absolute", "backslash", "symlink", "device", "setuid", "duplicate", "hook", "oversized", "wrong CPU", "non-ELF", "missing geodata", "canceled"} {
		t.Run(name, func(t *testing.T) {
			entries := testEntries("a")
			switch name {
			case "traversal":
				entries[2].name = "../geoip.dat"
			case "absolute":
				entries[2].name = "/geosite.dat"
			case "backslash":
				entries[2].name = `..\geosite.dat`
			case "symlink":
				entries[2].mode = os.ModeSymlink | 0777
			case "device":
				entries[2].mode = os.ModeDevice | 0666
			case "setuid":
				entries[0].mode |= os.ModeSetuid
			case "duplicate":
				entries = append(entries, entries[0])
			case "hook":
				entries = append(entries, testEntry{"install.sh", []byte("hook"), 0755})
			case "oversized":
				entries = append(entries, testEntry{"README.md", bytes.Repeat([]byte("a"), (1<<20)+1), 0644})
			case "wrong CPU":
				binary.LittleEndian.PutUint16(entries[0].data[18:20], uint16(elf.EM_386))
			case "non-ELF":
				entries[0].data[0] = 0
			case "missing geodata":
				entries[2].name = "LICENSE"
			}
			release, path, size := makeArchive(t, "v26.10.31", entries)
			switch name {
			case "wrong digest":
				release.SHA256 = strings.Repeat("0", 64)
			case "wrong length":
				size--
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if name == "canceled" {
				cancel()
			}
			dir := t.TempDir()
			err := extract(ctx, path, release, size, dir)
			if name != "valid" {
				if err == nil {
					t.Fatal("invalid Xray archive extracted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			files, err := bundleDigests(dir)
			if err != nil || len(files) != 4 {
				t.Fatalf("unexpected extracted files: %v, %v", files, err)
			}
		})
	}
}

func TestLifecycleRollsBackAndRecoversPendingIntent(t *testing.T) {
	ctx := context.Background()
	svc := &fakeService{}
	r := newRuntime(t, svc)
	first := stageFixture(t, r, "v26.10.31")
	svc.dir = r.dir
	applyFixture(t, r, Install, selection{Release: first, Running: true})
	second := stageFixture(t, r, "v26.11.9")
	svc.failedRelease = second.link()
	if err := r.change(ctx, readState(t, r), Upgrade, selection{Release: second, Running: true}); err == nil {
		t.Fatal("accepted a candidate that failed startup")
	}
	state := readState(t, r)
	if state.Current.Release != first || state.Pending != nil || state.LastResult != "rolled_back" || !svc.running {
		t.Fatalf("failed upgrade did not restore LKG: %+v", state)
	}
	point, err := r.readPointer("current")
	if err != nil || point != first.link() {
		t.Fatalf("failed upgrade selected %q: %v", point, err)
	}
	// Simulate interruption after a new selection is switched, but before
	// the trial can be committed. Reopen the journal as a separate invocation.
	second = stageFixture(t, r, "v26.11.9")
	state.Pending = &intent{Action: Upgrade, Next: selection{Release: second, Running: true}}
	if err := r.save(state); err != nil {
		t.Fatal(err)
	}
	if err := r.point("current", second); err != nil {
		t.Fatal(err)
	}
	svc.stopError = errors.New("stop failed")
	if err := r.Recover(ctx); err == nil || !strings.Contains(err.Error(), "ROLLBACK_FAILED") || readState(t, r).Pending == nil {
		t.Fatalf("failed rollback did not retain intent: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openRuntime(r.dir, svc, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	svc.stopError = nil
	if err := reopened.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	state = readState(t, reopened)
	if state.Current.Release != first || state.Pending != nil || state.LastResult != "rolled_back" || !svc.running {
		t.Fatalf("recovery did not restore LKG: %+v", state)
	}
}

func TestLifecycleControlsAndRequiresExplicitDowngrade(t *testing.T) {
	ctx := context.Background()
	svc := &fakeService{}
	r := newRuntime(t, svc)
	svc.dir = r.dir
	first := stageFixture(t, r, "v26.9.31")
	applyFixture(t, r, Install, selection{Release: first, Running: true})
	stale := Release{"v26.10.9", strings.Repeat("1", 64)}
	if err := r.Control(ctx, Stop, stale); err == nil || !svc.running {
		t.Fatalf("unexpected result for stale release: %v", err)
	}
	if err := r.Control(ctx, Stop, first); err != nil || svc.running {
		t.Fatalf("stop: %v", err)
	}
	second := stageFixture(t, r, "v26.10.9")
	starts := svc.starts
	applyFixture(t, r, Upgrade, selection{Release: second})
	if svc.running || svc.starts != starts+1 || readState(t, r).Previous != first {
		t.Fatal("stopped upgrade did not check the candidate and preserve stopped state")
	}
	if err := r.change(ctx, readState(t, r), Upgrade, selection{Release: first}); err == nil {
		t.Fatal("accepted an implicit downgrade")
	}
	applyFixture(t, r, Downgrade, selection{Release: first})
	if err := r.Control(ctx, Start, first); err != nil || !svc.running {
		t.Fatalf("start: %v", err)
	}
	if err := r.Control(ctx, Uninstall, first); err != nil || svc.running {
		t.Fatalf("uninstall: %v", err)
	}
	state := readState(t, r)
	entries, err := os.ReadDir(filepath.Join(r.dir, "versions"))
	if state.Current != (selection{}) || state.Previous != (Release{}) || err != nil || len(entries) != 0 {
		t.Fatalf("uninstall left selection or bundles: %+v, %v, %v", state, entries, err)
	}
}

func TestLifecycleRejectsUntrustedArtifactsAndConcurrentWriters(t *testing.T) {
	r := newRuntime(t, &fakeService{})
	release := Release{"v26.10.31", strings.Repeat("1", 64)}
	if err := r.Apply(context.Background(), Install, release, nil); err == nil {
		t.Fatal("installed without TUF authorization")
	}
	if other, err := openRuntime(r.dir, &fakeService{}, false); err == nil {
		other.Close()
		t.Fatal("accepted a second lifecycle writer")
	}
	if state := readState(t, r); state.Current != (selection{}) || state.Pending != nil {
		t.Fatalf("untrusted artifact changed state: %+v", state)
	}
}

type fakeService struct {
	dir           string
	failedRelease string
	stopError     error
	running       bool
	starts        int
}

func (s *fakeService) preflight(context.Context) error { return nil }

func (s *fakeService) start(context.Context) error {
	s.starts++
	link, err := os.Readlink(filepath.Join(s.dir, "current"))
	if err != nil {
		return err
	}
	if link == s.failedRelease {
		return errors.New("candidate failed to start")
	}
	s.running = true
	return nil
}

func (s *fakeService) stop(context.Context) error {
	if s.stopError != nil {
		return s.stopError
	}
	s.running = false
	return nil
}

func newRuntime(t *testing.T, svc service) *Runtime {
	t.Helper()
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("Xray release platform is unsupported")
	}
	instance, err := openRuntime(filepath.Join(t.TempDir(), "xray"), svc, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return instance
}

func readState(t *testing.T, r *Runtime) Status {
	t.Helper()
	state, err := r.Status()
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func applyFixture(t *testing.T, r *Runtime, action Action, next selection) {
	t.Helper()
	if err := r.change(context.Background(), readState(t, r), action, next); err != nil {
		t.Fatal(err)
	}
}

func stageFixture(t *testing.T, r *Runtime, version string) Release {
	t.Helper()
	release, path, size := makeArchive(t, version, testEntries(version))
	if err := r.stage(context.Background(), release, size, func() (string, error) { return path, nil }); err != nil {
		t.Fatal(err)
	}
	return release
}

type testEntry struct {
	name string
	data []byte
	mode os.FileMode
}

func testEntries(content string) []testEntry {
	binaryData := make([]byte, 64)
	copy(binaryData, elf.ELFMAG)
	binaryData[4], binaryData[5], binaryData[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	machine := elf.EM_X86_64
	if runtime.GOARCH == "arm64" {
		machine = elf.EM_AARCH64
	}
	binary.LittleEndian.PutUint16(binaryData[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(binaryData[18:20], uint16(machine))
	return []testEntry{{"xray", binaryData, 0755}, {"geoip.dat", []byte(content), 0644}, {"geosite.dat", []byte("test"), 0644}}
}

func makeArchive(t *testing.T, version string, entries []testEntry) (Release, string, int64) {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		header.SetMode(entry.mode)
		file, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	path := filepath.Join(t.TempDir(), "asset.zip")
	if err := writeNew(path, data, 0400); err != nil {
		t.Fatal(err)
	}
	return Release{version, fmt.Sprintf("%x", sha256.Sum256(data))}, path, int64(len(data))
}
