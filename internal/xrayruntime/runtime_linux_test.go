//go:build linux

package xrayruntime

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/xrayconfig"
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
	if err := r.change(ctx, readState(t, r), intent{Action: Upgrade, Next: selection{Release: second, Running: true}}); err == nil {
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

func TestRemoteInstallReceiptsAfterReopen(t *testing.T) {
	for _, outcome := range []string{"SUCCEEDED", "ROLLED_BACK"} {
		t.Run(outcome, func(t *testing.T) {
			ctx := t.Context()
			svc := &fakeService{}
			r := newRuntime(t, svc)
			svc.dir = r.dir
			release := stageFixture(t, r, "v26.10.31")
			hash := strings.Repeat("a", 64)
			attempt := intent{Action: Install, Next: selection{Release: release, Running: true}, InstallHash: hash}
			state := readState(t, r)
			if outcome == "SUCCEEDED" {
				if err := r.change(ctx, state, attempt); err != nil {
					t.Fatal(err)
				}
			} else {
				state.Pending = &attempt
				if err := r.save(state); err != nil {
					t.Fatal(err)
				}
				if err := r.point("current", release); err != nil {
					t.Fatal(err)
				}
				svc.running = true
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := openRuntime(r.dir, svc, false)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			starts := svc.starts
			if got, err := reopened.ReconcileTask(ctx, Install, release, strings.Repeat("b", 64)); err == nil || got != "" {
				t.Fatalf("different task got %q, %v", got, err)
			}
			if outcome == "ROLLED_BACK" {
				if readState(t, reopened).Pending == nil || !svc.running {
					t.Fatal("different task modified pending activation")
				}
				svc.stopError = errors.New("stop failed")
				if _, err := reopened.ReconcileTask(ctx, Install, release, hash); err == nil || readState(t, reopened).Pending == nil {
					t.Fatal("failed rollback produced a terminal receipt")
				}
				svc.stopError = nil
			}
			for range 2 {
				if got, err := reopened.ReconcileTask(ctx, Install, release, hash); err != nil || got != outcome {
					t.Fatalf("reconciliation = %q, %v, want %q", got, err, outcome)
				}
			}
			if state := readState(t, reopened); state.Pending != nil || svc.running != (outcome == "SUCCEEDED") || svc.starts != starts {
				t.Fatalf("reconciliation changed activation: %+v, starts=%d", state, svc.starts)
			}
		})
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
	if err := r.change(ctx, readState(t, r), intent{Action: Upgrade, Next: selection{Release: first}}); err == nil {
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

func TestRemoteControlUsesExpectedReleaseAndRecovers(t *testing.T) {
	ctx := t.Context()
	svc := &fakeService{}
	r := newRuntime(t, svc)
	svc.dir = r.dir
	release := stageFixture(t, r, "v26.10.31")
	applyFixture(t, r, Install, selection{Release: release, Running: true})
	stopHash, startHash := strings.Repeat("a", 64), strings.Repeat("b", 64)
	checks := 0
	authorize := func(context.Context) error { checks++; return nil }
	mismatch := Release{Version: release.Version, SHA256: strings.Repeat("c", 64)}
	if outcome, err := r.ControlAuthorized(ctx, Stop, mismatch, stopHash, authorize); err != nil || outcome != "FAILED" || !svc.running || checks != 0 {
		t.Fatalf("stale control changed the service: %q, %v", outcome, err)
	}
	if outcome, err := r.ControlAuthorized(ctx, Stop, release, stopHash, func(context.Context) error {
		return errors.New("lease denied")
	}); err != nil || outcome != "FAILED" || !svc.running || readState(t, r).Pending != nil {
		t.Fatalf("unauthorized stop changed the service: %q, %v", outcome, err)
	}
	if outcome, err := r.ControlAuthorized(ctx, Stop, release, stopHash, authorize); err != nil || outcome != "SUCCEEDED" || svc.running {
		t.Fatalf("stop = %q, %v", outcome, err)
	}
	if outcome, err := r.ReconcileTask(ctx, Start, release, stopHash); err == nil || outcome != "" {
		t.Fatalf("start accepted a stop receipt: %q, %v", outcome, err)
	}
	state := readState(t, r)
	state.Pending = &intent{Action: Start, Next: selection{Release: release, Running: true}, ControlHash: startHash}
	if err := r.save(state); err != nil {
		t.Fatal(err)
	}
	svc.running = true // Interrupted after start and before commit.
	if outcome, err := r.ReconcileTask(ctx, Start, release, startHash); err != nil || outcome != "ROLLED_BACK" || svc.running {
		t.Fatalf("interrupted start recovery = %q, %v", outcome, err)
	}
	if outcome, err := r.ControlAuthorized(ctx, Start, release, strings.Repeat("d", 64), authorize); err != nil || outcome != "SUCCEEDED" || !svc.running || checks != 2 {
		t.Fatalf("start = %q, %v; checks=%d", outcome, err, checks)
	}
}

func TestRemoteVersionChangeRestoresLastGoodRelease(t *testing.T) {
	ctx := t.Context()
	svc := &fakeService{}
	r := newRuntime(t, svc)
	svc.dir = r.dir
	old, oldPath, oldSize := makeArchive(t, "v26.10.31", testEntries("old"))
	if err := r.stage(ctx, old, oldSize, func() (string, error) { return oldPath, nil }); err != nil {
		t.Fatal(err)
	}
	applyFixture(t, r, Install, selection{Release: old, Running: true})
	target, path, size := makeArchive(t, "v26.11.9", testEntries("candidate"))
	trust := &fixtureTrust{target: versionFixture(target, size), path: path}
	authChecks := 0
	authorize := func(context.Context) error { authChecks++; return nil }
	hash := strings.Repeat("a", 64)
	stale := Release{Version: old.Version, SHA256: strings.Repeat("e", 64)}
	if got, err := r.ApplyAuthorized(ctx, Upgrade, stale, target, trust, 3, hash, authorize); err != nil || got != "FAILED" || trust.downloads != 0 {
		t.Fatalf("a stale source started the upgrade: %q, %v, downloads=%d", got, err, trust.downloads)
	}
	svc.failedRelease = target.link()
	if got, err := r.ApplyAuthorized(ctx, Upgrade, old, target, trust, 3, hash, authorize); err != nil || got != "ROLLED_BACK" {
		t.Fatalf("failed candidate = %q, %v", got, err)
	}
	if got, err := r.ReconcileTask(ctx, Upgrade, target, hash); err != nil || got != "ROLLED_BACK" {
		t.Fatalf("upgrade rollback receipt = %q, %v", got, err)
	}
	if state := readState(t, r); state.Current.Release != old || state.Pending != nil || !svc.running || authChecks != 2 {
		t.Fatalf("upgrade did not restore the previous running release: %+v, checks=%d", state, authChecks)
	}
	svc.failedRelease = ""
	if got, err := r.ApplyAuthorized(ctx, Upgrade, old, target, trust, 3, strings.Repeat("b", 64), authorize); err != nil || got != "SUCCEEDED" {
		t.Fatalf("upgrade retry with new authorization = %q, %v", got, err)
	}
	if err := r.Control(ctx, Stop, target); err != nil {
		t.Fatal(err)
	}
	oldTrust := &fixtureTrust{target: versionFixture(old, oldSize), path: oldPath}
	downHash := strings.Repeat("c", 64)
	if got, err := r.ApplyAuthorized(ctx, Downgrade, target, old, oldTrust, 3, downHash, authorize); err != nil || got != "SUCCEEDED" || svc.running {
		t.Fatalf("downgrade did not preserve stopped intent: %q, %v", got, err)
	}
	if got, err := r.ReconcileTask(ctx, Upgrade, old, downHash); err == nil || got != "" {
		t.Fatalf("an upgrade accepted a downgrade receipt: %q, %v", got, err)
	}
	if state := readState(t, r); state.Current.Release != old || state.Previous != target || state.Current.Running {
		t.Fatalf("unexpected downgraded state: %+v", state)
	}
}

func TestRemoteUninstallReceiptBindsRemovedRelease(t *testing.T) {
	ctx := t.Context()
	svc := &fakeService{}
	r := newRuntime(t, svc)
	svc.dir = r.dir
	release := stageFixture(t, r, "v26.10.31")
	applyFixture(t, r, Install, selection{Release: release, Running: true})
	state := readState(t, r)
	hash := strings.Repeat("a", 64)
	state.Pending = &intent{Action: Uninstall, ControlHash: hash}
	if err := r.save(state); err != nil {
		t.Fatal(err)
	}
	if err := r.point("current", Release{}); err != nil {
		t.Fatal(err)
	}
	svc.running = false
	if got, err := r.ReconcileTask(ctx, Uninstall, release, hash); err != nil || got != "ROLLED_BACK" || !svc.running {
		t.Fatalf("interrupted uninstall = %q, %v", got, err)
	}
	hash = strings.Repeat("b", 64)
	if got, err := r.ControlAuthorized(ctx, Uninstall, release, hash, func(context.Context) error { return nil }); err != nil || got != "SUCCEEDED" || svc.running {
		t.Fatalf("uninstall = %q, %v", got, err)
	}
	for range 2 {
		if got, err := r.ReconcileTask(ctx, Uninstall, release, hash); err != nil || got != "SUCCEEDED" {
			t.Fatalf("repeat uninstall receipt = %q, %v", got, err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(r.dir, "versions"))
	if state := readState(t, r); err != nil || len(entries) != 0 || state.Current != (selection{}) || state.Previous != (Release{}) {
		t.Fatalf("uninstall left state or versions: %+v, %v, %v", state, entries, err)
	}
}

type fixtureTrust struct {
	target    artifacttrust.Target
	path      string
	downloads int
}

func versionFixture(release Release, size int64) artifacttrust.Target {
	return artifacttrust.Target{Core: "xray", Version: release.Version, SHA256: release.SHA256, Size: size, ArchiveFormat: "zip", SignatureStatus: "not-provided"}
}

func (f *fixtureTrust) Lookup(context.Context, string, string) (artifacttrust.Target, error) {
	return artifacttrust.Target{}, artifacttrust.ErrUntrustedTarget
}

func (f *fixtureTrust) LookupCoreManifest(_ context.Context, core, version string, manifest int64) (artifacttrust.Target, error) {
	if core != f.target.Core || version != f.target.Version || manifest != 3 {
		return artifacttrust.Target{}, artifacttrust.ErrUntrustedTarget
	}
	return f.target, nil
}

func (f *fixtureTrust) Download(context.Context, artifacttrust.Target) (string, error) {
	f.downloads++
	return f.path, nil
}

func (f *fixtureTrust) Revalidate(context.Context, artifacttrust.Target) error { return nil }

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

func TestControlledConfigKeepsLastGoodBytesOnStartFailure(t *testing.T) {
	if runtime.GOARCH != xrayconfig.Architecture {
		t.Skip("controlled Xray template is not enabled for this architecture")
	}
	ctx := context.Background()
	svc := &fakeService{}
	r := newRuntime(t, svc)
	svc.dir = r.dir
	release := stageFixture(t, r, xrayconfig.Version)
	applyFixture(t, r, Install, selection{Release: release, Running: true})
	policyDir := t.TempDir()
	if err := os.Chmod(policyDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(policyDir, "controlled-inbound.json")
	policy := xrayconfig.Policy{
		ReleaseSHA256: release.SHA256, ListenPort: 1080, Password: strings.Repeat("A", 43),
		DestinationIP: "93.184.216.34", DestinationPort: 8080,
	}
	savePolicy := func() ([]byte, xrayconfig.Reference) {
		t.Helper()
		raw, err := json.Marshal(policy)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		data, ref, err := policy.Render(release.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		return data, ref
	}
	good, first := savePolicy()
	calls := 0
	authorize := func(context.Context) error { calls++; return nil }
	hash := strings.Repeat("a", 64)
	if err := r.configure(ctx, path, release, first, "", 2, hash, authorize); err != nil || calls != 2 {
		t.Fatalf("apply controlled config: %v, authorization calls %d", err, calls)
	}
	if state := readState(t, r); state.Current.Config != first || state.Current.Revision != 2 {
		t.Fatal("first configuration did not commit")
	}
	policy.ListenPort++
	_, second := savePolicy()
	calls = 0
	if err := r.configure(ctx, path, release, first, "", 3, hash, authorize); err == nil || calls != 0 {
		t.Fatal("policy drift did not prevent preflight")
	}
	svc.failedConfig = `"port":1081`
	hash = strings.Repeat("b", 64)
	if err := r.configure(ctx, path, release, second, "", 3, hash, authorize); !errors.Is(err, errRollback) {
		t.Fatalf("failed configuration did not roll back: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(r.dir, "control", "runtime-config.json"))
	if state := readState(t, r); err != nil || string(raw) != string(good) || !svc.running ||
		state.Current.Config != first || state.Current.Revision != 2 || state.ConfigRevision != 3 || state.Pending != nil {
		t.Fatal("rollback lost the last good configuration, service, or highest revision")
	}
	if outcome, err := r.ReconcileTask(ctx, Configure, release, hash); err != nil || outcome != "ROLLED_BACK" {
		t.Fatalf("reconcile configuration: %s, %v", outcome, err)
	}
	if err := r.configure(ctx, path, release, second, "", 3, hash, authorize); err == nil {
		t.Fatal("accepted a consumed configuration revision")
	}
}

func TestManagedConfigRevokesAndRejectsPolicyDrift(t *testing.T) {
	if runtime.GOARCH != xrayconfig.Architecture {
		t.Skip("managed Xray configuration requires amd64")
	}
	ctx := t.Context()
	svc := &fakeService{}
	r := newRuntime(t, svc)
	svc.dir = r.dir
	release := stageFixture(t, r, xrayconfig.Version)
	applyFixture(t, r, Install, selection{Release: release, Running: true})
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "controlled-inbound.json")
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	identity := &xrayconfig.TrojanTLS{
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		PrivateKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
	}
	certDigest, err := xrayconfig.TrojanCertificateDigest(identity.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := strings.Repeat("Q", 43)
	realityKey, err := xrayconfig.RealityPublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicEndpoint := xrayconfig.PublicEndpoint{Address: "93.184.216.35", Port: 443}
	catalog := xrayconfig.LocalCatalog{
		ReleaseSHA256: release.SHA256, Ports: []int{1080, 1081, 1082, 1083}, DestinationIP: "93.184.216.34", DestinationPort: 8080,
		Credentials:   map[string]string{"alice": strings.Repeat("A", 43), "bob": strings.Repeat("E", 43)},
		HTTPPorts:     []int{1081},
		PortProtocols: map[int]string{1082: xrayconfig.VLESSReality, 1083: xrayconfig.Trojan},
		ProtocolCredentials: map[string]map[string]string{
			xrayconfig.VLESSReality: {"alice": "cc2f34e1-8197-4751-b505-c27f9e2d841b:0123456789abcdef"},
			xrayconfig.Trojan:       {"bob": strings.Repeat("M", 43)},
		},
		TrojanTLS: identity, RealityPrivateKey: privateKey,
		PublicEndpoints: map[int]xrayconfig.PublicEndpoint{1082: publicEndpoint},
	}
	save := func() {
		t.Helper()
		raw, err := json.Marshal(catalog)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, catalogFilename), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	save()
	plan := xrayconfig.Plan{
		{Port: 1080, Users: []string{"alice", "bob"}}, {Port: 1081, Protocol: xrayconfig.HTTP, Users: []string{"bob"}},
		{Port: 1082, Protocol: xrayconfig.VLESSReality, RealityPublicKey: realityKey, PublicEndpoint: publicEndpoint, Users: []string{"alice"}},
		{Port: 1083, Protocol: xrayconfig.Trojan, TLSCertSHA256: certDigest, Users: []string{"bob"}},
	}
	data, ref, err := readCandidate(path, release, plan.Encode())
	if err != nil || !ref.Matches(data) {
		t.Fatalf("preview managed configuration: %v", err)
	}
	approve := func(context.Context) error { return nil }
	hash := strings.Repeat("a", 64)
	if err := r.configure(ctx, path, release, ref, plan.Encode(), 2, hash, approve); err != nil {
		t.Fatal(err)
	}
	view := r.Inventory(readState(t, r), "", true)
	if view.Applied == nil || view.Applied.Encode() != plan.Encode() {
		t.Fatal("applied inventory did not preserve the typed authorizations")
	}
	catalog.HTTPPorts = nil
	save()
	if err := r.configure(ctx, path, release, ref, plan.Encode(), 3, hash, approve); err == nil {
		t.Fatal("applied a stale protocol preview")
	}
	catalog.HTTPPorts = []int{1081}
	catalog.Credentials["bob"] = strings.Repeat("I", 43)
	save()
	if err := r.configure(ctx, path, release, ref, plan.Encode(), 3, hash, approve); err == nil {
		t.Fatal("applied a stale credential preview")
	}
	state := readState(t, r)
	if state.Current.Config != ref || state.Current.Revision != 2 || !svc.running {
		t.Fatal("stale preview changed committed state")
	}
	empty := xrayconfig.Plan{}.Encode()
	_, disabled, err := readCandidate(path, release, empty)
	if err != nil {
		t.Fatal(err)
	}
	hash = strings.Repeat("b", 64)
	if err := r.configure(ctx, path, release, disabled, empty, 3, hash, approve); err != nil {
		t.Fatal(err)
	}
	state = readState(t, r)
	view = r.Inventory(state, "", true)
	if state.Current.Config != disabled || state.Current.Revision != 3 || view.Applied == nil || len(*view.Applied) != 0 {
		t.Fatalf("empty plan did not commit as an explicit revocation: %+v", view)
	}
}

type fakeService struct {
	dir           string
	failedRelease string
	stopError     error
	running       bool
	starts        int
	failedConfig  string
}

func (s *fakeService) preflight(context.Context) error { return nil }
func (s *fakeService) checkConfigUnits(context.Context, string, []publishedInbound, bool) error {
	return nil
}

func (s *fakeService) start(context.Context) error {
	s.starts++
	link, err := os.Readlink(filepath.Join(s.dir, "current"))
	if err != nil {
		return err
	}
	if link == s.failedRelease {
		return errors.New("candidate failed to start")
	}
	if s.failedConfig != "" {
		raw, err := os.ReadFile(filepath.Join(s.dir, "control", "runtime-config.json"))
		if err != nil {
			return err
		}
		if strings.Contains(string(raw), s.failedConfig) {
			return errors.New("candidate configuration failed to start")
		}
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
	if err := r.change(context.Background(), readState(t, r), intent{Action: action, Next: next}); err != nil {
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
