package artifacttrust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type manifestTestTransport func(*http.Request) (*http.Response, error)

func (f manifestTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func manifestResponse(req *http.Request, status int, raw []byte) *http.Response {
	return &http.Response{StatusCode: status, Request: req, ContentLength: int64(len(raw)), Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}
}

func manifestFixture(now time.Time, payload []byte) Manifest {
	filename := "Xray-linux-64.zip"
	if runtime.GOARCH == "arm64" {
		filename = "Xray-linux-arm64-v8a.zip"
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(payload))
	return Manifest{SchemaVersion: 1, ManifestVersion: 7, ExpiresAt: now.Add(time.Hour), Artifacts: []Artifact{{
		ArtifactID: "xray-manifest-" + runtime.GOARCH + "-" + digest, Component: "xray", Version: "v26.10.31",
		OS: "linux", Architecture: runtime.GOARCH, Filename: filename, SourceID: "github:XTLS/Xray-core", ArchiveFormat: "zip",
		BuildOptions: "upstream-prebuilt", Length: int64(len(payload)), SHA256: digest, ReviewID: "review-1", SignatureStatus: "not-provided",
	}}}
}

func TestManifestStrictSignatureAndMapping(t *testing.T) {
	now := time.Now().UTC()
	key, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	m := manifestFixture(now, []byte("reviewed release"))
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, raw)
	if _, err := VerifyManifest(raw, signature, key, now); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		raw, sig []byte
		at       time.Time
	}{
		{append(bytes.Clone(raw), '\n'), signature, now},
		{raw, nil, now},
		{raw, signature, m.ExpiresAt},
	} {
		if _, err := VerifyManifest(bad.raw, bad.sig, key, bad.at); !errors.Is(err, ErrUntrustedTarget) {
			t.Fatalf("bad signature, bytes or expiry accepted: %v", err)
		}
	}
	for _, replace := range [][2]string{
		{`"schema_version":1`, `"schema_version":1,"schema_version":1`},
		{`"filename":`, `"url":"https://example.com/","filename":`},
		{`"source_id":"github:XTLS/Xray-core"`, `"source_id":"github:other/project"`},
		{`"os":"linux"`, `"os":"windows"`},
		{`"upstream_signature_status":"not-provided"`, `"upstream_signature_status":"unverified"`},
	} {
		bad := []byte(strings.Replace(string(raw), replace[0], replace[1], 1))
		if _, err := VerifyManifest(bad, ed25519.Sign(private, bad), key, now); !errors.Is(err, ErrUntrustedTarget) {
			t.Fatalf("invalid manifest %s accepted: %v", bad, err)
		}
	}
	m.Artifacts = append(m.Artifacts, m.Artifacts[0])
	duplicate, _ := json.Marshal(m)
	if _, err := ParseManifest(duplicate); !errors.Is(err, ErrUntrustedTarget) {
		t.Fatalf("duplicates accepted: %v", err)
	}
}

func TestPublishedManifestFirstUseAndReenrollment(t *testing.T) {
	now := time.Now().UTC()
	key, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	current := manifestFixture(now, []byte("reviewed release"))
	stage := filepath.Join(t.TempDir(), "manifest")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	online := true
	client := &manifestClient{
		stateDir: stage, key: key, now: func() (time.Time, error) { return now, nil },
		api: &http.Client{Transport: manifestTestTransport(func(req *http.Request) (*http.Response, error) {
			if !online {
				t.Fatal("existing bootstrap state caused a network request")
			}
			return manifestResponse(req, http.StatusOK, []byte(`{"tag_name":"v1.0.0"}`)), nil
		})},
		assets: &http.Client{Transport: manifestTestTransport(func(req *http.Request) (*http.Response, error) {
			raw, err := json.Marshal(current)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(req.URL.Path, ".sig") {
				raw = ed25519.Sign(private, raw)
			}
			return manifestResponse(req, http.StatusOK, raw), nil
		})},
	}
	if _, err := client.refresh(t.Context()); !errors.Is(err, errManifestNotInitialized) {
		t.Fatalf("ordinary refresh initialized missing trust: %v", err)
	}
	if _, err := client.refreshState(t.Context(), true, true); err != nil {
		t.Fatal(err)
	}
	online = false
	if _, err := client.refreshState(t.Context(), true, true); err != nil {
		t.Fatal(err)
	}
	online = true
	current.ManifestVersion--
	if _, err := client.refreshState(t.Context(), true, false); !errors.Is(err, ErrUntrustedTarget) {
		t.Fatalf("accepted a signed rollback after bootstrapping: %v", err)
	}
}

func TestSignedRefreshPinsReleaseAndSurvivesReopen(t *testing.T) {
	now := time.Now().UTC()
	key, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("reviewed release")
	baseline := manifestFixture(now, payload)
	current := baseline
	current.Artifacts = append([]Artifact(nil), baseline.Artifacts...)
	var observed []string
	var unavailable bool
	var wrongBytes bool
	var badFallback bool
	stage := filepath.Join(t.TempDir(), "manifest")
	got := func(m Manifest) ([]byte, []byte) {
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return raw, ed25519.Sign(private, raw)
	}
	raw, signature := got(baseline)
	if err := InitializeManifestState(stage, raw, signature, key, now); err != nil {
		t.Fatal(err)
	}
	api := &http.Client{Transport: manifestTestTransport(func(req *http.Request) (*http.Response, error) {
		observed = append(observed, req.URL.String())
		if unavailable {
			return manifestResponse(req, http.StatusBadGateway, nil), nil
		}
		return manifestResponse(req, http.StatusOK, []byte(`{"tag_name":"manifest-7","prerelease":false,"draft":false}`)), nil
	})}
	assets := &http.Client{Transport: manifestTestTransport(func(req *http.Request) (*http.Response, error) {
		observed = append(observed, req.URL.String())
		raw, sig := got(current)
		if strings.HasSuffix(req.URL.Path, ".sig") {
			return manifestResponse(req, http.StatusOK, sig), nil
		}
		return manifestResponse(req, http.StatusOK, raw), nil
	})}
	cache := filepath.Join(stage, "artifacts")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	newClient := func() *Client {
		return &Client{
			signed:          &manifestClient{stateDir: stage, key: key, now: func() (time.Time, error) { return now, nil }, api: api, assets: assets},
			requireCoreRole: true, targetCacheDir: cache, timeHealthy: func() error { return nil },
			artifactHTTP: &http.Client{Transport: manifestTestTransport(func(req *http.Request) (*http.Response, error) {
				if wrongBytes {
					return manifestResponse(req, http.StatusOK, bytes.Repeat([]byte("x"), len(payload))), nil
				}
				return manifestResponse(req, http.StatusNotFound, nil), nil
			})},
			backup: &masterBackup{url: "https://master.test" + BackupEndpoint, http: &http.Client{Transport: manifestTestTransport(func(req *http.Request) (*http.Response, error) {
				var in BackupRequest
				if req.Method != http.MethodPost || req.URL.Path != BackupEndpoint || json.NewDecoder(req.Body).Decode(&in) != nil ||
					len(in.LeaseID) != 32 || in.Length != int64(len(payload)) {
					t.Fatal("fallback did not carry the exact lease and requested size")
				}
				body := payload
				if badFallback {
					body = bytes.Repeat([]byte("x"), len(payload))
				}
				return manifestResponse(req, http.StatusOK, body), nil
			})}},
		}
	}
	client := newClient()
	version := baseline.Artifacts[0].Version
	target, err := client.LookupCoreManifest(t.Context(), "xray", version, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(observed) != 3 || observed[0] != latestManifestRelease ||
		observed[1] != manifestReleasePrefix+"manifest-7/manifest.json" || observed[2] != observed[1]+".sig" {
		t.Fatalf("manifest and signature did not come from one fixed release: %v", observed)
	}
	ctx := WithInstallLease(t.Context(), []byte(`{"signed":true}`), strings.Repeat("a", 32))
	wrongBytes = true
	if _, err := client.Download(ctx, target); !errors.Is(err, ErrDownload) {
		t.Fatalf("corrupted official bytes accepted: %v", err)
	}
	wrongBytes = false
	badFallback = true
	if _, err := client.Download(ctx, target); !errors.Is(err, ErrDownload) {
		t.Fatalf("corrupted backup bytes accepted: %v", err)
	}
	badFallback = false
	path, err := client.Download(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(path); err != nil || !bytes.Equal(raw, payload) {
		t.Fatalf("verified backup differs from authorized artifact: %v", err)
	}
	unavailable = true
	if _, err := client.Download(ctx, target); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cached artifact permitted without refreshing manifest: %v", err)
	}
	unavailable = false
	current.ExpiresAt = current.ExpiresAt.Add(time.Second)
	if err := client.Revalidate(ctx, target); !errors.Is(err, ErrUntrustedTarget) {
		t.Fatalf("replacement bytes for same version accepted: %v", err)
	}
	current.ManifestVersion++
	current.Artifacts = []Artifact{}
	if err := client.Revalidate(ctx, target); !errors.Is(err, ErrUntrustedTarget) {
		t.Fatalf("revoked artifact accepted: %v", err)
	}
	current = baseline
	if _, err := newClient().Lookup(ctx, "xray", version); !errors.Is(err, ErrUntrustedTarget) {
		t.Fatalf("reopened client accepted manifest rollback: %v", err)
	}
	current.ManifestVersion += 2
	if err := SuspendManifestState(stage); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Lookup(ctx, "xray", version); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("recovery hold was ignored: %v", err)
	}
	raw, signature = got(current)
	if err := InitializeManifestState(stage, raw, signature, key, now); err != nil {
		t.Fatal(err)
	}
	if _, err := client.LookupCoreManifest(context.Background(), "xray", version, current.ManifestVersion); err != nil {
		t.Fatal(err)
	}
}
