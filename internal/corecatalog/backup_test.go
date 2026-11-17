package corecatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type backupFixture struct {
	mu          sync.Mutex
	version     string
	failName    string
	corruptName string
	assetsByURL map[string][]byte
	apiCalls    int
	assetCalls  int
	clock       time.Time
}

func newBackupFixture(t *testing.T, version string) (*BackupStore, *backupFixture) {
	t.Helper()
	fixture := &backupFixture{version: version, assetsByURL: map[string][]byte{}, clock: time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)}
	catalog := NewClient()
	catalog.now = func() time.Time {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		return fixture.clock
	}
	catalog.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		fixture.mu.Lock()
		fixture.apiCalls++
		version := fixture.version
		fixture.mu.Unlock()
		var p provider
		for _, candidate := range providers {
			if req.URL.Path == "/repos/"+candidate.repository+"/releases" {
				p = candidate
				break
			}
		}
		if p.id == "" || req.URL.Query().Get("page") != "1" || req.URL.Query().Get("per_page") != fmt.Sprint(pageSize) {
			return nil, fmt.Errorf("unexpected catalog request: %s", req.URL)
		}
		release := upstreamRelease{
			TagName: version, Name: version, HTMLURL: "https://github.com/" + p.repository + "/releases/tag/" + version,
			PublishedAt: "2026-11-10T00:00:00Z",
			Assets:      []upstreamAsset{},
		}
		for _, arch := range []string{"amd64", "arm64"} {
			name, err := expectedAssetName(p.id, version, arch)
			if err != nil {
				return nil, err
			}
			data := []byte(p.id + "/" + version + "/" + arch)
			sum := sha256.Sum256(data)
			downloadURL := "https://github.com/" + p.repository + "/releases/download/" + version + "/" + name
			fixture.mu.Lock()
			fixture.assetsByURL[downloadURL] = data
			fixture.mu.Unlock()
			release.Assets = append(release.Assets, upstreamAsset{
				Name: name, Size: int64(len(data)), BrowserDownloadURL: downloadURL, Digest: "sha256:" + hex.EncodeToString(sum[:]),
			})
		}
		body, err := json.Marshal([]upstreamRelease{release})
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))), Request: req}, nil
	})}
	store, err := NewBackupStore(filepath.Join(t.TempDir(), "core-backups"), catalog)
	if err != nil {
		t.Fatal(err)
	}
	store.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		fixture.mu.Lock()
		fixture.assetCalls++
		data, ok := fixture.assetsByURL[req.URL.String()]
		failName, corruptName := fixture.failName, fixture.corruptName
		fixture.mu.Unlock()
		if strings.HasSuffix(req.URL.Path, failName) && failName != "" {
			return nil, errors.New("injected download failure")
		}
		if !ok {
			return nil, fmt.Errorf("unknown fixture asset URL: %s", req.URL)
		}
		payload := append([]byte{}, data...)
		if strings.HasSuffix(req.URL.Path, corruptName) && corruptName != "" {
			if len(payload) != 0 {
				payload[0] ^= 0xff
			}
		}
		headers := make(http.Header)
		headers.Set("Content-Length", fmt.Sprint(len(payload)))
		return &http.Response{StatusCode: http.StatusOK, Header: headers, ContentLength: int64(len(payload)), Body: io.NopCloser(strings.NewReader(string(payload))), Request: req}, nil
	})}
	return store, fixture
}

func TestBackupSyncCachesOneStableVersionPerCoreAndArchitecture(t *testing.T) {
	store, _ := newBackupFixture(t, "v1.2.3")
	manifest, err := store.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Cores) != 3 {
		t.Fatalf("got %d Core backups, want 3", len(manifest.Cores))
	}
	for _, core := range manifest.Cores {
		if core.Version != "v1.2.3" || len(core.Assets) != 2 {
			t.Fatalf("unexpected backup record: %+v", core)
		}
		if core.Assets[0].Architecture != "amd64" || core.Assets[1].Architecture != "arm64" {
			t.Fatalf("unexpected architecture order: %+v", core.Assets)
		}
	}
	entries, err := os.ReadDir(filepath.Join(store.root, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 6 {
		t.Fatalf("got %d cached artifact blobs, want 6", len(entries))
	}
	if _, err = store.Snapshot(); err != nil {
		t.Fatal(err)
	}
}

func TestBackupSyncKeepsOnlyOneVersionAndPreservesPreviousOnFailure(t *testing.T) {
	store, fixture := newBackupFixture(t, "v1.2.3")
	first, err := store.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	fixture.version = "v1.2.4"
	fixture.clock = fixture.clock.Add(11 * time.Minute)
	fixture.failName = "Xray-linux-arm64-v8a.zip"
	fixture.mu.Unlock()
	partial, err := store.Sync(context.Background())
	if err == nil {
		t.Fatal("injected download failure was not reported")
	}
	xray, ok := findBackupCore(partial, "xray")
	if !ok || xray.Version != first.Cores[0].Version {
		t.Fatalf("failed replacement changed the prior Xray backup: %+v", xray)
	}
	for _, core := range partial.Cores {
		if core.ID == "xray" && core.Version != first.Cores[0].Version {
			t.Fatalf("failed Xray replacement changed its prior backup: %+v", core)
		}
		if core.ID != "xray" && core.Version != "v1.2.4" {
			t.Fatalf("successful per-Core replacement was not published: %+v", core)
		}
	}
	entries, readErr := os.ReadDir(filepath.Join(store.root, "blobs"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 6 {
		t.Fatalf("failed replacement left %d blobs, want only the six previous assets", len(entries))
	}
	fixture.mu.Lock()
	fixture.failName = ""
	fixture.mu.Unlock()
	updated, err := store.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, core := range updated.Cores {
		if core.Version != "v1.2.4" {
			t.Fatalf("expected new latest version after successful retry, got %+v", core)
		}
	}
	entries, err = os.ReadDir(filepath.Join(store.root, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 6 {
		t.Fatalf("version replacement retained %d blobs, want only six current assets", len(entries))
	}
}

func TestBackupSyncRejectsWrongDigestAndUnapprovedRedirectHost(t *testing.T) {
	store, fixture := newBackupFixture(t, "v1.2.3")
	fixture.mu.Lock()
	fixture.corruptName = "Xray-linux-64.zip"
	fixture.mu.Unlock()
	manifest, err := store.Sync(context.Background())
	if err == nil {
		t.Fatal("corrupted upstream bytes were accepted")
	}
	if _, ok := findBackupCore(manifest, "xray"); ok {
		t.Fatal("Xray backup was published with a mismatched digest")
	}
	for _, raw := range []string{
		"http://github.com/XTLS/Xray-core/releases/download/v1/x.zip",
		"https://attacker.example/asset?signature=1",
		"https://github.com.evil.example/XTLS/Xray-core/releases/download/v1/x.zip",
	} {
		u, parseErr := url.Parse(raw)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if allowedAssetHost(u) {
			t.Fatalf("unapproved download host was accepted: %s", raw)
		}
	}
}
