package master

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/ACnoway/mcui/internal/store"
)

type fixedCoreCatalog struct {
	snapshot corecatalog.Snapshot
	err      error
	calls    int
}

type fixedCoreBackups struct {
	manifest corecatalog.BackupManifest
	err      error
	calls    int
}

func (f *fixedCoreBackups) Snapshot() (corecatalog.BackupManifest, error) {
	f.calls++
	return f.manifest, f.err
}

func (f *fixedCoreCatalog) List(context.Context) (corecatalog.Snapshot, error) {
	f.calls++
	return f.snapshot, f.err
}

func (f *fixedCoreCatalog) ListPage(_ context.Context, page int) (corecatalog.Snapshot, error) {
	f.calls++
	out := f.snapshot
	out.Page = page
	return out, f.err
}

func TestCoreReleasesRequiresAdminSession(t *testing.T) {
	s, _ := newCoreCatalogTestServer(t)
	source := &fixedCoreCatalog{snapshot: corecatalog.Snapshot{Cores: []corecatalog.Core{}}}
	s.coreCatalog = source

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/cores/releases", nil)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized || source.calls != 0 {
		t.Fatalf("unauthenticated catalog request status=%d calls=%d", response.Code, source.calls)
	}
}

func TestCoreReleasesReturnsAuthenticatedCatalog(t *testing.T) {
	s, st := newCoreCatalogTestServer(t)
	token, csrf := "session-catalog", "csrf-catalog"
	seedAdminSession(t, st, store.Admin{Role: "auditor", NodeGroups: []string{"g1"}}, token, csrf, time.Now().Unix())
	snapshot := corecatalog.Snapshot{
		RetrievedAt: time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC),
		Cores:       []corecatalog.Core{{ID: "xray", Name: "Xray", Repository: "XTLS/Xray-core", Releases: []corecatalog.Release{{Version: "v1.2.3", URL: "https://github.com/XTLS/Xray-core/releases/tag/v1.2.3", Assets: []corecatalog.Asset{}}}}},
	}
	source := &fixedCoreCatalog{snapshot: snapshot}
	s.coreCatalog = source

	response := requestAsAdmin(t, s.Handler(), http.MethodGet, "http://example.com/api/v1/admin/cores/releases", nil, token, "")
	if response.Code != http.StatusOK || source.calls != 1 {
		t.Fatalf("catalog request status=%d calls=%d body=%s", response.Code, source.calls, response.Body.String())
	}
	var got corecatalog.Snapshot
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Cores) != 1 || got.Cores[0].ID != "xray" || got.Cores[0].Releases[0].Version != "v1.2.3" {
		t.Fatalf("unexpected catalog response: %+v", got)
	}
}

func TestCoreReleasesHidesUpstreamFailureDetails(t *testing.T) {
	s, st := newCoreCatalogTestServer(t)
	token, csrf := "session-catalog-fail", "csrf-catalog-fail"
	seedAdminSession(t, st, store.Admin{Role: "auditor", NodeGroups: []string{"g1"}}, token, csrf, time.Now().Unix())
	s.coreCatalog = &fixedCoreCatalog{err: errors.New("upstream response included sensitive data")}

	response := requestAsAdmin(t, s.Handler(), http.MethodGet, "http://example.com/api/v1/admin/cores/releases", nil, token, "")
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "sensitive data") {
		t.Fatalf("unexpected failure response: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestCoreReleasesValidatesAndServesPages(t *testing.T) {
	s, st := newCoreCatalogTestServer(t)
	token, csrf := "session-catalog-page", "csrf-catalog-page"
	seedAdminSession(t, st, store.Admin{Role: "auditor", NodeGroups: []string{"g1"}}, token, csrf, time.Now().Unix())
	source := &fixedCoreCatalog{snapshot: corecatalog.Snapshot{Cores: []corecatalog.Core{}}}
	s.coreCatalog = source

	badPage := requestAsAdmin(t, s.Handler(), http.MethodGet, "http://example.com/api/v1/admin/cores/releases?page=11", nil, token, "")
	if badPage.Code != http.StatusBadRequest || source.calls != 0 {
		t.Fatalf("invalid page status=%d calls=%d", badPage.Code, source.calls)
	}
	page := requestAsAdmin(t, s.Handler(), http.MethodGet, "http://example.com/api/v1/admin/cores/releases?page=2", nil, token, "")
	if page.Code != http.StatusOK || source.calls != 1 || !strings.Contains(page.Body.String(), `"page":2`) {
		t.Fatalf("valid page status=%d calls=%d body=%s", page.Code, source.calls, page.Body.String())
	}
}

func TestCoreBackupsRequiresAdminSession(t *testing.T) {
	s, _ := newCoreCatalogTestServer(t)
	backups := &fixedCoreBackups{manifest: corecatalog.BackupManifest{SchemaVersion: 1}}
	s.coreBackups = backups

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/cores/backups", nil)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized || backups.calls != 0 {
		t.Fatalf("unauthenticated backup request status=%d calls=%d", response.Code, backups.calls)
	}
}

func TestCoreBackupsReturnsAuthenticatedSnapshot(t *testing.T) {
	s, st := newCoreCatalogTestServer(t)
	token, csrf := "session-core-backups", "csrf-core-backups"
	seedAdminSession(t, st, store.Admin{Role: "auditor", NodeGroups: []string{"g1"}}, token, csrf, time.Now().Unix())
	manifest := corecatalog.BackupManifest{
		SchemaVersion: 1,
		UpdatedAt:     time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC),
		Cores: []corecatalog.BackupCore{{
			ID: "xray", Name: "Xray", Repository: "XTLS/Xray-core", Version: "v1.2.3",
			ReleaseURL: "https://github.com/XTLS/Xray-core/releases/tag/v1.2.3",
			Assets:     []corecatalog.BackupAsset{{Architecture: "amd64", Name: "Xray-linux-64.zip", Size: 10, Digest: "sha256:" + strings.Repeat("a", 64), SourceURL: "https://github.com/XTLS/Xray-core/releases/download/v1.2.3/Xray-linux-64.zip", StorageKey: "blobs/" + strings.Repeat("a", 64)}},
		}},
	}
	backups := &fixedCoreBackups{manifest: manifest}
	s.coreBackups = backups

	response := requestAsAdmin(t, s.Handler(), http.MethodGet, "http://example.com/api/v1/admin/cores/backups", nil, token, "")
	if response.Code != http.StatusOK || backups.calls != 1 {
		t.Fatalf("backup request status=%d calls=%d body=%s", response.Code, backups.calls, response.Body.String())
	}
	var got corecatalog.BackupManifest
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Cores) != 1 || got.Cores[0].Version != "v1.2.3" || len(got.Cores[0].Assets) != 1 {
		t.Fatalf("unexpected backup response: %+v", got)
	}
}

func newCoreCatalogTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "mcui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st, "", ""), st
}
