package corecatalog

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestListUsesFixedOfficialSourcesAndValidatesReleaseLinks(t *testing.T) {
	var calls atomic.Int32
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		if req.URL.Scheme != "https" || req.URL.Host != "api.github.com" || req.Header.Get("User-Agent") != "mcui-core-catalog/1" {
			return nil, fmt.Errorf("unexpected source request: %s %s", req.Method, req.URL)
		}
		var p provider
		for _, candidate := range providers {
			if req.URL.Path == "/repos/"+candidate.repository+"/releases" {
				p = candidate
				break
			}
		}
		if p.id == "" || req.URL.Query().Get("per_page") != fmt.Sprint(pageSize) || req.URL.Query().Get("page") != "1" {
			return nil, fmt.Errorf("unexpected release endpoint: %s", req.URL)
		}
		body := fmt.Sprintf(`[
  {"tag_name":"v1.2.3","name":"Version 1.2.3","html_url":"https://github.com/%s/releases/tag/v1.2.3","draft":false,"prerelease":false,"published_at":"2026-11-01T12:00:00Z","assets":[
    {"name":"core-linux-amd64.zip","size":123,"browser_download_url":"https://github.com/%s/releases/download/v1.2.3/core-linux-amd64.zip","digest":"sha256:%s"},
    {"name":"evil.zip","size":123,"browser_download_url":"https://attacker.example/releases/download/v1.2.3/evil.zip","digest":"sha256:%s"},
    {"name":"bad-digest.zip","size":123,"browser_download_url":"https://github.com/%s/releases/download/v1.2.3/bad-digest.zip","digest":"sha256:broken"}
  ]},
  {"tag_name":"v1.2.2","name":"wrong host","html_url":"https://attacker.example/%s/releases/tag/v1.2.2","draft":false,"prerelease":false,"published_at":"2026-10-01T12:00:00Z","assets":[]},
  {"tag_name":"draft","name":"draft","html_url":"https://github.com/%s/releases/tag/draft","draft":true,"prerelease":false,"published_at":"2026-10-01T12:00:00Z","assets":[]}
]`, p.repository, p.repository, strings.Repeat("a", 64), strings.Repeat("b", 64), p.repository, p.repository, p.repository)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})}

	snapshot, err := client.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Cores) != 3 || calls.Load() != 3 {
		t.Fatalf("unexpected catalog size or request count: cores=%d calls=%d", len(snapshot.Cores), calls.Load())
	}
	for _, core := range snapshot.Cores {
		if len(core.Releases) != 1 || core.Releases[0].Version != "v1.2.3" {
			t.Fatalf("unexpected releases for %s: %+v", core.ID, core.Releases)
		}
		if len(core.Releases[0].Assets) != 1 || core.Releases[0].Assets[0].Digest != "sha256:"+strings.Repeat("a", 64) {
			t.Fatalf("untrusted asset was returned for %s: %+v", core.ID, core.Releases[0].Assets)
		}
	}
}

func TestListCachesAndReturnsIndependentSnapshots(t *testing.T) {
	var calls atomic.Int32
	client := newMockClient(t, &calls, http.StatusOK, nil)
	first, err := client.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first.Cores[0].Releases[0].Assets[0].Name = "changed-by-caller"
	second, err := client.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("cached response made %d source calls, want 3", calls.Load())
	}
	if second.Cores[0].Releases[0].Assets[0].Name == "changed-by-caller" {
		t.Fatal("caller mutation changed the cached catalog")
	}
}

func TestListServesRecentCacheWhenSourcesAreUnavailable(t *testing.T) {
	var calls atomic.Int32
	client := newMockClient(t, &calls, http.StatusOK, nil)
	if _, err := client.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	client.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("unavailable")), Request: req}, nil
	})
	client.mu.Lock()
	entry := client.cached[1]
	entry.expires = time.Time{}
	client.cached[1] = entry
	client.mu.Unlock()

	stale, err := client.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !stale.Stale || len(stale.Cores) != 3 {
		t.Fatalf("expected stale cached catalog, got %+v", stale)
	}
}

func TestListPageBoundsAndCatalogPagination(t *testing.T) {
	var calls atomic.Int32
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		if req.URL.Query().Get("per_page") != fmt.Sprint(pageSize) || req.URL.Query().Get("page") != "2" {
			return nil, fmt.Errorf("unexpected page request: %s", req.URL)
		}
		var p provider
		for _, candidate := range providers {
			if req.URL.Path == "/repos/"+candidate.repository+"/releases" {
				p = candidate
				break
			}
		}
		if p.id == "" {
			return nil, fmt.Errorf("unexpected source path: %s", req.URL.Path)
		}
		releases := make([]upstreamRelease, pageSize)
		for i := range releases {
			tag := fmt.Sprintf("v2.0.%d", i)
			releases[i] = upstreamRelease{
				TagName: tag, Name: tag, HTMLURL: "https://github.com/" + p.repository + "/releases/tag/" + tag,
				PublishedAt: time.Date(2026, 10, 1+i, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
				Assets:      []upstreamAsset{{Name: "artifact.zip", Size: 1, BrowserDownloadURL: "https://github.com/" + p.repository + "/releases/download/" + tag + "/artifact.zip", Digest: "sha256:" + strings.Repeat("d", 64)}},
			}
		}
		body, err := json.Marshal(releases)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))), Request: req}, nil
	})}

	if _, err := client.ListPage(context.Background(), MaxPage+1); err == nil {
		t.Fatal("out-of-range page was accepted")
	}
	page, err := client.ListPage(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if page.Page != 2 || !page.HasMore || calls.Load() != 3 {
		t.Fatalf("unexpected page metadata: page=%d has_more=%t calls=%d", page.Page, page.HasMore, calls.Load())
	}
	for _, core := range page.Cores {
		if !core.HasMore || len(core.Releases) != pageSize {
			t.Fatalf("unexpected per-Core pagination for %s: %+v", core.ID, core)
		}
	}
}

func TestListRejectsOversizeSourceResponse(t *testing.T) {
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", maxResponseBytes+1))), Request: req}, nil
	})}
	if _, err := client.List(context.Background()); err == nil {
		t.Fatal("oversize release response was accepted")
	}
}

func newMockClient(t *testing.T, calls *atomic.Int32, status int, body func(provider) string) *Client {
	t.Helper()
	if body == nil {
		body = func(p provider) string {
			return fmt.Sprintf(`[{"tag_name":"v1.0.0","name":"v1.0.0","html_url":"https://github.com/%s/releases/tag/v1.0.0","draft":false,"prerelease":false,"published_at":"2026-11-01T12:00:00Z","assets":[{"name":"artifact.zip","size":1,"browser_download_url":"https://github.com/%s/releases/download/v1.0.0/artifact.zip","digest":"sha256:%s"}]}]`, p.repository, p.repository, strings.Repeat("c", 64))
		}
	}
	client := NewClient()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		var p provider
		for _, candidate := range providers {
			if req.URL.Path == "/repos/"+candidate.repository+"/releases" {
				p = candidate
				break
			}
		}
		if p.id == "" || req.URL.Query().Get("per_page") != fmt.Sprint(pageSize) || req.URL.Query().Get("page") != "1" {
			return nil, fmt.Errorf("unexpected source path: %s", req.URL.Path)
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body(p))), Request: req}, nil
	})}
	return client
}
