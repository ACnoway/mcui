package corecatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxResponseBytes = 8 << 20
	pageSize         = 10
	cacheLifetime    = 10 * time.Minute
	staleLifetime    = 24 * time.Hour
	MaxPage          = 10
)

var (
	tagPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$`)
	assetPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+ -]{0,199}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Asset struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	DownloadURL string `json:"download_url"`
	Digest      string `json:"digest,omitempty"`
}

type Release struct {
	Version     string    `json:"version"`
	Title       string    `json:"title"`
	PublishedAt time.Time `json:"published_at"`
	Prerelease  bool      `json:"prerelease"`
	URL         string    `json:"url"`
	Assets      []Asset   `json:"assets"`
}

type Core struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Repository string    `json:"repository"`
	HasMore    bool      `json:"has_more"`
	Releases   []Release `json:"releases"`
}

type Snapshot struct {
	RetrievedAt time.Time `json:"retrieved_at"`
	Stale       bool      `json:"stale"`
	Page        int       `json:"page"`
	HasMore     bool      `json:"has_more"`
	Cores       []Core    `json:"cores"`
}

type Source interface {
	List(context.Context) (Snapshot, error)
}

type provider struct {
	id         string
	name       string
	repository string
	apiURL     string
}

var providers = []provider{
	{id: "xray", name: "Xray", repository: "XTLS/Xray-core", apiURL: "https://api.github.com/repos/XTLS/Xray-core/releases"},
	{id: "sing-box", name: "sing-box", repository: "SagerNet/sing-box", apiURL: "https://api.github.com/repos/SagerNet/sing-box/releases"},
	{id: "mita", name: "mita", repository: "enfein/mieru", apiURL: "https://api.github.com/repos/enfein/mieru/releases"},
}

type pageCache struct {
	snapshot Snapshot
	expires  time.Time
}

type Client struct {
	httpClient *http.Client
	now        func() time.Time

	mu       sync.Mutex
	cached   map[int]pageCache
	fetching map[int]chan struct{}
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now:      time.Now,
		cached:   make(map[int]pageCache),
		fetching: make(map[int]chan struct{}),
	}
}

func (c *Client) List(ctx context.Context) (Snapshot, error) {
	return c.ListPage(ctx, 1)
}

func (c *Client) ListPage(ctx context.Context, page int) (Snapshot, error) {
	if c == nil || c.httpClient == nil || c.now == nil {
		return Snapshot{}, errors.New("release catalog unavailable")
	}
	if page < 1 || page > MaxPage {
		return Snapshot{}, errors.New("release catalog page out of range")
	}
	for {
		c.mu.Lock()
		now := c.now()
		entry := c.cached[page]
		if len(entry.snapshot.Cores) != 0 && now.Before(entry.expires) {
			out := cloneSnapshot(entry.snapshot)
			c.mu.Unlock()
			return out, nil
		}
		if wait := c.fetching[page]; wait != nil {
			c.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return Snapshot{}, ctx.Err()
			}
		}
		wait := make(chan struct{})
		c.fetching[page] = wait
		old := cloneSnapshot(entry.snapshot)
		c.mu.Unlock()

		fresh, err := c.fetch(ctx, page)

		c.mu.Lock()
		if err == nil {
			c.cached[page] = pageCache{snapshot: cloneSnapshot(fresh), expires: c.now().Add(cacheLifetime)}
		} else if len(old.Cores) != 0 && c.now().Sub(old.RetrievedAt) <= staleLifetime {
			old.Stale = true
			c.cached[page] = pageCache{snapshot: cloneSnapshot(old), expires: c.now().Add(time.Minute)}
			fresh, err = old, nil
		}
		delete(c.fetching, page)
		close(wait)
		c.mu.Unlock()
		if err != nil {
			return Snapshot{}, err
		}
		return cloneSnapshot(fresh), nil
	}
}

func (c *Client) fetch(ctx context.Context, page int) (Snapshot, error) {
	type result struct {
		index int
		core  Core
		err   error
	}
	results := make(chan result, len(providers))
	for i, p := range providers {
		go func(index int, p provider) {
			core, err := c.fetchProvider(ctx, p, page)
			results <- result{index: index, core: core, err: err}
		}(i, p)
	}

	cores := make([]Core, len(providers))
	var failures []error
	for range providers {
		got := <-results
		if got.err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", providers[got.index].id, got.err))
			continue
		}
		cores[got.index] = got.core
	}
	if len(failures) != 0 {
		return Snapshot{}, errors.Join(failures...)
	}
	hasMore := false
	for _, core := range cores {
		hasMore = hasMore || core.HasMore
	}
	return Snapshot{RetrievedAt: c.now().UTC(), Page: page, HasMore: hasMore, Cores: cores}, nil
}

type upstreamRelease struct {
	TagName     string          `json:"tag_name"`
	Name        string          `json:"name"`
	HTMLURL     string          `json:"html_url"`
	Draft       bool            `json:"draft"`
	Prerelease  bool            `json:"prerelease"`
	PublishedAt string          `json:"published_at"`
	Assets      []upstreamAsset `json:"assets"`
}

type upstreamAsset struct {
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Digest             string `json:"digest"`
}

func (c *Client) fetchProvider(ctx context.Context, p provider, page int) (Core, error) {
	endpoint, err := url.Parse(p.apiURL)
	if err != nil {
		return Core{}, errors.New("release source endpoint is invalid")
	}
	query := endpoint.Query()
	query.Set("per_page", fmt.Sprint(pageSize))
	query.Set("page", fmt.Sprint(page))
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return Core{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "mcui-core-catalog/1")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Core{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Core{}, fmt.Errorf("release source returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return Core{}, err
	}
	if len(body) > maxResponseBytes {
		return Core{}, errors.New("release source response is too large")
	}
	trimmedBody := strings.TrimSpace(string(body))
	if len(trimmedBody) == 0 || trimmedBody[0] != '[' {
		return Core{}, errors.New("release source response is not a release list")
	}
	var releases []upstreamRelease
	if err = json.Unmarshal([]byte(trimmedBody), &releases); err != nil {
		return Core{}, errors.New("release source returned invalid JSON")
	}
	if len(releases) > pageSize {
		return Core{}, errors.New("release source returned too many releases")
	}
	out := Core{ID: p.id, Name: p.name, Repository: p.repository, HasMore: len(releases) == pageSize && page < MaxPage, Releases: make([]Release, 0, len(releases))}
	for _, release := range releases {
		if release.Draft || !tagPattern.MatchString(release.TagName) {
			continue
		}
		releaseURL, ok := validReleaseURL(release.HTMLURL, p, release.TagName)
		if !ok {
			continue
		}
		published, err := time.Parse(time.RFC3339, release.PublishedAt)
		if err != nil {
			continue
		}
		assets := make([]Asset, 0, len(release.Assets))
		for _, asset := range release.Assets {
			if !validAssetName(asset.Name) || asset.Size < 0 {
				continue
			}
			assetURL, ok := validAssetURL(asset.BrowserDownloadURL, p, release.TagName, asset.Name)
			if !ok {
				continue
			}
			if asset.Digest != "" && !digestPattern.MatchString(asset.Digest) {
				continue
			}
			assets = append(assets, Asset{Name: asset.Name, Size: asset.Size, DownloadURL: assetURL, Digest: asset.Digest})
		}
		if assets == nil {
			assets = []Asset{}
		}
		title := strings.TrimSpace(release.Name)
		if title == "" {
			title = release.TagName
		}
		out.Releases = append(out.Releases, Release{
			Version: release.TagName, Title: title, PublishedAt: published.UTC(),
			Prerelease: release.Prerelease, URL: releaseURL, Assets: assets,
		})
	}
	sort.SliceStable(out.Releases, func(i, j int) bool {
		return out.Releases[i].PublishedAt.After(out.Releases[j].PublishedAt)
	})
	return out, nil
}

func validReleaseURL(raw string, p provider, tag string) (string, bool) {
	u, ok := validGitHubURL(raw)
	if !ok || u.Path != "/"+p.repository+"/releases/tag/"+tag {
		return "", false
	}
	return u.String(), true
}

func validAssetURL(raw string, p provider, tag, name string) (string, bool) {
	u, ok := validGitHubURL(raw)
	if !ok {
		return "", false
	}
	expected := "/" + p.repository + "/releases/download/" + tag + "/" + name
	if u.Path != expected {
		return "", false
	}
	return u.String(), true
}

func validGitHubURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, "github.com") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, false
	}
	return u, true
}

func validAssetName(name string) bool {
	return name != "." && name != ".." && assetPattern.MatchString(name)
}

func cloneSnapshot(in Snapshot) Snapshot {
	out := in
	out.Cores = make([]Core, len(in.Cores))
	for i, core := range in.Cores {
		out.Cores[i] = core
		out.Cores[i].Releases = make([]Release, len(core.Releases))
		for j, release := range core.Releases {
			out.Cores[i].Releases[j] = release
			out.Cores[i].Releases[j].Assets = append([]Asset{}, release.Assets...)
		}
	}
	return out
}
