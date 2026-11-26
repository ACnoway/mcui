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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxResponseBytes = 16 << 20
	pageSize         = 10
	installPageSize  = 100
	cacheLifetime    = 10 * time.Minute
	staleLifetime    = 24 * time.Hour
	MaxPage          = 10
	maxAssetSize     = int64(512 << 20)
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

// ReleaseArtifact identifies the fixed upstream asset for an exact Core
// release. SHA256 is taken from GitHub's release API when present, or computed
// from the official asset when the caller does not supply an expected digest.
type ReleaseArtifact struct {
	Core         string
	Version      string
	Architecture string
	Filename     string
	Size         int64
	SHA256       string
	DownloadURL  string
	Prerelease   bool
}

type Source interface {
	List(context.Context) (Snapshot, error)
}

type provider struct {
	id         string
	name       string
	repository string
	apiURL     string
	sourceID   string
}

var providers = []provider{
	{id: "xray", name: "Xray", repository: "XTLS/Xray-core", apiURL: "https://api.github.com/repos/XTLS/Xray-core/releases", sourceID: "github:XTLS/Xray-core"},
	{id: "sing-box", name: "sing-box", repository: "SagerNet/sing-box", apiURL: "https://api.github.com/repos/SagerNet/sing-box/releases", sourceID: "github:SagerNet/sing-box"},
	{id: "mita", name: "mita", repository: "enfein/mieru", apiURL: "https://api.github.com/repos/enfein/mieru/releases", sourceID: "github:enfein/mieru"},
}

type pageCache struct {
	snapshot Snapshot
	expires  time.Time
}

type Client struct {
	httpClient *http.Client
	assetHTTP  *http.Client
	now        func() time.Time

	mu       sync.Mutex
	cached   map[int]pageCache
	fetching map[int]chan struct{}
	xray     pageCache
	xrayBusy chan struct{}
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		assetHTTP: &http.Client{
			Timeout: 15 * time.Minute,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 || !allowedAssetHost(req.URL) {
					return errors.New("Core asset redirect host is not approved")
				}
				return nil
			},
		},
		now:      time.Now,
		cached:   make(map[int]pageCache),
		fetching: make(map[int]chan struct{}),
	}
}

// ListXrayReleases returns up to 100 official Xray releases for installation
// choices. The general catalog remains paged in groups of ten.
func (c *Client) ListXrayReleases(ctx context.Context) (Snapshot, error) {
	if c == nil || c.httpClient == nil || c.now == nil {
		return Snapshot{}, errors.New("release catalog unavailable")
	}
	for {
		c.mu.Lock()
		now := c.now()
		if len(c.xray.snapshot.Cores) != 0 && now.Before(c.xray.expires) {
			out := cloneSnapshot(c.xray.snapshot)
			c.mu.Unlock()
			return out, nil
		}
		if c.xrayBusy != nil {
			wait := c.xrayBusy
			c.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return Snapshot{}, ctx.Err()
			}
		}
		wait := make(chan struct{})
		c.xrayBusy = wait
		old := cloneSnapshot(c.xray.snapshot)
		c.mu.Unlock()

		var fresh Snapshot
		core, err := c.fetchProviderPage(ctx, providers[0], 1, installPageSize)
		if err == nil {
			fresh = Snapshot{RetrievedAt: c.now().UTC(), Page: 1, Cores: []Core{core}}
		}

		c.mu.Lock()
		if err == nil {
			c.xray = pageCache{snapshot: cloneSnapshot(fresh), expires: c.now().Add(cacheLifetime)}
		} else if len(old.Cores) != 0 && c.now().Sub(old.RetrievedAt) <= staleLifetime {
			old.Stale = true
			c.xray = pageCache{snapshot: cloneSnapshot(old), expires: c.now().Add(time.Minute)}
			fresh, err = old, nil
		}
		c.xrayBusy = nil
		close(wait)
		c.mu.Unlock()
		if err != nil {
			return Snapshot{}, err
		}
		return cloneSnapshot(fresh), nil
	}
}

// ResolveRelease verifies that the exact release and architecture asset exist
// in the fixed upstream repository. expectedSHA256 is bound by the signed Core
// management task; GitHub's digest is checked whenever the API supplies one.
func (c *Client) ResolveRelease(ctx context.Context, coreID, version, architecture, expectedSHA256 string) (ReleaseArtifact, error) {
	if c == nil || c.httpClient == nil || c.assetHTTP == nil || !tagPattern.MatchString(version) {
		return ReleaseArtifact{}, errors.New("invalid Core release")
	}
	var p *provider
	for i := range providers {
		if providers[i].id == coreID {
			p = &providers[i]
			break
		}
	}
	if p == nil {
		return ReleaseArtifact{}, errors.New("unsupported Core release")
	}
	if coreID == "xray" && !ValidXrayVersion(version) {
		return ReleaseArtifact{}, errors.New("Xray release must be a stable semantic version")
	}
	filename, err := ExpectedAssetName(coreID, version, architecture)
	if err != nil {
		return ReleaseArtifact{}, err
	}
	endpoint := p.apiURL + "/tags/" + url.PathEscape(version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ReleaseArtifact{}, err
	}
	setGitHubHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ReleaseArtifact{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ReleaseArtifact{}, fmt.Errorf("release source returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxResponseBytes {
		return ReleaseArtifact{}, errors.New("invalid release source response")
	}
	var release upstreamRelease
	if err = json.Unmarshal(body, &release); err != nil || release.TagName != version || release.Draft ||
		(coreID == "xray" && release.Prerelease) || !tagPattern.MatchString(release.TagName) {
		return ReleaseArtifact{}, errors.New("requested Core version is not a published release")
	}
	var found *upstreamAsset
	for i := range release.Assets {
		if release.Assets[i].Name == filename {
			if found != nil {
				return ReleaseArtifact{}, errors.New("release has duplicate architecture assets")
			}
			copy := release.Assets[i]
			found = &copy
		}
	}
	if found == nil || found.Size <= 0 || found.Size > maxAssetSize {
		return ReleaseArtifact{}, errors.New("release has no usable asset for this architecture")
	}
	assetURL, ok := validAssetURL(found.BrowserDownloadURL, *p, version, filename)
	if !ok {
		return ReleaseArtifact{}, errors.New("release asset URL is outside the fixed official repository")
	}
	digest := ""
	if found.Digest != "" {
		if !digestPattern.MatchString(found.Digest) {
			return ReleaseArtifact{}, errors.New("release asset digest is invalid")
		}
		digest = strings.TrimPrefix(found.Digest, "sha256:")
	}
	if expectedSHA256 != "" {
		if !xrayDigest.MatchString(expectedSHA256) || digest != "" && digest != expectedSHA256 {
			return ReleaseArtifact{}, errors.New("release asset digest differs from the signed task")
		}
		digest = expectedSHA256
	} else if digest == "" {
		digest, err = c.hashOfficialAsset(ctx, assetURL, found.Size)
		if err != nil {
			return ReleaseArtifact{}, err
		}
	}
	return ReleaseArtifact{
		Core: coreID, Version: version, Architecture: architecture, Filename: filename,
		Size: found.Size, SHA256: digest, DownloadURL: assetURL, Prerelease: release.Prerelease,
	}, nil
}

func (c *Client) hashOfficialAsset(ctx context.Context, source string, size int64) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "mcui-core-catalog/1")
	resp, err := c.assetHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request == nil || !allowedAssetHost(resp.Request.URL) ||
		(resp.ContentLength >= 0 && resp.ContentLength != size) {
		return "", errors.New("official release asset download was rejected")
	}
	h := sha256.New()
	written, err := io.Copy(h, io.LimitReader(resp.Body, size+1))
	if err != nil || written != size {
		return "", errors.New("official release asset length is invalid")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
	return c.fetchProviderPage(ctx, p, page, pageSize)
}

func (c *Client) fetchProviderPage(ctx context.Context, p provider, page, size int) (Core, error) {
	endpoint, err := url.Parse(p.apiURL)
	if err != nil {
		return Core{}, errors.New("release source endpoint is invalid")
	}
	query := endpoint.Query()
	query.Set("per_page", fmt.Sprint(size))
	query.Set("page", fmt.Sprint(page))
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return Core{}, err
	}
	setGitHubHeaders(req)
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
	if len(releases) > size {
		return Core{}, errors.New("release source returned too many releases")
	}
	maxPages := MaxPage
	if size != pageSize {
		maxPages = 1
	}
	out := Core{ID: p.id, Name: p.name, Repository: p.repository, HasMore: len(releases) == size && page < maxPages, Releases: make([]Release, 0, len(releases))}
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

func setGitHubHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "mcui-core-catalog/1")
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
