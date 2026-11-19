package artifacttrust

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ACnoway/mcui/internal/corecatalog"
)

const (
	latestManifestRelease = "https://api.github.com/repos/ACnoway/mcui/releases/latest"
	manifestReleasePrefix = "https://github.com/ACnoway/mcui/releases/download/"
)

type manifestClient struct {
	stateDir string
	key      ed25519.PublicKey
	now      func() (time.Time, error)
	api      *http.Client
	assets   *http.Client
}

// OpenSignedCore opens the GitHub release stream using separately provisioned
// key material and the caller's own durable, initialized trust state.
func OpenSignedCore(keyPath, stateDir string, now func() (time.Time, error), otherKeys ...ed25519.PublicKey) (*Client, error) {
	if !filepath.IsAbs(stateDir) || now == nil {
		return nil, ErrUnavailable
	}
	key, err := readProvisionedManifestKey(keyPath)
	if err != nil {
		return nil, err
	}
	for _, other := range otherKeys {
		if key.Equal(other) {
			return nil, errors.New("release and task signing keys must be different")
		}
	}
	dir, err := preparePrivateDirectory(stateDir)
	if err != nil {
		return nil, err
	}
	unlock, err := lockManifestState(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if _, err := readManifestState(dir); err != nil {
		return nil, err
	}
	cache, err := preparePrivateDirectory(filepath.Join(dir, "artifacts"))
	if err != nil {
		return nil, err
	}
	transport := newPublicTransport(allowedArtifactHost)
	return &Client{
		targetCacheDir:  cache,
		timeHealthy:     func() error { _, err := now(); return err },
		requireCoreRole: true,
		artifactHTTP:    &http.Client{Timeout: artifactTimeout, Transport: transport, CheckRedirect: checkArtifactRedirect},
		signed: &manifestClient{
			stateDir: dir, key: key, now: now,
			api: &http.Client{
				Timeout:       metadataTimeout,
				Transport:     newPublicTransport(func(host string) bool { return host == "api.github.com" }),
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			},
			assets: &http.Client{Timeout: metadataTimeout, Transport: transport, CheckRedirect: checkArtifactRedirect},
		},
	}, nil
}

func (m *manifestClient) refresh(ctx context.Context) (Manifest, error) {
	unlock, err := lockManifestState(m.stateDir)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: lock release manifest state: %w", ErrUnavailable, err)
	}
	defer unlock()
	if _, err = os.Lstat(filepath.Join(m.stateDir, manifestSuspendedName)); !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, fmt.Errorf("%w: release manifest state requires recovery", ErrUnavailable)
	}
	prior, err := readManifestState(m.stateDir)
	if err != nil {
		return Manifest{}, err
	}
	if now, err := m.now(); err != nil || now.IsZero() {
		return Manifest{}, fmt.Errorf("%w: authenticated time is unavailable", ErrUnavailable)
	}
	metadata, err := fetchManifestPart(ctx, m.api, latestManifestRelease, MaxManifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	var release struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err = json.Unmarshal(metadata, &release); err != nil || release.Draft || release.Prerelease || !manifestTag.MatchString(release.Tag) {
		return Manifest{}, fmt.Errorf("%w: invalid stable release", ErrUnavailable)
	}
	base := manifestReleasePrefix + release.Tag + "/manifest.json"
	raw, err := fetchManifestPart(ctx, m.assets, base, MaxManifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	signature, err := fetchManifestPart(ctx, m.assets, base+".sig", ed25519.SignatureSize)
	if err != nil {
		return Manifest{}, err
	}
	now, err := m.now()
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: authenticated time is unavailable", ErrUnavailable)
	}
	verified, err := VerifyManifest(raw, signature, m.key, now)
	if err != nil {
		return Manifest{}, err
	}
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	if err = advanceManifestState(m.stateDir, prior, stateOf(verified, raw)); err != nil {
		return Manifest{}, err
	}
	return verified, nil
}

func fetchManifestPart(ctx context.Context, client *http.Client, source string, limit int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", "mcui-artifact-client/1")
	if source == latestManifestRelease {
		req.Header.Set("Accept", "application/vnd.github+json")
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch release manifest component", ErrUnavailable)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.ContentLength > int64(limit) {
		return nil, fmt.Errorf("%w: release manifest response rejected (HTTP %d)", ErrUnavailable, res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, int64(limit)+1))
	if err != nil || len(raw) > limit || len(raw) == 0 {
		return nil, fmt.Errorf("%w: invalid release manifest response size", ErrUnavailable)
	}
	return raw, nil
}

func (c *Client) lookupSigned(ctx context.Context, core, version, arch, filename string) (Target, error) {
	m, err := c.signed.refresh(ctx)
	if err != nil {
		return Target{}, err
	}
	for _, a := range m.Artifacts {
		if a.Component != core || a.Version != version || a.Architecture != arch || a.Filename != filename {
			continue
		}
		source, err := corecatalog.OfficialAssetURL(core, version, arch)
		if err != nil {
			return Target{}, ErrUntrustedTarget
		}
		return Target{
			ArtifactID: a.ArtifactID, Core: core, Version: version, OS: a.OS, Architecture: arch,
			Filename: a.Filename, ArchiveFormat: a.ArchiveFormat, BuildOptions: a.BuildOptions, SourceID: a.SourceID,
			ReviewID: a.ReviewID, SignatureStatus: a.SignatureStatus, Size: a.Length, SHA256: a.SHA256, SourceURL: source,
			owner: c, coreManifestVersion: m.ManifestVersion, requireManifestVersion: true,
		}, nil
	}
	return Target{}, fmt.Errorf("%w: artifact %s %s for %s is absent from the current release manifest", ErrUntrustedTarget, core, version, arch)
}

func (c *Client) UsesSignedManifest() bool { return c != nil && c.signed != nil }
