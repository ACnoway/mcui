// Package artifacttrust resolves and downloads authorized Core artifacts.
package artifacttrust

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/ACnoway/mcui/internal/tufrepo"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

const (
	maxRootBytes         = 512 << 10
	maxTargetBytes       = int64(512 << 20)
	metadataTimeout      = 8 * time.Second
	artifactTimeout      = 15 * time.Minute
	maxArtifactRedirects = 5
)

var (
	ErrUnavailable     = errors.New("artifact trust unavailable")
	ErrUntrustedTarget = errors.New("artifact target is not trusted")
	ErrChangedTarget   = errors.New("artifact authorization changed")
	ErrDownload        = errors.New("artifact download failed")
)

// Config contains local trust state and the operator-configured TUF metadata
// origin. TrustedRoot must be provisioned out of band; this package never
// bootstraps trust from a network response.
type Config struct {
	MetadataURL        string
	TrustedRoot        []byte
	MetadataDir        string
	RootHistoryDir     string
	TargetCacheDir     string
	TrustedTimeHealthy func() error
	RequireCoreRole    bool
}

// Target is an in-memory authorization result from verified TUF metadata.
// Its unexported fields prevent callers from fabricating a download grant.
type Target struct {
	ArtifactID      string
	Core            string
	Version         string
	OS              string
	Architecture    string
	Filename        string
	ArchiveFormat   string
	BuildOptions    string
	SourceID        string
	ReviewID        string
	SignatureStatus string
	Size            int64
	SHA256          string
	SourceURL       string

	owner                  *Client
	coreManifestVersion    int64
	requireManifestVersion bool
}

type Client struct {
	metadataURL     *url.URL
	trustedRoot     []byte
	metadataDir     string
	rootHistoryDir  string
	targetCacheDir  string
	timeHealthy     func() error
	metadataHTTP    *http.Client
	artifactHTTP    *http.Client
	requireCoreRole bool
	signed          *manifestClient
	backup          *masterBackup
	mu              sync.Mutex
}

type targetCustom struct {
	SchemaVersion   int    `json:"schema_version"`
	ArtifactID      string `json:"artifact_id"`
	Core            string `json:"core"`
	Version         string `json:"version"`
	OS              string `json:"os"`
	Architecture    string `json:"architecture"`
	BuildOptions    string `json:"build_options"`
	ArchiveFormat   string `json:"archive_format"`
	SourceID        string `json:"source_id"`
	ReviewID        string `json:"review_id"`
	SignatureStatus string `json:"upstream_signature_status"`
}

func New(cfg Config) (*Client, error) {
	metadataURL, err := validateMetadataURL(cfg.MetadataURL)
	if err != nil || len(cfg.TrustedRoot) == 0 || len(cfg.TrustedRoot) > maxRootBytes || cfg.TrustedTimeHealthy == nil {
		return nil, ErrUnavailable
	}
	initial, err := trustedmetadata.New(cfg.TrustedRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid offline TUF root", ErrUntrustedTarget)
	}
	if cfg.RequireCoreRole && tufrepo.ValidateRootLayout(initial.Root.Signed) != nil {
		return nil, fmt.Errorf("%w: offline TUF root lacks the MCUI release roles", ErrUntrustedTarget)
	}
	metadataDir, err := preparePrivateDirectory(cfg.MetadataDir)
	if err != nil {
		return nil, fmt.Errorf("prepare TUF metadata cache: %w", err)
	}
	rootHistoryDir, err := preparePrivateDirectory(cfg.RootHistoryDir)
	if err != nil {
		return nil, fmt.Errorf("prepare TUF root history: %w", err)
	}
	targetCacheDir, err := preparePrivateDirectory(cfg.TargetCacheDir)
	if err != nil {
		return nil, fmt.Errorf("prepare artifact cache: %w", err)
	}
	if pathsOverlap(metadataDir, rootHistoryDir) || pathsOverlap(metadataDir, targetCacheDir) || pathsOverlap(rootHistoryDir, targetCacheDir) {
		return nil, errors.New("TUF metadata, root history and artifact cache directories must be disjoint")
	}

	metadataHost := strings.ToLower(metadataURL.Hostname())
	metadataHTTP := &http.Client{
		Timeout: metadataTimeout,
		Transport: newPublicTransport(func(host string) bool {
			return strings.EqualFold(host, metadataHost)
		}),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxArtifactRedirects || !safeHTTPSURL(req.URL) || req.URL.Port() != "" || req.URL.RawQuery != "" || !strings.EqualFold(req.URL.Hostname(), metadataHost) {
				return errors.New("TUF metadata redirect is not approved")
			}
			return nil
		},
	}
	artifactHTTP := &http.Client{
		Timeout: artifactTimeout,
		Transport: newPublicTransport(func(host string) bool {
			return allowedArtifactHost(host)
		}),
		CheckRedirect: checkArtifactRedirect,
	}
	return &Client{
		metadataURL: metadataURL, trustedRoot: append([]byte(nil), cfg.TrustedRoot...),
		metadataDir: metadataDir, rootHistoryDir: rootHistoryDir, targetCacheDir: targetCacheDir,
		timeHealthy: cfg.TrustedTimeHealthy, metadataHTTP: metadataHTTP, artifactHTTP: artifactHTTP,
		requireCoreRole: cfg.RequireCoreRole,
	}, nil
}

// Lookup authorizes the exact local Linux architecture. Release versions and
// source URLs are resolved through fixed project mappings, never from tasks.
func (c *Client) Lookup(ctx context.Context, core, version string) (Target, error) {
	if c == nil || ctx == nil {
		return Target{}, ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lookupLocked(ctx, core, version)
}

// LookupCoreManifest requires exact authorization from the requested
// core-targets version. Download and activation must retain that authorization.
func (c *Client) LookupCoreManifest(ctx context.Context, core, version string, manifestVersion int64) (Target, error) {
	if c == nil || !c.requireCoreRole || manifestVersion <= 0 {
		return Target{}, ErrUntrustedTarget
	}
	target, err := c.Lookup(ctx, core, version)
	if err != nil {
		return Target{}, err
	}
	if target.coreManifestVersion != manifestVersion {
		return Target{}, fmt.Errorf("%w: Core manifest version differs from approval", ErrChangedTarget)
	}
	target.requireManifestVersion = true
	return target, nil
}

// Download refreshes and rechecks the target authorization immediately before
// fetching bytes. The artifact is written to a private content-addressed cache
// only after its exact length and SHA-256 match the current TUF target.
func (c *Client) Download(ctx context.Context, target Target) (string, error) {
	if c == nil || ctx == nil || target.owner != c {
		return "", ErrUntrustedTarget
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	current, err := c.lookupLocked(ctx, target.Core, target.Version)
	if err != nil {
		return "", err
	}
	if !sameTarget(target, current) {
		return "", ErrChangedTarget
	}
	if err = c.checkTime(); err != nil {
		return "", err
	}
	return c.downloadLocked(ctx, current)
}

// Revalidate checks that a staged artifact is still authorized before activation.
func (c *Client) Revalidate(ctx context.Context, target Target) error {
	if c == nil || ctx == nil || target.owner != c {
		return ErrUntrustedTarget
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	current, err := c.lookupLocked(ctx, target.Core, target.Version)
	if err != nil {
		return err
	}
	if !sameTarget(target, current) {
		return ErrChangedTarget
	}
	return c.checkTime()
}

func (c *Client) lookupLocked(ctx context.Context, core, version string) (Target, error) {
	if err := ctx.Err(); err != nil {
		return Target{}, err
	}
	if err := c.checkTime(); err != nil {
		return Target{}, err
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return Target{}, fmt.Errorf("%w: unsupported local platform", ErrUntrustedTarget)
	}
	filename, err := corecatalog.ExpectedAssetName(core, version, runtime.GOARCH)
	if err != nil {
		return Target{}, fmt.Errorf("%w: unsupported Core target", ErrUntrustedTarget)
	}
	if c.signed != nil {
		return c.lookupSigned(ctx, core, version, runtime.GOARCH, filename)
	}
	targetPath := "cores/" + core + "/" + version + "/linux/" + runtime.GOARCH + "/" + filename
	trustedRoot, err := c.latestTrustedRoot()
	if err != nil {
		return Target{}, fmt.Errorf("%w: local TUF root history is invalid", ErrUntrustedTarget)
	}
	updaterConfig, err := config.New(c.metadataURL.String(), trustedRoot)
	if err != nil {
		return Target{}, fmt.Errorf("%w: configure TUF client", ErrUnavailable)
	}
	updaterConfig.LocalMetadataDir = c.metadataDir
	updaterConfig.LocalTargetsDir = c.targetCacheDir
	updaterConfig.MaxRootRotations = 256
	updaterConfig.MaxDelegations = 32
	updaterConfig.RootMaxLength = maxRootBytes
	updaterConfig.TimestampMaxLength = 16 << 10
	updaterConfig.SnapshotMaxLength = 2 << 20
	updaterConfig.TargetsMaxLength = 5 << 20
	updaterConfig.PrefixTargetsWithHash = true
	updaterConfig.UnsafeLocalMode = false
	if err = updaterConfig.SetDefaultFetcherHTTPClient(c.metadataHTTP); err != nil {
		return Target{}, fmt.Errorf("%w: configure TUF transport", ErrUnavailable)
	}
	if err = updaterConfig.SetDefaultFetcherRetry(250*time.Millisecond, 1); err != nil {
		return Target{}, fmt.Errorf("%w: configure TUF retry policy", ErrUnavailable)
	}
	recorder := newRootRecordingFetcher(ctx, updaterConfig.Fetcher, c.requireCoreRole)
	updaterConfig.Fetcher = recorder
	tufClient, err := updater.New(updaterConfig)
	if err != nil {
		return Target{}, fmt.Errorf("%w: load trusted TUF root", ErrUntrustedTarget)
	}
	refreshErr := tufClient.Refresh()
	// A valid rotation must survive failure to fetch or verify a later role.
	// The updater may have fetched a newer root without accepting its signature.
	latestVersion := tufClient.GetTrustedMetadataSet().Root.Signed.Version
	if err = c.persistVerifiedRootChain(trustedRoot, recorder.snapshot(), latestVersion); err != nil {
		return Target{}, fmt.Errorf("%w: persist verified TUF root history", ErrUntrustedTarget)
	}
	if refreshErr != nil {
		return Target{}, fmt.Errorf("%w: refresh trusted TUF metadata", ErrUntrustedTarget)
	}
	if c.requireCoreRole {
		trusted := tufClient.GetTrustedMetadataSet()
		top := trusted.Targets[metadata.TARGETS]
		if top == nil {
			return Target{}, ErrUntrustedTarget
		}
		if err := tufrepo.ValidateDelegations(trusted.Root.Signed, top.Signed); err != nil {
			return Target{}, fmt.Errorf("%w: %v", ErrUntrustedTarget, err)
		}
	}
	if err = ctx.Err(); err != nil {
		return Target{}, err
	}
	files, err := tufClient.GetTargetInfo(targetPath)
	if err != nil || files == nil {
		return Target{}, fmt.Errorf("%w: target missing or delegated metadata invalid", ErrUntrustedTarget)
	}
	var coreManifestVersion int64
	if c.requireCoreRole {
		role := tufClient.GetTrustedMetadataSet().Targets[tufrepo.CoreRole]
		if role == nil || role.Signed.Delegations != nil || role.Signed.Targets[targetPath] != files {
			return Target{}, fmt.Errorf("%w: target lacks direct Core role authorization", ErrUntrustedTarget)
		}
		coreManifestVersion = role.Signed.Version
	}
	if err = ctx.Err(); err != nil {
		return Target{}, err
	}
	target, err := c.targetFromMetadata(files, core, version, runtime.GOARCH, filename)
	target.coreManifestVersion = coreManifestVersion
	return target, err
}

func (c *Client) targetFromMetadata(files *metadata.TargetFiles, core, version, arch, filename string) (Target, error) {
	if files.Path != "cores/"+core+"/"+version+"/linux/"+arch+"/"+filename || files.Length <= 0 || files.Length > maxTargetBytes {
		return Target{}, ErrUntrustedTarget
	}
	digest, ok := files.Hashes["sha256"]
	if !ok || len(digest) != 32 {
		return Target{}, fmt.Errorf("%w: target lacks a valid SHA-256", ErrUntrustedTarget)
	}
	if files.Custom == nil {
		return Target{}, fmt.Errorf("%w: target review metadata missing", ErrUntrustedTarget)
	}
	if err := rejectDuplicateCustomFields(*files.Custom); err != nil {
		return Target{}, fmt.Errorf("%w: invalid target review metadata", ErrUntrustedTarget)
	}
	var custom targetCustom
	decoder := json.NewDecoder(bytes.NewReader(*files.Custom))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&custom); err != nil {
		return Target{}, fmt.Errorf("%w: invalid target review metadata", ErrUntrustedTarget)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Target{}, fmt.Errorf("%w: trailing target review metadata", ErrUntrustedTarget)
	}
	if err := validateCustom(custom, core, version, arch, digest); err != nil {
		return Target{}, err
	}
	sourceURL, err := corecatalog.OfficialAssetURL(core, version, arch)
	if err != nil {
		return Target{}, ErrUntrustedTarget
	}
	return Target{
		ArtifactID: custom.ArtifactID, Core: custom.Core, Version: custom.Version,
		OS: custom.OS, Architecture: custom.Architecture, Filename: filename,
		ArchiveFormat: custom.ArchiveFormat, BuildOptions: custom.BuildOptions,
		SourceID: custom.SourceID, ReviewID: custom.ReviewID,
		SignatureStatus: custom.SignatureStatus, Size: files.Length,
		SHA256: fmt.Sprintf("%x", []byte(digest)), SourceURL: sourceURL,
		owner: c,
	}, nil
}

func (c *Client) checkTime() error {
	if c.timeHealthy == nil || c.timeHealthy() != nil {
		return fmt.Errorf("%w: authenticated time is unavailable", ErrUnavailable)
	}
	return nil
}

func validateMetadataURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || !safeHTTPSURL(u) || u.Port() != "" || !strings.EqualFold(u.Host, u.Hostname()) || u.RawQuery != "" || u.Fragment != "" || net.ParseIP(u.Hostname()) != nil {
		return nil, ErrUnavailable
	}
	if u.Path == "" || strings.Contains(u.Path, "\\") {
		return nil, ErrUnavailable
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return nil, ErrUnavailable
		}
	}
	u.Host = strings.ToLower(u.Host)
	return u, nil
}

func safeHTTPSURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Opaque == "" && u.Fragment == ""
}

func sameTarget(a, b Target) bool {
	return (!a.requireManifestVersion || a.coreManifestVersion == b.coreManifestVersion) &&
		a.ArtifactID == b.ArtifactID && a.Core == b.Core && a.Version == b.Version &&
		a.OS == b.OS && a.Architecture == b.Architecture && a.Filename == b.Filename &&
		a.ArchiveFormat == b.ArchiveFormat && a.BuildOptions == b.BuildOptions &&
		a.SourceID == b.SourceID && a.ReviewID == b.ReviewID &&
		a.SignatureStatus == b.SignatureStatus && a.Size == b.Size &&
		a.SHA256 == b.SHA256 && a.SourceURL == b.SourceURL
}

func preparePrivateDirectory(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("private directory path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	volume := filepath.VolumeName(abs)
	current := volume + string(os.PathSeparator)
	if filepath.Clean(abs) == filepath.Clean(current) {
		return "", errors.New("private storage cannot use a filesystem root")
	}
	relative := strings.TrimPrefix(abs, current)
	parts := strings.Split(relative, string(os.PathSeparator))
	for index, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			if err = os.Mkdir(current, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				return "", err
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", errors.New("private path contains a non-directory or symbolic link")
		}
		if index == len(parts)-1 && info.Mode().Perm() != 0700 {
			return "", errors.New("private directory must have mode 0700")
		}
	}
	return abs, nil
}

func pathsOverlap(first, second string) bool {
	first = filepath.Clean(first)
	second = filepath.Clean(second)
	firstRelative, err := filepath.Rel(first, second)
	if err != nil {
		return true
	}
	secondRelative, err := filepath.Rel(second, first)
	if err != nil {
		return true
	}
	return withinPath(firstRelative) || withinPath(secondRelative)
}

func withinPath(relative string) bool {
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)))
}
