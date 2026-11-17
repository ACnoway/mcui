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
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	backupManifestName = "manifest.json"
	backupSchema       = 1
	backupMaxAssetSize = int64(512 << 20)
)

type BackupAsset struct {
	Architecture string `json:"architecture"`
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	Digest       string `json:"digest"`
	SourceURL    string `json:"source_url"`
	StorageKey   string `json:"storage_key"`
}

type BackupCore struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Repository string        `json:"repository"`
	Version    string        `json:"version"`
	ReleaseURL string        `json:"release_url"`
	CachedAt   time.Time     `json:"cached_at"`
	Assets     []BackupAsset `json:"assets"`
}

type BackupManifest struct {
	SchemaVersion int          `json:"schema_version"`
	UpdatedAt     time.Time    `json:"updated_at"`
	Cores         []BackupCore `json:"cores"`
}

type BackupSnapshotter interface {
	Snapshot() (BackupManifest, error)
}

type BackupStore struct {
	root       string
	catalog    *Client
	httpClient *http.Client
	now        func() time.Time
	syncMu     sync.Mutex
}

func NewBackupStore(root string, catalog *Client) (*BackupStore, error) {
	if catalog == nil {
		return nil, errors.New("release catalog client is required")
	}
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("Core backup directory is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if abs == filepath.VolumeName(abs)+string(os.PathSeparator) {
		return nil, errors.New("Core backup directory cannot be a filesystem root")
	}
	if err = ensurePrivateDirectory(abs); err != nil {
		return nil, fmt.Errorf("prepare Core backup directory: %w", err)
	}
	client := &http.Client{
		Timeout: 15 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many Core asset redirects")
			}
			if !allowedAssetHost(req.URL) {
				return errors.New("Core asset redirect host is not approved")
			}
			return nil
		},
	}
	return &BackupStore{root: abs, catalog: catalog, httpClient: client, now: time.Now}, nil
}

func (b *BackupStore) Snapshot() (BackupManifest, error) {
	if b == nil {
		return emptyBackupManifest(), errors.New("Core backup store unavailable")
	}
	manifest, err := b.readManifest()
	if err != nil {
		return BackupManifest{}, err
	}
	return cloneBackupManifest(manifest), nil
}

func (b *BackupStore) Sync(ctx context.Context) (BackupManifest, error) {
	if b == nil || b.catalog == nil || b.httpClient == nil || b.now == nil {
		return BackupManifest{}, errors.New("Core backup store unavailable")
	}
	b.syncMu.Lock()
	defer b.syncMu.Unlock()
	if err := ensurePrivateDirectory(b.root); err != nil {
		return BackupManifest{}, err
	}
	blobsDir := filepath.Join(b.root, "blobs")
	if err := ensurePrivateDirectory(blobsDir); err != nil {
		return BackupManifest{}, err
	}
	manifest, err := b.readManifest()
	if err != nil {
		return BackupManifest{}, err
	}
	latest, err := b.latestReleases(ctx)
	if err != nil {
		return manifest, err
	}
	var failures []error
	for _, p := range providers {
		release := latest[p.id]
		assets, assetErr := requiredBackupAssets(p.id, release)
		if assetErr != nil {
			failures = append(failures, assetErr)
			continue
		}
		verifiedAssets := make([]BackupAsset, 0, len(assets))
		for _, asset := range assets {
			backupAsset, verifyErr := b.ensureBackupBlob(ctx, p, release.Version, asset)
			if verifyErr != nil {
				assetErr = verifyErr
				break
			}
			verifiedAssets = append(verifiedAssets, backupAsset)
		}
		if assetErr != nil {
			failures = append(failures, fmt.Errorf("%s %s backup: %w", p.id, release.Version, assetErr))
			if pruneErr := b.prune(manifest); pruneErr != nil {
				failures = append(failures, pruneErr)
			}
			continue
		}
		cachedAt := b.now().UTC()
		if previous, ok := findBackupCore(manifest, p.id); ok && sameBackup(previous, release, verifiedAssets) {
			cachedAt = previous.CachedAt
		}
		record := BackupCore{
			ID: p.id, Name: p.name, Repository: p.repository, Version: release.Version,
			ReleaseURL: release.URL, CachedAt: cachedAt, Assets: verifiedAssets,
		}
		candidate := replaceBackupCore(manifest, record)
		candidate.SchemaVersion = backupSchema
		candidate.UpdatedAt = b.now().UTC()
		if err = b.writeManifest(candidate); err != nil {
			failures = append(failures, err)
			if pruneErr := b.prune(manifest); pruneErr != nil {
				failures = append(failures, pruneErr)
			}
			continue
		}
		manifest = candidate
		if pruneErr := b.prune(manifest); pruneErr != nil {
			failures = append(failures, pruneErr)
		}
	}
	if manifest.UpdatedAt.IsZero() {
		manifest = emptyBackupManifest()
	}
	return cloneBackupManifest(manifest), errors.Join(failures...)
}

func (b *BackupStore) latestReleases(ctx context.Context) (map[string]Release, error) {
	selected := make(map[string]Release, len(providers))
	for page := 1; page <= MaxPage; page++ {
		snapshot, err := b.catalog.ListPage(ctx, page)
		if err != nil {
			return nil, err
		}
		if snapshot.Stale {
			return nil, errors.New("official release directory is stale; preserving existing Core backups")
		}
		for _, core := range snapshot.Cores {
			for _, release := range core.Releases {
				previous, exists := selected[core.ID]
				if !release.Prerelease && (!exists || release.PublishedAt.After(previous.PublishedAt)) {
					selected[core.ID] = release
				}
			}
		}
		if !snapshot.HasMore {
			break
		}
	}
	if len(selected) != len(providers) {
		return nil, errors.New("official release directory does not contain a stable release for each Core")
	}
	return selected, nil
}

func requiredBackupAssets(coreID string, release Release) ([]Asset, error) {
	arches := []string{"amd64", "arm64"}
	assets := make([]Asset, 0, len(arches))
	for _, arch := range arches {
		name, err := expectedAssetName(coreID, release.Version, arch)
		if err != nil {
			return nil, err
		}
		var found *Asset
		for i := range release.Assets {
			if release.Assets[i].Name == name {
				copy := release.Assets[i]
				found = &copy
				break
			}
		}
		if found == nil {
			return nil, fmt.Errorf("%s %s has no approved %s asset %q", coreID, release.Version, arch, name)
		}
		if !digestPattern.MatchString(found.Digest) || found.Size <= 0 || found.Size > backupMaxAssetSize {
			return nil, fmt.Errorf("%s %s asset %q has no usable SHA-256 or has an invalid size", coreID, release.Version, found.Name)
		}
		assets = append(assets, *found)
	}
	return assets, nil
}

func expectedAssetName(coreID, version, arch string) (string, error) {
	plainVersion := strings.TrimPrefix(version, "v")
	switch coreID {
	case "xray":
		switch arch {
		case "amd64":
			return "Xray-linux-64.zip", nil
		case "arm64":
			return "Xray-linux-arm64-v8a.zip", nil
		}
	case "sing-box":
		if arch == "amd64" || arch == "arm64" {
			return fmt.Sprintf("sing-box_%s_linux_%s.deb", plainVersion, arch), nil
		}
	case "mita":
		if arch == "amd64" || arch == "arm64" {
			return fmt.Sprintf("mita_%s_%s.deb", plainVersion, arch), nil
		}
	}
	return "", fmt.Errorf("unsupported Core asset mapping %s/%s", coreID, arch)
}

// ExpectedAssetName returns the fixed official asset filename for a supported
// Core, exact release tag, and Linux architecture. The result must not be
// replaced with a filename supplied by a task or release response.
func ExpectedAssetName(coreID, version, arch string) (string, error) {
	if !tagPattern.MatchString(version) {
		return "", errors.New("invalid Core version")
	}
	return expectedAssetName(coreID, version, arch)
}

// OfficialSourceID returns the stable identifier used in reviewed TUF target
// metadata. It is deliberately separate from any user-provided URL.
func OfficialSourceID(coreID string) (string, error) {
	for _, p := range providers {
		if p.id == coreID {
			return p.sourceID, nil
		}
	}
	return "", errors.New("unsupported Core source")
}

// OfficialAssetURL maps a reviewed Core release to its fixed GitHub release
// asset URL. Redirects are validated separately by the downloader.
func OfficialAssetURL(coreID, version, arch string) (string, error) {
	var p *provider
	for i := range providers {
		if providers[i].id == coreID {
			p = &providers[i]
			break
		}
	}
	if p == nil || !tagPattern.MatchString(version) {
		return "", errors.New("unsupported Core release")
	}
	name, err := expectedAssetName(coreID, version, arch)
	if err != nil {
		return "", err
	}
	return "https://github.com/" + p.repository + "/releases/download/" + version + "/" + name, nil
}

func (b *BackupStore) ensureBackupBlob(ctx context.Context, p provider, version string, asset Asset) (BackupAsset, error) {
	digest := strings.TrimPrefix(asset.Digest, "sha256:")
	if !digestPattern.MatchString(asset.Digest) || asset.Size <= 0 || asset.Size > backupMaxAssetSize {
		return BackupAsset{}, errors.New("invalid upstream digest or asset size")
	}
	if _, ok := validAssetURL(asset.DownloadURL, p, version, asset.Name); !ok {
		return BackupAsset{}, errors.New("asset URL is outside the fixed official release")
	}
	blobsDir := filepath.Join(b.root, "blobs")
	if err := ensurePrivateDirectory(blobsDir); err != nil {
		return BackupAsset{}, err
	}
	blobPath := filepath.Join(blobsDir, digest)
	if info, err := os.Lstat(blobPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return BackupAsset{}, errors.New("existing Core backup blob is not a regular file")
		}
		if err = verifyFile(blobPath, asset.Size, digest); err == nil {
			return backupAssetRecord(asset, digest), nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return BackupAsset{}, err
	}

	temp, err := os.CreateTemp(blobsDir, ".download-")
	if err != nil {
		return BackupAsset{}, err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err = temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return BackupAsset{}, err
	}
	if err = b.downloadAsset(ctx, asset, temp, digest); err != nil {
		_ = temp.Close()
		return BackupAsset{}, err
	}
	if err = temp.Sync(); err != nil {
		_ = temp.Close()
		return BackupAsset{}, err
	}
	if err = temp.Chmod(0444); err != nil {
		_ = temp.Close()
		return BackupAsset{}, err
	}
	if err = temp.Close(); err != nil {
		return BackupAsset{}, err
	}
	if err = verifyFile(tempName, asset.Size, digest); err != nil {
		return BackupAsset{}, err
	}
	if info, statErr := os.Lstat(blobPath); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return BackupAsset{}, errors.New("existing Core backup blob is not a regular file")
		}
		if err = verifyFile(blobPath, asset.Size, digest); err == nil {
			return backupAssetRecord(asset, digest), nil
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return BackupAsset{}, statErr
	}
	if err = os.Rename(tempName, blobPath); err != nil {
		return BackupAsset{}, err
	}
	if err = syncDirectory(blobsDir); err != nil {
		return BackupAsset{}, err
	}
	return backupAssetRecord(asset, digest), nil
}

func (b *BackupStore) downloadAsset(ctx context.Context, asset Asset, dst *os.File, expectedDigest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.DownloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "mcui-core-backup/1")
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("official asset returned HTTP %d", resp.StatusCode)
	}
	if resp.Request == nil || !allowedAssetHost(resp.Request.URL) {
		return errors.New("official asset ended at an unapproved download host")
	}
	if resp.ContentLength >= 0 && resp.ContentLength != asset.Size {
		return errors.New("official asset length does not match the release catalog")
	}
	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(dst, h), io.LimitReader(resp.Body, asset.Size+1))
	if err != nil {
		return err
	}
	if written != asset.Size {
		return errors.New("official asset byte length does not match the release catalog")
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != expectedDigest {
		return errors.New("official asset SHA-256 does not match the release catalog")
	}
	return nil
}

func backupAssetRecord(asset Asset, digest string) BackupAsset {
	arch := "amd64"
	if strings.Contains(asset.Name, "arm64") || strings.HasSuffix(asset.Name, "_arm64.deb") {
		arch = "arm64"
	}
	return BackupAsset{
		Architecture: arch, Name: asset.Name, Size: asset.Size, Digest: "sha256:" + digest,
		SourceURL: asset.DownloadURL, StorageKey: "blobs/" + digest,
	}
}

func allowedAssetHost(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "github.com":
		return u.RawQuery == ""
	case "objects.githubusercontent.com", "release-assets.githubusercontent.com":
		return true
	default:
		return false
	}
}

func verifyFile(path string, expectedSize int64, expectedDigest string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != expectedSize {
		return errors.New("stored Core backup has the wrong file type or size")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, io.LimitReader(f, expectedSize+1)); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != expectedDigest {
		return errors.New("stored Core backup digest mismatch")
	}
	return nil
}

func (b *BackupStore) readManifest() (BackupManifest, error) {
	path := filepath.Join(b.root, backupManifestName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return emptyBackupManifest(), nil
	}
	if err != nil {
		return BackupManifest{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return BackupManifest{}, errors.New("Core backup manifest is not a bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return BackupManifest{}, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, (1<<20)+1))
	decoder.DisallowUnknownFields()
	var manifest BackupManifest
	if err = decoder.Decode(&manifest); err != nil {
		return BackupManifest{}, err
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return BackupManifest{}, errors.New("Core backup manifest has trailing data")
	}
	if err = validateBackupManifest(manifest); err != nil {
		return BackupManifest{}, err
	}
	return manifest, nil
}

func validateBackupManifest(manifest BackupManifest) error {
	if manifest.SchemaVersion != backupSchema || len(manifest.Cores) > len(providers) {
		return errors.New("unsupported Core backup manifest")
	}
	seen := map[string]struct{}{}
	for _, core := range manifest.Cores {
		p, ok := providerByID(core.ID)
		if !ok || !tagPattern.MatchString(core.Version) || core.Repository != p.repository || len(core.Assets) != 2 || !core.CachedAt.IsZero() && core.CachedAt.After(manifest.UpdatedAt) {
			return errors.New("invalid Core backup record")
		}
		if _, exists := seen[core.ID]; exists {
			return errors.New("duplicate Core backup record")
		}
		seen[core.ID] = struct{}{}
		if _, ok := validReleaseURL(core.ReleaseURL, p, core.Version); !ok {
			return errors.New("Core backup release URL is not official")
		}
		arches := map[string]struct{}{}
		for _, asset := range core.Assets {
			if asset.Architecture != "amd64" && asset.Architecture != "arm64" || !validAssetName(asset.Name) || asset.Size <= 0 || asset.Size > backupMaxAssetSize || !digestPattern.MatchString(asset.Digest) || asset.StorageKey != "blobs/"+strings.TrimPrefix(asset.Digest, "sha256:") {
				return errors.New("invalid Core backup asset metadata")
			}
			expectedName, err := expectedAssetName(core.ID, core.Version, asset.Architecture)
			if err != nil || expectedName != asset.Name {
				return errors.New("Core backup asset does not match its fixed Core and architecture")
			}
			if _, ok := validAssetURL(asset.SourceURL, p, core.Version, asset.Name); !ok {
				return errors.New("Core backup source URL is not official")
			}
			if _, exists := arches[asset.Architecture]; exists {
				return errors.New("duplicate Core backup architecture")
			}
			arches[asset.Architecture] = struct{}{}
		}
		if _, amd64 := arches["amd64"]; !amd64 {
			return errors.New("Core backup lacks amd64 asset")
		}
		if _, arm64 := arches["arm64"]; !arm64 {
			return errors.New("Core backup lacks arm64 asset")
		}
	}
	return nil
}

func (b *BackupStore) writeManifest(manifest BackupManifest) error {
	if err := validateBackupManifest(manifest); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(b.root, ".manifest-")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err = temp.Chmod(0600); err == nil {
		_, err = temp.Write(data)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tempName, filepath.Join(b.root, backupManifestName)); err != nil {
		return err
	}
	return syncDirectory(b.root)
}

func (b *BackupStore) prune(manifest BackupManifest) error {
	used := make(map[string]struct{})
	for _, core := range manifest.Cores {
		for _, asset := range core.Assets {
			used[strings.TrimPrefix(asset.StorageKey, "blobs/")] = struct{}{}
		}
	}
	blobsDir := filepath.Join(b.root, "blobs")
	entries, err := os.ReadDir(blobsDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasPrefix(entry.Name(), ".download-") {
			info, err := os.Lstat(filepath.Join(blobsDir, entry.Name()))
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return errors.New("unexpected temporary file in Core backup blob directory")
			}
			if err = os.Remove(filepath.Join(blobsDir, entry.Name())); err != nil {
				return err
			}
			continue
		}
		if _, keep := used[entry.Name()]; keep {
			continue
		}
		info, err := os.Lstat(filepath.Join(blobsDir, entry.Name()))
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("unexpected file in Core backup blob directory")
		}
		if err = os.Remove(filepath.Join(blobsDir, entry.Name())); err != nil {
			return err
		}
	}
	return syncDirectory(blobsDir)
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("Core backup path is not a real directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		if err = os.Chmod(path, 0700); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func emptyBackupManifest() BackupManifest {
	return BackupManifest{SchemaVersion: backupSchema, Cores: []BackupCore{}}
}

func providerByID(id string) (provider, bool) {
	for _, p := range providers {
		if p.id == id {
			return p, true
		}
	}
	return provider{}, false
}

func findBackupCore(manifest BackupManifest, id string) (BackupCore, bool) {
	for _, core := range manifest.Cores {
		if core.ID == id {
			return core, true
		}
	}
	return BackupCore{}, false
}

func replaceBackupCore(manifest BackupManifest, record BackupCore) BackupManifest {
	out := cloneBackupManifest(manifest)
	for i := range out.Cores {
		if out.Cores[i].ID == record.ID {
			out.Cores[i] = record
			return out
		}
	}
	out.Cores = append(out.Cores, record)
	return out
}

func sameBackup(previous BackupCore, release Release, assets []BackupAsset) bool {
	if previous.Version != release.Version || previous.ReleaseURL != release.URL || len(previous.Assets) != len(assets) {
		return false
	}
	for i := range assets {
		if previous.Assets[i].Architecture != assets[i].Architecture || previous.Assets[i].Name != assets[i].Name || previous.Assets[i].SourceURL != assets[i].SourceURL || previous.Assets[i].Digest != assets[i].Digest || previous.Assets[i].Size != assets[i].Size {
			return false
		}
	}
	return true
}

func cloneBackupManifest(in BackupManifest) BackupManifest {
	out := in
	out.Cores = make([]BackupCore, len(in.Cores))
	for i, core := range in.Cores {
		out.Cores[i] = core
		out.Cores[i].Assets = append([]BackupAsset{}, core.Assets...)
	}
	return out
}
