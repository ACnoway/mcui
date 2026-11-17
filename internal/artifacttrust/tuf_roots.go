package artifacttrust

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

type rootRecordingFetcher struct {
	delegate fetcher.Fetcher
	mu       sync.Mutex
	roots    map[int64][]byte
}

func newRootRecordingFetcher(delegate fetcher.Fetcher) *rootRecordingFetcher {
	return &rootRecordingFetcher{delegate: delegate, roots: make(map[int64][]byte)}
}

func (f *rootRecordingFetcher) DownloadFile(urlPath string, maxLength int64, timeout time.Duration) ([]byte, error) {
	data, err := f.delegate.DownloadFile(urlPath, maxLength, timeout)
	if err != nil {
		return data, err
	}
	parsed, err := url.Parse(urlPath)
	if err != nil {
		return data, err
	}
	base := path.Base(parsed.Path)
	if !strings.HasSuffix(base, ".root.json") {
		return data, nil
	}
	versionText := strings.TrimSuffix(base, ".root.json")
	version, err := strconv.ParseInt(versionText, 10, 64)
	if err != nil || version < 1 {
		return data, errors.New("invalid versioned TUF root filename")
	}
	f.mu.Lock()
	f.roots[version] = append([]byte(nil), data...)
	f.mu.Unlock()
	return data, nil
}

func (f *rootRecordingFetcher) snapshot() map[int64][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[int64][]byte, len(f.roots))
	for version, data := range f.roots {
		out[version] = append([]byte(nil), data...)
	}
	return out
}

func (c *Client) latestTrustedRoot() ([]byte, error) {
	trusted, err := trustedmetadata.New(c.trustedRoot)
	if err != nil {
		return nil, err
	}
	latest := append([]byte(nil), c.trustedRoot...)
	entries, err := os.ReadDir(c.rootHistoryDir)
	if err != nil {
		return nil, err
	}
	type rootRecord struct {
		version int64
		path    string
	}
	records := make([]rootRecord, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".root-") {
			info, statErr := os.Lstat(filepath.Join(c.rootHistoryDir, name))
			if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return nil, errors.New("invalid temporary TUF root record")
			}
			if removeErr := os.Remove(filepath.Join(c.rootHistoryDir, name)); removeErr != nil {
				return nil, removeErr
			}
			continue
		}
		if !strings.HasSuffix(name, ".root.json") {
			return nil, errors.New("unknown file in TUF root history")
		}
		versionText := strings.TrimSuffix(name, ".root.json")
		version, parseErr := strconv.ParseInt(versionText, 10, 64)
		if parseErr != nil || version < 1 || strconv.FormatInt(version, 10) != versionText {
			return nil, errors.New("invalid versioned TUF root record")
		}
		filePath := filepath.Join(c.rootHistoryDir, name)
		info, statErr := os.Lstat(filePath)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || info.Size() <= 0 || info.Size() > maxRootBytes {
			return nil, errors.New("TUF root history record has invalid type or permissions")
		}
		records = append(records, rootRecord{version: version, path: filePath})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].version < records[j].version })
	expected := trusted.Root.Signed.Version + 1
	for _, record := range records {
		if record.version != expected {
			return nil, errors.New("TUF root history has a version gap or rollback")
		}
		data, readErr := os.ReadFile(record.path)
		if readErr != nil {
			return nil, readErr
		}
		updated, updateErr := trusted.UpdateRoot(data)
		if updateErr != nil || updated.Signed.Version != record.version {
			return nil, errors.New("TUF root history signature or version is invalid")
		}
		latest = data
		expected++
	}
	return latest, nil
}

func (c *Client) persistVerifiedRootChain(baseRoot []byte, candidates map[int64][]byte) error {
	trusted, err := trustedmetadata.New(baseRoot)
	if err != nil {
		return err
	}
	versions := make([]int64, 0, len(candidates))
	for version := range candidates {
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	expected := trusted.Root.Signed.Version + 1
	for _, version := range versions {
		if version != expected {
			return errors.New("downloaded TUF root chain has a version gap")
		}
		data := candidates[version]
		updated, updateErr := trusted.UpdateRoot(data)
		if updateErr != nil || updated.Signed.Version != version {
			return errors.New("downloaded TUF root failed sequential threshold verification")
		}
		if err = c.persistRootRecord(version, data); err != nil {
			return err
		}
		expected++
	}
	rootPath := filepath.Join(c.metadataDir, metadata.ROOT+".json")
	rootInfo, err := os.Lstat(rootPath)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.Mode().IsRegular() || rootInfo.Size() <= 0 || rootInfo.Size() > maxRootBytes {
		return errors.New("TUF updater did not persist a valid current root")
	}
	currentRoot, err := os.ReadFile(rootPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(currentRoot, lastTrustedRoot(baseRoot, candidates, versions)) {
		return errors.New("TUF updater current root differs from the verified root chain")
	}
	return nil
}

func lastTrustedRoot(baseRoot []byte, candidates map[int64][]byte, versions []int64) []byte {
	if len(versions) == 0 {
		return baseRoot
	}
	return candidates[versions[len(versions)-1]]
}

func (c *Client) persistRootRecord(version int64, data []byte) error {
	if version < 1 || len(data) == 0 || len(data) > maxRootBytes {
		return errors.New("invalid TUF root record")
	}
	name := fmt.Sprintf("%d.root.json", version)
	path := filepath.Join(c.rootHistoryDir, name)
	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSymlink != 0 || !existing.Mode().IsRegular() || existing.Mode().Perm() != 0400 {
			return errors.New("existing TUF root record has invalid type or permissions")
		}
		current, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(current, data) {
			return errors.New("existing TUF root record conflicts with verified metadata")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp, err := os.CreateTemp(c.rootHistoryDir, ".root-")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err = temp.Chmod(0600); err == nil {
		_, err = temp.Write(data)
	}
	if err == nil {
		err = temp.Sync()
	}
	if err == nil {
		err = temp.Chmod(0400)
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Link(tempPath, path); err != nil {
		if existing, readErr := os.ReadFile(path); readErr == nil && bytes.Equal(existing, data) {
			return nil
		}
		return err
	}
	return syncDirectory(c.rootHistoryDir)
}
