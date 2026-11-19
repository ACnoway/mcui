package artifacttrust

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// OpenProvisionedCore uses an independently distributed trust root and
// separate private state for the service calling it.
func OpenProvisionedCore(rootPath, origin, stateDir string, timeHealthy func() error) (*Client, error) {
	if !filepath.IsAbs(rootPath) || !filepath.IsAbs(stateDir) {
		return nil, ErrUnavailable
	}
	info, err := os.Lstat(rootPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxRootBytes ||
		(runtime.GOOS != "windows" && info.Mode().Perm()&0022 != 0) {
		return nil, errors.New("TUF root must be a bounded regular file protected from untrusted writes")
	}
	file, err := os.Open(rootPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrUnavailable
	}
	root, err := io.ReadAll(io.LimitReader(file, maxRootBytes+1))
	if err != nil {
		return nil, err
	}
	return New(Config{MetadataURL: origin, TrustedRoot: root,
		MetadataDir:     filepath.Join(stateDir, "metadata"),
		RootHistoryDir:  filepath.Join(stateDir, "roots"),
		TargetCacheDir:  filepath.Join(stateDir, "artifacts"),
		RequireCoreRole: true, TrustedTimeHealthy: timeHealthy,
	})
}
