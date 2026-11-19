package artifacttrust

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/corecatalog"
)

func (c *Client) downloadLocked(ctx context.Context, target Target) (string, error) {
	digest, err := hex.DecodeString(target.SHA256)
	if err != nil || len(digest) != sha256.Size || target.Size <= 0 || target.Size > maxTargetBytes {
		return "", ErrUntrustedTarget
	}
	path := filepath.Join(c.targetCacheDir, target.SHA256)
	if err = verifyCachedArtifact(path, target.Size, target.SHA256); err == nil {
		return path, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%w: existing content-addressed cache entry is invalid", ErrDownload)
	}
	if target.SourceURL == "" || target.SourceURL != expectedSourceURL(target) {
		return "", ErrUntrustedTarget
	}
	source, unavailable, err := c.openOfficial(ctx, target)
	if err != nil {
		if !unavailable || c.backup == nil {
			return "", err
		}
		backup, backupErr := c.backup.open(ctx, target)
		if backupErr != nil {
			return "", errors.Join(err, backupErr)
		}
		source = backup
	}
	defer source.Close()
	temp, err := os.CreateTemp(c.targetCacheDir, ".download-")
	if err != nil {
		return "", fmt.Errorf("%w: create private staging file", ErrDownload)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err = temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return "", fmt.Errorf("%w: secure staging file", ErrDownload)
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temp, hasher), io.LimitReader(source, target.Size+1))
	if copyErr != nil || written != target.Size || hex.EncodeToString(hasher.Sum(nil)) != target.SHA256 {
		_ = temp.Close()
		return "", fmt.Errorf("%w: downloaded bytes do not match authorized length and SHA-256", ErrDownload)
	}
	if err = temp.Sync(); err == nil {
		err = temp.Chmod(0400)
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", fmt.Errorf("%w: persist verified artifact", ErrDownload)
	}
	if err = verifyCachedArtifact(tempPath, target.Size, target.SHA256); err != nil {
		return "", fmt.Errorf("%w: staged artifact failed revalidation", ErrDownload)
	}
	if err = os.Link(tempPath, path); err != nil {
		if existingErr := verifyCachedArtifact(path, target.Size, target.SHA256); existingErr == nil {
			return path, nil
		}
		return "", fmt.Errorf("%w: publish verified artifact", ErrDownload)
	}
	if err = syncDirectory(c.targetCacheDir); err != nil {
		return "", fmt.Errorf("%w: sync artifact cache directory", ErrDownload)
	}
	return path, nil
}

func (c *Client) openOfficial(ctx context.Context, target Target) (io.ReadCloser, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.SourceURL, nil)
	if err != nil {
		return nil, false, fmt.Errorf("%w: invalid fixed source", ErrDownload)
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "mcui-artifact-client/1")
	res, err := c.artifactHTTP.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("%w: request to fixed official source failed", ErrDownload)
	}
	if res.Request == nil || !allowedArtifactHost(res.Request.URL.Hostname()) {
		_ = res.Body.Close()
		return nil, false, fmt.Errorf("%w: source returned an invalid response", ErrDownload)
	}
	if res.StatusCode != http.StatusOK {
		_ = res.Body.Close()
		retry := res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500
		return nil, retry, fmt.Errorf("%w: official source returned HTTP %d", ErrDownload, res.StatusCode)
	}
	if res.ContentLength >= 0 && res.ContentLength != target.Size {
		_ = res.Body.Close()
		return nil, false, fmt.Errorf("%w: declared length differs from authorized length", ErrDownload)
	}
	return res.Body, false, nil
}

func expectedSourceURL(target Target) string {
	sourceID, err := corecatalog.OfficialSourceID(target.Core)
	if err != nil || sourceID != target.SourceID {
		return ""
	}
	url, err := corecatalog.OfficialAssetURL(target.Core, target.Version, target.Architecture)
	if err != nil {
		return ""
	}
	return url
}

func verifyCachedArtifact(path string, size int64, digest string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != size || info.Mode().Perm() != 0400 {
		return errors.New("cached artifact has unexpected type, size or permissions")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(hasher, io.LimitReader(file, size+1))
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written != size || hex.EncodeToString(hasher.Sum(nil)) != digest {
		return errors.New("cached artifact failed SHA-256 verification")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func checkArtifactRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 || len(via) > maxArtifactRedirects || !safeHTTPSURL(req.URL) || req.URL.Port() != "" || !allowedArtifactHost(req.URL.Hostname()) {
		return errors.New("artifact redirect is not approved")
	}
	if strings.EqualFold(req.URL.Hostname(), "github.com") && (req.URL.RawQuery != "" || req.URL.Path != via[0].URL.Path) {
		return errors.New("GitHub release redirect changed the fixed asset path")
	}
	return nil
}

func allowedArtifactHost(host string) bool {
	switch strings.ToLower(strings.TrimSuffix(host, ".")) {
	case "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com":
		return true
	default:
		return false
	}
}

func newPublicTransport(allowedHost func(string) bool) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ResponseHeaderTimeout: 8 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || port != "443" || !allowedHost(host) || net.ParseIP(host) != nil {
				return nil, errors.New("outbound host or port is not approved")
			}
			addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			dialer := &net.Dialer{}
			var failures []error
			for _, address := range addresses {
				if !isPublicIP(address.IP) {
					continue
				}
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				failures = append(failures, dialErr)
			}
			if len(failures) == 0 {
				return nil, errors.New("outbound hostname did not resolve to a public address")
			}
			return nil, errors.Join(failures...)
		},
	}
}

func isPublicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	blocked := []string{
		"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32",
	}
	address, err := netip.ParseAddr(ip.String())
	if err != nil {
		return false
	}
	for _, value := range blocked {
		prefix := netip.MustParsePrefix(value)
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}
