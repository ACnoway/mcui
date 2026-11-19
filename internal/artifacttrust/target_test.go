package artifacttrust

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestManifestPinRequiresExactDelegationVersion(t *testing.T) {
	approved := Target{Core: "xray", Version: "v26.10.31", coreManifestVersion: 7, requireManifestVersion: true}
	for _, version := range []int64{0, 6, 7, 8} {
		current := approved
		current.coreManifestVersion = version
		current.requireManifestVersion = false
		if sameTarget(approved, current) != (version == 7) {
			t.Fatalf("approval for version 7 compared incorrectly to version %d", version)
		}
	}
	current := approved
	approved.requireManifestVersion = false
	current.coreManifestVersion++
	if !sameTarget(approved, current) {
		t.Fatal("a local unpinned operation rejected an unchanged target")
	}
	client := &Client{}
	if _, err := client.LookupCoreManifest(t.Context(), "xray", "v26.10.31", 7); !errors.Is(err, ErrUntrustedTarget) {
		t.Fatalf("accepted a client without independent Core role trust: %v", err)
	}
}

func TestValidateCustomRequiresExactReviewedBinding(t *testing.T) {
	digest := sha256.Sum256([]byte("artifact"))
	custom := validCustom("xray", "v26.10.31", "amd64", digest[:])
	if err := validateCustom(custom, "xray", "v26.10.31", "amd64", digest[:]); err != nil {
		t.Fatalf("valid target metadata rejected: %v", err)
	}

	cases := map[string]func(*targetCustom){
		"wrong core":                 func(value *targetCustom) { value.Core = "sing-box" },
		"wrong version":              func(value *targetCustom) { value.Version = "v26.10.30" },
		"wrong architecture":         func(value *targetCustom) { value.Architecture = "arm64" },
		"unapproved source":          func(value *targetCustom) { value.SourceID = "github:attacker/project" },
		"unpublished build options":  func(value *targetCustom) { value.BuildOptions = "shell-hook" },
		"wrong archive format":       func(value *targetCustom) { value.ArchiveFormat = "tar" },
		"missing upstream signature": func(value *targetCustom) { value.SignatureStatus = "" },
		"path-like artifact id":      func(value *targetCustom) { value.ArtifactID = "../other" },
		"path-like review id":        func(value *targetCustom) { value.ReviewID = "review/1" },
		"unsupported schema":         func(value *targetCustom) { value.SchemaVersion = 2 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := custom
			mutate(&candidate)
			if err := validateCustom(candidate, "xray", "v26.10.31", "amd64", digest[:]); !errors.Is(err, ErrUntrustedTarget) {
				t.Fatalf("validateCustom error=%v, want ErrUntrustedTarget", err)
			}
		})
	}
}

func TestRejectDuplicateAndTrailingCustomJSON(t *testing.T) {
	for _, raw := range []string{
		`{"schema_version":1,"core":"xray","core":"mita"}`,
		`{"schema_version":1} {"core":"xray"}`,
		`[]`,
		`{"schema_version":1} garbage`,
	} {
		if err := rejectDuplicateCustomFields([]byte(raw)); err == nil {
			t.Fatalf("accepted invalid custom metadata %q", raw)
		}
	}
	if err := rejectDuplicateCustomFields([]byte(`{"schema_version":1,"core":"xray"}`)); err != nil {
		t.Fatalf("valid custom metadata rejected: %v", err)
	}
}

func TestTargetFromMetadataBindsPathDigestAndSource(t *testing.T) {
	digest := sha256.Sum256([]byte("artifact"))
	custom := validCustom("xray", "v26.10.31", "amd64", digest[:])
	raw, err := json.Marshal(custom)
	if err != nil {
		t.Fatal(err)
	}
	files := &metadata.TargetFiles{
		Path:   "cores/xray/v26.10.31/linux/amd64/Xray-linux-64.zip",
		Length: 8,
		Hashes: metadata.Hashes{"sha256": metadata.HexBytes(digest[:])},
		Custom: (*json.RawMessage)(&raw),
	}
	client := &Client{}
	target, err := client.targetFromMetadata(files, "xray", "v26.10.31", "amd64", "Xray-linux-64.zip")
	if err != nil {
		t.Fatalf("target rejected: %v", err)
	}
	wantSource, err := corecatalog.OfficialAssetURL("xray", "v26.10.31", "amd64")
	if err != nil || target.SourceURL != wantSource || target.SourceID != "github:XTLS/Xray-core" || target.SHA256 != hex.EncodeToString(digest[:]) || target.Size != 8 || target.owner != client {
		t.Fatalf("unexpected resolved target: %+v", target)
	}

	cases := []struct {
		name   string
		change func(*metadata.TargetFiles)
	}{
		{"wrong path", func(value *metadata.TargetFiles) { value.Path = "cores/mita/v26.10.31/linux/amd64/mita.deb" }},
		{"missing digest", func(value *metadata.TargetFiles) { value.Hashes = nil }},
		{"wrong digest size", func(value *metadata.TargetFiles) { value.Hashes = metadata.Hashes{"sha256": metadata.HexBytes{1}} }},
		{"oversized target", func(value *metadata.TargetFiles) { value.Length = maxTargetBytes + 1 }},
		{"missing custom fields", func(value *metadata.TargetFiles) { value.Custom = nil }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			candidate := *files
			candidate.Hashes = make(metadata.Hashes, len(files.Hashes))
			for name, hash := range files.Hashes {
				candidate.Hashes[name] = append(metadata.HexBytes(nil), hash...)
			}
			test.change(&candidate)
			if _, err := client.targetFromMetadata(&candidate, "xray", "v26.10.31", "amd64", "Xray-linux-64.zip"); !errors.Is(err, ErrUntrustedTarget) {
				t.Fatalf("target error=%v, want ErrUntrustedTarget", err)
			}
		})
	}
}

func TestDownloadCachesOnlyVerifiedContent(t *testing.T) {
	content := []byte("approved test fixture")
	digest := sha256.Sum256(content)
	target := downloadFixture(content, digest)
	client := downloadTestClient(t, content)

	path, err := client.downloadLocked(context.Background(), target)
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(content) {
		t.Fatalf("cached bytes=%q err=%v", got, err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0400 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("cached file mode=%v err=%v", info, err)
	}
	entries, err := os.ReadDir(client.targetCacheDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("cache entries=%v err=%v", entries, err)
	}
}

func TestDownloadRejectsWrongBytesAndCleansStagingFile(t *testing.T) {
	content := []byte("approved test fixture")
	digest := sha256.Sum256(content)
	target := downloadFixture(content, digest)
	client := downloadTestClient(t, []byte("altered test fixture"))
	if _, err := client.downloadLocked(context.Background(), target); !errors.Is(err, ErrDownload) {
		t.Fatalf("download error=%v, want ErrDownload", err)
	}
	entries, err := os.ReadDir(client.targetCacheDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unverified bytes remained in cache: entries=%v err=%v", entries, err)
	}
}

func TestArtifactRedirectPolicy(t *testing.T) {
	initial, err := http.NewRequest(http.MethodGet, "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip", nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		url  string
		via  []*http.Request
		want bool
	}{
		{"approved asset CDN", "https://release-assets.githubusercontent.com/a?token=x", []*http.Request{initial}, true},
		{"approved object CDN", "https://objects.githubusercontent.com/a", []*http.Request{initial}, true},
		{"unapproved host", "https://attacker.example/a", []*http.Request{initial}, false},
		{"insecure HTTP", "http://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip", []*http.Request{initial}, false},
		{"alternate port", "https://release-assets.githubusercontent.com:444/a", []*http.Request{initial}, false},
		{"changed GitHub path", "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/other.zip", []*http.Request{initial}, false},
		{"too many redirects", "https://release-assets.githubusercontent.com/a", []*http.Request{initial, initial, initial, initial, initial, initial}, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, test.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = checkArtifactRedirect(request, test.via)
			if (err == nil) != test.want {
				t.Fatalf("redirect error=%v, want allowed=%t", err, test.want)
			}
		})
	}
}

func TestPublicIPFilter(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":              true,
		"2606:4700:4700::1111": true,
		"127.0.0.1":            false,
		"10.0.0.1":             false,
		"100.64.0.1":           false,
		"169.254.169.254":      false,
		"192.0.2.1":            false,
		"198.18.0.1":           false,
		"2001:db8::1":          false,
		"::1":                  false,
		"":                     false,
	}
	for raw, want := range cases {
		t.Run(raw, func(t *testing.T) {
			ip := net.ParseIP(raw)
			if got := isPublicIP(ip); got != want {
				t.Fatalf("isPublicIP(%q)=%t, want %t", raw, got, want)
			}
		})
	}
}

func TestMetadataURLRequiresPublicHTTPSOriginPath(t *testing.T) {
	for _, raw := range []string{
		"http://updates.example/metadata",
		"https://updates.example:8443/metadata",
		"https://updates.example/metadata?redirect=1",
		"https://user@updates.example/metadata",
		"https://127.0.0.1/metadata",
		"https://updates.example/../metadata",
	} {
		if _, err := validateMetadataURL(raw); err == nil {
			t.Errorf("accepted unsafe metadata URL %q", raw)
		}
	}
	if _, err := validateMetadataURL("https://updates.example/tuf/metadata"); err != nil {
		t.Fatalf("rejected valid metadata URL: %v", err)
	}
}

func TestPreparePrivateDirectoryRejectsLooseModeAndSymlink(t *testing.T) {
	loose := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(loose, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := preparePrivateDirectory(loose); err == nil {
		t.Fatal("accepted a group/world accessible private directory")
	}

	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := preparePrivateDirectory(link); err == nil {
		t.Fatal("accepted a symbolic link as private storage")
	}
}

func TestTargetCannotBeDownloadedByAnotherClient(t *testing.T) {
	client := &Client{}
	_, err := client.Download(context.Background(), Target{Core: "xray", Version: "v26.10.31"})
	if !errors.Is(err, ErrUntrustedTarget) {
		t.Fatalf("unowned target error=%v, want ErrUntrustedTarget", err)
	}
}

func validCustom(core, version, arch string, digest []byte) targetCustom {
	format := "deb"
	if core == "xray" {
		format = "zip"
	}
	sourceID, _ := corecatalog.OfficialSourceID(core)
	return targetCustom{
		SchemaVersion: 1, ArtifactID: artifactID(core, arch, digest), Core: core, Version: version,
		OS: "linux", Architecture: arch, BuildOptions: "upstream-prebuilt",
		ArchiveFormat: format, SourceID: sourceID, ReviewID: "review-2026-001",
		SignatureStatus: "unverified",
	}
}

func downloadFixture(content []byte, digest [sha256.Size]byte) Target {
	source, _ := corecatalog.OfficialAssetURL("xray", "v26.10.31", "amd64")
	return Target{
		ArtifactID: "artifact-001", Core: "xray", Version: "v26.10.31",
		OS: "linux", Architecture: "amd64", Filename: "Xray-linux-64.zip",
		ArchiveFormat: "zip", BuildOptions: "upstream-prebuilt",
		SourceID: "github:XTLS/Xray-core", ReviewID: "review-2026-001",
		SignatureStatus: "unverified", Size: int64(len(content)),
		SHA256: hex.EncodeToString(digest[:]), SourceURL: source,
	}
}

func downloadTestClient(t *testing.T, content []byte) *Client {
	t.Helper()
	cache := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	return &Client{
		targetCacheDir: cache,
		artifactHTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.String() != "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip" {
				return nil, errors.New("unexpected source URL")
			}
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        make(http.Header),
				Body:          io.NopCloser(strings.NewReader(string(content))),
				Request:       request,
				ContentLength: int64(len(content)),
			}, nil
		})},
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
