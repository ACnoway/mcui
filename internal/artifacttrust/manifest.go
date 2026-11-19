package artifacttrust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/ACnoway/mcui/internal/corecatalog"
)

const (
	MaxManifestBytes   = 1 << 20
	maxManifestVersion = 9007199254740991
	runtimeSource      = "github:ACnoway/mcui"
)

var manifestTag = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var lowercaseDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var runtimeBuild = regexp.MustCompile(`^mcui-build:[a-f0-9]{40}$`)

type Manifest struct {
	SchemaVersion   int        `json:"schema_version"`
	ManifestVersion int64      `json:"manifest_version"`
	ExpiresAt       time.Time  `json:"expires_at"`
	Artifacts       []Artifact `json:"artifacts"`
}

type Artifact struct {
	ArtifactID      string `json:"artifact_id"`
	Component       string `json:"component"`
	Version         string `json:"version"`
	OS              string `json:"os"`
	Architecture    string `json:"architecture"`
	Filename        string `json:"filename"`
	SourceID        string `json:"source_id"`
	ArchiveFormat   string `json:"archive_format"`
	BuildOptions    string `json:"build_options"`
	Length          int64  `json:"length"`
	SHA256          string `json:"sha256"`
	ReviewID        string `json:"review_id"`
	SignatureStatus string `json:"upstream_signature_status"`
}

// ParseManifest applies the same schema and asset mapping to offline signing
// and node verification. An empty array is valid and withdraws all artifacts.
func ParseManifest(raw []byte) (Manifest, error) {
	var m Manifest
	if len(raw) == 0 || len(raw) > MaxManifestBytes ||
		json.Unmarshal(raw, &m, json.RejectUnknownMembers(true)) != nil ||
		m.SchemaVersion != 1 || m.ManifestVersion < 1 || m.ManifestVersion > maxManifestVersion ||
		m.ExpiresAt.IsZero() || m.Artifacts == nil {
		return Manifest{}, fmt.Errorf("%w: invalid release manifest", ErrUntrustedTarget)
	}
	ids := make(map[string]bool, len(m.Artifacts))
	type selection struct{ component, version, arch string }
	selections := make(map[selection]bool, len(m.Artifacts))
	for _, a := range m.Artifacts {
		key := selection{a.Component, a.Version, a.Architecture}
		if !a.valid() || ids[a.ArtifactID] || selections[key] {
			return Manifest{}, fmt.Errorf("%w: invalid or duplicate release artifact %q", ErrUntrustedTarget, a.ArtifactID)
		}
		ids[a.ArtifactID], selections[key] = true, true
	}
	return m, nil
}

func (a Artifact) valid() bool {
	idPrefix := a.Component + "-"
	if a.Component == "xray" {
		idPrefix = "xray-manifest-"
	}
	if a.OS != "linux" || (a.Architecture != "amd64" && a.Architecture != "arm64") ||
		!manifestTag.MatchString(a.Version) || !lowercaseDigest.MatchString(a.SHA256) ||
		a.ArtifactID != idPrefix+a.Architecture+"-"+a.SHA256 ||
		a.Length <= 0 || a.Length > maxTargetBytes || !reviewIdentifier.MatchString(a.ReviewID) {
		return false
	}
	if a.Component == "mcui-runtime" {
		return a.SourceID == runtimeSource && a.ArchiveFormat == "zip" && runtimeBuild.MatchString(a.BuildOptions) &&
			a.Filename == "mcui-runtime-linux-"+a.Architecture+".zip" && a.SignatureStatus == "not-applicable"
	}
	filename, filenameErr := corecatalog.ExpectedAssetName(a.Component, a.Version, a.Architecture)
	source, sourceErr := corecatalog.OfficialSourceID(a.Component)
	format := "deb"
	if a.Component == "xray" {
		format = "zip"
		if !corecatalog.ValidXrayRelease(a.Version, a.SHA256) {
			return false
		}
	}
	return filenameErr == nil && sourceErr == nil && a.Filename == filename && a.SourceID == source &&
		a.ArchiveFormat == format && a.BuildOptions == "upstream-prebuilt" &&
		(a.SignatureStatus == "verified" || a.SignatureStatus == "not-provided")
}

func VerifyManifest(raw, signature []byte, key ed25519.PublicKey, now time.Time) (Manifest, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytes || len(signature) != ed25519.SignatureSize ||
		len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, raw, signature) {
		return Manifest{}, fmt.Errorf("%w: release manifest signature rejected", ErrUntrustedTarget)
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return Manifest{}, err
	}
	if now.IsZero() || !now.Before(m.ExpiresAt) {
		return Manifest{}, fmt.Errorf("%w: release manifest has expired", ErrUntrustedTarget)
	}
	return m, nil
}

type manifestState struct {
	Version int64  `json:"manifest_version"`
	SHA256  string `json:"sha256"`
}

func (s manifestState) valid() bool {
	return s.Version > 0 && s.Version <= maxManifestVersion && lowercaseDigest.MatchString(s.SHA256)
}

func (s manifestState) accepts(next manifestState) error {
	if next.Version < s.Version || (next.Version == s.Version && next.SHA256 != s.SHA256) {
		return fmt.Errorf("%w: release manifest version rollback or conflicting bytes", ErrUntrustedTarget)
	}
	return nil
}

func stateOf(m Manifest, raw []byte) manifestState {
	digest := sha256.Sum256(raw)
	return manifestState{Version: m.ManifestVersion, SHA256: hex.EncodeToString(digest[:])}
}

var errManifestNotInitialized = errors.New("manifest state is not initialized; provision a verified current manifest")
