package runtimeupdate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
)

const (
	RemoteEndpoint = "/api/v1/runtime/nodes/"
	MaxPackageJSON = 2 << 20
	MaxArchive     = 256 << 20

	Queued     = "QUEUED"
	Delivered  = "DELIVERED"
	Committed  = "COMMITTED"
	RolledBack = "ROLLED_BACK"
	Rejected   = "REJECTED"
	Expired    = "EXPIRED"
)

type Package struct {
	Authorization          []byte `json:"authorization"`
	AuthorizationSignature []byte `json:"authorization_signature"`
	Manifest               []byte `json:"manifest"`
	ManifestSignature      []byte `json:"manifest_signature"`
}

type Delivery struct {
	ID      string  `json:"id"`
	Package Package `json:"package"`
}

type Receipt struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	CurrentPair string `json:"current_pair_sha256"`
}

func ValidDigest(value string) bool { return digestPattern.MatchString(value) }

func (p Package) ID() string {
	return digest(p.Authorization)
}

func digest(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// Verify binds the independent proofs and target. A caller must also check the
// returned time window with its trusted clock before using the target.
func (p Package) Verify(releaseKey, updateKey ed25519.PublicKey) (Authorization, artifacttrust.Artifact, time.Time, error) {
	var target artifacttrust.Artifact
	auth, err := parseAuthorization(p.Authorization)
	if err != nil {
		return Authorization{}, target, time.Time{}, err
	}
	if releaseKey.Equal(updateKey) {
		return Authorization{}, target, time.Time{}, errors.New("runtime signing keys must be independent")
	}
	auth, err = verifyAuthorization(p.Authorization, p.AuthorizationSignature, updateKey, auth.NotBefore)
	if err != nil {
		return Authorization{}, target, time.Time{}, err
	}
	manifest, err := artifacttrust.VerifyManifest(p.Manifest, p.ManifestSignature, releaseKey, auth.NotBefore)
	if err != nil {
		return Authorization{}, target, time.Time{}, err
	}
	if manifest.ManifestVersion != auth.ManifestVersion || digest(p.Manifest) != auth.ManifestSHA256 {
		return Authorization{}, target, time.Time{}, errors.New("runtime manifest differs from the authorized manifest")
	}
	for _, entry := range manifest.Artifacts {
		if entry.Component != "mcui-runtime" {
			return Authorization{}, target, time.Time{}, errors.New("runtime signing stream must contain only runtime releases")
		}
		if entry.Architecture == auth.Architecture && entry.Version == auth.Version && entry.SHA256 == auth.SHA256 {
			target = entry
		}
	}
	if target.Component == "" || target.Length > MaxArchive {
		return Authorization{}, target, time.Time{}, errors.New("authorized runtime pair is absent from the manifest or exceeds the archive limit")
	}
	return auth, target, manifest.ExpiresAt, nil
}

func (a Authorization) MatchesTime(now, manifestExpiry time.Time) bool {
	return !now.IsZero() && !now.Before(a.NotBefore) && now.Before(a.ExpiresAt) && now.Before(manifestExpiry)
}

func (r Receipt) Valid() bool {
	return ValidDigest(r.ID) && ValidDigest(r.CurrentPair) &&
		(r.Status == Committed || r.Status == RolledBack || r.Status == Rejected)
}
