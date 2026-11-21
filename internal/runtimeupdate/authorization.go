package runtimeupdate

import (
	"crypto/ed25519"
	json "encoding/json/v2"
	"errors"
	"regexp"
	"time"

	"github.com/ACnoway/mcui/internal/runtimehealth"
	"github.com/ACnoway/mcui/internal/security"
)

const MaxAuthorizationBytes = 8192
const maxSequence = 9007199254740991
const authorizationDomain = "MCUI-RUNTIME-UPDATE-V1\n"

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Authorization struct {
	SchemaVersion   int       `json:"schema_version"`
	StateProtocol   int       `json:"state_protocol"`
	NodeID          string    `json:"node_id"`
	Sequence        int64     `json:"sequence"`
	CurrentPair     string    `json:"current_pair_sha256"`
	ManifestVersion int64     `json:"manifest_version"`
	ManifestSHA256  string    `json:"manifest_sha256"`
	Version         string    `json:"version"`
	Architecture    string    `json:"architecture"`
	SHA256          string    `json:"sha256"`
	NotBefore       time.Time `json:"not_before"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func parseAuthorization(raw []byte) (Authorization, error) {
	var a Authorization
	if len(raw) == 0 || len(raw) > MaxAuthorizationBytes || json.Unmarshal(raw, &a, json.RejectUnknownMembers(true)) != nil ||
		a.SchemaVersion != 1 || a.StateProtocol != runtimehealth.Protocol || !security.ValidNodeID(a.NodeID) ||
		a.Sequence < 1 || a.Sequence > maxSequence || a.ManifestVersion < 1 || a.ManifestVersion > maxSequence ||
		!digestPattern.MatchString(a.CurrentPair) || !digestPattern.MatchString(a.ManifestSHA256) || !digestPattern.MatchString(a.SHA256) ||
		!versionPattern.MatchString(a.Version) || (a.Architecture != "amd64" && a.Architecture != "arm64") ||
		a.NotBefore.IsZero() || !a.ExpiresAt.After(a.NotBefore) || a.ExpiresAt.Sub(a.NotBefore) > 24*time.Hour {
		return Authorization{}, errors.New("invalid runtime update authorization")
	}
	return a, nil
}

func SignAuthorization(raw []byte, key ed25519.PrivateKey) ([]byte, error) {
	if _, err := parseAuthorization(raw); err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid runtime update signing key")
	}
	return ed25519.Sign(key, append([]byte(authorizationDomain), raw...)), nil
}

func verifyAuthorization(raw, sig []byte, key ed25519.PublicKey, now time.Time) (Authorization, error) {
	a, err := parseAuthorization(raw)
	if err != nil {
		return Authorization{}, err
	}
	if now.IsZero() || now.Before(a.NotBefore) || !now.Before(a.ExpiresAt) ||
		len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(authorizationDomain), raw...), sig) {
		return Authorization{}, errors.New("runtime update authorization signature or validity rejected")
	}
	return a, nil
}
