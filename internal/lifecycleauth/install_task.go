package lifecycleauth

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/ACnoway/mcui/internal/protocol"
)

// InstallKey is provisioned independently of the read-only task signer.
type InstallKey struct {
	ID        string
	PublicKey ed25519.PublicKey
}

func (p *Policy) InstallKey() InstallKey {
	if p == nil {
		return InstallKey{}
	}
	return InstallKey{ID: p.keyID, PublicKey: append(ed25519.PublicKey(nil), p.signingKey...)}
}

type InstallTask struct {
	TaskID, NodeID, KeyID, ApprovalID string
	Sequence, ManifestVersion         int64
	Version, Architecture, SHA256     string
	NotBefore, ExpiresAt              time.Time
}

// Verify validates the exact signed V1 Xray install envelope against a
// purpose-specific local key. Callers must bind the local node and trusted time.
func (key InstallKey) Verify(raw []byte) (InstallTask, error) {
	var wire installTask
	if len(raw) == 0 || len(raw) > maxProofBytes || !identifier.MatchString(key.ID) ||
		len(key.PublicKey) != ed25519.PublicKeySize || protocol.Verify(protocol.Task, raw, key.PublicKey) != nil ||
		json.Unmarshal(raw, &wire) != nil || wire.SigningKeyID != key.ID || wire.Operation != "core.install" ||
		wire.Payload.Core != "xray" || !digestPattern.MatchString(wire.ApprovalID) || wire.IssuedAt != wire.NotBefore {
		return InstallTask{}, ErrDenied
	}
	architecture, digest, ok := strings.Cut(strings.TrimPrefix(wire.Payload.ArtifactID, "xray-"), "-")
	if !ok || wire.Payload.ArtifactID != "xray-"+architecture+"-"+digest ||
		(architecture != "amd64" && architecture != "arm64") || !corecatalog.ValidXrayRelease(wire.Payload.Version, digest) {
		return InstallTask{}, ErrDenied
	}
	before, err := time.Parse(time.RFC3339, wire.NotBefore)
	if err != nil {
		return InstallTask{}, ErrDenied
	}
	expires, err := time.Parse(time.RFC3339, wire.ExpiresAt)
	if err != nil || !expires.After(before) || expires.Sub(before) > taskTTL {
		return InstallTask{}, ErrDenied
	}
	return InstallTask{
		TaskID: wire.TaskID, NodeID: wire.NodeID, KeyID: key.ID, ApprovalID: wire.ApprovalID,
		Sequence: wire.Sequence, ManifestVersion: wire.Payload.ManifestVersion, Version: wire.Payload.Version,
		Architecture: architecture, SHA256: digest, NotBefore: before, ExpiresAt: expires,
	}, nil
}

func (t InstallTask) Matches(p Proposal, id string) bool {
	return id == t.ApprovalID && p.TaskID == t.TaskID && p.NodeID == t.NodeID && p.SigningKeyID == t.KeyID &&
		p.Sequence == t.Sequence && p.ManifestVersion == t.ManifestVersion && p.Version == t.Version &&
		p.Architecture == t.Architecture && p.SHA256 == t.SHA256 &&
		t.NotBefore.Unix() >= p.CreatedAt && t.ExpiresAt.Unix() <= p.ExpiresAt
}

func (t InstallTask) ActiveAt(now time.Time) bool {
	return !now.IsZero() && !now.Before(t.NotBefore) && now.Before(t.ExpiresAt)
}

type InstallResult struct {
	Outcome string `json:"outcome"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}
