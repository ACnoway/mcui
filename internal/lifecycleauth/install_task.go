package lifecycleauth

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/ACnoway/mcui/internal/protocol"
	"github.com/ACnoway/mcui/internal/xrayconfig"
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
	TaskID, NodeID, KeyID, ApprovalID        string
	Sequence, ManifestVersion                int64
	Operation, Version, Architecture, SHA256 string
	CurrentVersion, CurrentSHA256            string
	NotBefore, ExpiresAt                     time.Time
	SignedManifest                           bool
	Config                                   xrayconfig.Reference
	Plan                                     string
}

func IsControlOperation(operation string) bool {
	return operation == "core.start" || operation == "core.stop" || operation == "core.uninstall"
}

func IsVersionChange(operation string) bool {
	return operation == "core.upgrade" || operation == "core.downgrade"
}

func validVersionChange(operation, current, currentSHA256, target, targetSHA256 string) bool {
	if !corecatalog.ValidXrayRelease(current, currentSHA256) || !corecatalog.ValidXrayRelease(target, targetSHA256) {
		return false
	}
	order := corecatalog.CompareXrayVersions(target, current)
	return (operation == "core.upgrade" && order > 0) || (operation == "core.downgrade" && order < 0)
}

// Verify validates the exact signed V1 Xray lifecycle envelope against a
// purpose-specific local key. Callers must bind the local node and trusted time.
func (key InstallKey) Verify(raw []byte) (InstallTask, error) {
	var wire installTask
	if len(raw) == 0 || len(raw) > maxProofBytes || !identifier.MatchString(key.ID) ||
		len(key.PublicKey) != ed25519.PublicKeySize || protocol.Verify(protocol.Task, raw, key.PublicKey) != nil ||
		json.Unmarshal(raw, &wire) != nil || wire.SigningKeyID != key.ID ||
		wire.Payload.Core != "xray" || !digestPattern.MatchString(wire.ApprovalID) || wire.IssuedAt != wire.NotBefore {
		return InstallTask{}, ErrDenied
	}
	payload := wire.Payload
	var signedManifest bool
	var config xrayconfig.Reference
	switch {
	case wire.Operation == "core.install" || IsVersionChange(wire.Operation):
		prefix := "xray-"
		if strings.HasPrefix(payload.ArtifactID, "xray-manifest-") {
			prefix, signedManifest = "xray-manifest-", true
		}
		architecture, digest, ok := strings.Cut(strings.TrimPrefix(payload.ArtifactID, prefix), "-")
		if !ok || payload.ArtifactID != prefix+architecture+"-"+digest {
			return InstallTask{}, ErrDenied
		}
		payload.Architecture, payload.SHA256 = architecture, digest
		if IsVersionChange(wire.Operation) && (!signedManifest ||
			!validVersionChange(wire.Operation, payload.CurrentVersion, payload.CurrentSHA256, payload.Version, payload.SHA256)) {
			return InstallTask{}, ErrDenied
		}
	case IsControlOperation(wire.Operation):
		// Only a release-bound control envelope can pass the lifecycle key.
	case wire.Operation == xrayconfig.Operation:
		m := payload.Config
		config = xrayconfig.Reference{Port: payload.Port, SHA256: m.ContentSHA256, Size: m.ContentSize}
		configRaw, err := json.Marshal(m)
		if err != nil || !config.Valid() || payload.Version != xrayconfig.Version || payload.Architecture != xrayconfig.Architecture || m.Core != "xray" ||
			m.NodeID != wire.NodeID || m.CoreVersion != payload.Version || m.Revision != wire.Sequence ||
			m.SigningKeyID != key.ID || m.IssuedAt != wire.IssuedAt || m.NotBefore != wire.NotBefore || m.ExpiresAt != wire.ExpiresAt ||
			protocol.Verify(protocol.Config, configRaw, key.PublicKey) != nil {
			return InstallTask{}, ErrDenied
		}
		signedManifest = true
	default:
		return InstallTask{}, ErrDenied
	}
	if (payload.Architecture != "amd64" && payload.Architecture != "arm64") || !corecatalog.ValidXrayRelease(payload.Version, payload.SHA256) {
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
		Sequence: wire.Sequence, Operation: wire.Operation, Version: payload.Version, ManifestVersion: payload.ManifestVersion,
		CurrentVersion: payload.CurrentVersion, CurrentSHA256: payload.CurrentSHA256,
		Architecture: payload.Architecture, SHA256: payload.SHA256, NotBefore: before, ExpiresAt: expires, SignedManifest: signedManifest,
		Config: config, Plan: payload.Plan,
	}, nil
}

func (t InstallTask) Matches(p Proposal, id string) bool {
	return id == t.ApprovalID && p.TaskID == t.TaskID && p.NodeID == t.NodeID && p.SigningKeyID == t.KeyID &&
		p.Sequence == t.Sequence && p.Operation == t.Operation && p.ManifestVersion == t.ManifestVersion && p.Version == t.Version &&
		p.CurrentVersion == t.CurrentVersion && p.CurrentSHA256 == t.CurrentSHA256 &&
		t.SignedManifest == (p.SchemaVersion == SignedManifestProposalVersion || IsVersionChange(p.Operation) || p.Operation == xrayconfig.Operation) &&
		t.Config == p.Config && t.Plan == p.Plan &&
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
