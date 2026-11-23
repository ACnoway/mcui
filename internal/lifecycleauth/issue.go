package lifecycleauth

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
	"github.com/ACnoway/mcui/internal/tasksigner"
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

type installPayload struct {
	Core            string         `json:"core"`
	Version         string         `json:"version"`
	ArtifactID      string         `json:"artifact_id,omitempty"`
	ManifestVersion int64          `json:"manifest_version,omitempty"`
	Architecture    string         `json:"architecture,omitempty"`
	SHA256          string         `json:"sha256,omitempty"`
	CurrentVersion  string         `json:"current_version,omitempty"`
	CurrentSHA256   string         `json:"current_sha256,omitempty"`
	Port            int            `json:"port,omitempty"`
	Config          configMetadata `json:"config,omitzero"`
	Plan            string         `json:"plan,omitempty"`
}

type configMetadata struct {
	SchemaVersion      int    `json:"schema_version"`
	NodeID             string `json:"node_id"`
	Core               string `json:"core"`
	CoreVersion        string `json:"core_version"`
	Revision           int64  `json:"revision"`
	ContentSHA256      string `json:"content_sha256"`
	ContentSize        int    `json:"content_size"`
	IssuedAt           string `json:"issued_at"`
	NotBefore          string `json:"not_before"`
	ExpiresAt          string `json:"expires_at"`
	SigningKeyID       string `json:"signing_key_id"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	Signature          string `json:"signature"`
}

type installTask struct {
	SchemaVersion      int            `json:"schema_version"`
	TaskID             string         `json:"task_id"`
	NodeID             string         `json:"node_id"`
	Sequence           int64          `json:"sequence"`
	Operation          string         `json:"operation"`
	IssuedAt           string         `json:"issued_at"`
	NotBefore          string         `json:"not_before"`
	ExpiresAt          string         `json:"expires_at"`
	Payload            installPayload `json:"payload"`
	ApprovalID         string         `json:"approval_id"`
	SigningKeyID       string         `json:"signing_key_id"`
	SignatureAlgorithm string         `json:"signature_algorithm"`
	Signature          string         `json:"signature"`
}

// Issue consumes this request in the signer's private ledger. The caller
// supplies current authority policy and authenticated time. Replaying valid,
// identical evidence returns the committed, byte-identical task.
func (policy *Policy) Issue(ctx context.Context, ledger *Ledger, request Request, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if ledger == nil || ledger.db == nil || policy == nil || !matchesPrivate(key, policy.signingKey) {
		return nil, ErrDenied
	}
	id, err := policy.VerifyRequest(request, now)
	if err != nil {
		return nil, err
	}
	evidence, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	task, err := signInstallTask(request, id, key, policy.signingKey)
	if err != nil {
		return nil, err
	}
	return ledger.consume(ctx, request.Proposal, id, evidence, task)
}

func signInstallTask(request Request, requestID string, key ed25519.PrivateKey, public ed25519.PublicKey) ([]byte, error) {
	task := expectedInstallTask(request, requestID)
	if task.Operation == xrayconfig.Operation {
		m := &task.Payload.Config
		m.Signature = tasksigner.PlaceholderSignature
		configRaw, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		canonical, err := protocol.CanonicalSignedBytes(protocol.Config, configRaw)
		if err != nil {
			return nil, err
		}
		m.Signature = sign(key, canonical)
	}
	task.Signature = tasksigner.PlaceholderSignature
	raw, err := json.Marshal(task)
	if err != nil {
		return nil, err
	}
	canonical, err := protocol.CanonicalSignedBytes(protocol.Task, raw)
	if err != nil {
		return nil, err
	}
	task.Signature = sign(key, canonical)
	raw, err = json.Marshal(task)
	if err != nil {
		return nil, err
	}
	if err = protocol.Verify(protocol.Task, raw, public); err != nil {
		return nil, err
	}
	return raw, nil
}

func expectedInstallTask(request Request, requestID string) installTask {
	p := request.Proposal
	prefix := "xray-"
	if p.SchemaVersion == SignedManifestProposalVersion || IsVersionChange(p.Operation) {
		prefix = "xray-manifest-"
	}
	payload := installPayload{Core: p.Core, Version: p.Version}
	issued := time.Unix(request.RequestedAt, 0).UTC().Format(time.RFC3339)
	expires := time.Unix(request.taskExpiry(), 0).UTC().Format(time.RFC3339)
	switch {
	case p.Operation == xrayconfig.Operation:
		payload.Architecture, payload.SHA256, payload.ManifestVersion = p.Architecture, p.SHA256, p.ManifestVersion
		payload.Port, payload.Plan = p.Config.Port, p.Plan
		payload.Config = configMetadata{
			SchemaVersion: 1, NodeID: p.NodeID, Core: p.Core, CoreVersion: p.Version, Revision: p.Sequence,
			ContentSHA256: p.Config.SHA256, ContentSize: p.Config.Size, IssuedAt: issued, NotBefore: issued, ExpiresAt: expires,
			SigningKeyID: p.SigningKeyID, SignatureAlgorithm: "Ed25519",
		}
	case IsControlOperation(p.Operation):
		payload.Architecture, payload.SHA256 = p.Architecture, p.SHA256
	default:
		payload.ArtifactID, payload.ManifestVersion = prefix+p.Architecture+"-"+p.SHA256, p.ManifestVersion
		payload.CurrentVersion, payload.CurrentSHA256 = p.CurrentVersion, p.CurrentSHA256
	}
	return installTask{
		SchemaVersion: 1, TaskID: p.TaskID, NodeID: p.NodeID, Sequence: p.Sequence, Operation: p.Operation,
		IssuedAt: issued, NotBefore: issued, ExpiresAt: expires,
		Payload:    payload,
		ApprovalID: requestID, SigningKeyID: p.SigningKeyID, SignatureAlgorithm: "Ed25519",
	}
}

// VerifyIssuedTask returns the request digest after verifying both signatures
// and comparing every field against the task the signer could issue.
func (policy *Policy) VerifyIssuedTask(raw []byte, request Request, now time.Time) (string, error) {
	if len(raw) == 0 || len(raw) > maxProofBytes {
		return "", ErrDenied
	}
	id, err := policy.VerifyRequest(request, now)
	if err != nil || protocol.Verify(protocol.Task, raw, policy.signingKey) != nil {
		return "", ErrDenied
	}
	var task installTask
	if err := json.Unmarshal(raw, &task); err != nil {
		return "", ErrDenied
	}
	task.Signature = ""
	if task != expectedInstallTask(request, id) {
		return "", ErrDenied
	}
	return id, nil
}
