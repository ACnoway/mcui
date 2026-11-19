package lifecycleauth

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
	"github.com/ACnoway/mcui/internal/tasksigner"
)

type installPayload struct {
	Core            string `json:"core"`
	Version         string `json:"version"`
	ArtifactID      string `json:"artifact_id"`
	ManifestVersion int64  `json:"manifest_version"`
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
	if p.SchemaVersion == SignedManifestProposalVersion {
		prefix = "xray-manifest-"
	}
	issued := time.Unix(request.RequestedAt, 0).UTC().Format(time.RFC3339)
	return installTask{
		SchemaVersion: 1, TaskID: p.TaskID, NodeID: p.NodeID, Sequence: p.Sequence, Operation: p.Operation,
		IssuedAt: issued, NotBefore: issued, ExpiresAt: time.Unix(request.taskExpiry(), 0).UTC().Format(time.RFC3339),
		Payload: installPayload{Core: p.Core, Version: p.Version,
			ArtifactID: prefix + p.Architecture + "-" + p.SHA256, ManifestVersion: p.ManifestVersion},
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
