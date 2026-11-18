package lifecycleauth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
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

// Issue consumes this approval in the signer's private ledger. The caller
// supplies current authority policy and authenticated time. Replaying valid,
// identical evidence returns the committed, byte-identical task.
func (policy *Policy) Issue(ctx context.Context, ledger *Ledger, approval Approval, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if ledger == nil || ledger.db == nil || policy == nil || !matchesPrivate(key, policy.signingKey) {
		return nil, ErrDenied
	}
	if err := policy.verifyApproval(approval, now); err != nil {
		return nil, err
	}
	evidence, err := json.Marshal(approval)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(evidence)
	id := hex.EncodeToString(hash[:])
	task, err := signInstallTask(approval, id, key, policy.signingKey)
	if err != nil {
		return nil, err
	}
	return ledger.consume(ctx, approval.Request.Proposal, id, evidence, task)
}

func signInstallTask(approval Approval, approvalID string, key ed25519.PrivateKey, public ed25519.PublicKey) ([]byte, error) {
	p := approval.Request.Proposal
	issued := time.Unix(approval.ApprovedAt, 0).UTC().Format(time.RFC3339)
	task := installTask{
		SchemaVersion: 1, TaskID: p.TaskID, NodeID: p.NodeID, Sequence: p.Sequence, Operation: p.Operation,
		IssuedAt: issued, NotBefore: issued, ExpiresAt: time.Unix(approval.taskExpiry(), 0).UTC().Format(time.RFC3339),
		Payload: installPayload{Core: p.Core, Version: p.Version,
			ArtifactID: "xray-" + p.Architecture + "-" + p.SHA256, ManifestVersion: p.ManifestVersion},
		ApprovalID: approvalID, SigningKeyID: p.SigningKeyID, SignatureAlgorithm: "Ed25519", Signature: tasksigner.PlaceholderSignature,
	}
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
