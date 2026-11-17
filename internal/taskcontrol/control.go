// Package taskcontrol verifies frozen V1 cancel and skip authorizations without
// applying them. It does not implement replay, rollback, or sequence protection.
// The caller must supply locally configured, non-revoked task-purpose keys and a
// trustworthy current clock, detect clock rollback, and enforce persistent ledger
// state, target task matching, skip eligibility, and atomic transitions.
package taskcontrol

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
)

const PurposeTask = "task"

// Trust must come from local configuration, never from the signed body. Now
// must come from a trusted clock; a nonzero time alone does not establish trust.
// Configure a key only while it is active and authorized for the task purpose.
type Trust struct {
	NodeID    string
	KeyID     string
	Purpose   string
	PublicKey ed25519.PublicKey
	Now       time.Time
}

// Verified contains data authenticated at verification time, not an unforgeable
// authorization or permission to alter the ledger. All fields, including the
// bytes in Raw, are mutable, and callers can construct Verified values directly.
// Raw is initially an owned copy of the exact input bytes, including JSON
// whitespace and order. At the atomic application point, callers must reverify
// the bytes against the current locally authorized key, node, and trusted time,
// then enforce the ledger and transition requirements before applying them.
type Verified struct {
	Kind      protocol.Kind
	NodeID    string
	TaskID    string
	Sequence  uint64
	Reason    string
	KeyID     string
	IssuedAt  time.Time
	NotBefore time.Time
	ExpiresAt time.Time
	Raw       []byte
}

var (
	ErrTrust     = errors.New("invalid local trust")
	ErrSignature = errors.New("invalid signed control object")
	ErrTarget    = errors.New("control target does not match local node")
	ErrKey       = errors.New("control signing key does not match local key")
	ErrTime      = errors.New("control authorization is outside its validity window")
)

// Verify validates the exact V1 schema and the kind-specific Ed25519 domain,
// then binds the signed key ID and node ID to independently configured trust.
// It accepts not_before <= Now < expires_at, and issued_at at most 30 seconds
// ahead of Now. The returned Verified value is forgeable and all its fields,
// including Raw, are mutable; do not treat it as an authorization. At the
// atomic application point, reverify the bytes against the current locally
// authorized key, node, and trusted time, and use that freshly verified result
// while enforcing ledger state and transitions. Verify does not validate ledger
// state or persist any information.
func Verify(kind protocol.Kind, raw []byte, trust Trust) (Verified, error) {
	var zero Verified
	if kind != protocol.Cancel && kind != protocol.Skip {
		return zero, fmt.Errorf("%w: unsupported kind", ErrSignature)
	}
	if trust.NodeID == "" || trust.KeyID == "" || trust.Purpose != PurposeTask || len(trust.PublicKey) != ed25519.PublicKeySize || trust.Now.IsZero() {
		return zero, ErrTrust
	}
	if len(raw) == 0 || len(raw) > 64*1024 {
		return zero, fmt.Errorf("%w: invalid message length", ErrSignature)
	}
	snapshot := append([]byte(nil), raw...)
	if err := protocol.Verify(kind, snapshot, trust.PublicKey); err != nil {
		return zero, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	var body struct {
		NodeID    string    `json:"node_id"`
		TaskID    string    `json:"task_id"`
		Sequence  uint64    `json:"sequence"`
		Reason    string    `json:"reason"`
		KeyID     string    `json:"signing_key_id"`
		IssuedAt  time.Time `json:"issued_at"`
		NotBefore time.Time `json:"not_before"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(snapshot, &body); err != nil {
		return zero, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	if body.KeyID != trust.KeyID {
		return zero, ErrKey
	}
	if body.NodeID != trust.NodeID {
		return zero, ErrTarget
	}
	if body.IssuedAt.After(trust.Now.Add(30*time.Second)) || trust.Now.Before(body.NotBefore) || !trust.Now.Before(body.ExpiresAt) {
		return zero, ErrTime
	}
	return Verified{Kind: kind, NodeID: body.NodeID, TaskID: body.TaskID, Sequence: body.Sequence, Reason: body.Reason, KeyID: body.KeyID, IssuedAt: body.IssuedAt, NotBefore: body.NotBefore, ExpiresAt: body.ExpiresAt, Raw: snapshot}, nil
}
