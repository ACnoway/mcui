// Package taskauth verifies signed V2 status tasks without applying them.
// It does not provide authorization, replay protection, clock-health/rollback
// detection, persistence, or runtime integration.
package taskauth

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
)

const PurposeTask = "task"
const MaxMessageBytes = 64 * 1024

type Key struct {
	PublicKey ed25519.PublicKey
	Active    bool
	Purpose   string
}

// Trust must be supplied by local trusted configuration, not by the task.
// Now must come from an externally validated clock. A nonzero time alone is
// not evidence of clock health. Callers must synchronize mutations of Trust,
// its key map, public keys, and raw input during verification.
type Trust struct {
	NodeID string
	Keys   map[string]Key
	Now    time.Time
}

// Verified is mutable and forgeable, including Raw. Raw initially owns a copy
// of the exact signed input. At the atomic persistence/application boundary,
// reverify those bytes using current trust and time, derive all persisted fields
// from that fresh result, and enforce authorization, replay/sequence and state
// transition rules atomically. Verification alone grants no execution permission.
type Verified struct {
	NodeID    string
	TaskID    string
	Sequence  uint64
	KeyID     string
	Core      string
	IssuedAt  time.Time
	NotBefore time.Time
	ExpiresAt time.Time
	Raw       []byte
}

var (
	ErrTrust     = errors.New("invalid local trust")
	ErrKey       = errors.New("unknown, inactive or unauthorized signing key")
	ErrTarget    = errors.New("task targets another node")
	ErrTime      = errors.New("task outside validity window")
	ErrSignature = errors.New("invalid signed task")
)

// Verify checks the strict V2 schema and Ed25519 signature using the locally
// selected task-purpose key, then binds the node and supplied trustworthy time.
// It requires issued_at <= Now+30s and not_before <= Now < expires_at. The V2
// schema additionally requires issued_at <= not_before, so the not_before check
// makes any future issued_at invalid in practice. No clock skew is allowed at
// not_before or expires_at. This function does not make trust or time trustworthy.
func Verify(raw []byte, trust Trust) (Verified, error) {
	var zero Verified
	if trust.NodeID == "" || trust.Now.IsZero() {
		return zero, ErrTrust
	}
	if len(raw) == 0 || len(raw) > MaxMessageBytes {
		return zero, fmt.Errorf("%w: invalid size", ErrSignature)
	}
	snapshot := append([]byte(nil), raw...)
	// Strict validation precedes decoding for key selection, so duplicate or extra
	// fields cannot make the selection differ from the signed interpretation.
	if _, err := protocol.CanonicalV2TaskBytes(snapshot); err != nil {
		return zero, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	var body struct {
		NodeID    string    `json:"node_id"`
		TaskID    string    `json:"task_id"`
		Sequence  uint64    `json:"sequence"`
		KeyID     string    `json:"signing_key_id"`
		IssuedAt  time.Time `json:"issued_at"`
		NotBefore time.Time `json:"not_before"`
		ExpiresAt time.Time `json:"expires_at"`
		Payload   struct {
			Core string `json:"core"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(snapshot, &body); err != nil {
		return zero, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	key, ok := trust.Keys[body.KeyID]
	if !ok || !key.Active || key.Purpose != PurposeTask || len(key.PublicKey) != ed25519.PublicKeySize {
		return zero, ErrKey
	}
	if err := protocol.VerifyV2Task(snapshot, key.PublicKey); err != nil {
		return zero, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	if body.NodeID != trust.NodeID {
		return zero, ErrTarget
	}
	if body.IssuedAt.After(trust.Now.Add(30*time.Second)) || trust.Now.Before(body.NotBefore) || !trust.Now.Before(body.ExpiresAt) {
		return zero, ErrTime
	}
	return Verified{NodeID: body.NodeID, TaskID: body.TaskID, Sequence: body.Sequence, KeyID: body.KeyID, Core: body.Payload.Core, IssuedAt: body.IssuedAt, NotBefore: body.NotBefore, ExpiresAt: body.ExpiresAt, Raw: snapshot}, nil
}
