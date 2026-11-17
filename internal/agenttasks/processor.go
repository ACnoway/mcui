// Package agenttasks implements the signed status-task intake and replayable
// ACK path. Privileged observation remains inside the separately secured
// Helper and requires a live Master lease checkpoint.
package agenttasks

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
	"github.com/ACnoway/mcui/internal/taskauth"
	"github.com/ACnoway/mcui/internal/taskledger"
)

// Config is trusted local configuration. Now must supply externally validated
// time; neither a nonzero timestamp nor this package proves clock health.
// Keys and node identity are pinned at construction. The caller must not mutate
// configuration concurrently with New and must exclusively own the ledger.
// Revocation requires stopping intake and replacing the processor. Receive
// repeats signature and time verification inside the ledger's write transaction,
// but this package does not establish that the supplied clock is trustworthy.
// It is not by itself a production authorization or anti-rollback boundary.
type Config struct {
	NodeID string
	Keys   map[string]taskauth.Key
	Now    func() time.Time
	Ledger *taskledger.Ledger
}

type Processor struct {
	mu     sync.Mutex
	node   string
	keys   map[string]taskauth.Key
	now    func() time.Time
	ledger *taskledger.Ledger
}

func New(c Config) (*Processor, error) {
	if c.NodeID == "" || c.Now == nil || c.Ledger == nil || len(c.Keys) == 0 {
		return nil, errors.New("incomplete trusted configuration")
	}
	keys := make(map[string]taskauth.Key, len(c.Keys))
	for id, key := range c.Keys {
		key.PublicKey = append(ed25519.PublicKey(nil), key.PublicKey...)
		keys[id] = key
	}
	return &Processor{node: c.NodeID, keys: keys, now: c.Now, ledger: c.Ledger}, nil
}

// Receive snapshots and authenticates the exact delivery, then persists it in
// the local ledger. It never calls Start or invokes a helper. Caller must not
// mutate signedBytes concurrently while Receive copies it. Context cancellation
// is checked before acceptance; the ledger cannot cancel an in-flight write.
func (p *Processor) Receive(ctx context.Context, signedBytes []byte) (taskledger.Task, error) {
	var zero taskledger.Task
	if p == nil || ctx == nil {
		return zero, errors.New("invalid processor or context")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if len(signedBytes) == 0 || len(signedBytes) > taskauth.MaxMessageBytes {
		return zero, taskauth.ErrSignature
	}
	raw := append([]byte(nil), signedBytes...)
	now := p.now()
	v, err := verifyForReceipt(raw, p.node, p.keys, now)
	if err != nil {
		return zero, err
	}
	if v.Sequence > math.MaxInt64 {
		return zero, errors.New("sequence overflow")
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	task := taskledger.Task{ID: v.TaskID, Sequence: int64(v.Sequence), Envelope: v.Raw, NotBefore: v.NotBefore, ExpiresAt: v.ExpiresAt}
	return p.ledger.AcceptValidated(task, func() (time.Time, error) {
		current := p.now()
		if current.IsZero() || current.Before(now) {
			return time.Time{}, taskauth.ErrTrust
		}
		if _, verifyErr := verifyForReceipt(raw, p.node, p.keys, current); verifyErr != nil {
			return time.Time{}, verifyErr
		}
		return current, nil
	})
}

// verifyForReceipt accepts an expired but authentic envelope only so the
// durable Agent ledger can advance it as terminal without executing it. The
// signature, key purpose, target and signed time bounds are still checked.
func verifyForReceipt(raw []byte, nodeID string, keys map[string]taskauth.Key, now time.Time) (taskauth.Verified, error) {
	trust := taskauth.Trust{NodeID: nodeID, Keys: keys, Now: now}
	verified, err := taskauth.Verify(raw, trust)
	if err == nil || !errors.Is(err, taskauth.ErrTime) || now.IsZero() {
		return verified, err
	}
	var times struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	if _, schemaErr := protocol.CanonicalV2TaskBytes(raw); schemaErr != nil || json.Unmarshal(raw, &times) != nil || times.ExpiresAt.IsZero() || now.Before(times.ExpiresAt) {
		return taskauth.Verified{}, err
	}
	return taskauth.Verify(raw, taskauth.Trust{NodeID: nodeID, Keys: keys, Now: times.ExpiresAt.Add(-time.Nanosecond)})
}
