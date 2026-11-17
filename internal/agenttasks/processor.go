// Package agenttasks implements experimental signed status-task intake only.
// It is not a runtime or an anti-rollback mechanism. No task is executed here.
// A separately secured, durable independent checkpoint and helper integration
// must be designed and wired before any active runtime is authorized.
package agenttasks

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/ACnoway/mcui/internal/taskauth"
	"github.com/ACnoway/mcui/internal/taskledger"
)

// Config is trusted local configuration. Now must supply externally validated
// time; neither a nonzero timestamp nor this package proves clock health.
// Keys and node identity are pinned at construction. The caller must not mutate
// configuration concurrently with New and must exclusively own the ledger.
// Revocation requires stopping intake and replacing the processor. Ledger.Accept
// does not expose a validation callback inside its transaction: therefore this
// experimental intake cannot guarantee time validity at the SQLite commit point.
// It must not be used as a production authorization or execution boundary.
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
	v, err := taskauth.Verify(raw, taskauth.Trust{NodeID: p.node, Keys: p.keys, Now: now})
	if err != nil {
		return zero, err
	}
	if v.Sequence > math.MaxInt64 {
		return zero, errors.New("sequence overflow")
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	return p.ledger.Accept(taskledger.Task{ID: v.TaskID, Sequence: int64(v.Sequence), Envelope: v.Raw, NotBefore: v.NotBefore, ExpiresAt: v.ExpiresAt}, now)
}
