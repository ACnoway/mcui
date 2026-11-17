// Package agenttasks implements signed status-task intake, restricted V1
// controls, and the replayable ACK path. Privileged observation remains inside
// the separately secured Helper and requires a live Master lease checkpoint.
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
	"github.com/ACnoway/mcui/internal/taskcontrol"
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
	if p == nil {
		return taskledger.Task{}, errors.New("invalid processor")
	}
	return p.receive(ctx, signedBytes, p.now)
}

// ReceiveAt accepts the signed delivery using a timestamp supplied by the
// authenticated Master response. The caller remains responsible for validating
// time freshness and rollback; this method only uses the supplied instant.
func (p *Processor) ReceiveAt(ctx context.Context, signedBytes []byte, serverNow time.Time) (taskledger.Task, error) {
	return p.receive(ctx, signedBytes, func() time.Time { return serverNow })
}

func (p *Processor) receive(ctx context.Context, signedBytes []byte, currentTime func() time.Time) (taskledger.Task, error) {
	var zero taskledger.Task
	if p == nil || ctx == nil || currentTime == nil {
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
	now := currentTime()
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
		current := currentTime()
		if current.IsZero() || current.Before(now) {
			return time.Time{}, taskauth.ErrTrust
		}
		if _, verifyErr := verifyForReceipt(raw, p.node, p.keys, current); verifyErr != nil {
			return time.Time{}, verifyErr
		}
		return current, nil
	})
}

// ApplyCancel verifies a V1 cancel and records its exact bytes atomically with
// the task ledger transition. The cancel must target the already received
// status task. current time is supplied by the authenticated Master delivery.
func (p *Processor) ApplyCancel(ctx context.Context, raw []byte, serverNow time.Time, taskID string, sequence int64) error {
	if p == nil || ctx == nil || taskID == "" || sequence < 1 || serverNow.IsZero() || len(raw) == 0 || len(raw) > taskauth.MaxMessageBytes {
		return errors.New("invalid task cancellation")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	snapshot := append([]byte(nil), raw...)
	verified, err := p.verifyControl(protocol.Cancel, snapshot, serverNow)
	if err != nil {
		return err
	}
	if verified.TaskID != taskID || verified.Sequence != uint64(sequence) {
		return taskcontrol.ErrTarget
	}
	return p.ledger.AcceptCancelValidated(sequence, taskID, snapshot, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, verifyErr := p.verifyControl(protocol.Cancel, snapshot, serverNow)
		if verifyErr != nil {
			return verifyErr
		}
		if current.TaskID != taskID || current.Sequence != uint64(sequence) {
			return taskcontrol.ErrTarget
		}
		return nil
	})
}

// ApplySkip verifies an EXPIRED skip for a terminal task already recorded in
// the durable ledger. EXPIRED is the only skip reason emitted by this runtime.
func (p *Processor) ApplySkip(ctx context.Context, raw []byte, serverNow time.Time, taskID string, sequence int64) (taskledger.Task, error) {
	var zero taskledger.Task
	if p == nil || ctx == nil || taskID == "" || sequence < 1 || serverNow.IsZero() || len(raw) == 0 || len(raw) > taskauth.MaxMessageBytes {
		return zero, errors.New("invalid task skip")
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	verified, err := p.verifyControl(protocol.Skip, append([]byte(nil), raw...), serverNow)
	if err != nil {
		return zero, err
	}
	if verified.Sequence != uint64(sequence) || verified.Reason != "EXPIRED" {
		return zero, taskcontrol.ErrTarget
	}
	task, err := p.ledger.Get(sequence)
	if err != nil {
		return zero, err
	}
	if task.ID != taskID {
		return zero, taskledger.ErrConflict
	}
	if task.State != taskledger.Expired {
		return zero, taskledger.ErrTooLate
	}
	if verified.IssuedAt.Before(task.ExpiresAt) || serverNow.Before(task.ExpiresAt) {
		return zero, taskcontrol.ErrTarget
	}
	return task, nil
}

// ApplySequenceSkip consumes a taskless VOID_UNISSUED slot. It cannot close
// issued tasks; those require the original expired task and its signed receipt.
func (p *Processor) ApplySequenceSkip(ctx context.Context, raw []byte, serverNow time.Time, sequence int64) (taskledger.Task, error) {
	var zero taskledger.Task
	if p == nil || ctx == nil || sequence < 1 || serverNow.IsZero() || len(raw) == 0 || len(raw) > taskauth.MaxMessageBytes {
		return zero, errors.New("invalid sequence skip")
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	snapshot := append([]byte(nil), raw...)
	verified, err := p.verifyControl(protocol.Skip, snapshot, serverNow)
	if err != nil {
		return zero, err
	}
	if verified.Sequence != uint64(sequence) || verified.Reason != "VOID_UNISSUED" {
		return zero, taskcontrol.ErrTarget
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	return p.ledger.ConsumeVoid(sequence, snapshot, verified.NotBefore, verified.ExpiresAt)
}

func (p *Processor) verifyControl(kind protocol.Kind, raw []byte, now time.Time) (taskcontrol.Verified, error) {
	var zero taskcontrol.Verified
	if _, err := protocol.CanonicalSignedBytes(kind, raw); err != nil {
		return zero, taskcontrol.ErrSignature
	}
	var header struct {
		KeyID string `json:"signing_key_id"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return zero, taskcontrol.ErrSignature
	}
	key, ok := p.keys[header.KeyID]
	if !ok || !key.Active || key.Purpose != taskauth.PurposeTask {
		return zero, taskcontrol.ErrKey
	}
	return taskcontrol.Verify(kind, raw, taskcontrol.Trust{
		NodeID: p.node, KeyID: header.KeyID, Purpose: taskcontrol.PurposeTask,
		PublicKey: key.PublicKey, Now: now,
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
