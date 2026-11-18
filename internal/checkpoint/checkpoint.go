// Package checkpoint implements a transport-neutral transition model.
// Callers supply durable storage and authenticated transport.
// Security depends on independently protected, authenticated, linearizable
// authority and crash-durable, integrity-protected journal implementations.
// The journal and transition requests must be authorized:
// a forged intent can otherwise cause recovery to anchor an attacker-chosen
// digest. This model does not authenticate requests or compute/verify digests.
package checkpoint

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
)

var ErrDenied = errors.New("checkpoint reconciliation denied")

// ErrOutcomeUnknown indicates a mutating operation may have taken effect.
var ErrOutcomeUnknown = errors.New("checkpoint mutation outcome unknown")

type Record struct {
	Node            string
	Epoch, Revision uint64
	Digest          [32]byte
}
type Challenge [32]byte
type Intent struct{ Previous, Next Record }
type State struct {
	Committed Record
	Intent    *Intent
}
type Observation struct {
	Record    Record
	Challenge Challenge
}

// Authority must authenticate observations and bind the fresh challenge, node,
// epoch, revision and digest to its response. Read and CompareAndSwap must be
// linearizable. CAS compares the complete previous record and returns the
// current record whether or not it changed. Any error may mean an unknown outcome.
type Authority interface {
	Read(context.Context, string, uint64, Challenge) (Observation, error)
	CompareAndSwap(context.Context, Record, Record, Challenge) (Observation, error)
}

// Journal operations must be atomic, durable before success, and serialized
// across users of the same checkpoint. Load must not silently initialize state.
// Begin and Commit compare their inputs with durable state. An error can mean
// the write occurred; callers must reload and reconcile before proceeding.
type Journal interface {
	Load(context.Context) (State, error)
	Begin(context.Context, Record, Intent) error
	Commit(context.Context, Intent) error
}

// Machine requires exclusive ownership across a complete operation, including
// recovery; Journal atomicity alone does not serialize separate machines.
type Machine struct {
	Journal   Journal
	Authority Authority
}

func valid(r Record) bool { return r.Node != "" && r.Epoch != 0 && r.Digest != ([32]byte{}) }
func validIntent(i Intent) bool {
	return valid(i.Previous) && valid(i.Next) && i.Previous.Node == i.Next.Node && i.Previous.Epoch == i.Next.Epoch && i.Previous.Revision < math.MaxUint64 && i.Next.Revision == i.Previous.Revision+1
}
func challenge() (Challenge, error) { var c Challenge; _, err := rand.Read(c[:]); return c, err }
func (m Machine) read(ctx context.Context, r Record) (Record, error) {
	c, err := challenge()
	if err != nil {
		return Record{}, err
	}
	o, err := m.Authority.Read(ctx, r.Node, r.Epoch, c)
	if err != nil {
		return Record{}, err
	}
	if o.Challenge != c || o.Record.Node != r.Node || o.Record.Epoch != r.Epoch {
		return Record{}, ErrDenied
	}
	return o.Record, nil
}

// Recover resolves a durable intent only when authority is exactly at its old
// or new record. If still old it retries the same CAS, then commits locally.
// With no intent, exact equality is mandatory. Mismatches are never repaired.
func (m Machine) Recover(ctx context.Context) error {
	if m.Journal == nil || m.Authority == nil {
		return ErrDenied
	}
	s, err := m.Journal.Load(ctx)
	if err != nil {
		return err
	}
	if !valid(s.Committed) {
		return ErrDenied
	}
	if s.Intent != nil && (!validIntent(*s.Intent) || s.Intent.Previous != s.Committed) {
		return ErrDenied
	}
	observed, err := m.read(ctx, s.Committed)
	if err != nil {
		return err
	}
	if s.Intent == nil {
		if observed != s.Committed {
			return ErrDenied
		}
		return nil
	}
	i := *s.Intent
	if observed == i.Previous {
		c, e := challenge()
		if e != nil {
			return e
		}
		o, e := m.Authority.CompareAndSwap(ctx, i.Previous, i.Next, c)
		if e != nil {
			return fmt.Errorf("%w: authority CAS: %w", ErrOutcomeUnknown, e)
		}
		if o.Challenge != c {
			return fmt.Errorf("%w: %w: invalid CAS challenge", ErrOutcomeUnknown, ErrDenied)
		}
		observed = o.Record
	}
	if observed != i.Next {
		return ErrDenied
	}
	if err := m.Journal.Commit(ctx, i); err != nil {
		return fmt.Errorf("%w: journal commit: %w", ErrOutcomeUnknown, err)
	}
	return nil
}

// Transition first reconciles all prior work; an error never means it is safe
// to assume either side unchanged. The caller must recover before use. Errors
// from Begin or subsequent recovery wrap ErrOutcomeUnknown and their cause;
// earlier errors may also require recovery even if they do not wrap it.
func (m Machine) Transition(ctx context.Context, next Record) error {
	if err := m.Recover(ctx); err != nil {
		return err
	}
	s, err := m.Journal.Load(ctx)
	if err != nil {
		return err
	}
	i := Intent{Previous: s.Committed, Next: next}
	if s.Intent != nil || !validIntent(i) {
		return ErrDenied
	}
	if err = m.Journal.Begin(ctx, s.Committed, i); err != nil {
		return fmt.Errorf("%w: journal intent: %w", ErrOutcomeUnknown, err)
	}
	if err := m.Recover(ctx); err != nil {
		return fmt.Errorf("%w: recovery after journal intent: %w", ErrOutcomeUnknown, err)
	}
	return nil
}
