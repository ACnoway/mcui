package checkpoint

import (
	"context"
	"errors"
	"testing"
)

var errLost = errors.New("response lost")

type lostCAS struct {
	*memoryAuthority
	after bool
}

func (a *lostCAS) CompareAndSwap(ctx context.Context, old, next Record, c Challenge) (Observation, error) {
	if a.after {
		_, _ = a.memoryAuthority.CompareAndSwap(ctx, old, next, c)
	}
	return Observation{}, errLost
}
func TestUnknownCASRequiresRecovery(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[after], func(t *testing.T) {
			old := Record{Node: "n", Epoch: 1, Revision: 1, Digest: [32]byte{1}}
			next := old
			next.Revision++
			next.Digest = [32]byte{2}
			j := &memoryJournal{state: State{Committed: old}}
			a := &memoryAuthority{record: old}
			err := (Machine{Journal: j, Authority: &lostCAS{memoryAuthority: a, after: after}}).Transition(context.Background(), next)
			if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, errLost) {
				t.Fatalf("expected unknown CAS result preserving cause, got %v", err)
			}
			if j.state.Intent == nil || j.state.Committed != old {
				t.Fatal("intent not retained")
			}
			if err = (Machine{Journal: j, Authority: a}).Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			if j.state.Intent != nil || j.state.Committed != next || a.record != next {
				t.Fatal("recovery failed")
			}
		})
	}
}
