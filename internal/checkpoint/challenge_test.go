package checkpoint

import (
	"context"
	"errors"
	"testing"
)

type badCASChallenge struct{ *memoryAuthority }

func (a badCASChallenge) CompareAndSwap(ctx context.Context, old, next Record, c Challenge) (Observation, error) {
	o, e := a.memoryAuthority.CompareAndSwap(ctx, old, next, c)
	o.Challenge = Challenge{}
	return o, e
}
func TestBadCASChallengeIsUnknownAndDenied(t *testing.T) {
	old := Record{Node: "n", Epoch: 1, Revision: 1, Digest: [32]byte{1}}
	next := old
	next.Revision++
	next.Digest = [32]byte{2}
	j := &memoryJournal{state: State{Committed: old}}
	a := &memoryAuthority{record: old}
	err := (Machine{Journal: j, Authority: badCASChallenge{a}}).Transition(context.Background(), next)
	if !errors.Is(err, ErrDenied) || !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("CAS response must be denied with unknown outcome: %v", err)
	}
	if j.state.Intent == nil || j.state.Committed != old || a.record != next {
		t.Fatal("incorrect durable state")
	}
	if err = (Machine{Journal: j, Authority: a}).Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
}
