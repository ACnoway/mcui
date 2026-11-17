package checkpoint

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
)

type memoryJournal struct{ state State }

func (j *memoryJournal) Load(context.Context) (State, error) { return j.state, nil }
func (j *memoryJournal) Begin(_ context.Context, old Record, intent Intent) error {
	if j.state.Intent != nil || j.state.Committed != old {
		return errors.New("conflict")
	}
	j.state.Intent = &intent
	return nil
}
func (j *memoryJournal) Commit(_ context.Context, intent Intent) error {
	if j.state.Intent == nil || *j.state.Intent != intent || j.state.Committed != intent.Previous {
		return errors.New("conflict")
	}
	j.state.Committed = intent.Next
	j.state.Intent = nil
	return nil
}

type memoryAuthority struct{ record Record }

func (a *memoryAuthority) Read(_ context.Context, node string, epoch uint64, challenge Challenge) (Observation, error) {
	return Observation{Record: a.record, Challenge: challenge}, nil
}
func (a *memoryAuthority) CompareAndSwap(_ context.Context, old, next Record, challenge Challenge) (Observation, error) {
	if a.record == old {
		a.record = next
	}
	return Observation{Record: a.record, Challenge: challenge}, nil
}
func TestTransitionAnchorsAndPersists(t *testing.T) {
	old := Record{Node: "node-a", Epoch: 1, Revision: 3, Digest: sha256.Sum256([]byte("old"))}
	next := old
	next.Revision++
	next.Digest = sha256.Sum256([]byte("new"))
	local := &memoryJournal{state: State{Committed: old}}
	authority := &memoryAuthority{record: old}
	m := Machine{Journal: local, Authority: authority}
	if err := m.Transition(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if local.state.Committed != next || local.state.Intent != nil || authority.record != next {
		t.Fatalf("not committed: local=%+v authority=%+v", local.state, authority.record)
	}
}
