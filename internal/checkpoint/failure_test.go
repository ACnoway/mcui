package checkpoint

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

type failBeforeJournalWrite struct {
	Journal
	stage string
}

func (j failBeforeJournalWrite) Begin(ctx context.Context, old Record, i Intent) error {
	if j.stage == "begin" {
		return errLost
	}
	return j.Journal.Begin(ctx, old, i)
}

func (j failBeforeJournalWrite) Commit(ctx context.Context, i Intent) error {
	if j.stage == "commit" {
		return errLost
	}
	return j.Journal.Commit(ctx, i)
}

func TestJournalFailureBeforeMutationRequiresRecovery(t *testing.T) {
	for _, stage := range []string{"begin", "commit"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			old := Record{Node: "n", Epoch: 1, Revision: 1, Digest: [32]byte{1}}
			next := old
			next.Revision++
			next.Digest = [32]byte{2}
			j := &memoryJournal{state: State{Committed: old}}
			a := &memoryAuthority{record: old}
			err := (Machine{Journal: failBeforeJournalWrite{Journal: j, stage: stage}, Authority: a}).Transition(ctx, next)
			if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, errLost) {
				t.Fatalf("expected unknown outcome preserving cause, got %v", err)
			}
			if stage == "begin" {
				if j.state.Committed != old || j.state.Intent != nil || a.record != old {
					t.Fatalf("begin mutated state: journal=%+v authority=%+v", j.state, a.record)
				}
			} else if j.state.Committed != old || j.state.Intent == nil || *j.state.Intent != (Intent{Previous: old, Next: next}) || a.record != next {
				t.Fatalf("unexpected state before commit: journal=%+v authority=%+v", j.state, a.record)
			}
			if err := (Machine{Journal: j, Authority: a}).Recover(ctx); err != nil {
				t.Fatal(err)
			}
			want := old
			if stage == "commit" {
				want = next
			}
			if j.state.Committed != want || j.state.Intent != nil || a.record != want {
				t.Fatalf("unexpected recovery: journal=%+v authority=%+v", j.state, a.record)
			}
		})
	}
}

type failSecondRead struct {
	*memoryAuthority
	reads int
}

func (a *failSecondRead) Read(ctx context.Context, node string, epoch uint64, c Challenge) (Observation, error) {
	a.reads++
	if a.reads == 2 {
		return Observation{}, errLost
	}
	return a.memoryAuthority.Read(ctx, node, epoch, c)
}

func TestTransitionReadFailureAfterBeginRequiresRecovery(t *testing.T) {
	ctx := context.Background()
	old := Record{Node: "n", Epoch: 1, Revision: 1, Digest: [32]byte{1}}
	next := old
	next.Revision++
	next.Digest = [32]byte{2}
	path := filepath.Join(t.TempDir(), "journal.json")
	j := &diskJournal{path: path}
	if err := j.save(State{Committed: old}); err != nil {
		t.Fatal(err)
	}
	a := &memoryAuthority{record: old}
	err := (Machine{Journal: j, Authority: &failSecondRead{memoryAuthority: a}}).Transition(ctx, next)
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, errLost) {
		t.Fatalf("expected unknown outcome preserving read error, got %v", err)
	}
	j2 := &diskJournal{path: path}
	s, err := j2.Load(ctx)
	if err != nil || s.Committed != old || s.Intent == nil || *s.Intent != (Intent{Previous: old, Next: next}) || a.record != old {
		t.Fatalf("unexpected state after read failure: journal=%+v authority=%+v error=%v", s, a.record, err)
	}
	if err := (Machine{Journal: j2, Authority: a}).Recover(ctx); err != nil {
		t.Fatal(err)
	}
	s, err = j2.Load(ctx)
	if err != nil || s.Intent != nil || s.Committed != next || a.record != next {
		t.Fatalf("recovery failed: journal=%+v authority=%+v error=%v", s, a.record, err)
	}
}
