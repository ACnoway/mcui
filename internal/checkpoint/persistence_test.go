package checkpoint

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// diskJournal simulates persistent state across machine reconstruction. It is
// only a test model: WriteFile is not a durable production implementation.
type diskJournal struct {
	path                  string
	failBegin, failCommit bool
}

func (j *diskJournal) Load(context.Context) (State, error) {
	var s State
	b, e := os.ReadFile(j.path)
	if e != nil {
		return s, e
	}
	e = json.Unmarshal(b, &s)
	return s, e
}
func (j *diskJournal) save(s State) error {
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	return os.WriteFile(j.path, b, 0600)
}
func (j *diskJournal) Begin(ctx context.Context, old Record, i Intent) error {
	s, e := j.Load(ctx)
	if e != nil {
		return e
	}
	if s.Committed != old || s.Intent != nil {
		return errors.New("conflict")
	}
	s.Intent = &i
	if e = j.save(s); e != nil {
		return e
	}
	if j.failBegin {
		return errLost
	}
	return nil
}
func (j *diskJournal) Commit(ctx context.Context, i Intent) error {
	s, e := j.Load(ctx)
	if e != nil {
		return e
	}
	if s.Committed != i.Previous || s.Intent == nil || *s.Intent != i {
		return errors.New("conflict")
	}
	s.Committed = i.Next
	s.Intent = nil
	if e = j.save(s); e != nil {
		return e
	}
	if j.failCommit {
		return errLost
	}
	return nil
}
func TestRestartAfterJournalResponseLoss(t *testing.T) {
	for _, stage := range []string{"begin", "commit"} {
		t.Run(stage, func(t *testing.T) {
			old := Record{Node: "node", Epoch: 1, Revision: 10, Digest: [32]byte{1}}
			next := old
			next.Revision++
			next.Digest = [32]byte{2}
			path := filepath.Join(t.TempDir(), "journal.json")
			j := &diskJournal{path: path, failBegin: stage == "begin", failCommit: stage == "commit"}
			if err := j.save(State{Committed: old}); err != nil {
				t.Fatal(err)
			}
			a := &memoryAuthority{record: old}
			err := (Machine{Journal: j, Authority: a}).Transition(context.Background(), next)
			if !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("unknown: %v", err)
			}
			j2 := &diskJournal{path: path}
			if err = (Machine{Journal: j2, Authority: a}).Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			s, err := j2.Load(context.Background())
			if err != nil || s.Committed != next || s.Intent != nil || a.record != next {
				t.Fatalf("restart state %+v %v", s, err)
			}
		})
	}
}
func TestMismatchDeniesWithoutChangingEitherSide(t *testing.T) {
	old := Record{Node: "n", Epoch: 1, Revision: 1, Digest: [32]byte{1}}
	other := old
	other.Digest = [32]byte{9}
	next := old
	next.Revision++
	next.Digest = [32]byte{2}
	for _, intent := range []bool{false, true} {
		j := &memoryJournal{state: State{Committed: old}}
		if intent {
			j.state.Intent = &Intent{Previous: old, Next: next}
		}
		a := &memoryAuthority{record: other}
		if err := (Machine{Journal: j, Authority: a}).Recover(context.Background()); !errors.Is(err, ErrDenied) {
			t.Fatalf("expected denial: %v", err)
		}
		if j.state.Committed != old || a.record != other || (j.state.Intent != nil) != intent {
			t.Fatal("mismatch altered state")
		}
	}
}

type replayAuthority struct{ *memoryAuthority }

func (a replayAuthority) Read(ctx context.Context, node string, epoch uint64, c Challenge) (Observation, error) {
	return Observation{Record: a.record}, nil
}
func TestReplayedChallengeDenied(t *testing.T) {
	old := Record{Node: "n", Epoch: 1, Revision: 1, Digest: [32]byte{1}}
	j := &memoryJournal{state: State{Committed: old}}
	a := replayAuthority{&memoryAuthority{record: old}}
	if err := (Machine{Journal: j, Authority: a}).Recover(context.Background()); !errors.Is(err, ErrDenied) {
		t.Fatalf("expected challenge denial: %v", err)
	}
}
