package checkpointjournal

import (
	"context"
	"errors"
	"github.com/ACnoway/mcui/internal/checkpoint"
	"github.com/ACnoway/mcui/internal/checkpointstore"
	"path/filepath"
	"testing"
)

type loseJournal struct {
	checkpoint.Journal
	stage string
	after bool
}

func (j loseJournal) Begin(ctx context.Context, r checkpoint.Record, i checkpoint.Intent) error {
	if j.stage != "begin" {
		return j.Journal.Begin(ctx, r, i)
	}
	if j.after {
		if err := j.Journal.Begin(ctx, r, i); err != nil {
			return err
		}
	}
	return errLost
}
func (j loseJournal) Commit(ctx context.Context, i checkpoint.Intent) error {
	if j.stage != "commit" {
		return j.Journal.Commit(ctx, i)
	}
	if j.after {
		if err := j.Journal.Commit(ctx, i); err != nil {
			return err
		}
	}
	return errLost
}
func TestMachineUnknownJournalMutation(t *testing.T) {
	for _, stage := range []string{"begin", "commit"} {
		for _, after := range []bool{false, true} {
			t.Run(stage+map[bool]string{false: "-before", true: "-after"}[after], func(t *testing.T) {
				ctx := context.Background()
				d := t.TempDir()
				jp := filepath.Join(d, "j")
				ap := filepath.Join(d, "a")
				old := checkpoint.Record{Node: "n", Epoch: 1, Digest: [32]byte{1}}
				next := old
				next.Revision++
				next.Digest[0] = 2
				j, err := Create(jp, old)
				if err != nil {
					t.Fatal(err)
				}
				a, err := checkpointstore.Create(ap, old)
				if err != nil {
					t.Fatal(err)
				}
				err = (checkpoint.Machine{Journal: loseJournal{j, stage, after}, Authority: a}).Transition(ctx, next)
				if !errors.Is(err, checkpoint.ErrOutcomeUnknown) || !errors.Is(err, errLost) {
					t.Fatalf("transition: %v", err)
				}
				if err = j.Close(); err != nil {
					t.Fatal(err)
				}
				if err = a.Close(); err != nil {
					t.Fatal(err)
				}
				j, err = Open(jp)
				if err != nil {
					t.Fatal(err)
				}
				defer j.Close()
				a, err = checkpointstore.Open(ap)
				if err != nil {
					t.Fatal(err)
				}
				defer a.Close()
				if err = (checkpoint.Machine{Journal: j, Authority: a}).Recover(ctx); err != nil {
					t.Fatal(err)
				}
				s, err := j.Load(ctx)
				want := next
				if stage == "begin" && !after {
					want = old
				}
				if err != nil || s.Committed != want || s.Intent != nil {
					t.Fatalf("state %+v err %v", s, err)
				}
			})
		}
	}
}
