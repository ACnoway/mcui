package checkpointjournal

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ACnoway/mcui/internal/checkpoint"
	"github.com/ACnoway/mcui/internal/checkpointstore"
)

// This same-host arrangement is test-only: it is neither independent nor authenticated.
type loseCAS struct {
	checkpoint.Authority
	after bool
}

var errLost = errors.New("lost response")

func (a loseCAS) CompareAndSwap(ctx context.Context, p, n checkpoint.Record, c checkpoint.Challenge) (checkpoint.Observation, error) {
	if a.after {
		if _, err := a.Authority.CompareAndSwap(ctx, p, n, c); err != nil {
			return checkpoint.Observation{}, err
		}
	}
	return checkpoint.Observation{}, errLost
}
func TestMachineCrashRecovery(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-cas", true: "after-cas"}[after], func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			jp := filepath.Join(dir, "journal")
			ap := filepath.Join(dir, "authority")
			old := checkpoint.Record{Node: "node", Epoch: 1, Digest: [32]byte{1}}
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
			err = (checkpoint.Machine{Journal: j, Authority: loseCAS{a, after}}).Transition(ctx, next)
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
			if err != nil || s.Committed != next || s.Intent != nil {
				t.Fatalf("%+v %v", s, err)
			}
		})
	}
}
