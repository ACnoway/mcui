package checkpointjournal

import (
	"context"
	"github.com/ACnoway/mcui/internal/checkpoint"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestInvalidUTF8Rejected(t *testing.T) {
	_, err := Create(filepath.Join(t.TempDir(), "x"), checkpoint.Record{Node: string([]byte{0xff}), Epoch: 1, Digest: [32]byte{1}})
	if err == nil {
		t.Fatal("invalid UTF-8 must not be silently normalized")
	}
}
func TestConcurrentConditionalMutations(t *testing.T) {
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "x")
	old := checkpoint.Record{Node: "n", Epoch: math.MaxUint64, Revision: math.MaxUint64 - 1, Digest: [32]byte{1}}
	next := old
	next.Revision++
	next.Digest[0] = 2
	i := checkpoint.Intent{Previous: old, Next: next}
	a, err := Create(p, old)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	race := func(f func(*Journal) error) {
		var wg sync.WaitGroup
		wg.Add(2)
		results := make(chan error, 2)
		for _, j := range []*Journal{a, b} {
			go func(j *Journal) { defer wg.Done(); results <- f(j) }(j)
		}
		wg.Wait()
		close(results)
		n := 0
		for err := range results {
			if err == nil {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("successes: %d", n)
		}
	}
	race(func(j *Journal) error { return j.Begin(ctx, old, i) })
	wrong := i
	wrong.Next.Digest[1] = 3
	if err := a.Commit(ctx, wrong); err == nil {
		t.Fatal("accepted different intent")
	}
	race(func(j *Journal) error { return j.Commit(ctx, i) })
	if err := a.Begin(ctx, next, checkpoint.Intent{Previous: next, Next: old}); err == nil {
		t.Fatal("overflow accepted")
	}
	s, err := b.Load(ctx)
	if err != nil || s.Committed != next || s.Intent != nil {
		t.Fatalf("%+v %v", s, err)
	}
}
func TestMissingAndInvalidDoNotReset(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	if _, err := Open(p); err == nil {
		t.Fatal("missing accepted")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("created missing file")
	}
	if err := os.WriteFile(p, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); err == nil {
		t.Fatal("invalid accepted")
	}
	if _, err := Create(p, checkpoint.Record{Node: "n", Epoch: 1, Digest: [32]byte{1}}); err == nil {
		t.Fatal("existing file reset")
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "invalid" {
		t.Fatal("file changed", err)
	}
}
