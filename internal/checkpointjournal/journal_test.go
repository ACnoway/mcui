package checkpointjournal

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ACnoway/mcui/internal/checkpoint"
)

func TestRestartRetainsIntent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "journal.db")
	old := checkpoint.Record{Node: "node", Epoch: 1, Digest: [32]byte{1}}
	next := old
	next.Revision++
	next.Digest[0] = 2
	j, err := Create(path, old)
	if err != nil {
		t.Fatal(err)
	}
	i := checkpoint.Intent{Previous: old, Next: next}
	if err = j.Begin(ctx, old, i); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	s, err := j.Load(ctx)
	if err != nil || s.Committed != old || s.Intent == nil || *s.Intent != i {
		t.Fatalf("state=%+v err=%v", s, err)
	}
	if err = j.Commit(ctx, i); err != nil {
		t.Fatal(err)
	}
}
