package checkpointjournal

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ACnoway/mcui/internal/checkpoint"
)

// SQLite automatically rolls back on RAISE(ROLLBACK); our cleanup rollback
// then fails, so the connection must be discarded rather than returned dirty.
func TestRollbackFailureDiscardsConnection(t *testing.T) {
	ctx := context.Background()
	old := checkpoint.Record{Node: "n", Epoch: 1, Digest: [32]byte{1}}
	next := old
	next.Revision++
	next.Digest[0] = 2
	intent := checkpoint.Intent{Previous: old, Next: next}
	j, err := Create(filepath.Join(t.TempDir(), "journal"), old)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err = j.db.Exec(`CREATE TRIGGER fail_update BEFORE UPDATE ON journal BEGIN SELECT RAISE(ROLLBACK, 'forced rollback'); END`); err != nil {
		t.Fatal(err)
	}
	err = j.Begin(ctx, old, intent)
	if err == nil || !strings.Contains(err.Error(), "journal rollback") {
		t.Fatalf("expected cleanup rollback failure, got %v", err)
	}
	s, err := j.Load(ctx)
	if err != nil || s.Committed != old || s.Intent != nil {
		t.Fatalf("state=%+v err=%v", s, err)
	}
	var sync int
	if err = j.db.QueryRow(`PRAGMA synchronous`).Scan(&sync); err != nil || sync != 3 {
		t.Fatalf("replacement connection synchronous=%d err=%v", sync, err)
	}
	if _, err = j.db.Exec(`DROP TRIGGER fail_update`); err != nil {
		t.Fatal(err)
	}
	if err = j.Begin(ctx, old, intent); err != nil {
		t.Fatalf("subsequent begin: %v", err)
	}
}
