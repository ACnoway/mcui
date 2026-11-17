package checkpointstore

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ACnoway/mcui/internal/checkpoint"
)

// RAISE(ROLLBACK) ends the transaction before cleanup, forcing the explicit
// rollback to fail. The connection must then be discarded.
func TestRollbackFailureDiscardsConnection(t *testing.T) {
	ctx := context.Background()
	old := checkpoint.Record{Node: "n", Epoch: 1, Digest: [32]byte{1}}
	next := old
	next.Revision++
	next.Digest[0] = 2
	s, err := Create(filepath.Join(t.TempDir(), "authority"), old)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.db.Exec(`PRAGMA busy_timeout=20`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`CREATE TRIGGER fail_update BEFORE UPDATE ON checkpoint BEGIN SELECT RAISE(ROLLBACK, 'forced rollback'); END`); err != nil {
		t.Fatal(err)
	}
	_, err = s.CompareAndSwap(ctx, old, next, checkpoint.Challenge{})
	if err == nil || !strings.Contains(err.Error(), "checkpoint rollback") {
		t.Fatalf("expected cleanup rollback failure, got %v", err)
	}
	got, err := s.Read(ctx, old.Node, old.Epoch, checkpoint.Challenge{})
	if err != nil || got.Record != old {
		t.Fatalf("state=%+v err=%v", got, err)
	}
	var sync, timeout int
	if err = s.db.QueryRow(`PRAGMA synchronous`).Scan(&sync); err != nil || sync != 3 {
		t.Fatalf("replacement synchronous=%d err=%v", sync, err)
	}
	if err = s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); err != nil || timeout != 10000 {
		t.Fatalf("connection was not replaced: busy_timeout=%d err=%v", timeout, err)
	}
	if _, err = s.db.Exec(`DROP TRIGGER fail_update`); err != nil {
		t.Fatal(err)
	}
	got, err = s.CompareAndSwap(ctx, old, next, checkpoint.Challenge{})
	if err != nil || got.Record != next {
		t.Fatalf("subsequent CAS: %+v %v", got, err)
	}
}
