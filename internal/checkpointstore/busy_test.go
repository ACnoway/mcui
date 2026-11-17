package checkpointstore

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/checkpoint"
)

func TestBusyCommitDoesNotExposeUncommittedCheckpoint(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "authority.db")
	old := checkpoint.Record{Node: "node", Epoch: 1, Digest: [32]byte{1}}
	next := old
	next.Revision++
	next.Digest[0] = 2
	s, err := Create(path, old)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec("PRAGMA busy_timeout=20"); err != nil {
		t.Fatal(err)
	}
	reader, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	tx, err := reader.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRow("SELECT count(*) FROM checkpoint").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompareAndSwap(ctx, old, next, checkpoint.Challenge{}); err == nil || !strings.Contains(strings.ToLower(err.Error()), "busy") {
		t.Fatalf("expected SQLITE_BUSY at COMMIT, got %v", err)
	}
	checkCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	got, err := s.Read(checkCtx, old.Node, old.Epoch, checkpoint.Challenge{})
	if err != nil || got.Record != old {
		t.Fatalf("uncommitted checkpoint exposed: %+v %v", got, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	got, err = s.CompareAndSwap(checkCtx, old, next, checkpoint.Challenge{})
	if err != nil || got.Record != next {
		t.Fatalf("retry after failed COMMIT: %+v %v", got, err)
	}
}
