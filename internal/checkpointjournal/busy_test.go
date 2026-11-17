package checkpointjournal

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/checkpoint"
)

// A second connection holds a read lock: BEGIN IMMEDIATE and UPDATE succeed,
// but COMMIT returns SQLITE_BUSY in rollback-journal mode.
func TestBusyCommitDoesNotLeakTransaction(t *testing.T) {
	for _, operation := range []string{"begin", "commit"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "journal.db")
			old := checkpoint.Record{Node: "n", Epoch: 1, Digest: [32]byte{1}}
			next := old
			next.Revision++
			next.Digest[0] = 2
			intent := checkpoint.Intent{Previous: old, Next: next}
			j, err := Create(path, old)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			if _, err := j.db.Exec("PRAGMA busy_timeout=20"); err != nil {
				t.Fatal(err)
			}
			if operation == "commit" {
				if err := j.Begin(ctx, old, intent); err != nil {
					t.Fatal(err)
				}
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
			if err := tx.QueryRow("SELECT count(*) FROM journal").Scan(&count); err != nil {
				t.Fatal(err)
			}
			if operation == "begin" {
				err = j.Begin(ctx, old, intent)
			} else {
				err = j.Commit(ctx, intent)
			}
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "busy") {
				t.Fatalf("expected SQLITE_BUSY COMMIT, got %v", err)
			}
			checkCtx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			state, err := j.Load(checkCtx)
			if err != nil {
				t.Fatalf("load after failed COMMIT: %v", err)
			}
			if state.Committed != old || (operation == "begin" && state.Intent != nil) || (operation == "commit" && (state.Intent == nil || *state.Intent != intent)) {
				t.Fatalf("uncommitted state exposed: %+v", state)
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			if operation == "begin" {
				err = j.Begin(checkCtx, old, intent)
			} else {
				err = j.Commit(checkCtx, intent)
			}
			if err != nil {
				t.Fatalf("subsequent operation: %v", err)
			}
		})
	}
}
