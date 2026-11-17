package taskslots

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestBusyCommitDoesNotLeakReservation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "slots.db")
	s, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.db.SetMaxOpenConns(1)
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
	if err := tx.QueryRow("SELECT count(*) FROM slots").Scan(&count); err != nil {
		t.Fatal(err)
	}
	_, err = s.Reserve("node", "task", []byte("intent"))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "busy") {
		t.Fatalf("expected busy COMMIT, got %v", err)
	}
	if err := s.Complete("node", "task", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("uncommitted reservation visible to Complete: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	slot, err := s.Reserve("node", "task", []byte("intent"))
	if err != nil || slot.Sequence != 1 || slot.Complete {
		t.Fatalf("retry: %+v, %v", slot, err)
	}
}
