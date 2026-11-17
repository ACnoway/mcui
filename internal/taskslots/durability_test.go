package taskslots

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestDurabilitySettingsAndRejectWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "slots.db")
	s, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	var sync int
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("PRAGMA synchronous").Scan(&sync); err != nil {
		t.Fatal(err)
	}
	if mode != "delete" || sync != 3 {
		t.Fatalf("unsafe settings: %s %d", mode, sync)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("set WAL: %s %v", mode, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err == nil {
		reopened.Close()
		t.Fatal("accepted WAL database")
	}
}
