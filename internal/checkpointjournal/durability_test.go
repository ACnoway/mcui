package checkpointjournal

import (
	"path/filepath"
	"testing"

	"github.com/ACnoway/mcui/internal/checkpoint"
)

func TestDurabilityPragmas(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	j, err := Create(path, checkpoint.Record{Node: "n", Epoch: 1, Digest: [32]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	var sync int
	var mode string
	if err := j.db.QueryRow("PRAGMA synchronous").Scan(&sync); err != nil {
		t.Fatal(err)
	}
	if err := j.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if sync != 3 || mode != "delete" {
		t.Fatalf("unsafe SQLite settings: synchronous=%d journal_mode=%s", sync, mode)
	}
}

func TestOpenRejectsWALMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	j, err := Create(path, checkpoint.Record{Node: "n", Epoch: 1, Digest: [32]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	if err := j.db.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("enable WAL: %s %v", mode, err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = Open(path)
	if err == nil {
		j.Close()
		t.Fatal("accepted unverified WAL mode")
	}
}
