package checkpointjournal

import (
	"path/filepath"
	"testing"

	"github.com/ACnoway/mcui/internal/checkpoint"
)

func TestOpenRejectsSQLiteLikeTrigger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	j, err := Create(path, checkpoint.Record{Node: "n", Epoch: 1, Digest: [32]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = j.db.Exec(`CREATE TRIGGER sqlitexevil AFTER UPDATE ON journal BEGIN DELETE FROM journal; END`); err != nil {
		j.Close()
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = Open(path)
	if err == nil {
		j.Close()
		t.Fatal("Open accepted an unexpected sqlite-like trigger")
	}
}
