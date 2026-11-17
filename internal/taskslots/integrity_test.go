package taskslots

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenRejectsHiddenTrigger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	// The underscore in the old sqlite_% LIKE filter matched the x in this name.
	if _, err = s.db.Exec(`CREATE TRIGGER sqlitexevil AFTER INSERT ON slots BEGIN DELETE FROM slots WHERE task_id=NEW.task_id; END`); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err == nil {
		s.Close()
		t.Fatal("opened database with hidden trigger")
	}
	if !strings.Contains(err.Error(), "invalid task slot schema") {
		t.Fatalf("expected schema rejection, got %v", err)
	}
}

func TestReserveRejectsSequenceAboveProtocolMaximum(t *testing.T) {
	s, err := Init(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const max = int64(9007199254740991)
	// Seed the boundary directly; materializing all preceding slots is impractical.
	if _, err := s.db.Exec(`INSERT INTO slots(task_id,node_id,sequence,intent,completed) VALUES('last','node',?,X'78',1)`, max); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reserve("node", "next", []byte("x")); err == nil {
		t.Fatal("reserved a sequence beyond the protocol maximum")
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM slots`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("mutation after exhaustion: count=%d err=%v", count, err)
	}
}

func TestOpenRejectsInvalidSlotData(t *testing.T) {
	for _, tc := range []struct{ name, mutate string }{
		{"empty node", `UPDATE slots SET node_id=''`},
		{"empty task", `UPDATE slots SET task_id=''`},
		{"empty intent", `UPDATE slots SET intent=X''`},
		{"non-blob intent", `UPDATE slots SET intent='text'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "db")
			s, err := Init(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Reserve("node", "task", []byte("x")); err != nil {
				t.Fatal(err)
			}
			if _, err = s.db.Exec(tc.mutate); err != nil {
				t.Fatal(err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(path)
			if err == nil {
				s.Close()
				t.Fatal("opened database with invalid slot")
			}
		})
	}
}

func TestReserveAllowsProtocolMaximum(t *testing.T) {
	s, err := Init(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const max = int64(9007199254740991)
	if _, err = s.db.Exec(`INSERT INTO slots(task_id,node_id,sequence,intent,completed) VALUES('prior','node',?,X'78',1)`, max-1); err != nil {
		t.Fatal(err)
	}
	slot, err := s.Reserve("node", "last", []byte("x"))
	if err != nil || slot.Sequence != max {
		t.Fatalf("maximum slot: %+v %v", slot, err)
	}
}

func TestOpenRejectsActiveEarlierThanLatest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Reserve("node", "first", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err = s.Complete("node", "first", 1); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Reserve("node", "second", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err = s.Complete("node", "second", 2); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE slots SET completed=0 WHERE task_id='first'`); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err == nil {
		s.Close()
		t.Fatal("opened database with older active slot")
	}
}

func TestOpenRejectsDiscontinuousHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"one", "two", "three"} {
		slot, err := s.Reserve("node", id, []byte(id))
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Complete("node", id, slot.Sequence); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`DELETE FROM slots WHERE task_id='two'`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err == nil {
		s.Close()
		t.Fatal("opened a database with a missing middle sequence")
	}
}
