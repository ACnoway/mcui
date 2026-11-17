package taskslots

import (
	"path/filepath"
	"testing"
)

func TestReservationSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "slots.db")
	s, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Reserve("node", "task", []byte("intent"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Sequence != 1 {
		t.Fatalf("sequence = %d", got.Sequence)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	again, err := s.Reserve("node", "task", []byte("intent"))
	if err != nil {
		t.Fatal(err)
	}
	if again.Sequence != got.Sequence || string(again.Intent) != "intent" {
		t.Fatalf("unexpected retry: %+v", again)
	}
}

func TestCompleteAdvancesSequence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "slots.db")
	s, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.Reserve("node", "first", []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Complete("node", "first", 1); err != nil {
		t.Fatal(err)
	}
	if err = s.Complete("node", "first", 1); err != nil {
		t.Fatal(err)
	}
	second, err := s.Reserve("node", "second", []byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	if second.Sequence != 2 {
		t.Fatalf("sequence = %d", second.Sequence)
	}
}
