package store

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestOpenPersistsAtomicUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(st *State) error {
		st.Nodes["node-a"] = Node{ID: "node-a", Name: "test"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.View(func(st State) error {
		if got := st.Nodes["node-a"].Name; got != "test" {
			t.Fatalf("node name = %q", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFailedUpdateDoesNotCommit(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("abort")
	if err := s.Update(func(st *State) error { st.Nodes["bad"] = Node{ID: "bad"}; return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("Update error = %v", err)
	}
	if err := s.View(func(st State) error {
		if _, ok := st.Nodes["bad"]; ok {
			t.Fatal("failed transaction was committed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
