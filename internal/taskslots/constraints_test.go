package taskslots

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestConflictsAndCompletionIdentity(t *testing.T) {
	s, err := Init(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.Reserve("a", "id", []byte("x")); err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct{ node, id, intent string }{{"a", "id", "y"}, {"b", "id", "x"}, {"a", "other", "x"}} {
		if _, err = s.Reserve(x.node, x.id, []byte(x.intent)); !errors.Is(err, ErrConflict) {
			t.Fatalf("expected conflict: %v", err)
		}
	}
	if err = s.Complete("b", "id", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong node: %v", err)
	}
	if err = s.Complete("a", "id", 2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong sequence: %v", err)
	}
	if err = s.Complete("a", "id", 1); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Reserve("b", "id", []byte("x")); !errors.Is(err, ErrConflict) {
		t.Fatalf("ID reuse: %v", err)
	}
	old, err := s.Reserve("a", "id", []byte("x"))
	if err != nil || !old.Complete {
		t.Fatalf("terminal retry: %+v %v", old, err)
	}
}

func TestOpenFailsClosedAndInitExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	if _, err := Open(path); err == nil {
		t.Fatal("missing database opened")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("missing database created: %v", err)
	}
	s, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err = Init(path); err == nil {
		t.Fatal("init overwrote existing database")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DROP INDEX one_active_per_node; CREATE INDEX one_active_per_node ON slots(node_id)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if s, err = Open(path); err == nil {
		s.Close()
		t.Fatal("unsafe schema accepted")
	}
}

func TestConcurrentReservationsAcrossStores(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	a, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var wg sync.WaitGroup
	results := make(chan error, 24)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a
			if i%2 != 0 {
				s = b
			}
			_, e := s.Reserve("node", fmt.Sprint(i), []byte("intent"))
			results <- e
		}(i)
	}
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if errors.Is(e, ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected: %v", e)
		}
	}
	if success != 1 || conflicts != 23 {
		t.Fatalf("success=%d conflicts=%d", success, conflicts)
	}
}
