package checkpointstore_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/ACnoway/mcui/internal/checkpoint"
	"github.com/ACnoway/mcui/internal/checkpointstore"
)

func record() checkpoint.Record {
	return checkpoint.Record{Node: "node", Epoch: 1, Revision: 0, Digest: [32]byte{1}}
}

func TestPersistenceAndExplicitInitialization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority.db")
	if _, err := checkpointstore.Open(path); err == nil {
		t.Fatal("open created a missing store")
	}
	initial := record()
	s, err := checkpointstore.Create(path, initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := checkpointstore.Create(path, initial); err == nil {
		t.Fatal("create replaced existing store")
	}
	s, err = checkpointstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	challenge := checkpoint.Challenge{4}
	got, err := s.Read(context.Background(), initial.Node, initial.Epoch, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if got.Record != initial || got.Challenge != challenge {
		t.Fatalf("got %+v", got)
	}
}

func TestCASReplayConflictAndBinding(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "a.db")
	initial := record()
	s, err := checkpointstore.Create(path, initial)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	next := initial
	next.Revision++
	next.Digest = [32]byte{2}
	c := checkpoint.Challenge{3}
	wrongPrev := initial
	wrongPrev.Digest = [32]byte{8}
	got, err := s.CompareAndSwap(ctx, wrongPrev, next, c)
	if err != nil || got.Record != initial || got.Challenge != c {
		t.Fatalf("same-revision digest conflict: %+v %v", got, err)
	}
	persisted, err := s.Read(ctx, initial.Node, initial.Epoch, c)
	if err != nil || persisted.Record != initial || persisted.Challenge != c {
		t.Fatalf("conflict changed stored record: %+v %v", persisted, err)
	}
	for i := 0; i < 2; i++ {
		got, err := s.CompareAndSwap(ctx, initial, next, c)
		if err != nil || got.Record != next || got.Challenge != c {
			t.Fatalf("CAS: %+v %v", got, err)
		}
	}
	stale := next
	stale.Digest = [32]byte{9}
	got, err = s.CompareAndSwap(ctx, initial, stale, c)
	if err != nil || got.Record != next {
		t.Fatalf("conflict: %+v %v", got, err)
	}
	bad := initial
	bad.Node = "other"
	other := bad
	other.Revision++
	if _, err = s.CompareAndSwap(ctx, bad, other, c); err == nil {
		t.Fatal("cross-node accepted")
	}
	bad = initial
	bad.Epoch++
	other = bad
	other.Revision++
	if _, err = s.CompareAndSwap(ctx, bad, other, c); err == nil {
		t.Fatal("cross-epoch accepted")
	}
	if _, err = s.Read(ctx, "other", initial.Epoch, c); err == nil {
		t.Fatal("cross-node read")
	}
	if _, err = s.Read(ctx, initial.Node, 2, c); err == nil {
		t.Fatal("cross-epoch read")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = checkpointstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err = s.Read(ctx, next.Node, next.Epoch, c)
	if err != nil || got.Record != next {
		t.Fatalf("restart: %+v %v", got, err)
	}
}

func TestConcurrentCASSeparateHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "race.db")
	initial := record()
	a, err := checkpointstore.Create(path, initial)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := checkpointstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	x := initial
	x.Revision++
	x.Digest = [32]byte{2}
	y := x
	y.Digest = [32]byte{3}
	type result struct {
		o   checkpoint.Observation
		err error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for i, s := range []*checkpointstore.Store{a, b} {
		next := []checkpoint.Record{x, y}[i]
		go func() {
			<-start
			o, e := s.CompareAndSwap(context.Background(), initial, next, checkpoint.Challenge{})
			results <- result{o, e}
		}()
	}
	close(start)
	r1, r2 := <-results, <-results
	if r1.err != nil || r2.err != nil || r1.o.Record != r2.o.Record || (r1.o.Record != x && r1.o.Record != y) {
		t.Fatalf("results %+v %+v", r1, r2)
	}
}

func TestCASRejectsUnexpectedTransactionalMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	initial := record()
	s, err := checkpointstore.Create(path, initial)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Simulate an unexpected trigger after validation; this is a defense-in-depth
	// check, not a guarantee against an adversary with ongoing database access.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TRIGGER mutation AFTER UPDATE ON checkpoint BEGIN UPDATE checkpoint SET digest=x'0303030303030303030303030303030303030303030303030303030303030303' WHERE id=1; END`); err != nil {
		t.Fatal(err)
	}
	next := initial
	next.Revision++
	next.Digest = [32]byte{2}
	if got, err := s.CompareAndSwap(context.Background(), initial, next, checkpoint.Challenge{7}); err == nil {
		t.Fatalf("CAS returned success despite unexpected stored state: %+v", got)
	}
	got, err := s.Read(context.Background(), initial.Node, initial.Epoch, checkpoint.Challenge{})
	if err != nil || got.Record != initial {
		t.Fatalf("failed CAS did not roll back: %+v %v", got, err)
	}
}

func TestInvalidStoresAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blank")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := checkpointstore.Open(path); err == nil {
		t.Fatal("blank accepted")
	}
	path = filepath.Join(dir, "valid")
	s, err := checkpointstore.Create(path, record())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("mode: %v %v", info, err)
	}
	link := filepath.Join(dir, "link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = checkpointstore.Open(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = checkpointstore.Open(path); err == nil {
		t.Fatal("insecure permissions accepted")
	}
}

func TestRejectsTamperedSchemaAndMalformedRecord(t *testing.T) {
	for _, mutation := range []string{
		`CREATE TABLE extra (x INTEGER)`,
		`CREATE TABLE sqlitexextra (x INTEGER)`,
		`CREATE VIEW sqlitexview AS SELECT * FROM checkpoint`,
		`CREATE INDEX sqlitexindex ON checkpoint (digest)`,
		`CREATE TRIGGER sqlitexevil AFTER UPDATE ON checkpoint BEGIN UPDATE checkpoint SET digest=zeroblob(32) WHERE id=1; END`,
		`UPDATE checkpoint SET epoch=x'01'`,
	} {
		t.Run(mutation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "db")
			s, err := checkpointstore.Create(path, record())
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			if s, err = checkpointstore.Open(path); err == nil {
				s.Close()
				t.Fatal("accepted invalid database")
			}
		})
	}
}
