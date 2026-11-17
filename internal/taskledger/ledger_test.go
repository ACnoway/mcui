package taskledger

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOpenRejectsReplacedTaskSchema(t *testing.T) {
	path := filepath.Join(privateDir(t), "db")
	l, err := Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	// Keep all rows valid, but remove the ID uniqueness constraint.
	_, err = l.db.Exec(`DROP TABLE tasks;
CREATE TABLE tasks (seq INTEGER PRIMARY KEY, id TEXT NOT NULL, envelope BLOB NOT NULL, not_before INTEGER NOT NULL, expires INTEGER NOT NULL, state TEXT NOT NULL, result BLOB);`)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		l, err = Open(path)
		if err == nil {
			l.Close()
			t.Fatal("opened ledger without task ID uniqueness")
		}
		if !strings.Contains(err.Error(), "schema") {
			t.Fatalf("expected schema error, got: %v", err)
		}
	}
}

func TestOpenRejectsSchemaChangesBeforeRecovery(t *testing.T) {
	cases := []struct {
		name string
		sql  string
	}{
		{"metadata check", `DROP TABLE metadata; CREATE TABLE metadata (id INTEGER PRIMARY KEY, version INTEGER NOT NULL, next_seq INTEGER NOT NULL); INSERT INTO metadata VALUES(1,1,1)`},
		{"quarantine check", `DROP TABLE quarantine; CREATE TABLE quarantine (id INTEGER PRIMARY KEY, reason TEXT NOT NULL)`},
		{"cancellation unique", `DROP TABLE cancellations; CREATE TABLE cancellations (seq INTEGER PRIMARY KEY, id TEXT NOT NULL)`},
		{"task not null", `DROP TABLE tasks; CREATE TABLE tasks (seq INTEGER PRIMARY KEY, id TEXT UNIQUE, envelope BLOB NOT NULL, not_before INTEGER NOT NULL, expires INTEGER NOT NULL, state TEXT NOT NULL, result BLOB)`},
		{"extra index", `CREATE INDEX extra ON tasks(state)`},
		{"extra trigger", `CREATE TRIGGER extra AFTER UPDATE ON tasks BEGIN DELETE FROM tasks; END`},
		{"extra table", `CREATE TABLE extra (id INTEGER)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(privateDir(t), "db")
			l, err := Initialize(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = l.db.Exec(tc.sql); err != nil {
				t.Fatal(err)
			}
			if err = l.Close(); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				l, err = Open(path)
				if err == nil {
					l.Close()
					t.Fatal("modified schema accepted")
				}
				if !strings.Contains(err.Error(), "schema") {
					t.Fatalf("expected schema error: %v", err)
				}
			}
		})
	}
}

func TestInitializeAndOpenFailClosed(t *testing.T) {
	path := filepath.Join(privateDir(t), "ledger.db")
	if _, err := Open(path); err == nil {
		t.Fatal("missing ledger opened")
	}
	l, err := Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(path); err == nil {
		t.Fatal("initialized existing ledger")
	}
	l, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("lost ledger recreated")
	}
}

func TestAcceptSequenceDuplicatesAndExpiry(t *testing.T) {
	l, err := Initialize(filepath.Join(privateDir(t), "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	now := time.Unix(100, 0)
	a := Task{ID: "a", Sequence: 1, Envelope: []byte("signed-a"), NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}
	got, err := l.Accept(a, now)
	if err != nil || got.State != Pending {
		t.Fatalf("accept: %+v %v", got, err)
	}
	got, err = l.Accept(a, now)
	if err != nil || got.State != Pending {
		t.Fatalf("duplicate: %+v %v", got, err)
	}
	future := a
	future.ID = "b"
	future.Sequence = 2
	if _, err = l.Accept(future, now); !errors.Is(err, ErrGap) {
		t.Fatalf("gap: %v", err)
	}
	got, err = l.Start(1, now.Add(time.Minute))
	if err != nil || got.State != Expired {
		t.Fatalf("expiry: %+v %v", got, err)
	}
	future.ExpiresAt = now
	got, err = l.Accept(future, now)
	if err != nil || got.State != Expired {
		t.Fatalf("expired acceptance: %+v %v", got, err)
	}
	next, err := l.Next()
	if err != nil || next != 3 {
		t.Fatalf("next %d %v", next, err)
	}
}

func TestCancelStartAndRestart(t *testing.T) {
	path := filepath.Join(privateDir(t), "db")
	l, err := Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	a := Task{ID: "a", Sequence: 1, Envelope: []byte("a"), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	if err = l.AcceptCancel(1, "a", []byte("cancel a")); err != nil {
		t.Fatal(err)
	}
	got, err := l.Accept(a, now)
	if err != nil || got.State != Canceled {
		t.Fatalf("cancel tombstone: %+v %v", got, err)
	}
	a.ID = "b"
	a.Sequence = 2
	a.Envelope = []byte("b")
	if _, err = l.Accept(a, now); err != nil {
		t.Fatal(err)
	}
	if _, err = l.Start(2, now); err != nil {
		t.Fatal(err)
	}
	if err = l.AcceptCancel(2, "b", []byte("cancel b")); !errors.Is(err, ErrTooLate) {
		t.Fatalf("cancel running: %v", err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got, err = l.Get(2)
	if err != nil || got.State != Reconciliation {
		t.Fatalf("restart: %+v %v", got, err)
	}
	if err = l.Finish(2, Succeeded, []byte("result")); !errors.Is(err, ErrState) {
		t.Fatalf("finish reconciliation: %v", err)
	}
}

func TestConcurrentStartVersusCancel(t *testing.T) {
	path := filepath.Join(privateDir(t), "db")
	a, err := Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	now := time.Now().UTC()
	task := Task{ID: "task", Sequence: 1, Envelope: []byte("signed"), NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}
	if _, err = a.Accept(task, now); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var startErr, cancelErr error
	wg.Add(2)
	go func() { defer wg.Done(); _, startErr = a.Start(1, now) }()
	go func() { defer wg.Done(); cancelErr = a.AcceptCancel(1, "task", []byte("cancel task")) }()
	wg.Wait()
	got, err := a.Get(1)
	if err != nil {
		t.Fatal(err)
	}
	if got.State == Running {
		if startErr != nil || !errors.Is(cancelErr, ErrTooLate) {
			t.Fatalf("running: %v %v", startErr, cancelErr)
		}
	} else if got.State == Canceled {
		if !errors.Is(startErr, ErrState) || cancelErr != nil {
			t.Fatalf("canceled: %v %v", startErr, cancelErr)
		}
	} else {
		t.Fatalf("state %s", got.State)
	}
}
func TestFinishAndNotBefore(t *testing.T) {
	l, err := Initialize(filepath.Join(privateDir(t), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	now := time.Now().UTC()
	task := Task{ID: "x", Sequence: 1, Envelope: []byte("signed"), NotBefore: now.Add(time.Second), ExpiresAt: now.Add(time.Minute)}
	if _, err = l.Accept(task, now); err != nil {
		t.Fatal(err)
	}
	if _, err = l.Start(1, now); !errors.Is(err, ErrNotYet) {
		t.Fatal(err)
	}
	if _, err = l.Start(1, task.NotBefore); err != nil {
		t.Fatal(err)
	}
	if err = l.Finish(1, Succeeded, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if err = l.Finish(1, Succeeded, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if err = l.Finish(1, Succeeded, []byte("other")); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	got, err := l.Get(1)
	if err != nil || got.State != Succeeded || string(got.Result) != "ok" {
		t.Fatalf("%+v %v", got, err)
	}
	n, err := l.Next()
	if err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestRejectInsecureDirectoryAndFile(t *testing.T) {
	base := privateDir(t)
	dir := filepath.Join(base, "insecure")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(filepath.Join(dir, "db")); err == nil {
		t.Fatal("insecure directory accepted")
	}
	path := filepath.Join(base, "ledger")
	l, err := Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(path); err == nil {
		t.Fatal("insecure file accepted")
	}
}

func privateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDuplicateIDAndTimestampOverflowRejected(t *testing.T) {
	l, e := Initialize(filepath.Join(privateDir(t), "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	now := time.Now().UTC()
	a := Task{ID: "a", Sequence: 1, Envelope: []byte("a"), NotBefore: now, ExpiresAt: now.Add(time.Minute)}
	if _, e = l.Accept(a, now); e != nil {
		t.Fatal(e)
	}
	if _, e = l.Start(1, now); e != nil {
		t.Fatal(e)
	}
	if e = l.Finish(1, Succeeded, nil); e != nil {
		t.Fatal(e)
	}
	a.Sequence = 2
	if _, e = l.Accept(a, now); !errors.Is(e, ErrConflict) {
		t.Fatalf("duplicate ID: %v", e)
	}
	a.ID = "b"
	a.NotBefore = time.Date(2500, 1, 1, 0, 0, 0, 0, time.UTC)
	a.ExpiresAt = a.NotBefore.Add(time.Minute)
	if _, e = l.Accept(a, now); e == nil {
		t.Fatal("out-of-range date accepted")
	}
}

func TestSecondOpenDoesNotFenceActiveWorker(t *testing.T) {
	path := filepath.Join(privateDir(t), "db")
	l, err := Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	now := time.Now().UTC()
	task := Task{ID: "a", Sequence: 1, Envelope: []byte("a"), NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}
	if _, err = l.Accept(task, now); err != nil {
		t.Fatal(err)
	}
	if _, err = l.Start(1, now); err != nil {
		t.Fatal(err)
	}
	other, err := Open(path)
	if err == nil {
		other.Close()
		t.Fatal("second owner opened")
	}
	got, err := l.Get(1)
	if err != nil || got.State != Running {
		t.Fatalf("active worker fenced: %+v %v", got, err)
	}
}

func TestOpenRejectsMissingConsumedSequence(t *testing.T) {
	path := filepath.Join(privateDir(t), "db")
	l, err := Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	task := Task{ID: "a", Sequence: 1, Envelope: []byte("a"), NotBefore: now.Add(-time.Minute), ExpiresAt: now}
	if _, err = l.Accept(task, now); err != nil {
		t.Fatal(err)
	}
	if _, err = l.db.Exec("DELETE FROM tasks WHERE seq=1"); err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = Open(path)
	if err == nil {
		l.Close()
		t.Fatal("opened ledger with missing sequence")
	}
}

func TestConflictQuarantinesAcrossRestart(t *testing.T) {
	path := filepath.Join(privateDir(t), "db")
	l, err := Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	task := Task{ID: "a", Sequence: 1, Envelope: []byte("a"), NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}
	if _, err = l.Accept(task, now); err != nil {
		t.Fatal(err)
	}
	task.Envelope = []byte("altered")
	if _, err = l.Accept(task, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict %v", err)
	}
	if _, err = l.Start(1, now); err == nil {
		t.Fatal("quarantined task started")
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = Open(path)
	if err == nil {
		defer l.Close()
		if _, err = l.Start(1, now); err == nil {
			t.Fatal("quarantine lost after restart")
		}
	}
}

func TestOpenRejectsMissingHistoryWithCurrentTask(t *testing.T) {
	path := filepath.Join(privateDir(t), "db")
	l, err := Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	task := Task{ID: "a", Sequence: 1, Envelope: []byte("a"), NotBefore: now.Add(-time.Minute), ExpiresAt: now}
	if _, err = l.Accept(task, now); err != nil {
		t.Fatal(err)
	}
	task.ID = "b"
	task.Sequence = 2
	task.ExpiresAt = now.Add(time.Minute)
	if _, err = l.Accept(task, now); err != nil {
		t.Fatal(err)
	}
	if _, err = l.db.Exec("DELETE FROM tasks WHERE seq=1"); err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = Open(path)
	if err == nil {
		l.Close()
		t.Fatal("missing history hidden by current task")
	}
}

func TestCancelReusedTaskIDQuarantines(t *testing.T) {
	path := filepath.Join(privateDir(t), "db")
	l, err := Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	now := time.Now().UTC()
	task := Task{ID: "same", Sequence: 1, Envelope: []byte("a"), NotBefore: now.Add(-time.Minute), ExpiresAt: now}
	if _, err = l.Accept(task, now); err != nil {
		t.Fatal(err)
	}
	if err = l.AcceptCancel(2, "same", []byte("cancel same")); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused ID: %v", err)
	}
	if _, err = l.Accept(Task{ID: "other", Sequence: 2, Envelope: []byte("b"), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}, now); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("expected quarantine: %v", err)
	}
}

func TestQuarantineBlocksNext(t *testing.T) {
	l, err := Initialize(filepath.Join(privateDir(t), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	now := time.Now().UTC()
	task := Task{ID: "a", Sequence: 1, Envelope: []byte("a"), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	if _, err = l.Accept(task, now); err != nil {
		t.Fatal(err)
	}
	task.ID = "b"
	if _, err = l.Accept(task, now); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err = l.Next(); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("Next bypasses quarantine: %v", err)
	}
}
