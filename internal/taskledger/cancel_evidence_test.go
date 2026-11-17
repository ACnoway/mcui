package taskledger

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestFutureSignedCancellationSurvivesRestart(t *testing.T) {
	path := filepath.Join(privateDir(t), "db")
	l, err := Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"signature":"original"}`)
	if err = l.AcceptCancel(3, "third", raw); err != nil {
		t.Fatal(err)
	}
	if err = l.AcceptCancel(3, "third", raw); err != nil {
		t.Fatal(err)
	}
	if n, e := l.Next(); e != nil || n != 1 {
		t.Fatalf("next %d: %v", n, e)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var stored []byte
	if err = l.db.QueryRow(`SELECT envelope FROM cancellations WHERE seq=3`).Scan(&stored); err != nil || !bytes.Equal(stored, raw) {
		t.Fatalf("evidence %q: %v", stored, err)
	}
	now := time.Unix(100, 0)
	for i, id := range []string{"first", "second", "third"} {
		task := Task{ID: id, Sequence: int64(i + 1), Envelope: []byte(id), NotBefore: now.Add(-time.Minute), ExpiresAt: now}
		got, e := l.Accept(task, now)
		if e != nil {
			t.Fatal(e)
		}
		want := Expired
		if i == 2 {
			want = Canceled
		}
		if got.State != want {
			t.Fatalf("state %s want %s", got.State, want)
		}
	}
	if n, e := l.Next(); e != nil || n != 4 {
		t.Fatalf("next %d: %v", n, e)
	}
}

func TestSignedCancellationConflictQuarantines(t *testing.T) {
	path := filepath.Join(privateDir(t), "db")
	l, err := Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.AcceptCancel(8, "x", []byte("signature-1")); err != nil {
		t.Fatal(err)
	}
	if err = l.AcceptCancel(8, "x", []byte("signature-2")); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict: %v", err)
	}
	if _, err = l.Next(); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("quarantine: %v", err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	if l, err = Open(path); err == nil {
		l.Close()
		t.Fatal("quarantine lost")
	}
}

func TestCancellationAPIsRequireEvidence(t *testing.T) {
	if _, ok := reflect.TypeOf(&Ledger{}).MethodByName("Cancel"); ok {
		t.Fatal("legacy Cancel exposes cancellation without evidence")
	}
}

func TestCancellationEvidenceLookup(t *testing.T) {
	path := filepath.Join(privateDir(t), "db")
	l, err := Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("signed\x00envelope")
	if err = l.AcceptCancel(9, "future", raw); err != nil {
		t.Fatal(err)
	}
	lookup := func(seq int64) (string, []byte, error) { return l.GetCancel(seq) }
	id, got, err := lookup(9)
	if err != nil || id != "future" || !bytes.Equal(got, raw) {
		t.Fatalf("lookup %q %q %v", id, got, err)
	}
	got[0] ^= 1
	_, got, err = lookup(9)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("mutable evidence %q %v", got, err)
	}
	if _, _, err = lookup(8); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	id, got, err = lookup(9)
	if err != nil || id != "future" || !bytes.Equal(got, raw) {
		t.Fatalf("restart lookup %q %q %v", id, got, err)
	}
}

func TestOpenRejectsLegacyCancellationWithoutEvidence(t *testing.T) {
	for _, tombstone := range []bool{false, true} {
		t.Run(fmt.Sprint(tombstone), func(t *testing.T) {
			path := filepath.Join(privateDir(t), "db")
			l, err := Initialize(path)
			if err != nil {
				t.Fatal(err)
			}
			if tombstone {
				_, err = l.db.Exec(`INSERT INTO cancellations(seq,id,envelope) VALUES(1,'x',NULL)`)
			} else {
				_, err = l.db.Exec(`INSERT INTO tasks(seq,id,envelope,not_before,expires,state) VALUES(1,'x',X'01',1,2,'CANCELED')`)
				if err == nil {
					_, err = l.db.Exec(`UPDATE metadata SET next_seq=2`)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = l.Close(); err != nil {
				t.Fatal(err)
			}
			l, err = Open(path)
			if err == nil {
				l.Close()
				t.Fatal("accepted cancellation without evidence")
			}
		})
	}
}

func TestMissingEvidenceCannotCancelPendingTask(t *testing.T) {
	l, err := Initialize(filepath.Join(privateDir(t), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	now := time.Unix(100, 0)
	_, err = l.Accept(Task{ID: "x", Sequence: 1, Envelope: []byte("delivery"), NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.AcceptCancel(1, "x", nil); err == nil {
		t.Fatal("accepted cancellation without evidence")
	}
	task, err := l.Get(1)
	if err != nil || task.State != Pending {
		t.Fatalf("task changed: %+v %v", task, err)
	}
	if _, _, err = l.GetCancel(1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unexpected evidence: %v", err)
	}
	raw := []byte("verified cancellation")
	if err = l.AcceptCancel(1, "x", raw); err != nil {
		t.Fatal(err)
	}
	id, got, err := l.GetCancel(1)
	if err != nil || id != "x" || !bytes.Equal(got, raw) {
		t.Fatalf("lookup: %q %q %v", id, got, err)
	}
}
