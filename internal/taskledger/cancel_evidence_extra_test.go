package taskledger

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFutureTombstoneTaskIdentityConflicts(t *testing.T) {
	for _, tc := range []struct {
		name, id string
		seq      int64
	}{{"same sequence", "other", 1}, {"same id", "target", 1}} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := Initialize(filepath.Join(privateDir(t), "db"))
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			tombSeq := int64(1)
			if tc.name == "same id" {
				tombSeq = 3
			}
			if err = l.AcceptCancel(tombSeq, "target", []byte("evidence")); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			_, err = l.Accept(Task{ID: tc.id, Sequence: tc.seq, Envelope: []byte("task"), NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}, now)
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("expected conflict: %v", err)
			}
			if _, err = l.Next(); !errors.Is(err, ErrQuarantined) {
				t.Fatalf("expected quarantine: %v", err)
			}
		})
	}
}

func TestSignedCancelStartLinearization(t *testing.T) {
	l, err := Initialize(filepath.Join(privateDir(t), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	now := time.Now().UTC()
	_, err = l.Accept(Task{ID: "task", Sequence: 1, Envelope: []byte("task"), NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var startErr, cancelErr error
	wg.Add(2)
	go func() { defer wg.Done(); _, startErr = l.Start(1, now) }()
	go func() { defer wg.Done(); cancelErr = l.AcceptCancel(1, "task", []byte("signed cancel")) }()
	wg.Wait()
	got, err := l.Get(1)
	if err != nil {
		t.Fatal(err)
	}
	switch got.State {
	case Running:
		if startErr != nil || !errors.Is(cancelErr, ErrTooLate) {
			t.Fatalf("running %v %v", startErr, cancelErr)
		}
	case Canceled:
		if !errors.Is(startErr, ErrState) || cancelErr != nil {
			t.Fatalf("canceled %v %v", startErr, cancelErr)
		}
		if err = l.AcceptCancel(1, "task", []byte("signed cancel")); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("state %s", got.State)
	}
}
