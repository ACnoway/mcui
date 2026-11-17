package taskdispatch

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestLeaseRejectsCorruptStoredRawWithoutMutation(t *testing.T) {
	s, path := newStore(t)
	raw, key := signed(t)
	if err := s.Provision("node-001", 1, raw, "test-key", key); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE tasks SET raw=? WHERE task_id='task-001'`, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if d, err := s.Lease("node-001", time.Now(), "test-key", key); err == nil {
		t.Fatalf("delivered corrupt task: %s", d.Raw)
	}
	var leaseID, deadline any
	if err := s.db.QueryRow(`SELECT lease_id,lease_deadline FROM tasks WHERE task_id='task-001'`).Scan(&leaseID, &deadline); err != nil {
		t.Fatal(err)
	}
	if leaseID != nil || deadline != nil {
		t.Fatalf("corrupt delivery mutated lease: %v %v", leaseID, deadline)
	}
}

func TestAckRejectsOversizedResultWithoutMutation(t *testing.T) {
	s, _ := newStore(t)
	raw, key := signed(t)
	if err := s.Provision("node-001", 1, raw, "test-key", key); err != nil {
		t.Fatal(err)
	}
	a := Ack{NodeID: "node-001", TaskID: "task-001", Sequence: 1, StatusVersion: 1, Status: "SUCCEEDED", Result: bytes.Repeat([]byte{'x'}, 4097)}
	if err := s.Acknowledge(a.NodeID, a); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized result accepted: %v", err)
	}
	var n, active int
	if err := s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM acks),active FROM tasks WHERE task_id='task-001'`).Scan(&n, &active); err != nil {
		t.Fatal(err)
	}
	if n != 0 || active != 1 {
		t.Fatalf("oversized ACK mutated state: acks=%d active=%d", n, active)
	}
	a.Result = a.Result[:4096]
	if err := s.Acknowledge(a.NodeID, a); err != nil {
		t.Fatalf("boundary result: %v", err)
	}
}

func TestNonStatusFailureKeepsSlotUntilRollback(t *testing.T) {
	s, path := newStore(t)
	raw, key := signed(t)
	if err := s.Provision("node-001", 1, raw, "test-key", key); err != nil {
		t.Fatal(err)
	}
	// Keep the rollback transition coverage for a future mutating operation.
	// The current V2 core.status failure is terminal because it has no side effect.
	legacyRaw := bytes.Replace(raw, []byte(`"operation":"core.status"`), []byte(`"operation":"core.install"`), 1)
	if _, err := s.db.Exec(`UPDATE tasks SET raw=? WHERE task_id='task-001'`, legacyRaw); err != nil {
		t.Fatal(err)
	}
	a := Ack{NodeID: "node-001", TaskID: "task-001", Sequence: 1, StatusVersion: 1, Status: "FAILED"}
	if err := s.Acknowledge(a.NodeID, a); err != nil {
		t.Fatal(err)
	}
	next, k := makeTask(t, "node-001", "task-002", "2")
	if err := s.Provision(a.NodeID, 2, next, "test-key", k); !errors.Is(err, ErrConflict) {
		t.Fatalf("FAILED released slot: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a.StatusVersion, a.Status = 2, "ROLLING_BACK"
	if err := s.Acknowledge(a.NodeID, a); err != nil {
		t.Fatal(err)
	}
	a.StatusVersion, a.Status = 3, "ROLLED_BACK"
	if err := s.Acknowledge(a.NodeID, a); err != nil {
		t.Fatal(err)
	}
	if err := s.Provision(a.NodeID, 2, next, "test-key", k); err != nil {
		t.Fatal(err)
	}
}
