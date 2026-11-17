package taskdispatch

import (
	"errors"
	"strings"
	"testing"
)

func TestRollbackCannotBeRepeated(t *testing.T) {
	s, path := newStore(t)
	raw, key := signed(t)
	if err := s.Provision("node-001", 1, raw, "test-key", key); err != nil {
		t.Fatal(err)
	}
	ack := Ack{NodeID: "node-001", TaskID: "task-001", Sequence: 1, Result: []byte("report")}
	for i, status := range []string{"FAILED", "ROLLING_BACK", "FAILED"} {
		ack.StatusVersion, ack.Status = int64(i+1), status
		if err := s.Acknowledge(ack.NodeID, ack); err != nil {
			t.Fatalf("version %d: %v", ack.StatusVersion, err)
		}
	}
	for version := int64(4); version <= 20; version++ {
		ack.StatusVersion, ack.Status = version, "ROLLING_BACK"
		if err := s.Acknowledge(ack.NodeID, ack); !errors.Is(err, ErrConflict) {
			t.Fatalf("repeated rollback at %d: %v", version, err)
		}
	}
	var count, active int
	if err := s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM acks),active FROM tasks WHERE task_id='task-001'`).Scan(&count, &active); err != nil {
		t.Fatal(err)
	}
	if count != 3 || active != 1 {
		t.Fatalf("rejected attempts mutated task: count=%d active=%d", count, active)
	}
	ack.StatusVersion, ack.Status = 1, "FAILED"
	if err := s.Acknowledge(ack.NodeID, ack); err != nil {
		t.Fatalf("old duplicate: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	ack.StatusVersion, ack.Status = 4, "ROLLING_BACK"
	if err := reopened.Acknowledge(ack.NodeID, ack); !errors.Is(err, ErrConflict) {
		t.Fatalf("repeated rollback after reopen: %v", err)
	}
}

// Inject a legacy history at the cap to isolate the cap check from transition rules.
func TestAckHistoryLimitBeforeMutation(t *testing.T) {
	const limit = 9
	s, _ := newStore(t)
	raw, key := signed(t)
	if err := s.Provision("node-001", 1, raw, "test-key", key); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= limit; version++ {
		status := "FAILED"
		if version%2 == 0 {
			status = "ROLLING_BACK"
		}
		if _, err := s.db.Exec(`INSERT INTO acks VALUES('task-001',?,'node-001',1,?,x'')`, version, status); err != nil {
			t.Fatal(err)
		}
	}
	ack := Ack{NodeID: "node-001", TaskID: "task-001", Sequence: 1, StatusVersion: limit + 1, Status: "ROLLED_BACK"}
	if err := s.Acknowledge(ack.NodeID, ack); !errors.Is(err, ErrConflict) {
		t.Fatalf("ACK beyond history limit: %v", err)
	}
	var count, active int
	if err := s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM acks),active FROM tasks`).Scan(&count, &active); err != nil {
		t.Fatal(err)
	}
	if count != limit || active != 1 {
		t.Fatalf("limit rejection mutated task: count=%d active=%d", count, active)
	}
	ack.StatusVersion, ack.Status = 1, "FAILED"
	if err := s.Acknowledge(ack.NodeID, ack); err != nil {
		t.Fatalf("old duplicate at cap: %v", err)
	}
	ack.Result = []byte("different")
	if err := s.Acknowledge(ack.NodeID, ack); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed duplicate: %v", err)
	}
}

func TestOpenRejectsOversizedAckHistory(t *testing.T) {
	s, path := newStore(t)
	raw, key := signed(t)
	if err := s.Provision("node-001", 1, raw, "test-key", key); err != nil {
		t.Fatal(err)
	}
	legacyRaw := strings.Replace(string(raw), `"operation":"core.status"`, `"operation":"core.install"`, 1)
	if _, err := s.db.Exec(`UPDATE tasks SET raw=CAST(? AS BLOB) WHERE task_id='task-001'`, legacyRaw); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 10; version++ {
		status := "FAILED"
		if version%2 == 0 {
			status = "ROLLING_BACK"
		}
		if _, err := s.db.Exec(`INSERT INTO acks VALUES('task-001',?,'node-001',1,?,x'')`, version, status); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := Open(path)
	if err == nil {
		other.Close()
		t.Fatal("accepted oversized ACK history")
	}
	if !strings.Contains(err.Error(), "ACK history limit") {
		t.Fatalf("wrong rejection: %v", err)
	}
}
