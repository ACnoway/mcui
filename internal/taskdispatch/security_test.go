package taskdispatch

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/tasksigner"
)

func makeTask(t *testing.T, node, id string, seq string) ([]byte, ed25519.PublicKey) {
	t.Helper()
	k := ed25519.NewKeyFromSeed(make([]byte, 32))
	s, e := tasksigner.New("test-key", k)
	if e != nil {
		t.Fatal(e)
	}
	in := strings.ReplaceAll(taskInput, "node-001", node)
	in = strings.ReplaceAll(in, "task-001", id)
	in = strings.Replace(in, `"sequence":1`, `"sequence":`+seq, 1)
	b, e := s.SignStatus([]byte(in))
	if e != nil {
		t.Fatal(e)
	}
	return b, k.Public().(ed25519.PublicKey)
}
func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "db")
	s, e := Init(p)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, p
}
func TestProvisionRejectsMismatches(t *testing.T) {
	s, _ := newStore(t)
	raw, key := signed(t)
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
	cases := []struct {
		node string
		seq  int64
		raw  []byte
		id   string
		key  ed25519.PublicKey
	}{
		{"node-002", 1, raw, "test-key", key}, {"node-001", 2, raw, "test-key", key}, {"node-001", 1, raw, "wrong", key}, {"node-001", 1, raw, "test-key", wrong}, {"node-001", 1, append([]byte("{"), raw...), "test-key", key},
	}
	for _, c := range cases {
		if e := s.Provision(c.node, c.seq, c.raw, c.id, c.key); e == nil {
			t.Fatal("accepted invalid input")
		}
	}
	if e := s.Provision("node-001", 1, raw, "test-key", key); e != nil {
		t.Fatal(e)
	}
	altered := append([]byte(" "), raw...)
	if e := s.Provision("node-001", 1, altered, "test-key", key); !errors.Is(e, ErrConflict) {
		t.Fatalf("slot replaced: %v", e)
	}
	if _, e := s.Lease("node-002", time.Now(), "test-key", key); !errors.Is(e, ErrNotFound) {
		t.Fatalf("wrong identity leased: %v", e)
	}
}
func TestAckVersionAndTerminalRules(t *testing.T) {
	s, _ := newStore(t)
	raw, key := signed(t)
	if e := s.Provision("node-001", 1, raw, "test-key", key); e != nil {
		t.Fatal(e)
	}
	ack := Ack{NodeID: "node-001", TaskID: "task-001", Sequence: 1, StatusVersion: 2, Status: "RUNNING", Result: []byte("ok")}
	if e := s.Acknowledge("node-001", ack); e == nil {
		t.Fatal("first version must be 1")
	}
	ack.StatusVersion = 1
	if e := s.Acknowledge("node-002", ack); e == nil {
		t.Fatal("wrong identity")
	}
	if e := s.Acknowledge("node-001", ack); e != nil {
		t.Fatal(e)
	}
	if e := s.Acknowledge("node-001", ack); e != nil {
		t.Fatal(e)
	}
	bad := ack
	bad.Result = []byte("different")
	if e := s.Acknowledge("node-001", bad); !errors.Is(e, ErrConflict) {
		t.Fatalf("duplicate conflict: %v", e)
	}
	ack.StatusVersion = 2
	ack.Status = "NEEDS_RECONCILIATION"
	if e := s.Acknowledge("node-001", ack); e != nil {
		t.Fatal(e)
	}
	next, k := makeTask(t, "node-001", "task-002", "2")
	if e := s.Provision("node-001", 2, next, "test-key", k); e == nil {
		t.Fatal("reconciliation must keep slot active")
	}
}
func TestConcurrentDuplicateAck(t *testing.T) {
	s, p := newStore(t)
	b, k := signed(t)
	if e := s.Provision("node-001", 1, b, "test-key", k); e != nil {
		t.Fatal(e)
	}
	s2, e := Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer s2.Close()
	ack := Ack{NodeID: "node-001", TaskID: "task-001", Sequence: 1, StatusVersion: 1, Status: "SUCCEEDED", Result: []byte("ok")}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st := s
			if i%2 == 0 {
				st = s2
			}
			errs <- st.Acknowledge("node-001", ack)
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
}
func TestOpenRejectsChangedConstraints(t *testing.T) {
	s, p := newStore(t)
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(`DROP INDEX one_active_per_node; CREATE INDEX one_active_per_node ON tasks(node_id)`); e != nil {
		t.Fatal(e)
	}
	db.Close()
	other, e := Open(p)
	if e == nil {
		other.Close()
		t.Fatal("accepted weakened index")
	}
}

func TestAckRejectsGapsAndRegression(t *testing.T) {
	s, _ := newStore(t)
	raw, key := signed(t)
	if e := s.Provision("node-001", 1, raw, "test-key", key); e != nil {
		t.Fatal(e)
	}
	a := Ack{NodeID: "node-001", TaskID: "task-001", Sequence: 1, StatusVersion: 1, Status: "RUNNING"}
	if e := s.Acknowledge(a.NodeID, a); e != nil {
		t.Fatal(e)
	}
	a.StatusVersion = 3
	a.Status = "SUCCEEDED"
	if e := s.Acknowledge(a.NodeID, a); e == nil {
		t.Fatal("accepted version gap")
	}
	a.StatusVersion = 2
	a.Status = "QUEUED"
	if e := s.Acknowledge(a.NodeID, a); e == nil {
		t.Fatal("accepted status regression")
	}
}
func TestOpenRejectsUnexpectedTrigger(t *testing.T) {
	s, p := newStore(t)
	s.Close()
	db, e := sql.Open("sqlite", p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(`CREATE TRIGGER evil AFTER INSERT ON acks BEGIN DELETE FROM acks; END`); e != nil {
		t.Fatal(e)
	}
	db.Close()
	other, e := Open(p)
	if e == nil {
		other.Close()
		t.Fatal("accepted unexpected trigger")
	}
}
func TestReconciliationSurvivesReopen(t *testing.T) {
	s, p := newStore(t)
	raw, key := signed(t)
	if e := s.Provision("node-001", 1, raw, "test-key", key); e != nil {
		t.Fatal(e)
	}
	a := Ack{NodeID: "node-001", TaskID: "task-001", Sequence: 1, StatusVersion: 1, Status: "NEEDS_RECONCILIATION"}
	if e := s.Acknowledge(a.NodeID, a); e != nil {
		t.Fatal(e)
	}
	s.Close()
	other, e := Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	next, k := makeTask(t, "node-001", "task-002", "2")
	if e = other.Provision("node-001", 2, next, "test-key", k); e == nil {
		t.Fatal("unblocked reconciliation")
	}
}

func TestOpenRejectsAckHistoryGaps(t *testing.T) {
	s, p := newStore(t)
	raw, key := signed(t)
	if e := s.Provision("node-001", 1, raw, "test-key", key); e != nil {
		t.Fatal(e)
	}
	s.Close()
	db, e := sql.Open("sqlite", p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(`INSERT INTO acks(task_id,status_version,node_id,sequence,status,result) VALUES('task-001',2,'node-001',1,'RUNNING',x'')`); e != nil {
		t.Fatal(e)
	}
	db.Close()
	other, e := Open(p)
	if e == nil {
		other.Close()
		t.Fatal("accepted ACK history gap")
	}
}

func TestLeaseBlockedByReconciliation(t *testing.T) {
	s, _ := newStore(t)
	raw, key := signed(t)
	if e := s.Provision("node-001", 1, raw, "test-key", key); e != nil {
		t.Fatal(e)
	}
	a := Ack{NodeID: "node-001", TaskID: "task-001", Sequence: 1, StatusVersion: 1, Status: "NEEDS_RECONCILIATION"}
	if e := s.Acknowledge(a.NodeID, a); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Lease(a.NodeID, time.Now(), "test-key", key); e == nil {
		t.Fatal("re-delivered reconciliation task")
	}
}
func TestFailedCommitCannotLeakPooledTransaction(t *testing.T) {
	s, _ := newStore(t)
	tx, e := s.db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(`PRAGMA defer_foreign_keys=ON`); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(`INSERT INTO acks(task_id,status_version,node_id,sequence,status,result) VALUES('missing',1,'node',1,'RUNNING',x'')`); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e == nil {
		t.Fatal("commit should fail")
	}
	var n int
	if e = s.db.QueryRow(`SELECT COUNT(*) FROM acks`).Scan(&n); e != nil {
		t.Fatal(e)
	}
	if n != 0 {
		t.Fatal("failed commit leaked uncommitted state")
	}
}
