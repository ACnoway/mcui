package taskdispatch

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
)

func TestLeaseValidatesConfiguredTrustAndStoredBindings(t *testing.T) {
	cases := []struct {
		name     string
		alter    func(*testing.T, *Store, []byte, ed25519.PublicKey)
		keyID    string
		wrongKey bool
	}{
		{name: "wrong public key", wrongKey: true},
		{name: "wrong configured key ID", keyID: "other"},
		{name: "stored key ID mismatch", alter: func(t *testing.T, s *Store, _ []byte, _ ed25519.PublicKey) {
			if _, err := s.db.Exec(`UPDATE tasks SET key_id='other'`); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "signed task ID mismatch", alter: func(t *testing.T, s *Store, _ []byte, _ ed25519.PublicKey) {
			if _, err := s.db.Exec(`UPDATE tasks SET task_id='other'`); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "signed sequence mismatch", alter: func(t *testing.T, s *Store, _ []byte, _ ed25519.PublicKey) {
			if _, err := s.db.Exec(`UPDATE tasks SET sequence=2`); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "signed node mismatch", alter: func(t *testing.T, s *Store, _ []byte, _ ed25519.PublicKey) {
			if _, err := s.db.Exec(`UPDATE tasks SET node_id='other'`); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "bad signature", alter: func(t *testing.T, s *Store, raw []byte, key ed25519.PublicKey) {
			raw = bytes.Replace(raw, []byte(`"core":"xray"`), []byte(`"core":"sing-box"`), 2)
			if _, err := protocol.CanonicalV2TaskBytes(raw); err != nil {
				t.Fatalf("invalid fixture schema: %v", err)
			}
			if err := protocol.VerifyV2Task(raw, key); err == nil || !strings.Contains(err.Error(), "signature: verification failed") {
				t.Fatalf("invalid signature fixture: %v", err)
			}
			if _, err := s.db.Exec(`UPDATE tasks SET raw=?`, raw); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newStore(t)
			raw, key := signed(t)
			if err := s.Provision("node-001", 1, raw, "test-key", key); err != nil {
				t.Fatal(err)
			}
			if tc.alter != nil {
				tc.alter(t, s, raw, key)
			}
			if tc.wrongKey {
				key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
			}
			keyID := tc.keyID
			if keyID == "" {
				keyID = "test-key"
			}
			node := "node-001"
			if tc.name == "signed node mismatch" {
				node = "other"
			}
			d, err := s.Lease(node, time.Now(), keyID, key)
			if err == nil {
				t.Fatalf("accepted %s: %+v", tc.name, d)
			}
			if tc.name == "bad signature" && (!errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "signature: verification failed")) {
				t.Fatalf("wrong rejection layer: %v", err)
			}
			var id, deadline any
			if err := s.db.QueryRow(`SELECT lease_id,lease_deadline FROM tasks`).Scan(&id, &deadline); err != nil {
				t.Fatal(err)
			}
			if id != nil || deadline != nil {
				t.Fatalf("lease mutated: %v %v", id, deadline)
			}
		})
	}
}

func TestLeaseRequiresConfiguredKey(t *testing.T) {
	s, _ := newStore(t)
	raw, key := signed(t)
	if err := s.Provision("node-001", 1, raw, "test-key", key); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id  string
		key ed25519.PublicKey
	}{{"", key}, {"test-key", nil}} {
		if _, err := s.Lease("node-001", time.Now(), tc.id, tc.key); !errors.Is(err, ErrInvalid) {
			t.Fatalf("missing trust: %v", err)
		}
	}
}

func TestOpenRejectsOversizedStoredAck(t *testing.T) {
	s, path := newStore(t)
	raw, key := signed(t)
	if err := s.Provision("node-001", 1, raw, "test-key", key); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO acks VALUES('task-001',1,'node-001',1,'RUNNING',?)`, bytes.Repeat([]byte{'x'}, 4097)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := Open(path)
	if err == nil {
		other.Close()
		t.Fatal("accepted oversized stored result")
	}
}

func TestFailedBlocksRedelivery(t *testing.T) {
	s, _ := newStore(t)
	raw, key := signed(t)
	if err := s.Provision("node-001", 1, raw, "test-key", key); err != nil {
		t.Fatal(err)
	}
	a := Ack{NodeID: "node-001", TaskID: "task-001", Sequence: 1, StatusVersion: 1, Status: "FAILED"}
	if err := s.Acknowledge(a.NodeID, a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lease(a.NodeID, time.Now(), "test-key", key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("redelivered failure: %v", err)
	}
}
