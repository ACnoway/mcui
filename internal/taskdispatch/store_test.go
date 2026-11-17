package taskdispatch

import (
	"crypto/ed25519"
	"github.com/ACnoway/mcui/internal/tasksigner"
	"path/filepath"
	"testing"
	"time"
)

const taskInput = `{"schema_version":2,"task_id":"task-001","node_id":"node-001","sequence":1,"operation":"core.status","issued_at":"2026-11-16T00:00:00Z","not_before":"2026-11-16T00:00:00Z","expires_at":"2026-11-16T00:10:00Z","payload":{"core":"xray"},"step":{"step_id":"core.status","parameters":{"core":"xray"},"artifact_sha256":"not-applicable","architecture":"not-applicable","expected_state":"observe"},"signing_key_id":"test-key","signature_algorithm":"Ed25519","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}`

func signed(t *testing.T) ([]byte, ed25519.PublicKey) {
	t.Helper()
	k := ed25519.NewKeyFromSeed(make([]byte, 32))
	s, e := tasksigner.New("test-key", k)
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.SignStatus([]byte(taskInput))
	if e != nil {
		t.Fatal(e)
	}
	return b, k.Public().(ed25519.PublicKey)
}
func TestProvisionAndDeliveryPersists(t *testing.T) {
	p := filepath.Join(t.TempDir(), "delivery.db")
	s, e := Init(p)
	if e != nil {
		t.Fatal(e)
	}
	b, k := signed(t)
	if e = s.Provision("node-001", 1, b, "test-key", k); e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	d, e := s.Lease("node-001", now, "test-key", k)
	if e != nil {
		t.Fatal(e)
	}
	if string(d.Raw) != string(b) || !d.Deadline.Equal(now.Add(time.Minute)) || d.LeaseID == "" {
		t.Fatal("bad delivery")
	}
	s.Close()
	s, e = Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Lease("node-001", now.Add(time.Second), "test-key", k); e == nil {
		t.Fatal("active lease redelivered")
	}
	d, e = s.Lease("node-001", now.Add(time.Minute), "test-key", k)
	if e != nil || string(d.Raw) != string(b) {
		t.Fatalf("redelivery: %v", e)
	}
}
