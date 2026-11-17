//go:build linux

package helper

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
)

func signed(t *testing.T, priv ed25519.PrivateKey, node string, seq int) []byte {
	t.Helper()
	task := map[string]any{"schema_version": 2, "task_id": "task-001", "node_id": node, "sequence": seq, "operation": "core.status", "issued_at": "2026-11-17T00:00:00Z", "not_before": "2026-11-17T00:00:00Z", "expires_at": "2026-11-17T00:10:00Z", "payload": map[string]any{"core": "xray"}, "step": map[string]any{"step_id": "core.status", "parameters": map[string]any{"core": "xray"}, "artifact_sha256": "not-applicable", "architecture": "not-applicable", "expected_state": "observe"}, "signing_key_id": "key-1", "signature_algorithm": "Ed25519", "signature": base64.StdEncoding.EncodeToString(make([]byte, 64))}
	raw, _ := json.Marshal(task)
	msg, err := protocol.CanonicalV2TaskBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	task["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	raw, _ = json.Marshal(task)
	return raw
}
func TestStatusReplayPersists(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		t.Skip("root-private ledger requires root")
	}
	now := func() time.Time { return time.Date(2026, 11, 17, 0, 1, 0, 0, time.UTC) }
	calls := 0
	cfg := Config{TrustedTimeHealthy: func() bool { return true }, NodeID: "node-001", AllowedUID: uint32(os.Getuid()), Keys: map[string]TrustedKey{"key-1": {PublicKey: pub, Purpose: "task"}}, Now: now, ReadStatus: func(unit string) (string, error) {
		calls++
		if unit != "xray.service" {
			t.Fatalf("unit %q", unit)
		}
		return "active", nil
	}}
	h, err := Initialize(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw := signed(t, priv, "node-001", 1)
	got, err := h.executeUID(uint32(os.Getuid()), raw)
	if err != nil || got != "active" {
		t.Fatalf("%q %v", got, err)
	}
	h, err = Open(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err = h.executeUID(uint32(os.Getuid()), raw)
	if err != nil || got != "active" || calls != 1 {
		t.Fatalf("%q %v calls=%d", got, err, calls)
	}
	// A completed task remains retrievable after expiry without another read.
	h.cfg.Now = func() time.Time { return time.Date(2026, 11, 17, 1, 0, 0, 0, time.UTC) }
	got, err = h.executeUID(uint32(os.Getuid()), raw)
	if err != nil || got != "active" || calls != 1 {
		t.Fatalf("expired replay: %q %v calls=%d", got, err, calls)
	}
}
