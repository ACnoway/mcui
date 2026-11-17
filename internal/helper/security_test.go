//go:build linux

package helper

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRejectsMalformedLedgerRecord(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	c := Config{TrustedTimeHealthy: func() bool { return true }, NodeID: "node-001", AllowedUID: uint32(os.Getuid()), Keys: map[string]TrustedKey{"key-1": {PublicKey: pub, Purpose: "task"}}, Now: func() time.Time { return time.Date(2026, 11, 17, 0, 1, 0, 0, time.UTC) }, ReadStatus: func(string) (string, error) { t.Fatal("must not call status"); return "", nil }}
	h, e := Initialize(dir, c)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	bad, _ := json.Marshal(ledger{Version: 1, Node: "node-001", Records: []record{{Hash: "bad", TaskID: "task-001"}}})
	if e = os.WriteFile(filepath.Join(dir, "ledger.json"), bad, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = h.executeUID(uint32(os.Getuid()), signed(t, priv, "node-001", 2)); e != ErrReconciliation {
		t.Fatalf("expected reconciliation, got %v", e)
	}
}
