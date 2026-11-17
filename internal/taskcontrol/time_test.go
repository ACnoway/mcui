package taskcontrol

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
)

func TestValidityBoundaries(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{"schema_version": 1, "node_id": "node-1", "task_id": "task-1", "sequence": 1, "issued_at": "2026-01-01T00:00:00Z", "not_before": "2026-01-01T00:00:00Z", "expires_at": "2026-01-01T00:01:00Z", "signing_key_id": "key-1", "signature_algorithm": "Ed25519"}
	raw := signed(t, protocol.Cancel, fields, priv)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name  string
		now   time.Time
		valid bool
	}{
		{"one nanosecond before", start.Add(-time.Nanosecond), false},
		{"start inclusive", start, true},
		{"one nanosecond before expiry", start.Add(time.Minute - time.Nanosecond), true},
		{"expiry exclusive", start.Add(time.Minute), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Verify(protocol.Cancel, raw, Trust{NodeID: "node-1", KeyID: "key-1", Purpose: PurposeTask, PublicKey: pub, Now: c.now})
			if c.valid && err != nil {
				t.Fatal(err)
			}
			if !c.valid && !errors.Is(err, ErrTime) {
				t.Fatalf("expected time rejection, got %v", err)
			}
		})
	}
}
