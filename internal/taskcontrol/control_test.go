package taskcontrol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
)

func signed(t *testing.T, kind protocol.Kind, fields map[string]any, private ed25519.PrivateKey) []byte {
	t.Helper()
	fields["signature"] = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := protocol.CanonicalSignedBytes(kind, raw)
	if err != nil {
		t.Fatal(err)
	}
	fields["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(private, msg))
	raw, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifyCancel(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{"schema_version": 1, "node_id": "node-1", "task_id": "task-1", "sequence": 7, "issued_at": "2026-01-01T00:00:00Z", "not_before": "2026-01-01T00:00:00Z", "expires_at": "2026-01-01T00:01:00Z", "signing_key_id": "key-1", "signature_algorithm": "Ed25519"}
	raw := signed(t, protocol.Cancel, fields, priv)
	trust := Trust{NodeID: "node-1", KeyID: "key-1", Purpose: PurposeTask, PublicKey: pub, Now: time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)}
	got, err := Verify(protocol.Cancel, raw, trust)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != protocol.Cancel || got.NodeID != "node-1" || got.TaskID != "task-1" || got.Sequence != 7 || !bytes.Equal(got.Raw, raw) {
		t.Fatalf("unexpected verified cancel: %+v", got)
	}
	for _, tc := range []struct {
		name, replacement, wantError string
	}{
		{"invalid UTF-8", "task-\xff", "invalid or oversized signed message"},
		{"lone surrogate", `task-\ud800`, `invalid identifier field "task_id"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := []byte(`"task_id":"task-1"`)
			if bytes.Count(raw, old) != 1 {
				t.Fatal("fixture does not contain exactly one task_id field")
			}
			mutated := bytes.Replace(raw, old, []byte(`"task_id":"`+tc.replacement+`"`), 1)
			_, err := Verify(protocol.Cancel, mutated, trust)
			if !errors.Is(err, ErrSignature) || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("Verify() error = %v; want ErrSignature containing %q", err, tc.wantError)
			}
		})
	}
	raw[0] = 'x'
	if got.Raw[0] == 'x' {
		t.Fatal("verified bytes alias input")
	}
}
