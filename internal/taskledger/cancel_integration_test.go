package taskledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
	"github.com/ACnoway/mcui/internal/taskcontrol"
)

func TestVerifiedCancellationEvidenceIntegration(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{"schema_version": 1, "node_id": "node-1", "task_id": "task-1", "sequence": 7, "issued_at": "2026-01-01T00:00:00Z", "not_before": "2026-01-01T00:00:00Z", "expires_at": "2026-01-01T00:01:00Z", "signing_key_id": "key-1", "signature_algorithm": "Ed25519", "signature": base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}
	sign := func() []byte {
		raw, e := json.Marshal(fields)
		if e != nil {
			t.Fatal(e)
		}
		msg, e := protocol.CanonicalSignedBytes(protocol.Cancel, raw)
		if e != nil {
			t.Fatal(e)
		}
		fields["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
		raw, e = json.Marshal(fields)
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	raw := sign()
	trust := taskcontrol.Trust{NodeID: "node-1", KeyID: "key-1", Purpose: taskcontrol.PurposeTask, PublicKey: pub, Now: time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)}
	v, err := taskcontrol.Verify(protocol.Cancel, raw, trust)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Initialize(filepath.Join(privateDir(t), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err = l.AcceptCancel(int64(v.Sequence), v.TaskID, v.Raw); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err = l.db.QueryRow(`SELECT envelope FROM cancellations WHERE seq=7`).Scan(&stored); err != nil || !bytes.Equal(stored, raw) {
		t.Fatalf("evidence %q: %v", stored, err)
	}
	fields["expires_at"] = "2026-01-01T00:02:00Z"
	other := sign()
	v, err = taskcontrol.Verify(protocol.Cancel, other, trust)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.AcceptCancel(int64(v.Sequence), v.TaskID, v.Raw); !errors.Is(err, ErrConflict) {
		t.Fatalf("valid conflicting signature: %v", err)
	}
}
