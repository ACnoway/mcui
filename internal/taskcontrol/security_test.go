package taskcontrol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
)

func TestSkipTrustAndSchema(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)
	trust := Trust{NodeID: "node-1", KeyID: "key-1", Purpose: PurposeTask, PublicKey: pub, Now: now}
	fields := map[string]any{"schema_version": 1, "node_id": "node-1", "sequence": 7, "reason": "EXPIRED", "issued_at": "2026-01-01T00:00:00Z", "not_before": "2026-01-01T00:00:00Z", "expires_at": "2026-01-01T00:01:00Z", "signing_key_id": "key-1", "signature_algorithm": "Ed25519"}
	raw := signed(t, protocol.Skip, fields, priv)
	got, err := Verify(protocol.Skip, raw, trust)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != protocol.Skip || got.Reason != "EXPIRED" || got.TaskID != "" || got.Sequence != 7 || !bytes.Equal(got.Raw, raw) {
		t.Fatalf("unexpected: %+v", got)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	type tc struct {
		name  string
		kind  protocol.Kind
		raw   []byte
		trust Trust
		want  error
	}
	cases := []tc{
		{"unsupported kind", protocol.Task, raw, trust, ErrSignature},
		{"wrong schema", protocol.Cancel, raw, trust, ErrSignature},
		{"extra", protocol.Skip, []byte(strings.Replace(string(raw), `"reason":`, `"extra":1,"reason":`, 1)), trust, ErrSignature},
		{"duplicate", protocol.Skip, []byte(strings.Replace(string(raw), `"reason":`, `"reason":"EXPIRED","reason":`, 1)), trust, ErrSignature},
		{"escaped duplicate", protocol.Skip, []byte(strings.Replace(string(raw), `"reason":`, `"re\u0061son":"EXPIRED","reason":`, 1)), trust, ErrSignature},
		{"unknown reason", protocol.Skip, []byte(strings.Replace(string(raw), `"reason":"EXPIRED"`, `"reason":"OTHER"`, 1)), trust, ErrSignature},
		{"zero sequence", protocol.Skip, []byte(strings.Replace(string(raw), `"sequence":7`, `"sequence":0`, 1)), trust, ErrSignature},
		{"unknown version", protocol.Skip, []byte(strings.Replace(string(raw), `"schema_version":1`, `"schema_version":2`, 1)), trust, ErrSignature},
		{"invalid algorithm", protocol.Skip, []byte(strings.Replace(string(raw), `"Ed25519"`, `"Ed25519ph"`, 1)), trust, ErrSignature},
		{"BOM", protocol.Skip, append([]byte{0xef, 0xbb, 0xbf}, raw...), trust, ErrSignature},
		{"tamper", protocol.Skip, []byte(strings.Replace(string(raw), `"sequence":7`, `"sequence":8`, 1)), trust, ErrSignature},
	}
	tr := trust
	tr.PublicKey = other
	cases = append(cases, tc{"wrong public key", protocol.Skip, raw, tr, ErrSignature})
	tr = trust
	tr.KeyID = "unknown"
	cases = append(cases, tc{"unknown key", protocol.Skip, raw, tr, ErrKey})
	tr = trust
	tr.Purpose = "config"
	cases = append(cases, tc{"wrong purpose", protocol.Skip, raw, tr, ErrTrust})
	tr = trust
	tr.NodeID = "other"
	cases = append(cases, tc{"wrong node", protocol.Skip, raw, tr, ErrTarget})
	tr = trust
	tr.Now = time.Time{}
	cases = append(cases, tc{"zero clock", protocol.Skip, raw, tr, ErrTrust})
	tr = trust
	tr.Now = now.Add(50 * time.Second)
	cases = append(cases, tc{"expired", protocol.Skip, raw, tr, ErrTime})
	tr = trust
	tr.Now = now.Add(-11 * time.Second)
	cases = append(cases, tc{"not before", protocol.Skip, raw, tr, ErrTime})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Verify(c.kind, c.raw, c.trust)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v want %v", err, c.want)
			}
		})
	}
}

func TestRejectWrongDomainSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{"schema_version": 1, "node_id": "node-1", "task_id": "task-1", "sequence": 7, "issued_at": "2026-01-01T00:00:00Z", "not_before": "2026-01-01T00:00:00Z", "expires_at": "2026-01-01T00:01:00Z", "signing_key_id": "key-1", "signature_algorithm": "Ed25519"}
	raw := signed(t, protocol.Cancel, fields, priv)
	// Same canonical body and key, but signature made under a different domain.
	msg, err := protocol.CanonicalSignedBytes(protocol.Cancel, raw)
	if err != nil {
		t.Fatal(err)
	}
	wrong := append([]byte("MCUI-SKIP-V1\n"), bytes.TrimPrefix(msg, []byte("MCUI-CANCEL-V1\n"))...)
	sig := ed25519.Sign(priv, wrong)
	// Replace the existing signature without changing any signed field.
	old := fields["signature"].(string)
	raw = []byte(strings.Replace(string(raw), old, base64.StdEncoding.EncodeToString(sig), 1))
	trust := Trust{NodeID: "node-1", KeyID: "key-1", Purpose: PurposeTask, PublicKey: pub, Now: time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)}
	if _, err := Verify(protocol.Cancel, raw, trust); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong-domain signature accepted: %v", err)
	}
}
