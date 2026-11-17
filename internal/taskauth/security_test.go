package taskauth_test

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
	"github.com/ACnoway/mcui/internal/taskauth"
)

var issued = time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)

func signedTask(t *testing.T) ([]byte, taskauth.Trust) {
	return signedTaskBefore(t, "2026-11-16T00:00:00Z")
}

func signedTaskBefore(t *testing.T, notBefore string) ([]byte, taskauth.Trust) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{
		"schema_version": 2, "task_id": "task-1", "node_id": "node-1", "sequence": 7, "operation": "core.status",
		"issued_at": "2026-11-16T00:00:00Z", "not_before": notBefore, "expires_at": "2026-11-16T00:10:00Z",
		"payload": map[string]any{"core": "mita"}, "step": map[string]any{"step_id": "core.status", "parameters": map[string]any{"core": "mita"}, "artifact_sha256": "not-applicable", "architecture": "not-applicable", "expected_state": "observe"}, "signing_key_id": "key-1", "signature_algorithm": "Ed25519", "signature": base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := protocol.CanonicalV2TaskBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	fields["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	raw, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw, taskauth.Trust{NodeID: "node-1", Keys: map[string]taskauth.Key{"key-1": {PublicKey: pub, Active: true, Purpose: taskauth.PurposeTask}}, Now: issued.Add(time.Minute)}
}

func TestIndependentSignatureAndOwnedBytes(t *testing.T) {
	raw, trust := signedTask(t)
	original := bytes.Clone(raw)
	got, err := taskauth.Verify(raw, trust)
	if err != nil {
		t.Fatal(err)
	}
	if got.TaskID != "task-1" || got.NodeID != "node-1" || got.Sequence != 7 || got.KeyID != "key-1" || got.Core != "mita" || !got.IssuedAt.Equal(issued) || !got.NotBefore.Equal(issued) || !got.ExpiresAt.Equal(issued.Add(10*time.Minute)) || !bytes.Equal(got.Raw, original) {
		t.Fatalf("incorrect verified fields: %+v", got)
	}
	raw[0] = '!'
	if !bytes.Equal(got.Raw, original) {
		t.Fatal("result aliases input")
	}
	got.Raw[0] = '!'
	if _, err := taskauth.Verify(got.Raw, trust); !errors.Is(err, taskauth.ErrSignature) {
		t.Fatalf("mutated bytes accepted: %v", err)
	}
}

func TestRejectUntrustedConfiguration(t *testing.T) {
	cases := []struct {
		name   string
		change func(*taskauth.Trust)
		want   error
	}{
		{"empty node", func(x *taskauth.Trust) { x.NodeID = "" }, taskauth.ErrTrust},
		{"zero time", func(x *taskauth.Trust) { x.Now = time.Time{} }, taskauth.ErrTrust},
		{"unknown key", func(x *taskauth.Trust) { delete(x.Keys, "key-1") }, taskauth.ErrKey},
		{"revoked key", func(x *taskauth.Trust) { k := x.Keys["key-1"]; k.Active = false; x.Keys["key-1"] = k }, taskauth.ErrKey},
		{"wrong purpose", func(x *taskauth.Trust) { k := x.Keys["key-1"]; k.Purpose = "approval"; x.Keys["key-1"] = k }, taskauth.ErrKey},
		{"invalid key length", func(x *taskauth.Trust) { k := x.Keys["key-1"]; k.PublicKey = []byte{1}; x.Keys["key-1"] = k }, taskauth.ErrKey},
		{"wrong node", func(x *taskauth.Trust) { x.NodeID = "node-2" }, taskauth.ErrTarget},
		{"wrong public key", func(x *taskauth.Trust) {
			k := x.Keys["key-1"]
			k.PublicKey = make([]byte, ed25519.PublicKeySize)
			x.Keys["key-1"] = k
		}, taskauth.ErrSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, trust := signedTask(t)
			tc.change(&trust)
			got, err := taskauth.Verify(raw, trust)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v; got %+v, %v", tc.want, got, err)
			}
			if len(got.Raw) != 0 {
				t.Fatal("returned data on failure")
			}
		})
	}
}

func TestTimeBoundaries(t *testing.T) {
	raw, trust := signedTask(t)
	for _, tc := range []struct {
		name  string
		now   time.Time
		valid bool
	}{
		{"before issued", issued.Add(-time.Nanosecond), false},
		{"issued and not before inclusive", issued, true},
		{"before expiry", issued.Add(10*time.Minute - time.Nanosecond), true},
		{"expiry exclusive", issued.Add(10 * time.Minute), false},
		{"after expiry", issued.Add(11 * time.Minute), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trust.Now = tc.now
			_, err := taskauth.Verify(raw, trust)
			if tc.valid && err != nil {
				t.Fatal(err)
			}
			if !tc.valid && !errors.Is(err, taskauth.ErrTime) {
				t.Fatalf("want time rejection: %v", err)
			}
		})
	}
	raw, trust = signedTaskBefore(t, "2026-11-16T00:02:00Z")
	trust.Now = issued.Add(2*time.Minute - time.Nanosecond)
	if _, err := taskauth.Verify(raw, trust); !errors.Is(err, taskauth.ErrTime) {
		t.Fatalf("before not_before: %v", err)
	}
	trust.Now = issued.Add(2 * time.Minute)
	if _, err := taskauth.Verify(raw, trust); err != nil {
		t.Fatalf("at not_before: %v", err)
	}
}

func TestRejectMalformedOrAlteredSignedBytes(t *testing.T) {
	raw, trust := signedTask(t)
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil}, {"oversized", bytes.Repeat([]byte(" "), taskauth.MaxMessageBytes+1)},
		{"signed field mutation", []byte(strings.Replace(string(raw), `"task-1"`, `"task-2"`, 1))},
		{"extra top field", []byte(strings.Replace(string(raw), `"task_id":`, `"extra":1,"task_id":`, 1))},
		{"duplicate key", []byte(strings.Replace(string(raw), `"task_id":`, `"task_id":"task-1","task_id":`, 1))},
		{"extra nested field", []byte(strings.Replace(string(raw), `"core":"mita"`, `"extra":1,"core":"mita"`, 1))},
		{"BOM", append([]byte{0xef, 0xbb, 0xbf}, raw...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := taskauth.Verify(tc.data, trust)
			if !errors.Is(err, taskauth.ErrSignature) {
				t.Fatalf("want signature/schema rejection: %v", err)
			}
		})
	}
}
