package tasksigner

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ACnoway/mcui/internal/protocol"
)

const inputTask = `{"schema_version":2,"task_id":"task-001","node_id":"node-001","sequence":1,"operation":"core.status","issued_at":"2026-11-16T00:00:00Z","not_before":"2026-11-16T00:00:00Z","expires_at":"2026-11-16T00:10:00Z","payload":{"core":"xray"},"step":{"step_id":"core.status","parameters":{"core":"xray"},"artifact_sha256":"not-applicable","architecture":"not-applicable","expected_state":"observe"},"signing_key_id":"test-key","signature_algorithm":"Ed25519","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}`

func TestSignStatusProducesVerifiableTask(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // public test key; never use in production
	signer, err := New("test-key", key)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignStatus([]byte(inputTask))
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifyV2Task(signed, key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
}

func TestRejectInvalidInputs(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s, err := New("test-key", key)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"key mismatch":       strings.Replace(inputTask, `"test-key"`, `"other-key"`, 1),
		"other operation":    strings.Replace(inputTask, `"operation":"core.status"`, `"operation":"core.start"`, 1),
		"existing signature": strings.Replace(inputTask, PlaceholderSignature, "BA"+PlaceholderSignature[2:], 1),
		"missing signature":  strings.Replace(inputTask, `,"signature":"`+PlaceholderSignature+`"`, "", 1),
		"duplicate key":      strings.Replace(inputTask, `"schema_version":2`, `"schema_version":2,"schema_version":2`, 1),
		"unknown field":      strings.Replace(inputTask, `"schema_version":2`, `"schema_version":2,"extra":1`, 1),
		"invalid schema":     strings.Replace(inputTask, `"sequence":1`, `"sequence":0`, 1),
		"malformed":          `{`,
		"bom":                "\xef\xbb\xbf" + inputTask,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			out, err := s.SignStatus([]byte(input))
			if err == nil || out != nil {
				t.Fatalf("accepted %s: %s", name, out)
			}
		})
	}
}

func TestInvalidKeys(t *testing.T) {
	valid := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	bad := append(ed25519.PrivateKey(nil), valid...)
	bad[63] ^= 1
	for _, tc := range []struct {
		id  string
		key ed25519.PrivateKey
	}{{"", valid}, {"test-key", nil}, {"test-key", valid[:32]}, {"test-key", bad}} {
		if _, err := New(tc.id, tc.key); err == nil {
			t.Fatal("accepted invalid key or ID")
		}
	}
	var s *Signer
	if _, err := s.SignStatus([]byte(inputTask)); err == nil {
		t.Fatal("nil signer accepted")
	}
}

func TestImmutabilityAndAlternateJSON(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := append(ed25519.PublicKey(nil), key[32:]...)
	s, err := New("test-key", key)
	if err != nil {
		t.Fatal(err)
	}
	key[0] ^= 1
	raw := []byte(inputTask)
	original := append([]byte(nil), raw...)
	signed, err := s.SignStatus(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, original) {
		t.Fatal("input mutated")
	}
	if err := protocol.VerifyV2Task(signed, public); err != nil {
		t.Fatal(err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(original, &obj); err != nil {
		t.Fatal(err)
	}
	// Move the signature to the front and use an equivalent escaped task ID.
	alternate := `{"signature":` + string(obj["signature"]) + `,` + strings.TrimPrefix(inputTask, "{")
	alternate = strings.Replace(alternate, `,"signature":"`+PlaceholderSignature+`"`, "", 1)
	alternate = strings.Replace(alternate, `task-001`, `task-\u0030\u0030\u0031`, 1)
	altSigned, err := s.SignStatus([]byte(alternate))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signed, altSigned) {
		t.Fatalf("equivalent task signed differently: %s", altSigned)
	}
	tampered := bytes.Replace(signed, []byte("task-001"), []byte("task-002"), 1)
	if err := protocol.VerifyV2Task(tampered, public); err == nil {
		t.Fatal("tampered signature accepted")
	}
}
