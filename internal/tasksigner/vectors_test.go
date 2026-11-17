package tasksigner

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ACnoway/mcui/internal/protocol"
)

func TestSignStatusSharedVectors(t *testing.T) {
	data, err := os.ReadFile("../protocol/testdata/protocol-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Seed    string `json:"test_private_seed_hex"`
		Vectors []struct {
			ID              string `json:"id"`
			Input           string `json:"input_json"`
			Reordered       string `json:"input_json_reordered"`
			Canonical       string `json:"canonical_json"`
			SigningInputHex string `json:"signing_input_hex"`
			Signature       string `json:"signature_base64"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(set.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatal("invalid vector seed")
	}
	key := ed25519.NewKeyFromSeed(seed)
	if len(set.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range set.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			for _, input := range []string{v.Input, v.Reordered} {
				var fields struct {
					KeyID     string `json:"signing_key_id"`
					Signature string `json:"signature"`
				}
				if err := json.Unmarshal([]byte(input), &fields); err != nil {
					t.Fatal(err)
				}
				if fields.Signature != v.Signature {
					t.Fatal("vector signature metadata mismatch")
				}
				if strings.Count(input, `"`+v.Signature+`"`) != 1 {
					t.Fatal("expected one signature")
				}
				unsigned := strings.Replace(input, `"`+v.Signature+`"`, `"`+PlaceholderSignature+`"`, 1)
				s, err := New(fields.KeyID, key)
				if err != nil {
					t.Fatal(err)
				}
				signed, err := s.SignStatus([]byte(unsigned))
				if err != nil {
					t.Fatal(err)
				}
				var got struct {
					Signature string `json:"signature"`
				}
				if err := json.Unmarshal(signed, &got); err != nil {
					t.Fatal(err)
				}
				if got.Signature != v.Signature {
					t.Fatalf("signature = %q, want %q", got.Signature, v.Signature)
				}
				canonical, err := protocol.CanonicalV2TaskBytes(signed)
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(canonical) != v.SigningInputHex || string(canonical) != "MCUI-TASK-V2\n"+v.Canonical {
					t.Fatal("canonical vector mismatch")
				}
				if err := protocol.VerifyV2Task(signed, key.Public().(ed25519.PublicKey)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestSignStatusMessageSizeBoundary(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s, err := New("test-key", key)
	if err != nil {
		t.Fatal(err)
	}
	const limit = 64 * 1024
	raw := append([]byte(inputTask), bytes.Repeat([]byte(" "), limit-len(inputTask))...)
	signed, err := s.SignStatus(raw)
	if err != nil {
		t.Fatalf("at limit: %v", err)
	}
	if err := protocol.VerifyV2Task(signed, key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	out, err := s.SignStatus(append(raw, ' '))
	if err == nil || !strings.Contains(err.Error(), "size:") || out != nil {
		t.Fatalf("over limit: output %q, error %v", out, err)
	}
}

func TestSignStatusRejectsMalformedSignature(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s, err := New("test-key", key)
	if err != nil {
		t.Fatal(err)
	}
	for _, signature := range []string{"not-base64", PlaceholderSignature + "=", "AA=="} {
		raw := strings.Replace(inputTask, PlaceholderSignature, signature, 1)
		out, err := s.SignStatus([]byte(raw))
		if err == nil || !strings.Contains(err.Error(), "schema: invalid signature encoding") || out != nil {
			t.Fatalf("signature %q: output %q, error %v", signature, out, err)
		}
	}
}
