package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestV2SharedVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/protocol-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		PublicKeyHex string `json:"public_key_hex"`
		SeedHex      string `json:"test_private_seed_hex"`
		Vectors      []struct {
			ID              string `json:"id"`
			Domain          string `json:"domain_hex"`
			CanonicalHex    string `json:"canonical_json_hex"`
			PublicKeyHex    string `json:"public_key_hex"`
			SignatureBase64 string `json:"signature_base64"`
			ExpectedValid   *bool  `json:"expected_valid"`
			Input           string `json:"input_json"`
			Reordered       string `json:"input_json_reordered"`
			Canonical       string `json:"canonical_json"`
			InputHex        string `json:"signing_input_hex"`
			SignatureHex    string `json:"signature_hex"`
		} `json:"vectors"`
		Negatives []struct {
			ID           string `json:"id"`
			Input        string `json:"input_json"`
			InputHex     string `json:"input_hex"`
			PublicKeyHex string `json:"public_key_hex"`
			Reject       string `json:"expected_reject"`
		} `json:"negative_cases"`
	}
	if err = json.Unmarshal(data, &set); err != nil {
		t.Fatal(err)
	}
	public, err := hex.DecodeString(set.PublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(set.SeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatal("invalid seed")
	}
	if hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)) != set.PublicKeyHex {
		t.Fatal("public key does not match seed")
	}
	if len(set.Vectors) == 0 || len(set.Negatives) == 0 {
		t.Fatal("empty vector set")
	}
	for _, v := range set.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			if v.ExpectedValid == nil || !*v.ExpectedValid || v.Domain != hex.EncodeToString([]byte("MCUI-TASK-V2\n")) || v.CanonicalHex != hex.EncodeToString([]byte(v.Canonical)) || v.PublicKeyHex != set.PublicKeyHex {
				t.Fatal("invalid vector metadata")
			}
			m, err := CanonicalV2TaskBytes([]byte(v.Input))
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(m) != v.InputHex || string(m[len("MCUI-TASK-V2\n"):]) != v.Canonical {
				t.Fatal("canonical vector mismatch")
			}
			if err = VerifyV2Task([]byte(v.Input), public); err != nil {
				t.Fatal(err)
			}
			reordered, err := CanonicalV2TaskBytes([]byte(v.Reordered))
			if err != nil || string(reordered) != string(m) {
				t.Fatalf("reordered mismatch: %v", err)
			}
			if err = VerifyV2Task([]byte(v.Reordered), public); err != nil {
				t.Fatalf("reordered verify: %v", err)
			}
			sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), m)
			if hex.EncodeToString(sig) != v.SignatureHex || base64.StdEncoding.EncodeToString(sig) != v.SignatureBase64 {
				t.Fatal("Go signature mismatch")
			}
		})
	}
	for _, v := range set.Negatives {
		t.Run(v.ID, func(t *testing.T) {
			raw := []byte(v.Input)
			if v.InputHex != "" {
				raw, err = hex.DecodeString(v.InputHex)
				if err != nil {
					t.Fatal(err)
				}
			}
			key := public
			if v.PublicKeyHex != "" {
				key, err = hex.DecodeString(v.PublicKeyHex)
				if err != nil {
					t.Fatal(err)
				}
			}
			err = VerifyV2Task(raw, key)
			if err == nil || !strings.HasPrefix(err.Error(), v.Reject+":") {
				t.Fatalf("expected %s rejection, got %v", v.Reject, err)
			}
		})
	}
}
