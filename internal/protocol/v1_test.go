package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type vectorSet struct {
	PublicKeyHex string `json:"public_key_hex"`
	Vectors      []struct {
		ID                 string `json:"id"`
		Kind               Kind   `json:"kind"`
		InputJSON          string `json:"input_json"`
		InputJSONReordered string `json:"input_json_reordered"`
		CanonicalJSON      string `json:"canonical_json"`
		SigningInputHex    string `json:"signing_input_hex"`
		PublicKeyHex       string `json:"public_key_hex"`
		SignatureHex       string `json:"signature_hex"`
		SignatureBase64    string `json:"signature_base64"`
		ConfigBytesHex     string `json:"config_bytes_hex,omitempty"`
		ConfigSize         int    `json:"config_size,omitempty"`
		ConfigSHA256       string `json:"config_sha256,omitempty"`
	} `json:"vectors"`
	NegativeCases []struct {
		ID             string `json:"id"`
		Kind           Kind   `json:"kind"`
		InputJSON      string `json:"input_json"`
		ExpectedReject string `json:"expected_reject"`
	} `json:"negative_cases"`
}

func readVectorSet(t *testing.T) vectorSet {
	t.Helper()
	data, err := os.ReadFile("testdata/protocol-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors vectorSet
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func TestV1PositiveVectorsMatchCanonicalSigningBytes(t *testing.T) {
	vectors := readVectorSet(t)
	publicKeyBytes, err := hex.DecodeString(vectors.PublicKeyHex)
	if err != nil || len(publicKeyBytes) != ed25519.PublicKeySize {
		t.Fatalf("invalid test public key: %v", err)
	}
	publicKey := ed25519.PublicKey(publicKeyBytes)
	for _, vector := range vectors.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			if err := Verify(vector.Kind, []byte(vector.InputJSON), publicKey); err != nil {
				t.Fatalf("positive vector rejected: %v", err)
			}
			message, err := CanonicalSignedBytes(vector.Kind, []byte(vector.InputJSON))
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(message); got != vector.SigningInputHex {
				t.Fatalf("signing bytes mismatch\n got: %s\nwant: %s", got, vector.SigningInputHex)
			}
			if got := string(message[len(mustDomain(t, vector.Kind)):]); got != vector.CanonicalJSON {
				t.Fatalf("canonical JSON mismatch\n got: %s\nwant: %s", got, vector.CanonicalJSON)
			}
			reordered, err := CanonicalSignedBytes(vector.Kind, []byte(vector.InputJSONReordered))
			if err != nil {
				t.Fatalf("reordered vector rejected: %v", err)
			}
			if string(reordered) != string(message) {
				t.Fatalf("field order changed the signing input\n got: %s\nwant: %s", reordered, message)
			}
			if vector.ConfigBytesHex != "" {
				config, err := hex.DecodeString(vector.ConfigBytesHex)
				if err != nil || len(config) != vector.ConfigSize {
					t.Fatalf("invalid config bytes binding: %v", err)
				}
				digest := sha256.Sum256(config)
				if hex.EncodeToString(digest[:]) != vector.ConfigSHA256 {
					t.Fatalf("config byte digest mismatch: %x", digest)
				}
			}
		})
	}
}

func mustDomain(t *testing.T, kind Kind) []byte {
	t.Helper()
	domain, err := Domain(kind)
	if err != nil {
		t.Fatal(err)
	}
	return domain
}

func TestV1NegativeVectorsAreRejected(t *testing.T) {
	vectors := readVectorSet(t)
	publicKeyBytes, err := hex.DecodeString(vectors.PublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors.NegativeCases {
		t.Run(vector.ID, func(t *testing.T) {
			if err := Verify(vector.Kind, []byte(vector.InputJSON), ed25519.PublicKey(publicKeyBytes)); err == nil {
				t.Fatalf("negative vector unexpectedly passed (%s)", vector.ExpectedReject)
			}
		})
	}
}

func TestV1RejectsInvalidUTF8AndLoneSurrogateStrings(t *testing.T) {
	if _, err := CanonicalSignedBytes(Task, []byte{0xff, '{', '}'}); err == nil {
		t.Fatal("invalid UTF-8 was accepted")
	}
	vectors := readVectorSet(t)
	input := vectors.Vectors[0].InputJSON
	input = input[:len(input)-1] + `,"unused":"\ud800"}`
	if _, err := CanonicalSignedBytes(Task, []byte(input)); err == nil {
		t.Fatal("lone surrogate was accepted")
	}
}

func TestOfficialXrayReleaseTasksOmitManifestVersion(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, operation := range []string{"core.install", "core.upgrade", "core.downgrade"} {
		payload := map[string]any{
			"core": "xray", "version": "v26.10.31", "artifact_id": "xray-amd64-" + digest,
		}
		if operation != "core.install" {
			payload["current_version"] = "v26.11.9"
			payload["current_sha256"] = strings.Repeat("b", 64)
		}
		if err := validateTaskPayload(operation, payload); err != nil {
			t.Errorf("%s without manifest_version was rejected: %v", operation, err)
		}
	}

	if err := validateTaskPayload("core.install", map[string]any{
		"core": "xray", "version": "v26.10.31", "artifact_id": "xray-manifest-amd64-" + digest,
	}); err == nil {
		t.Fatal("legacy signed-manifest artifact without its manifest version was accepted")
	}

	for _, vector := range readVectorSet(t).Vectors {
		if vector.Kind != Task {
			continue
		}
		decoded, err := decodeStrict([]byte(vector.InputJSON))
		if err != nil {
			t.Fatal(err)
		}
		message := decoded.(map[string]any)
		if message["operation"] != "config.apply" {
			continue
		}
		payload := message["payload"].(map[string]any)
		delete(payload, "manifest_version")
		if err := validateTaskPayload("config.apply", payload); err != nil {
			t.Fatalf("official Xray configuration without manifest_version was rejected: %v", err)
		}
		return
	}
	t.Fatal("protocol vectors did not include an Xray configuration task")
}
