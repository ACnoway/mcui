package taskauth_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/taskauth"
)

func TestSharedVectors(t *testing.T) {
	data, err := os.ReadFile("../protocol/testdata/protocol-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Public  string `json:"public_key_hex"`
		Vectors []struct {
			ID        string `json:"id"`
			Input     string `json:"input_json"`
			Reordered string `json:"input_json_reordered"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	pub, err := hex.DecodeString(set.Public)
	if err != nil {
		t.Fatal(err)
	}
	trust := taskauth.Trust{NodeID: "node-001", Now: time.Date(2026, 11, 16, 0, 1, 0, 0, time.UTC), Keys: map[string]taskauth.Key{"test-key-01": {PublicKey: ed25519.PublicKey(pub), Active: true, Purpose: taskauth.PurposeTask}}}
	for _, v := range set.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			for _, raw := range []string{v.Input, v.Reordered} {
				got, err := taskauth.Verify([]byte(raw), trust)
				if err != nil {
					t.Fatal(err)
				}
				if got.NodeID != "node-001" || got.TaskID != "task-status-001" || got.KeyID != "test-key-01" || got.Core != "xray" {
					t.Fatalf("wrong fields: %+v", got)
				}
			}
		})
	}
}
