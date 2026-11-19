package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/protocol"
)

func TestLifecycleCLI(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	writeJSON := func(name string, value any) string {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return write(name, raw)
	}
	key := func(name string) (string, ed25519.PublicKey) {
		t.Helper()
		pub, private, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		return write(name, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})), pub
	}
	operatorPath, operatorKey := key("operator.pem")
	signerPath, signerKey := key("signer.pem")
	policy := writeJSON("policy.json", map[string]any{
		"schema_version": 1, "signing_key_id": "test-install-key",
		"signing_public_key": base64.StdEncoding.EncodeToString(signerKey),
		"principals": []lifecycleauth.Principal{
			{ID: "op", Role: "operator", PublicKey: base64.StdEncoding.EncodeToString(operatorKey), NodeIDs: []string{"test-node"}},
		},
	})
	now := time.Now().UTC()
	proposal := writeJSON("proposal.json", lifecycleauth.Proposal{
		SchemaVersion: 2, Operation: "core.install", Core: "xray", TaskID: "cli-test-install-000001",
		NodeID: "test-node", Sequence: 1, Version: "v26.10.31", Architecture: "arm64",
		SHA256: strings.Repeat("73", 32), ManifestVersion: 6, RequesterID: "op",
		SigningKeyID: "test-install-key", CreatedAt: now.Add(-time.Minute).Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	})
	var output bytes.Buffer
	if err := run([]string{"request", "-policy", policy, "-key", operatorPath, "-input", proposal}, &output, nil); err != nil {
		t.Fatal(err)
	}
	request := write("request.json", output.Bytes())
	output.Reset()
	ledger := filepath.Join(dir, "issues.db")
	if err := run([]string{"init-ledger", "-ledger", ledger}, &output, nil); err != nil {
		t.Fatal(err)
	}
	issueFlags := []string{"issue", "-policy", policy, "-key", signerPath, "-input", request, "-ledger", ledger}
	untrusted := errors.New("test clock unavailable")
	if err := run(issueFlags, &output, func() (time.Time, error) { return time.Time{}, untrusted }); !errors.Is(err, untrusted) || output.Len() != 0 {
		t.Fatalf("untrusted clock output=%d bytes, err=%v", output.Len(), err)
	}
	trusted := func() (time.Time, error) { return time.Now(), nil }
	if err := run(issueFlags, &output, trusted); err != nil {
		t.Fatal(err)
	}
	task := bytes.Clone(output.Bytes())
	if err := protocol.Verify(protocol.Task, task, signerKey); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run(issueFlags, &output, trusted); err != nil || !bytes.Equal(task, output.Bytes()) {
		t.Fatalf("CLI retry changed output: %v", err)
	}
}
