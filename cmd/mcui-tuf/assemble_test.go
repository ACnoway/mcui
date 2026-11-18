package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/tufrepo"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestAssembleChecksThresholdsAndPublishesRevocation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release directory publication requires Linux directory sync")
	}
	work := t.TempDir()
	staged := filepath.Join(work, "signed")
	if err := os.Mkdir(staged, 0700); err != nil {
		t.Fatal(err)
	}
	rootKeys, topKeys := map[string][]string{}, map[string][]string{}
	private := map[string][]string{}
	for role, count := range map[string]int{metadata.ROOT: 3, metadata.TARGETS: 3, metadata.SNAPSHOT: 1, metadata.TIMESTAMP: 1, tufrepo.CoreRole: 3, tufrepo.RuntimeRole: 3} {
		for range count {
			pub, key := generateTestKey(t, work)
			manifest := rootKeys
			if role == tufrepo.CoreRole || role == tufrepo.RuntimeRole {
				manifest = topKeys
			}
			manifest[role] = append(manifest[role], pub)
			private[role] = append(private[role], key)
		}
	}
	rootManifest := writeTestJSON(t, filepath.Join(work, "root-keys.json"), rootKeys)
	targetManifest := writeTestJSON(t, filepath.Join(work, "target-keys.json"), topKeys)
	inventory := writeTestJSON(t, filepath.Join(work, "review.json"), []artifacttrust.CoreReview{{
		Core: "xray", Version: "v26.10.31", Architecture: "amd64", Length: 42, SHA256: strings.Repeat("1", 64),
		ReviewID: "release-test", SignatureStatus: "verified",
	}})
	runtimeReview := writeTestJSON(t, filepath.Join(work, "runtime.json"), []tufrepo.RuntimeReview{{
		Version: "v0.1.0", Architecture: "amd64", Length: 100, SHA256: strings.Repeat("2", 64), ReviewID: "runtime-test",
	}})
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	build := func(role, input, output string, version int64, keys ...string) {
		t.Helper()
		doc, err := prepare(role, input, version, expires)
		if err != nil {
			t.Fatalf("prepare %s: %v", role, err)
		}
		name := filepath.Join(t.TempDir(), "envelope.json")
		writeTestDocument(t, name, doc)
		for _, key := range keys {
			doc, err = sign(role, name, key)
			if err != nil {
				t.Fatalf("sign %s: %v", role, err)
			}
			writeTestDocument(t, name, doc)
		}
		writeTestDocument(t, output, doc)
	}
	rebuildBindings := func(version int64) {
		t.Helper()
		build(metadata.SNAPSHOT, staged, filepath.Join(staged, "snapshot.json"), version, private[metadata.SNAPSHOT]...)
		build(metadata.TIMESTAMP, staged, filepath.Join(staged, "timestamp.json"), version, private[metadata.TIMESTAMP]...)
	}
	root := filepath.Join(work, "offline-root.json")
	build(metadata.ROOT, rootManifest, root, 1, private[metadata.ROOT][:2]...)
	build(metadata.TARGETS, targetManifest, filepath.Join(staged, "targets.json"), 1, private[metadata.TARGETS][:2]...)
	build(tufrepo.RuntimeRole, runtimeReview, filepath.Join(staged, tufrepo.RuntimeRole+".json"), 1, private[tufrepo.RuntimeRole][:2]...)
	build(tufrepo.CoreRole, inventory, filepath.Join(staged, tufrepo.CoreRole+".json"), 1, private[tufrepo.CoreRole][:1]...)
	rebuildBindings(1)
	first := filepath.Join(work, "generation-1")
	if err := assemble(root, staged, "", first); err == nil {
		t.Fatal("assembled Core metadata below the release threshold")
	}
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Fatalf("failed publication left public files: %v", err)
	}
	build(tufrepo.CoreRole, inventory, filepath.Join(staged, tufrepo.CoreRole+".json"), 1, private[tufrepo.CoreRole][:2]...)
	rebuildBindings(1)
	if err := assemble(root, staged, "", first); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(first, "1.core-targets.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(first, "1.runtime-targets.json")); err != nil {
		t.Fatal(err)
	}

	revoke := writeTestJSON(t, filepath.Join(work, "revocation.json"), []artifacttrust.CoreReview{})
	build(tufrepo.CoreRole, revoke, filepath.Join(staged, tufrepo.CoreRole+".json"), 2, private[tufrepo.CoreRole][:2]...)
	rebuildBindings(2)
	second := filepath.Join(work, "generation-2")
	if err := assemble(root, staged, "", second); err == nil {
		t.Fatal("published new metadata without checking the previous generation")
	}
	if err := assemble(root, staged, first, second); err != nil {
		t.Fatal(err)
	}
	if err := assemble(root, staged, second, filepath.Join(work, "timestamp-reuse")); err == nil {
		t.Fatal("accepted a reused timestamp version")
	}

	replacementPub, replacementKey := generateTestKey(t, work)
	rootKeys[metadata.ROOT][0] = replacementPub
	rotation := writeTestJSON(t, filepath.Join(work, "rotation-keys.json"), rootKeys)
	nextRoot := filepath.Join(staged, "2.root.json")
	third := filepath.Join(work, "generation-3")
	rebuildBindings(3)
	build(metadata.ROOT, rotation, nextRoot, 2, private[metadata.ROOT][:2]...)
	if err := assemble(root, staged, second, third); err == nil {
		t.Fatal("rotated root without the new root threshold")
	}
	build(metadata.ROOT, rotation, nextRoot, 2, append(private[metadata.ROOT][:2:2], replacementKey)...)
	if err := assemble(root, staged, second, third); err != nil {
		t.Fatalf("valid root rotation failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(third, "2.root.json")); err != nil {
		t.Fatal(err)
	}
}

func generateTestKey(t *testing.T, dir string) (string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDir, err := os.MkdirTemp(dir, "custodian-")
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(keyDir, "pub.pem")
	data, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: data}), 0644); err != nil {
		t.Fatal(err)
	}
	data, err = x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(keyDir, "private.pem")
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data}), 0600); err != nil {
		t.Fatal(err)
	}
	return publicPath, privatePath
}

func writeTestDocument(t *testing.T, path string, doc document) {
	t.Helper()
	data, err := doc.ToBytes(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func writeTestJSON(t *testing.T, path string, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
