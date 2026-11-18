//go:build linux

package artifacttrust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/corecatalog"
)

func TestRevalidateUsesCurrentThresholdSignedRepository(t *testing.T) {
	const version = "v26.10.31"
	name, err := corecatalog.ExpectedAssetName("xray", version, runtime.GOARCH)
	if err != nil {
		t.Skip("no Xray artifact for this architecture")
	}
	keys, private := repositoryTestKeys(t)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)
	base := func(role string, sequence int, fields map[string]any) map[string]any {
		fields["_type"], fields["spec_version"], fields["version"], fields["expires"] = role, "1.0.31", sequence, expires
		return fields
	}
	roles := map[string]any{}
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		roles[role] = map[string]any{"keyids": []string{"first", "second"}, "threshold": 2}
	}
	root := func(sequence int) map[string]any {
		return base("root", sequence, map[string]any{"keys": keys, "roles": roles, "consistent_snapshot": false})
	}
	root1 := signRepositoryTestMetadata(t, root(1), private, "first", "second")
	root2 := signRepositoryTestMetadata(t, root(2), private, "first", "second")
	root3 := signRepositoryTestMetadata(t, root(3), private, "first")
	digest := sha256.Sum256([]byte("candidate"))
	path := "cores/xray/" + version + "/linux/" + runtime.GOARCH + "/" + name
	custom := validCustom("xray", version, runtime.GOARCH, digest[:])
	custom.SignatureStatus = "not-provided"
	var responses = map[string][]byte{}
	publish := func(sequence int, targets map[string]any, signatures ...string) {
		targetData := signRepositoryTestMetadata(t, base("targets", sequence, map[string]any{"targets": targets}), private, signatures...)
		snapshot := signRepositoryTestMetadata(t, base("snapshot", sequence, map[string]any{"meta": map[string]any{
			"targets.json": repoFileBinding(sequence, targetData),
		}}), private, "first", "second")
		timestamp := signRepositoryTestMetadata(t, base("timestamp", sequence, map[string]any{"meta": map[string]any{
			"snapshot.json": repoFileBinding(sequence, snapshot),
		}}), private, "first", "second")
		responses["/repository/targets.json"], responses["/repository/snapshot.json"], responses["/repository/timestamp.json"] = targetData, snapshot, timestamp
	}
	targets := map[string]any{path: map[string]any{
		"length": 9, "hashes": map[string]string{"sha256": fmt.Sprintf("%x", digest)}, "custom": custom,
	}}
	dir := t.TempDir()
	client, err := New(Config{
		MetadataURL: "https://tuf.example.org/repository", TrustedRoot: root1,
		MetadataDir: filepath.Join(dir, "metadata"), RootHistoryDir: filepath.Join(dir, "roots"),
		TargetCacheDir: filepath.Join(dir, "cache"), TrustedTimeHealthy: func() error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	client.metadataHTTP.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		data, exists := responses[req.URL.Path]
		status := http.StatusOK
		if !exists {
			status = http.StatusNotFound
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data)), Request: req}, nil
	})
	ctx := context.Background()
	publish(1, targets, "first")
	if _, err := client.Lookup(ctx, "xray", version); !errors.Is(err, ErrUntrustedTarget) {
		t.Fatalf("accepted an insufficient targets threshold: %v", err)
	}
	publish(2, targets, "first", "second")
	target, err := client.Lookup(ctx, "xray", version)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Revalidate(ctx, target); err != nil {
		t.Fatal(err)
	}
	responses["/repository/2.root.json"], responses["/repository/3.root.json"] = root2, root3
	if err := client.Revalidate(ctx, target); !errors.Is(err, ErrUntrustedTarget) {
		t.Fatalf("accepted an insufficient root threshold: %v", err)
	}
	saved, err := os.ReadFile(filepath.Join(dir, "roots", "2.root.json"))
	if err != nil || !bytes.Equal(saved, root2) {
		t.Fatalf("valid root rotation was lost on refresh failure: %v", err)
	}
	delete(responses, "/repository/2.root.json")
	delete(responses, "/repository/3.root.json")
	publish(3, map[string]any{}, "first", "second")
	if err := client.Revalidate(ctx, target); !errors.Is(err, ErrUntrustedTarget) {
		t.Fatalf("accepted a target removed from current metadata: %v", err)
	}
}

func repositoryTestKeys(t *testing.T) (map[string]any, map[string]ed25519.PrivateKey) {
	t.Helper()
	keys, private := map[string]any{}, map[string]ed25519.PrivateKey{}
	for _, id := range []string{"first", "second"} {
		public, secret, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[id] = map[string]any{"keytype": "ed25519", "scheme": "ed25519", "keyval": map[string]string{"public": fmt.Sprintf("%x", public)}}
		private[id] = secret
	}
	return keys, private
}

func signRepositoryTestMetadata(t *testing.T, signed map[string]any, keys map[string]ed25519.PrivateKey, ids ...string) []byte {
	t.Helper()
	// The test uses only ASCII strings, maps, and integer values, a subset
	// where Go's sorted JSON map encoding matches TUF canonical JSON.
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var canonical map[string]any
	if err := json.Unmarshal(raw, &canonical); err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(canonical)
	if err != nil {
		t.Fatal(err)
	}
	var signatures []map[string]string
	for _, id := range ids {
		signatures = append(signatures, map[string]string{"keyid": id, "sig": fmt.Sprintf("%x", ed25519.Sign(keys[id], raw))})
	}
	data, err := json.Marshal(map[string]any{"signed": canonical, "signatures": signatures})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func repoFileBinding(version int, bytes []byte) map[string]any {
	return map[string]any{"version": version, "length": len(bytes), "hashes": map[string]string{"sha256": fmt.Sprintf("%x", sha256.Sum256(bytes))}}
}
