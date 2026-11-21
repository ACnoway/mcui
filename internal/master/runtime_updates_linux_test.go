package master

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/runtimeupdate"
	"github.com/ACnoway/mcui/internal/store"
)

func TestRuntimeUpdateMasterQueue(t *testing.T) {
	t.Run("single-host", func(t *testing.T) { testRuntimeUpdateMasterQueue(t, false) })
	t.Run("independent-checkpoint", func(t *testing.T) { testRuntimeUpdateMasterQueue(t, true) })
}

func testRuntimeUpdateMasterQueue(t *testing.T, independent bool) {
	client := newTaskTestClient(t)
	now := time.Now().UTC()
	if err := client.store.Update(func(st *store.State) error {
		admin := st.Admins["operator-1"]
		admin.Role = "security_admin"
		st.Admins[admin.ID] = admin
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if independent {
		enrollTestCheckpoint(t, client)
	}
	taskRuntime := *client.server.taskRuntime
	taskRuntime.TrustedNow = func() (time.Time, error) { return now, nil }
	if err := client.server.ConfigureTaskRuntime(taskRuntime); err != nil {
		t.Fatal(err)
	}
	release := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	update := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	token, err := randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	policy := RuntimeUpdatePolicy{
		ArchiveDir: dir, NodeTokens: map[string]string{client.nodeID: hash(token)},
		ReleaseKey: release.Public().(ed25519.PublicKey), AuthorizationKey: update.Public().(ed25519.PublicKey),
	}
	if err := client.server.ConfigureRuntimeUpdates(policy); err != nil {
		t.Fatal(err)
	}
	archive := []byte("archive pass-through fixture")
	digest := fmt.Sprintf("%x", sha256.Sum256(archive))
	if err := os.WriteFile(filepath.Join(dir, digest+".zip"), archive, 0444); err != nil {
		t.Fatal(err)
	}
	pair := strings.Repeat("c", 64)
	manifest := artifacttrust.Manifest{SchemaVersion: 1, ManifestVersion: 1, ExpiresAt: now.Add(time.Hour), Artifacts: []artifacttrust.Artifact{{
		ArtifactID: "mcui-runtime-amd64-" + digest, Component: "mcui-runtime", Version: "v1.0.1", OS: "linux", Architecture: "amd64",
		Filename: "mcui-runtime-linux-amd64.zip", SourceID: "github:ACnoway/mcui", ArchiveFormat: "zip",
		BuildOptions: "mcui-build:" + strings.Repeat("a", 40), Length: int64(len(archive)), SHA256: digest, ReviewID: "runtime-test",
		SignatureStatus: "not-applicable",
	}}}
	marshal := func(value any) []byte {
		t.Helper()
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return append(raw, '\n')
	}
	rawManifest := marshal(manifest)
	proof := func(sequence int64) runtimeupdate.Package {
		t.Helper()
		auth := runtimeupdate.Authorization{
			SchemaVersion: 1, StateProtocol: 1, NodeID: client.nodeID, Sequence: sequence, CurrentPair: pair, ManifestVersion: 1,
			ManifestSHA256: fmt.Sprintf("%x", sha256.Sum256(rawManifest)), Version: "v1.0.1", Architecture: "amd64", SHA256: digest,
			NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
		}
		raw := marshal(auth)
		sig, err := runtimeupdate.SignAuthorization(raw, update)
		if err != nil {
			t.Fatal(err)
		}
		return runtimeupdate.Package{Authorization: raw, AuthorizationSignature: sig, Manifest: rawManifest, ManifestSignature: ed25519.Sign(release, rawManifest)}
	}
	doRequest := func(method, path, csrf, bearer string, body any) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "https://example.com"+path, bytes.NewReader(marshal(body)))
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("X-CSRF-Token", csrf)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		} else {
			req.AddCookie(&http.Cookie{Name: "mcui_session", Value: "test-session-token"})
		}
		res := httptest.NewRecorder()
		client.server.Handler().ServeHTTP(res, req)
		return res
	}
	request := func(code int, method, path, csrf, bearer string, body any) *httptest.ResponseRecorder {
		t.Helper()
		res := doRequest(method, path, csrf, bearer, body)
		if res.Code != code {
			t.Fatalf("%s %s: HTTP %d, want %d: %s", method, path, res.Code, code, res.Body.String())
		}
		return res
	}
	adminPath := "/api/v1/admin/nodes/" + client.nodeID + "/runtime-updates"
	rootPath := runtimeupdate.RemoteEndpoint + client.nodeID
	first := proof(1)
	bad := first
	bad.AuthorizationSignature = first.ManifestSignature
	request(403, "POST", adminPath, "bad", "", map[string]any{"package": first})
	request(400, "POST", adminPath, client.csrf, "", map[string]any{"package": bad})
	request(400, "POST", "/api/v1/admin/nodes/other/runtime-updates", client.csrf, "", map[string]any{"package": first})
	path := filepath.Join(dir, digest+".zip")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{1}, len(archive)), 0444); err != nil {
		t.Fatal(err)
	}
	request(503, "POST", adminPath, client.csrf, "", map[string]any{"package": first})
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, archive, 0444); err != nil {
		t.Fatal(err)
	}
	request(201, "POST", adminPath, client.csrf, "", map[string]any{"package": first})
	request(200, "POST", adminPath, client.csrf, "", map[string]any{"package": first})
	request(409, "POST", adminPath, client.csrf, "", map[string]any{"package": proof(2)})
	task := statusTaskRequest{RequestID: "request-1234567890123456", NodeID: client.nodeID, Core: "xray"}
	request(409, "POST", "/api/v1/admin/tasks", client.csrf, "", task)
	request(401, "POST", rootPath+"/poll", "", client.token, nil)
	request(404, "GET", rootPath+"/archive/"+first.ID(), "", token, nil)
	response := request(200, "POST", rootPath+"/poll", "", token, nil)
	var delivery runtimeupdate.Delivery
	if err := json.Unmarshal(response.Body.Bytes(), &delivery); err != nil || delivery.ID != first.ID() ||
		!bytes.Equal(delivery.Package.Authorization, first.Authorization) || !bytes.Equal(delivery.Package.Manifest, first.Manifest) {
		t.Fatalf("changed signed bytes: %v", err)
	}
	response = request(200, "GET", rootPath+"/archive/"+first.ID(), "", token, nil)
	if !bytes.Equal(response.Body.Bytes(), archive) {
		t.Fatal("incorrect archive")
	}
	now = now.Add(2 * time.Minute)
	request(200, "POST", rootPath+"/poll", "", token, nil)
	request(404, "GET", rootPath+"/archive/"+first.ID(), "", token, nil)
	request(409, "POST", "/api/v1/admin/tasks", client.csrf, "", task)
	receipt := runtimeupdate.Receipt{ID: first.ID(), Status: runtimeupdate.RolledBack, CurrentPair: pair}
	request(401, "POST", rootPath+"/receipt", "", client.token, receipt)
	request(204, "POST", rootPath+"/receipt", "", token, receipt)
	if err := client.server.ReconcileTaskRuntime(); err != nil {
		t.Fatal(err)
	}
	request(204, "POST", rootPath+"/receipt", "", token, receipt)
	receipt.Status = runtimeupdate.Rejected
	request(409, "POST", rootPath+"/receipt", "", token, receipt)
	request(204, "POST", rootPath+"/poll", "", token, nil)
	response = request(200, "GET", adminPath, "", "", nil)
	var history []store.RuntimeUpdate
	if err := json.Unmarshal(response.Body.Bytes(), &history); err != nil || len(history) != 1 ||
		history[0].Status != runtimeupdate.RolledBack || history[0].Package != nil {
		t.Fatalf("unexpected history: %+v, %v", history, err)
	}
	// Competing updates in the panel store and task dispatch store must never
	// both reserve the same node, regardless of the checkpoint mode.
	second := map[string]any{"package": proof(2)}
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
	for path, body := range map[string]any{"/api/v1/admin/tasks": task, adminPath: second} {
		go func() {
			<-start
			results <- doRequest("POST", path, client.csrf, "", body)
		}()
	}
	close(start)
	firstResult, secondResult := <-results, <-results
	if firstResult.Code == http.StatusConflict {
		firstResult, secondResult = secondResult, firstResult
	}
	if firstResult.Code != http.StatusCreated || secondResult.Code != http.StatusConflict {
		t.Fatalf("competing requests: HTTP %d %s and HTTP %d %s",
			firstResult.Code, firstResult.Body, secondResult.Code, secondResult.Body)
	}
}
