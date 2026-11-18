package agent

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/master"
	"github.com/ACnoway/mcui/internal/store"
)

func TestAgentMigratesIdentityAndAuthenticatesOverVerifiedHTTPS(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "agent")
	if err := os.Mkdir(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(stateDir, "identity.json")
	t.Setenv("MCUI_AGENT_STATE", statePath)
	st, err := store.Open(filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	nodeID := "node-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	code := strings.Repeat("A", 43)
	digest := sha256.Sum256([]byte(code))
	codeHash := hex.EncodeToString(digest[:])
	if err = st.Update(func(state *store.State) error {
		state.Nodes[nodeID] = store.Node{ID: nodeID, Name: "existing", Enrolled: true, InstallCodeHash: codeHash, InstallCodeExpiresAt: time.Now().Add(time.Minute).Unix()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(master.New(st, "", "").Handler())
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	if err = os.WriteFile(statePath, []byte(`{"node_id":"node-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","private_key":"legacy","certificate_pem":"legacy"}`), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := New(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Enroll(nodeID, code); err == nil {
		t.Fatal("trusted a private test certificate through system roots")
	}
	ca := filepath.Join(dir, "ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	client, err = New(server.URL, ca)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Enroll("another-node", code); err == nil {
		t.Fatal("would replace an existing local node ID")
	}
	if err = client.Enroll(nodeID, code); err != nil {
		t.Fatal(err)
	}
	if err = client.RunOnce(); err != nil {
		t.Fatal(err)
	}
	state, err := client.load()
	if err != nil || state.NodeID != nodeID || state.NodeToken == "" {
		t.Fatal("enrollment did not persist the expected identity")
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("credential file permissions are not 0600")
	}
	raw, err := os.ReadFile(statePath)
	if err != nil || strings.Contains(string(raw), "legacy") {
		t.Fatal("legacy private identity was retained")
	}
	if err = st.View(func(state store.State) error {
		if state.Nodes[nodeID].LastSeen == 0 {
			t.Error("heartbeat did not update the existing node")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEnrollmentDoesNotFollowRedirects(t *testing.T) {
	t.Setenv("MCUI_AGENT_STATE", filepath.Join(t.TempDir(), "agent", "identity.json"))
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("enrollment redirected to another origin")
	}))
	defer target.Close()
	master := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer master.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: master.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := New(master.URL, ca)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Enroll("node-test", strings.Repeat("A", 43)); err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("expected enrollment to reject redirect: %v", err)
	}
}
