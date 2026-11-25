package master

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/store"
)

func TestInstallCommandOneLineAndVerifyBeforeExecution(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("shell execution requires Linux")
	}
	dir := t.TempDir()
	installer := filepath.Join(dir, "installer")
	result := filepath.Join(dir, "result")
	contents := []byte("#!/bin/bash\nread -r code\nprintf '%s\\n' \"$code\" \"$@\" >\"$RESULT\"\n")
	if err := os.WriteFile(installer, contents, 0600); err != nil {
		t.Fatal(err)
	}
	// Simulate the download while retaining the real checksum and shell execution.
	curl := "#!/bin/sh\nwhile [ \"$1\" != --output ]; do shift; done\ncp -- \"$INSTALLER\" \"$2\"\n"
	for name, script := range map[string]string{"curl": curl, "id": "#!/bin/sh\necho 0\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256(contents)
	i := agentInstaller{masterURL: "https://master.example.com", url: "https://example.com/install.sh", sha256: fmt.Sprintf("%x", digest)}
	run := func() error {
		command := i.command("node-1", "one-time-code", false)
		if strings.ContainsAny(command, "\r\n") {
			t.Fatal("installation command spans multiple lines")
		}
		cmd := exec.Command("/bin/bash", "-c", command)
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "INSTALLER="+installer, "RESULT="+result)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("command output: %s", output)
		}
		return err
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(result)
	if err != nil || string(got) != "one-time-code\n--master\nhttps://master.example.com\n--node-id\nnode-1\n" {
		t.Fatalf("unexpected installer input: %q, %v", got, err)
	}
	if err := os.Remove(result); err != nil {
		t.Fatal(err)
	}
	i.sha256 = strings.Repeat("0", 64)
	if err := run(); err == nil {
		t.Fatal("checksum mismatch succeeded")
	}
	if _, err := os.Stat(result); !os.IsNotExist(err) {
		t.Fatal("installer ran despite checksum mismatch")
	}
}

func TestAgentInstallCommandIncludesExplicitTaskTrust(t *testing.T) {
	s, _ := testServer(t)
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureAgentInstallerTrust("status-1", key, nil); err == nil {
		t.Fatal("trust configuration accepted without an approved installer")
	}
	if err := s.ConfigureAgentInstaller("https://master.example.com", "https://releases.example.com/install.sh", strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s.installer.command("node-1", "test-install-code", false), "--task-key-id") {
		t.Fatal("the command for a legacy installer included unsupported trust flags")
	}
	if err := s.ConfigureAgentInstallerTrust("bad\nkey-id", key, nil); err == nil {
		t.Fatal("accepted an invalid key ID")
	}
	if err := s.ConfigureAgentInstallerTrust("status-1", key, []byte("not a CA certificate")); err == nil {
		t.Fatal("accepted an invalid Master CA")
	}
	if err := s.ConfigureAgentInstallerTrust("status-1", key, nil); err != nil {
		t.Fatal(err)
	}
	cmd := s.installer.command("node-1", "test-install-code", true)
	opts := "--preserve-state --task-key-id 'status-1' --task-public-key '" + base64.StdEncoding.EncodeToString(key) + "'"
	verifyAt, executeAt := strings.Index(cmd, "sha256sum --check"), strings.Index(cmd, "as_root /bin/bash")
	if !strings.Contains(cmd, opts) || strings.Contains(cmd, "--master-ca-base64") || verifyAt < 0 || executeAt < verifyAt {
		t.Fatal("installation command did not verify the release before using configured trust")
	}
	s.taskRuntime = &TaskRuntime{KeyID: "another-signer", PublicKey: key}
	if err := s.ConfigureAgentInstallerTrust("status-1", key, nil); err == nil {
		t.Fatal("accepted installer trust different from the Master task runtime")
	}
}

func TestGitHubInstallCommandUsesDeploymentKeys(t *testing.T) {
	s, st := testServer(t)
	task, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	core, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureGitHubAgentInstaller("", "v2.1.3", strings.Repeat("b", 64), "status-test", task, "core-test", core, nil); err != nil {
		t.Fatal(err)
	}
	seedAdminSession(t, st, store.Admin{Role: "security_admin", AllNodes: true}, "session", "csrf", time.Now().Unix())
	handler := s.Handler()
	const nodesURL = "https://panel.example.com/api/v1/admin/nodes"
	response := requestAsAdmin(t, handler, http.MethodPost, nodesURL, map[string]string{"name": "Test node", "node_group": "test"}, "session", "csrf")
	var node NodeView
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &node) != nil {
		t.Fatalf("create node: HTTP %d", response.Code)
	}
	response = requestAsAdmin(t, handler, http.MethodPost, nodesURL+"/"+node.ID+"/install-command", map[string]string{}, "session", "csrf")
	var result map[string]any
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &result) != nil {
		t.Fatalf("create install command: HTTP %d", response.Code)
	}
	command, _ := result["command"].(string)
	for _, want := range []string{
		"https://github.com/ACnoway/mcui/releases/download/v2.1.3/install-mcui-agent.sh",
		"--master 'https://panel.example.com'",
		"--task-key-id 'status-test' --task-public-key '" + base64.StdEncoding.EncodeToString(task) + "'",
		"--core-key-id 'core-test' --core-public-key '" + base64.StdEncoding.EncodeToString(core) + "'",
	} {
		if !strings.Contains(command, want) {
			t.Errorf("installation command is missing %q", want)
		}
	}
}

func TestNodeInstallationCodeLifecycle(t *testing.T) {
	s, st := testServer(t)
	if err := s.ConfigureAgentInstaller("https://master.example.com", "https://releases.example.com/install.sh", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	session, csrf := "test-session", "test-csrf"
	seedAdminSession(t, st, store.Admin{Role: "security_admin", NodeGroups: []string{"west"}}, session, csrf, time.Now().Add(-20*time.Minute).Unix())
	nodesURL := "https://example.com/api/v1/admin/nodes"
	body := map[string]any{"name": "Node 01", "node_group": "east"}
	if denied := requestAsAdmin(t, s.Handler(), http.MethodPost, nodesURL, body, session, csrf); denied.Code != http.StatusNotFound {
		t.Fatalf("out-of-scope creation returned %d", denied.Code)
	}
	body["node_group"] = "west"
	created := requestAsAdmin(t, s.Handler(), http.MethodPost, nodesURL, body, session, csrf)
	var node NodeView
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &node) != nil || node.ID == "" || !node.Pending || node.LastSeen != 0 {
		t.Fatalf("expected a pending node, HTTP %d: %s", created.Code, created.Body)
	}
	commandURL := nodesURL + "/" + node.ID + "/install-command"
	if denied := requestAsAdmin(t, s.Handler(), http.MethodPost, commandURL, map[string]string{}, session, ""); denied.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF returned %d", denied.Code)
	}
	if denied := requestAsAdmin(t, s.Handler(), http.MethodPost, commandURL, map[string]string{}, session, csrf); denied.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing MFA returned %d", denied.Code)
	}
	generate := func(mfa string, preserve bool) string {
		t.Helper()
		resp := requestAsAdmin(t, s.Handler(), http.MethodPost, commandURL, map[string]string{"mfa_code": mfa}, session, csrf)
		var result struct {
			Command   string `json:"command"`
			ExpiresAt int64  `json:"expires_at"`
		}
		if resp.Code != http.StatusCreated || json.Unmarshal(resp.Body.Bytes(), &result) != nil || resp.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("install command returned %d", resp.Code)
		}
		if !strings.Contains(result.Command, node.ID) || !strings.Contains(result.Command, "https://master.example.com") ||
			strings.Contains(result.Command, "--preserve-state") != preserve || result.ExpiresAt <= time.Now().Unix() {
			t.Fatal("incorrect installer target, state mode, or expiry")
		}
		match := regexp.MustCompile("'([A-Za-z0-9_-]{43})'").FindStringSubmatch(result.Command)
		if len(match) != 2 {
			t.Fatal("installation command does not contain an installation code")
		}
		return match[1]
	}
	secret, _ := base32Decode("JBSWY3DPEHPK3PXP")
	expired := generate(fmt.Sprintf("%06d", totpAt(secret, time.Now().Unix()/30)), false)
	if err := st.Update(func(state *store.State) error {
		n := state.Nodes[node.ID]
		n.InstallCodeExpiresAt = time.Now().Add(-time.Second).Unix()
		state.Nodes[node.ID] = n
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	enroll := func(code string, useTLS bool) *httptest.ResponseRecorder {
		return requestAsNode(s, "/api/v1/agent/enroll", map[string]string{"install_code": code}, "", useTLS)
	}
	if resp := enroll(expired, true); resp.Code != http.StatusForbidden {
		t.Fatalf("expired code returned %d", resp.Code)
	}
	replaced := generate("", false)
	code := generate("", false)
	if resp := enroll(replaced, true); resp.Code != http.StatusForbidden {
		t.Fatalf("replaced code returned %d", resp.Code)
	}
	if resp := enroll(code, false); resp.Code != http.StatusUpgradeRequired {
		t.Fatalf("enrollment over HTTP returned %d", resp.Code)
	}

	responses := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() { responses <- enroll(code, true) }()
	}
	readToken := func(response *httptest.ResponseRecorder) string {
		t.Helper()
		var payload map[string]string
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
			json.Unmarshal(response.Body.Bytes(), &payload) != nil || payload["node_id"] != node.ID || len(payload["node_token"]) != 43 {
			t.Fatalf("unexpected enrollment response, HTTP %d", response.Code)
		}
		return payload["node_token"]
	}
	first, second := <-responses, <-responses
	if first.Code == http.StatusForbidden {
		first, second = second, first
	}
	token := readToken(first)
	if second.Code != http.StatusForbidden {
		t.Fatalf("concurrent code reuse returned %d", second.Code)
	}
	heartbeat := func(token, id string, useTLS bool) int {
		return requestAsNode(s, "/api/v1/agent/heartbeat", map[string]string{"node_id": id}, token, useTLS).Code
	}
	if heartbeat(token, node.ID, false) != http.StatusUnauthorized || heartbeat("", node.ID, true) != http.StatusUnauthorized ||
		heartbeat(token, "other-node", true) != http.StatusForbidden || heartbeat(token, node.ID, true) != http.StatusOK {
		t.Fatal("heartbeat did not enforce HTTPS, node Token, and the reported node ID")
	}
	detail := requestAsAdmin(t, s.Handler(), http.MethodGet, nodesURL+"/"+node.ID, nil, session, "")
	if json.Unmarshal(detail.Body.Bytes(), &node) != nil || node.Pending || node.LastSeen == 0 {
		t.Fatal("original node did not come online")
	}
	rotation := generate("", true)
	if heartbeat(token, node.ID, true) != http.StatusOK {
		t.Fatal("generating a replacement command revoked the existing Token")
	}
	newToken := readToken(enroll(rotation, true))
	if newToken == token || heartbeat(token, node.ID, true) != http.StatusUnauthorized || heartbeat(newToken, node.ID, true) != http.StatusOK {
		t.Fatal("rotation did not revoke the previous Token")
	}
	pending := generate("", true)
	disabled := requestAsAdmin(t, s.Handler(), http.MethodPost, nodesURL+"/disable", map[string]string{"node_id": node.ID}, session, csrf)
	if disabled.Code != http.StatusOK || heartbeat(newToken, node.ID, true) != http.StatusUnauthorized || enroll(pending, true).Code != http.StatusForbidden {
		t.Fatal("disable did not revoke the Token and pending code")
	}
	if err := st.View(func(state store.State) error {
		n := state.Nodes[node.ID]
		raw, err := json.Marshal(state)
		if err != nil {
			return err
		}
		for _, credential := range []string{expired, replaced, code, token, newToken, rotation, pending} {
			if strings.Contains(string(raw), credential) {
				return fmt.Errorf("plaintext credential was persisted")
			}
		}
		if n.TokenHash != "" || n.InstallCodeHash != "" || n.InstallCodeExpiresAt != 0 || len(state.Nodes) != 1 {
			return fmt.Errorf("disable retained credentials or changed the node inventory")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func requestAsNode(s *Server, path string, body map[string]string, token string, useTLS bool) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	if useTLS {
		req.TLS = &tls.ConnectionState{}
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp := httptest.NewRecorder()
	s.Handler().ServeHTTP(resp, req)
	return resp
}
