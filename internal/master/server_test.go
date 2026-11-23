package master

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/store"
)

func testServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st, "", ""), st
}

func TestSubscriptionPageServesBrowserApp(t *testing.T) {
	_, st := testServer(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<main id=\"app\"></main>"), 0600); err != nil {
		t.Fatal(err)
	}
	s := New(st, "", dir)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://panel.example.test/subscription", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `id="app"`) ||
		response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("unexpected subscription page response: %d %v", response.Code, response.Header())
	}
}

func seedAdminSession(t *testing.T, st *store.Store, admin store.Admin, sessionToken, csrfToken string, mfaAt int64) {
	t.Helper()
	now := time.Now().Unix()
	if admin.ID == "" {
		admin.ID = "admin-test"
	}
	if admin.Username == "" {
		admin.Username = "test-admin"
	}
	if admin.TOTPSecret == "" {
		admin.TOTPSecret = "JBSWY3DPEHPK3PXP"
	}
	if err := st.Update(func(state *store.State) error {
		state.Admins[admin.ID] = admin
		state.Sessions[hash(sessionToken)] = store.Session{ID: hash(sessionToken), AdminID: admin.ID, CreatedAt: now, LastSeen: now, MFAAt: mfaAt, ExpiresAt: now + 3600, CSRFToken: csrfToken}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func requestAsAdmin(t *testing.T, h http.Handler, method, path string, value any, token, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, path, strings.NewReader(string(body)))
	r.AddCookie(&http.Cookie{Name: "mcui_session", Value: token})
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", r.URL.Scheme+"://"+r.Host)
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestNodeInventoryDetailAndAuditRespectAdminScope(t *testing.T) {
	s, st := testServer(t)
	_ = st.Update(func(state *store.State) error {
		state.Nodes["node-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] = store.Node{ID: "node-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Name: "allowed", Group: "g1", LastSeen: 10}
		state.Nodes["node-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"] = store.Node{ID: "node-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Name: "secret", Group: "g2", LastSeen: 20, TokenHash: "private-digest"}
		state.Audits = append(state.Audits,
			store.Audit{At: 1, Actor: "x", Action: "node.status", ResourceType: "node", Resource: "node-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Outcome: "ok"},
			store.Audit{At: 2, Actor: "x", Action: "node.status", ResourceType: "node", Resource: "node-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Outcome: "secret"},
		)
		return nil
	})
	token, csrf := "session-scope", "csrf-scope"
	seedAdminSession(t, st, store.Admin{Role: "auditor", NodeGroups: []string{"g1"}}, token, csrf, time.Now().Unix())
	nodes := requestAsAdmin(t, s.Handler(), http.MethodGet, "http://example.com/api/v1/admin/nodes", map[string]string{}, token, "")
	if nodes.Code != http.StatusOK || strings.Contains(nodes.Body.String(), "secret") || !strings.Contains(nodes.Body.String(), "allowed") || strings.Contains(nodes.Body.String(), "private-digest") {
		t.Fatalf("scoped inventory leaked or omitted data: %d %s", nodes.Code, nodes.Body)
	}
	deniedDetail := requestAsAdmin(t, s.Handler(), http.MethodGet, "http://example.com/api/v1/admin/nodes/node-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil, token, "")
	if deniedDetail.Code != http.StatusNotFound {
		t.Fatalf("out-of-scope detail status=%d", deniedDetail.Code)
	}
	audits := requestAsAdmin(t, s.Handler(), http.MethodGet, "http://example.com/api/v1/admin/audit", nil, token, "")
	if audits.Code != http.StatusOK || strings.Contains(audits.Body.String(), "node-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") || !strings.Contains(audits.Body.String(), "node-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatalf("scoped audit leaked or omitted data: %d %s", audits.Code, audits.Body)
	}
}

func TestSecurityAdminCanCreateScopedReadOnlyAdminWithoutSecretListing(t *testing.T) {
	s, st := testServer(t)
	_ = st.Update(func(state *store.State) error {
		state.Nodes["node-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] = store.Node{ID: "node-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Name: "edge-a", Group: "g1"}
		state.Nodes["node-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"] = store.Node{ID: "node-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Name: "edge-b", Group: "g2"}
		return nil
	})
	token, csrf := "session-create-admin", "csrf-create-admin"
	seedAdminSession(t, st, store.Admin{Role: "security_admin", AllNodes: true}, token, csrf, time.Now().Unix())
	body := map[string]any{"username": "auditor-one", "password": "one-time-strong-password", "role": "auditor", "node_groups": []string{"g1"}}
	created := requestAsAdmin(t, s.Handler(), http.MethodPost, "http://example.com/api/v1/admin/admins", body, token, csrf)
	if created.Code != http.StatusCreated {
		t.Fatalf("create administrator status=%d body=%s", created.Code, created.Body)
	}
	var response struct {
		Admin      AdminView `json:"admin"`
		TOTPSecret string    `json:"totp_secret"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Admin.ID == "" || response.Admin.Role != "auditor" || len(response.Admin.NodeGroups) != 1 || response.Admin.NodeGroups[0] != "g1" || response.TOTPSecret == "" {
		t.Fatalf("unexpected created admin response: %+v", response)
	}
	secret, err := base32Decode(response.TOTPSecret)
	if err != nil || len(secret) != 20 {
		t.Fatalf("invalid one-time TOTP secret: %v", err)
	}
	if strings.Contains(created.Body.String(), "password_hash") || strings.Contains(created.Body.String(), "one-time-strong-password") {
		t.Fatalf("creation response disclosed password data: %s", created.Body)
	}
	listed := requestAsAdmin(t, s.Handler(), http.MethodGet, "http://example.com/api/v1/admin/admins", nil, token, "")
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), "password_hash") || strings.Contains(listed.Body.String(), response.TOTPSecret) || strings.Contains(listed.Body.String(), "one-time-strong-password") {
		t.Fatalf("administrator listing disclosed credentials: %d %s", listed.Code, listed.Body)
	}
	if !strings.Contains(listed.Body.String(), "auditor-one") || strings.Contains(listed.Body.String(), "edge-b") {
		t.Fatalf("administrator list or stored credential scope is unexpected: %s", listed.Body)
	}
}

func TestScopedSecurityAdminCannotDelegateOutsideItsScope(t *testing.T) {
	s, st := testServer(t)
	_ = st.Update(func(state *store.State) error {
		state.Nodes["node-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] = store.Node{ID: "node-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Name: "edge-a", Group: "g1"}
		state.Nodes["node-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"] = store.Node{ID: "node-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Name: "edge-b", Group: "g2"}
		return nil
	})
	token, csrf := "session-scoped-security", "csrf-scoped-security"
	seedAdminSession(t, st, store.Admin{Role: "security_admin", NodeGroups: []string{"g1"}}, token, csrf, time.Now().Unix())
	body := map[string]any{"username": "auditor-two", "password": "one-time-strong-password", "role": "auditor", "node_groups": []string{"g2"}}
	denied := requestAsAdmin(t, s.Handler(), http.MethodPost, "http://example.com/api/v1/admin/admins", body, token, csrf)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope delegation status=%d body=%s", denied.Code, denied.Body)
	}
	_ = st.View(func(state store.State) error {
		for _, admin := range state.Admins {
			if admin.Username == "auditor-two" {
				t.Fatal("out-of-scope account was created")
			}
		}
		return nil
	})
}

func TestGlobalSecurityAdminCannotDelegateUnknownNodeID(t *testing.T) {
	s, st := testServer(t)
	token, csrf := "session-unknown-node", "csrf-unknown-node"
	seedAdminSession(t, st, store.Admin{Role: "security_admin", AllNodes: true}, token, csrf, time.Now().Unix())
	body := map[string]any{"username": "auditor-unknown-node", "password": "one-time-strong-password", "role": "auditor", "node_ids": []string{"node-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	denied := requestAsAdmin(t, s.Handler(), http.MethodPost, "http://example.com/api/v1/admin/admins", body, token, csrf)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("unknown-node delegation status=%d body=%s", denied.Code, denied.Body)
	}
	_ = st.View(func(state store.State) error {
		for _, admin := range state.Admins {
			if admin.Username == "auditor-unknown-node" {
				t.Fatal("account with an unknown node ID was created")
			}
		}
		return nil
	})
}

func TestDisableScopedAdminRevokesAllSessions(t *testing.T) {
	s, st := testServer(t)
	adminToken, adminCSRF := "session-disable-admin", "csrf-disable-admin"
	targetToken, targetCSRF := "session-target-admin", "csrf-target-admin"
	seedAdminSession(t, st, store.Admin{Role: "security_admin", AllNodes: true}, adminToken, adminCSRF, time.Now().Unix())
	target := store.Admin{ID: "target-auditor", Username: "auditor-three", Role: "auditor", NodeGroups: []string{"g1"}}
	seedAdminSession(t, st, target, targetToken, targetCSRF, time.Now().Unix())
	disabled := requestAsAdmin(t, s.Handler(), http.MethodPost, "http://example.com/api/v1/admin/admins/disable", map[string]string{"admin_id": target.ID}, adminToken, adminCSRF)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable administrator status=%d body=%s", disabled.Code, disabled.Body)
	}
	if response := requestAsAdmin(t, s.Handler(), http.MethodGet, "http://example.com/api/v1/admin/me", nil, targetToken, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("disabled session remains usable: %d %s", response.Code, response.Body)
	}
	_ = st.View(func(state store.State) error {
		if !state.Admins[target.ID].Disabled {
			t.Fatal("administrator was not disabled")
		}
		if _, exists := state.Sessions[hash(targetToken)]; exists {
			t.Fatal("administrator session was not revoked")
		}
		return nil
	})
}

func TestAdminProvisioningRejectsMissingCSRFOrRecentMFA(t *testing.T) {
	s, st := testServer(t)
	token, csrf := "session-admin-guard", "csrf-admin-guard"
	seedAdminSession(t, st, store.Admin{Role: "security_admin", AllNodes: true}, token, csrf, time.Now().Add(-20*time.Minute).Unix())
	body := map[string]any{"username": "auditor-four", "password": "one-time-strong-password", "role": "auditor", "node_groups": []string{"g1"}}
	noCSRF := requestAsAdmin(t, s.Handler(), http.MethodPost, "http://example.com/api/v1/admin/admins", body, token, "")
	if noCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d", noCSRF.Code)
	}
	noMFA := requestAsAdmin(t, s.Handler(), http.MethodPost, "http://example.com/api/v1/admin/admins", body, token, csrf)
	if noMFA.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing MFA status=%d body=%s", noMFA.Code, noMFA.Body)
	}
}
