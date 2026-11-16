package master

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/store"
)

func testNodeCA(t *testing.T) *security.CertificateAuthority {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "MCUI Test Node CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := security.LoadCertificateAuthority(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func testServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return NewWithNodeCA(st, "", "", testNodeCA(t)), st
}

func requestJSON(t *testing.T, h http.Handler, method, path string, value any, tlsState *tls.ConnectionState) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, path, strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	if method != http.MethodGet {
		r.Header.Set("Origin", "http://example.com")
	}
	r.TLS = tlsState
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestEnrollmentRequiresTLSAndIsIdempotent(t *testing.T) {
	s, st := testServer(t)
	invite := "one-time-secret"
	_ = st.Update(func(state *store.State) error {
		state.Invites[hash(invite)] = store.Invite{Hash: hash(invite), NodeGroup: "group-a", ExpiresAt: time.Now().Add(time.Hour).Unix()}
		return nil
	})
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := security.NewCSR(key)
	if err != nil {
		t.Fatal(err)
	}
	requestID := "12345678901234567890123456789012"
	body := map[string]string{"invite": invite, "name": "node-a", "request_id": requestID, "csr_pem": base64.RawStdEncoding.EncodeToString(csr)}
	if response := requestJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/enroll", body, nil); response.Code != http.StatusUpgradeRequired {
		t.Fatalf("HTTP enrollment status=%d", response.Code)
	}
	if response := requestJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/enroll", body, &tls.ConnectionState{}); response.Code != http.StatusCreated {
		t.Fatalf("enrollment status=%d body=%s", response.Code, response.Body)
	}
	first := requestJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/enroll", body, &tls.ConnectionState{})
	var issued struct {
		NodeID         string `json:"node_id"`
		CertificatePEM string `json:"certificate_pem"`
		Serial         string `json:"serial"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	if issued.NodeID == "" || issued.CertificatePEM == "" || issued.Serial == "" || strings.Contains(first.Body.String(), "node_token") {
		t.Fatalf("unexpected enrollment response: %s", first.Body)
	}
	retry := requestJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/enroll", body, &tls.ConnectionState{})
	if retry.Code != http.StatusCreated || retry.Body.String() != first.Body.String() {
		t.Fatalf("idempotent retry mismatch: %d %s", retry.Code, retry.Body)
	}
	body["name"] = "other-name"
	conflict := requestJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/enroll", body, &tls.ConnectionState{})
	if conflict.Code != http.StatusForbidden {
		t.Fatalf("reused request ID status=%d", conflict.Code)
	}
	newRequest := map[string]string{"invite": invite, "name": "node-b", "request_id": "abcdefghijklmnopqrstuvwx12345678", "csr_pem": base64.RawStdEncoding.EncodeToString(csr)}
	if denied := requestJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/enroll", newRequest, &tls.ConnectionState{}); denied.Code != http.StatusForbidden {
		t.Fatalf("reused invitation status=%d", denied.Code)
	}
}

func TestHeartbeatRequiresRegisteredClientCertificateAndDisableRevokes(t *testing.T) {
	s, st := testServer(t)
	ca := s.nodeCA
	invite := "invite-one"
	_ = st.Update(func(state *store.State) error {
		state.Invites[hash(invite)] = store.Invite{Hash: hash(invite), NodeGroup: "g1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
		return nil
	})
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	csr, _ := security.NewCSR(key)
	body := map[string]string{"invite": invite, "name": "node-a", "request_id": "abcdefghijklmnopqrstuvwxyz123456", "csr_pem": base64.RawStdEncoding.EncodeToString(csr)}
	response := requestJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/enroll", body, &tls.ConnectionState{})
	if response.Code != http.StatusCreated {
		t.Fatalf("enrollment status=%d: %s", response.Code, response.Body)
	}
	var enrolled struct {
		NodeID string `json:"node_id"`
	}
	_ = json.Unmarshal(response.Body.Bytes(), &enrolled)
	var result struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	_ = json.Unmarshal(response.Body.Bytes(), &result)
	block, _ := pem.Decode([]byte(result.CertificatePEM))
	leaf, _ := x509.ParseCertificate(block.Bytes)
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, ca.Certificate}, VerifiedChains: [][]*x509.Certificate{{leaf, ca.Certificate}}}
	if got := requestJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/heartbeat", map[string]string{}, nil); got.Code != http.StatusUnauthorized {
		t.Fatalf("missing certificate status=%d", got.Code)
	}
	if got := requestJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/heartbeat", map[string]string{}, state); got.Code != http.StatusOK {
		t.Fatalf("valid certificate status=%d body=%s", got.Code, got.Body)
	}
	_ = st.Update(func(current *store.State) error {
		n := current.Nodes[enrolled.NodeID]
		n.Disabled = true
		for currentSerial, cert := range n.Certificates {
			cert.Revoked = true
			n.Certificates[currentSerial] = cert
		}
		current.Nodes[n.ID] = n
		return nil
	})
	if got := requestJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/heartbeat", map[string]string{}, state); got.Code != http.StatusUnauthorized {
		t.Fatalf("revoked certificate status=%d", got.Code)
	}
}

func TestCertificateRotationIsIdempotentAndRetainsShortOverlap(t *testing.T) {
	s, st := testServer(t)
	ca := s.nodeCA
	invite := "invite-rotation"
	_ = st.Update(func(state *store.State) error {
		state.Invites[hash(invite)] = store.Invite{Hash: hash(invite), NodeGroup: "g1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
		return nil
	})
	_, oldKey, _ := ed25519.GenerateKey(rand.Reader)
	oldCSR, _ := security.NewCSR(oldKey)
	requestID := "rotate-request-0123456789012345"
	response := requestJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/enroll", map[string]string{
		"invite": invite, "name": "node-a", "request_id": "enroll-request-0123456789012345", "csr_pem": base64.RawStdEncoding.EncodeToString(oldCSR),
	}, &tls.ConnectionState{})
	if response.Code != http.StatusCreated {
		t.Fatalf("enrollment status=%d", response.Code)
	}
	var enrolled struct {
		NodeID         string `json:"node_id"`
		CertificatePEM string `json:"certificate_pem"`
		Serial         string `json:"serial"`
	}
	_ = json.Unmarshal(response.Body.Bytes(), &enrolled)
	block, _ := pem.Decode([]byte(enrolled.CertificatePEM))
	oldLeaf, _ := x509.ParseCertificate(block.Bytes)
	oldTLS := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{oldLeaf, ca.Certificate}, VerifiedChains: [][]*x509.Certificate{{oldLeaf, ca.Certificate}}}
	_, newKey, _ := ed25519.GenerateKey(rand.Reader)
	newCSR, _ := security.NewCSR(newKey)
	rotationBody := map[string]string{"request_id": requestID, "csr_pem": base64.RawStdEncoding.EncodeToString(newCSR)}
	rotated := requestJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/cert/rotate", rotationBody, oldTLS)
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotation status=%d body=%s", rotated.Code, rotated.Body)
	}
	var issued struct {
		CertificatePEM string `json:"certificate_pem"`
		Serial         string `json:"serial"`
	}
	_ = json.Unmarshal(rotated.Body.Bytes(), &issued)
	if issued.Serial == enrolled.Serial || issued.CertificatePEM == "" {
		t.Fatalf("rotation did not produce new identity: %s", rotated.Body)
	}
	retry := requestJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/cert/rotate", rotationBody, oldTLS)
	if retry.Code != http.StatusOK || retry.Body.String() != rotated.Body.String() {
		t.Fatalf("rotation retry mismatch: %d %s", retry.Code, retry.Body)
	}
	if heartbeat := requestJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/heartbeat", map[string]string{}, oldTLS); heartbeat.Code != http.StatusOK {
		t.Fatalf("old certificate should overlap briefly, got %d", heartbeat.Code)
	}
	newBlock, _ := pem.Decode([]byte(issued.CertificatePEM))
	newLeaf, _ := x509.ParseCertificate(newBlock.Bytes)
	newTLS := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{newLeaf, ca.Certificate}, VerifiedChains: [][]*x509.Certificate{{newLeaf, ca.Certificate}}}
	if heartbeat := requestJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/heartbeat", map[string]string{}, newTLS); heartbeat.Code != http.StatusOK {
		t.Fatalf("new certificate heartbeat status=%d", heartbeat.Code)
	}
	_ = st.View(func(state store.State) error {
		node := state.Nodes[enrolled.NodeID]
		if node.CurrentSerial != issued.Serial || node.Certificates[enrolled.Serial].ValidUntil > time.Now().Add(certificateOverlap+time.Minute).Unix() {
			t.Fatalf("invalid certificate state after rotation: %+v", node)
		}
		return nil
	})
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
	r.Header.Set("Origin", "http://example.com")
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
		state.Nodes["node-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"] = store.Node{ID: "node-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Name: "secret", Group: "g2", LastSeen: 20, Certificates: map[string]store.NodeCertificate{"123": {NotAfter: 999}}}
		state.Audits = append(state.Audits,
			store.Audit{At: 1, Actor: "x", Action: "node.status", ResourceType: "node", Resource: "node-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Outcome: "ok"},
			store.Audit{At: 2, Actor: "x", Action: "node.status", ResourceType: "node", Resource: "node-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Outcome: "secret"},
		)
		return nil
	})
	token, csrf := "session-scope", "csrf-scope"
	seedAdminSession(t, st, store.Admin{Role: "auditor", NodeGroups: []string{"g1"}}, token, csrf, time.Now().Unix())
	nodes := requestAsAdmin(t, s.Handler(), http.MethodGet, "http://example.com/api/v1/admin/nodes", map[string]string{}, token, "")
	if nodes.Code != http.StatusOK || strings.Contains(nodes.Body.String(), "secret") || !strings.Contains(nodes.Body.String(), "allowed") || strings.Contains(nodes.Body.String(), "certificates") {
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

func TestSensitiveAdminWritesRequireCSRFAndMFAReverification(t *testing.T) {
	s, st := testServer(t)
	token, csrf := "session-write", "csrf-write"
	seedAdminSession(t, st, store.Admin{Role: "security_admin", AllNodes: true}, token, csrf, time.Now().Add(-20*time.Minute).Unix())
	body := map[string]any{"node_group": "group-a", "ttl_seconds": 3600}
	noCSRF := requestAsAdmin(t, s.Handler(), http.MethodPost, "http://example.com/api/v1/admin/invites", body, token, "")
	if noCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF token status=%d", noCSRF.Code)
	}
	needsMFA := requestAsAdmin(t, s.Handler(), http.MethodPost, "http://example.com/api/v1/admin/invites", body, token, csrf)
	if needsMFA.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing MFA status=%d body=%s", needsMFA.Code, needsMFA.Body)
	}
	// Generate a current code for the deterministic test secret.
	secret, _ := base32Decode("JBSWY3DPEHPK3PXP")
	body["mfa_code"] = fmt.Sprintf("%06d", totpAt(secret, time.Now().Unix()/30))
	created := requestAsAdmin(t, s.Handler(), http.MethodPost, "http://example.com/api/v1/admin/invites", body, token, csrf)
	if created.Code != http.StatusCreated {
		t.Fatalf("valid MFA invite status=%d body=%s", created.Code, created.Body)
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
