package master

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/checkpoint"
	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/store"
)

func TestXrayInstallReservationAndApproval(t *testing.T) {
	client := newTaskTestClient(t)
	now := time.Now().UTC().Truncate(time.Second)
	const totpSecret = "JBSWY3DPEHPK3PXP"
	if err := client.store.Update(func(st *store.State) error {
		operator := st.Admins["operator-1"]
		operator.TOTPSecret = totpSecret
		st.Admins[operator.ID] = operator
		session := st.Sessions[hash("test-session-token")]
		session.MFAAt = now.Add(-11 * time.Minute).Unix()
		st.Sessions[session.ID] = session
		st.Admins["approver-1"] = store.Admin{ID: "approver-1", Role: "security_admin", NodeIDs: []string{client.nodeID}}
		st.Sessions[hash("approval-session")] = store.Session{ID: hash("approval-session"), AdminID: "approver-1", CreatedAt: now.Unix(), LastSeen: now.Unix(), MFAAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), CSRFToken: "approver-csrf"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	makeKey := func() (string, ed25519.PrivateKey) {
		t.Helper()
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(public), private
	}
	operatorKey, operatorPrivate := makeKey()
	approverKey, approverPrivate := makeKey()
	signerKey, signerPrivate := makeKey()
	nodeIDs := []string{client.nodeID}
	rawPolicy, err := json.Marshal(map[string]any{
		"schema_version": 1, "signing_key_id": "xray-install-key", "signing_public_key": signerKey,
		"principals": []map[string]any{
			{"id": "operator-1", "role": "operator", "node_ids": nodeIDs, "public_key": operatorKey},
			{"id": "approver-1", "role": "security_admin", "node_ids": nodeIDs, "public_key": approverKey},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := lifecycleauth.ParsePolicy(rawPolicy)
	if err != nil {
		t.Fatal(err)
	}
	_, authority, initial := enrollTestCheckpoint(t, client)
	runtime := *client.server.taskRuntime
	runtime.XrayInstallPolicy = policy
	runtime.TrustedNow = func() (time.Time, error) { return now, nil }
	if err := client.server.ConfigureTaskRuntime(runtime); err != nil {
		t.Fatal(err)
	}

	request := func(method, path, session, csrf string, body any) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, "https://example.com"+path, bytes.NewReader(raw))
		req.AddCookie(&http.Cookie{Name: "mcui_session", Value: session})
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("X-CSRF-Token", csrf)
		res := httptest.NewRecorder()
		client.server.Handler().ServeHTTP(res, req)
		return res
	}
	assertStatus := func(res *httptest.ResponseRecorder, expected int) {
		t.Helper()
		if res.Code != expected {
			t.Fatalf("HTTP %d, want %d: %s", res.Code, expected, res.Body)
		}
	}

	const base = "/api/v1/admin/xray-installs"
	in := xrayInstallRequest{TaskID: "xray-install-0000000000001", NodeID: client.nodeID, ApproverID: "approver-1", Version: "v26.10.31", Architecture: "amd64", SHA256: strings.Repeat("a", 64), ManifestVersion: 2}
	assertStatus(request(http.MethodPost, base, "test-session-token", "bad-csrf", in), http.StatusForbidden)
	assertStatus(request(http.MethodPost, base, "approval-session", "approver-csrf", in), http.StatusNotFound)
	assertStatus(request(http.MethodPost, base, "test-session-token", client.csrf, in), http.StatusPreconditionRequired)
	totpKey, err := base32Decode(totpSecret)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	mac := hmacSHA1(totpKey, counter[:])
	offset := int(mac[len(mac)-1] & 15)
	in.MFACode = fmtCode((binary.BigEndian.Uint32(mac[offset:]) & 0x7fffffff) % 1000000)
	res := request(http.MethodPost, base, "test-session-token", client.csrf, in)
	assertStatus(res, http.StatusCreated)
	var record xrayInstallView
	if err := json.Unmarshal(res.Body.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	proposal, err := lifecycleauth.ParseProposal(record.Proposal)
	if err != nil || proposal.Sequence != 1 || record.Status != "AWAITING_APPROVAL" {
		t.Fatalf("proposal = %+v, status = %s, error = %v", proposal, record.Status, err)
	}
	retry := request(http.MethodPost, base, "test-session-token", client.csrf, in)
	assertStatus(retry, http.StatusCreated)
	if retry.Body.String() != res.Body.String() {
		t.Fatal("exact proposal retry changed the response")
	}
	changed := in
	changed.Version = "v26.11.9"
	assertStatus(request(http.MethodPost, base, "test-session-token", client.csrf, changed), http.StatusConflict)
	assertStatus(client.request(http.MethodGet, "/api/v1/agent/tasks/next?next_sequence=1", nil, true), http.StatusNoContent)
	status := statusTaskRequest{RequestID: "status-query-000000000001", NodeID: client.nodeID, Core: "xray"}
	assertStatus(client.request(http.MethodPost, "/api/v1/admin/tasks", status, false), http.StatusConflict)

	requestProof, err := policy.SignRequest(proposal, operatorPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := policy.Approve(requestProof, approverPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	approve := base + "/" + in.TaskID + "/approve"
	acceptSigned := base + "/" + in.TaskID + "/signed-task"
	ledgerPath := filepath.Join(t.TempDir(), "signer.db")
	if err := lifecycleauth.InitLedger(ledgerPath); err != nil {
		t.Fatal(err)
	}
	ledger, err := lifecycleauth.OpenLedger(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	task, err := policy.Issue(t.Context(), ledger, evidence, signerPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	issueBody := map[string]any{"approval": evidence, "task": json.RawMessage(task)}
	assertStatus(request(http.MethodPost, acceptSigned, "approval-session", "approver-csrf", issueBody), http.StatusConflict)
	assertStatus(request(http.MethodPost, approve, "test-session-token", client.csrf, map[string]any{"approval": evidence}), http.StatusNotFound)
	res = request(http.MethodPost, approve, "approval-session", "approver-csrf", map[string]any{"approval": evidence})
	assertStatus(res, http.StatusOK)
	if err := json.Unmarshal(res.Body.Bytes(), &record); err != nil || record.Status != "APPROVAL_RECORDED" || len(record.ApprovalID) != 64 {
		t.Fatalf("approval result = %+v, error = %v", record, err)
	}
	res = request(http.MethodPost, acceptSigned, "approval-session", "approver-csrf", issueBody)
	assertStatus(res, http.StatusOK)
	if err := json.Unmarshal(res.Body.Bytes(), &record); err != nil || record.Status != "SIGNED_TASK_VERIFIED" {
		t.Fatalf("signed task result = %+v, error = %v", record, err)
	}
	assertStatus(request(http.MethodPost, acceptSigned, "approval-session", "approver-csrf", issueBody), http.StatusOK)
	assertStatus(client.request(http.MethodGet, "/api/v1/agent/tasks/next?next_sequence=1", nil, true), http.StatusNoContent)
	res = request(http.MethodGet, base+"?node_id="+client.nodeID, "approval-session", "", nil)
	assertStatus(res, http.StatusOK)
	if !strings.Contains(res.Body.String(), record.ApprovalID) {
		t.Fatalf("approval missing from list: %s", res.Body)
	}
	anchored, err := authority.Read(t.Context(), initial.Node, initial.Epoch, checkpoint.Challenge{1})
	if err != nil || anchored.Record.Revision < initial.Revision+3 {
		t.Fatalf("reservation, approval and signed task were not independently anchored: %+v, %v", anchored, err)
	}

	now = now.Add(30 * time.Minute)
	assertStatus(request(http.MethodPost, approve, "approval-session", "approver-csrf", map[string]any{"approval": evidence}), http.StatusConflict)
	changed.TaskID = "xray-install-0000000000002"
	assertStatus(request(http.MethodPost, base, "test-session-token", client.csrf, changed), http.StatusConflict)
	assertStatus(client.request(http.MethodPost, "/api/v1/admin/tasks", status, false), http.StatusCreated)
}
