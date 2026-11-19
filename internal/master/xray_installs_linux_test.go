package master

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/agent"
	"github.com/ACnoway/mcui/internal/agenttasks"
	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/checkpoint"
	"github.com/ACnoway/mcui/internal/helper"
	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/taskauth"
	"github.com/ACnoway/mcui/internal/taskledger"
)

func TestXrayInstallReservationAndApproval(t *testing.T) {
	client := newTaskTestClient(t)
	now := time.Now().UTC().Truncate(time.Second)
	var clockValue atomic.Int64
	clockValue.Store(now.UnixNano())
	clock := func() time.Time { return time.Unix(0, clockValue.Load()).UTC() }
	advance := func(d time.Duration) {
		now = now.Add(d)
		clockValue.Store(now.UnixNano())
	}
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
	runtime.TrustedNow = func() (time.Time, error) { return clock(), nil }
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
	in := xrayInstallRequest{TaskID: "xray-install-0000000000001", NodeID: client.nodeID, ApproverID: "approver-1", Version: "v26.10.31", Architecture: goruntime.GOARCH, SHA256: strings.Repeat("a", 64), ManifestVersion: 2}
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

	dispatch := base + "/" + in.TaskID + "/dispatch"
	assertStatus(request(http.MethodPost, dispatch, "test-session-token", client.csrf, map[string]any{}), http.StatusNotFound)
	assertStatus(request(http.MethodPost, dispatch, "approval-session", "approver-csrf", map[string]any{}), http.StatusCreated)
	assertStatus(request(http.MethodPost, dispatch, "approval-session", "approver-csrf", map[string]any{}), http.StatusOK)
	assertStatus(client.request(http.MethodGet, "/api/v1/agent/tasks/next?next_sequence=1", nil, true), http.StatusNoContent)
	download := func(expected string) helperAuthorizationRequest {
		t.Helper()
		response := client.request(http.MethodGet, "/api/v1/agent/tasks/next?install=xray-v1&next_sequence="+expected, nil, true)
		assertStatus(response, http.StatusOK)
		var check helperAuthorizationRequest
		if err := json.Unmarshal(response.Body.Bytes(), &check); err != nil || len(check.LeaseID) != 32 || !bytes.Equal(check.Task, task) {
			t.Fatalf("unexpected installation delivery: %s (%v)", response.Body, err)
		}
		return check
	}
	leased := download("1")
	assertStatus(client.request(http.MethodPost, "/api/v1/helper/tasks/authorize", leased, true), http.StatusOK)
	assertStatus(client.request(http.MethodPost, "/api/v1/agent/tasks/renew-install", leased, true), http.StatusNoContent)
	nodeLedger, err := taskledger.Initialize(filepath.Join(privateTestDir(t), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer nodeLedger.Close()
	trustedClock := func() (time.Time, error) { return clock(), nil }
	proc, err := agenttasks.New(agenttasks.Config{NodeID: client.nodeID, Now: clock, Ledger: nodeLedger, Keys: map[string]taskauth.Key{
		runtime.KeyID: {PublicKey: runtime.PublicKey, Active: true, Purpose: taskauth.PurposeTask},
	}})
	if err != nil {
		t.Fatal(err)
	}
	runner, err := agenttasks.NewRunner(proc, nodeLedger, testInstallExecutor{}, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.SetTrustedClock(trustedClock); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var executor agenttasks.InstallExecutor = testInstallExecutor{install: func(raw []byte, lease string) (json.RawMessage, error) {
		calls.Add(1)
		assertStatus(client.request(http.MethodPost, "/api/v1/helper/tasks/authorize", helperAuthorizationRequest{LeaseID: lease, Task: raw}, true), http.StatusOK)
		return json.Marshal(lifecycleauth.InstallResult{Outcome: "SUCCEEDED", Version: in.Version, SHA256: in.SHA256})
	}}
	if os.Geteuid() == 0 {
		executor = rootInstallTestExecutor(t, client.server, client.nodeID, policy.InstallKey(), clock, &calls)
	}
	artifacts := testInstallArtifacts{target: artifacttrust.Target{Core: "xray", Version: in.Version, Architecture: in.Architecture, SHA256: in.SHA256, SignatureStatus: "not-provided"}}
	if err := runner.ConfigureXrayInstall(policy.InstallKey(), artifacts, executor); err != nil {
		t.Fatal(err)
	}
	acks, err := runner.ProcessXrayInstall(t.Context(), leased.Task, leased.LeaseID, nil, 0, now)
	if err != nil || len(acks) != 4 || acks[3].Status != "SUCCEEDED" {
		t.Fatalf("Agent installation result = %+v, %v", acks, err)
	}
	advance(61 * time.Second)
	recovered := download("2")
	if recovered.LeaseID == leased.LeaseID {
		t.Fatal("expired delivery reused the old lease")
	}
	assertStatus(client.request(http.MethodPost, "/api/v1/helper/tasks/authorize", leased, true), http.StatusForbidden)
	assertStatus(client.request(http.MethodPost, "/api/v1/helper/tasks/authorize", recovered, true), http.StatusOK)
	acks, err = runner.ProcessXrayInstall(t.Context(), recovered.Task, recovered.LeaseID, nil, 0, now)
	if err != nil || calls.Load() != 1 || len(acks) != 4 || acks[3].Status != "SUCCEEDED" {
		t.Fatalf("Agent did not replay the durable result: calls=%d %+v %v", calls.Load(), acks, err)
	}
	for _, ack := range acks {
		in := taskAckRequest{TaskID: in.TaskID, Sequence: 1, StatusVersion: ack.StatusVersion, Status: ack.Status, Result: ack.Result}
		assertStatus(client.request(http.MethodPost, "/api/v1/agent/tasks/ack", in, true), http.StatusNoContent)
	}
	if err := client.server.ReconcileTaskRuntime(); err != nil {
		t.Fatalf("reconcile recorded installation: %v", err)
	}
	assertStatus(client.request(http.MethodGet, "/api/v1/agent/tasks/next?install=xray-v1&next_sequence=2", nil, true), http.StatusNoContent)

	advance(30 * time.Minute)
	assertStatus(request(http.MethodPost, approve, "approval-session", "approver-csrf", map[string]any{"approval": evidence}), http.StatusConflict)
	changed.TaskID = "xray-install-0000000000002"
	assertStatus(request(http.MethodPost, base, "test-session-token", client.csrf, changed), http.StatusCreated)
	advance(30 * time.Minute)
	changed.TaskID = "xray-install-0000000000003"
	assertStatus(request(http.MethodPost, base, "test-session-token", client.csrf, changed), http.StatusConflict)
	assertStatus(client.request(http.MethodPost, "/api/v1/admin/tasks", status, false), http.StatusCreated)
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func rootInstallTestExecutor(t *testing.T, master *Server, node string, key lifecycleauth.InstallKey, clock func() time.Time, calls *atomic.Int32) agenttasks.InstallExecutor {
	t.Helper()
	server := httptest.NewTLSServer(master.Handler())
	t.Cleanup(server.Close)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	cp, err := helper.NewHTTPCheckpoint(server.URL, certificate)
	if err != nil {
		t.Fatal(err)
	}
	dir := privateTestDir(t)
	h, err := helper.Initialize(dir, helper.Config{
		NodeID: node, AllowedUID: uint32(os.Getuid()), Now: clock,
		TrustedTimeHealthy: func() bool { return true },
		Keys:               map[string]helper.TrustedKey{master.taskRuntime.KeyID: {PublicKey: master.taskRuntime.PublicKey, Purpose: "task"}},
		ReadStatus:         func(string) (string, error) { return "", lifecycleauth.ErrDenied },
		Checkpoint:         cp,
		XrayInstall: &helper.XrayInstallConfig{Key: key, Apply: func(ctx context.Context, _ lifecycleauth.InstallTask, authorize func(context.Context) error) (string, error) {
			for range 2 {
				if err := authorize(ctx); err != nil {
					return "", err
				}
			}
			calls.Add(1)
			return "SUCCEEDED", nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	path := filepath.Join(dir, "helper.sock")
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan error, 1)
	go func() { served <- h.RunSocket(ctx, path, 65534) }()
	t.Cleanup(func() {
		cancel()
		if err := <-served; err != nil {
			t.Error(err)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Helper socket did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	executor, err := agent.NewUnixStatusExecutor(path)
	if err != nil {
		t.Fatal(err)
	}
	return executor.(agenttasks.InstallExecutor)
}

type testInstallExecutor struct {
	install func([]byte, string) (json.RawMessage, error)
}

func (e testInstallExecutor) ExecuteStatus(context.Context, []byte, string) (json.RawMessage, error) {
	return nil, lifecycleauth.ErrDenied
}

func (e testInstallExecutor) ExecuteInstall(_ context.Context, raw []byte, lease string) (json.RawMessage, error) {
	return e.install(raw, lease)
}

type testInstallArtifacts struct{ target artifacttrust.Target }

func (s testInstallArtifacts) LookupCoreManifest(_ context.Context, core, version string, manifest int64) (artifacttrust.Target, error) {
	if manifest != 2 || core != s.target.Core || version != s.target.Version {
		return artifacttrust.Target{}, lifecycleauth.ErrDenied
	}
	return s.target, nil
}

func (s testInstallArtifacts) Download(context.Context, artifacttrust.Target) (string, error) {
	return "test-only", nil
}
