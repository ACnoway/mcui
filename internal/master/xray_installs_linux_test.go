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
	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/ACnoway/mcui/internal/helper"
	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/taskauth"
	"github.com/ACnoway/mcui/internal/taskledger"
)

func TestXrayInstallReservationAndOperatorAuthorization(t *testing.T) {
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
		st.Admins["other-operator"] = store.Admin{ID: "other-operator", Role: "operator", NodeIDs: []string{client.nodeID}}
		st.Sessions[hash("other-session")] = store.Session{ID: hash("other-session"), AdminID: "other-operator", CreatedAt: now.Unix(), LastSeen: now.Unix(), MFAAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), CSRFToken: "other-csrf"}
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
	signerKey, signerPrivate := makeKey()
	nodeIDs := []string{client.nodeID}
	rawPolicy, err := json.Marshal(map[string]any{
		"schema_version": 1, "signing_key_id": "xray-install-key", "signing_public_key": signerKey,
		"principals": []map[string]any{
			{"id": "operator-1", "role": "operator", "node_ids": nodeIDs, "public_key": operatorKey},
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
	in := xrayInstallRequest{TaskID: "xray-install-0000000000001", NodeID: client.nodeID, Version: "v26.10.31", Architecture: goruntime.GOARCH, SHA256: strings.Repeat("a", 64), ManifestVersion: 2}
	assertStatus(request(http.MethodPost, base, "test-session-token", "bad-csrf", in), http.StatusForbidden)
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
	if err != nil || proposal.SchemaVersion != lifecycleauth.SignedManifestProposalVersion || proposal.Sequence != 1 || record.Status != "AWAITING_SIGNATURE" {
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
	task, err := policy.Issue(t.Context(), ledger, requestProof, signerPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	issueBody := map[string]any{"request": requestProof, "task": json.RawMessage(task)}
	assertStatus(request(http.MethodPost, base+"/"+in.TaskID+"/approve", "test-session-token", client.csrf, issueBody), http.StatusNotFound)
	assertStatus(request(http.MethodPost, acceptSigned, "other-session", "other-csrf", issueBody), http.StatusNotFound)
	tampered := requestProof
	tampered.Proposal.ManifestVersion++
	assertStatus(request(http.MethodPost, acceptSigned, "test-session-token", client.csrf, map[string]any{"request": tampered, "task": json.RawMessage(task)}), http.StatusConflict)
	res = request(http.MethodPost, acceptSigned, "test-session-token", client.csrf, issueBody)
	assertStatus(res, http.StatusOK)
	if err := json.Unmarshal(res.Body.Bytes(), &record); err != nil || record.Status != "SIGNED_TASK_VERIFIED" {
		t.Fatalf("signed task result = %+v, error = %v", record, err)
	}
	assertStatus(request(http.MethodPost, acceptSigned, "test-session-token", client.csrf, issueBody), http.StatusOK)
	assertStatus(client.request(http.MethodGet, "/api/v1/agent/tasks/next?next_sequence=1", nil, true), http.StatusNoContent)
	res = request(http.MethodGet, base+"?node_id="+client.nodeID, "other-session", "", nil)
	assertStatus(res, http.StatusOK)
	if strings.Contains(res.Body.String(), in.TaskID) {
		t.Fatalf("another operator's proposal appeared in the list: %s", res.Body)
	}
	res = request(http.MethodGet, base+"?node_id="+client.nodeID, "test-session-token", "", nil)
	assertStatus(res, http.StatusOK)
	if !strings.Contains(res.Body.String(), in.TaskID) {
		t.Fatalf("operator proposal missing from list: %s", res.Body)
	}
	anchored, err := authority.Read(t.Context(), initial.Node, initial.Epoch, checkpoint.Challenge{1})
	if err != nil || anchored.Record.Revision < initial.Revision+2 {
		t.Fatalf("reservation and signed task were not independently anchored: %+v, %v", anchored, err)
	}

	dispatch := base + "/" + in.TaskID + "/dispatch"
	assertStatus(request(http.MethodPost, dispatch, "other-session", "other-csrf", map[string]any{}), http.StatusNotFound)
	assertStatus(request(http.MethodPost, dispatch, "test-session-token", client.csrf, map[string]any{}), http.StatusCreated)
	assertStatus(request(http.MethodPost, dispatch, "test-session-token", client.csrf, map[string]any{}), http.StatusOK)
	assertStatus(client.request(http.MethodGet, "/api/v1/agent/tasks/next?next_sequence=1", nil, true), http.StatusNoContent)
	assertStatus(client.request(http.MethodGet, "/api/v1/agent/tasks/next?install=xray-v1&next_sequence=1", nil, true), http.StatusNoContent)
	download := func(expected string) helperAuthorizationRequest {
		t.Helper()
		response := client.request(http.MethodGet, "/api/v1/agent/tasks/next?install=xray-manifest-v1&next_sequence="+expected, nil, true)
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
	backupPath := filepath.Join(t.TempDir(), "test-backup")
	const backupPayload = "cached fixture"
	if err := os.WriteFile(backupPath, []byte(backupPayload), 0600); err != nil {
		t.Fatal(err)
	}
	client.server.ConfigureCoreBackups(installTestCache(func(core, version, arch, digest string, size int64) (*os.File, error) {
		if core != "xray" || version != in.Version || arch != in.Architecture || digest != in.SHA256 || size != int64(len(backupPayload)) {
			return nil, os.ErrNotExist
		}
		return os.Open(backupPath)
	}))
	backupReq := artifacttrust.BackupRequest{Task: leased.Task, LeaseID: leased.LeaseID, Length: int64(len(backupPayload))}
	res = client.request(http.MethodPost, artifacttrust.BackupEndpoint, backupReq, true)
	assertStatus(res, http.StatusOK)
	if res.Body.String() != backupPayload {
		t.Fatalf("received wrong cached artifact: %s", res.Body)
	}
	wrongSize := backupReq
	wrongSize.Length++
	assertStatus(client.request(http.MethodPost, artifacttrust.BackupEndpoint, wrongSize, true), http.StatusNotFound)
	agentLedgerPath := filepath.Join(privateTestDir(t), "agent.db")
	nodeLedger, err := taskledger.Initialize(agentLedgerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nodeLedger.Close() }()
	trustedClock := func() (time.Time, error) { return clock(), nil }
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
	newRunner := func(ledger *taskledger.Ledger) *agenttasks.Runner {
		t.Helper()
		proc, err := agenttasks.New(agenttasks.Config{NodeID: client.nodeID, Now: clock, Ledger: ledger, Keys: map[string]taskauth.Key{
			runtime.KeyID: {PublicKey: runtime.PublicKey, Active: true, Purpose: taskauth.PurposeTask},
		}})
		if err != nil {
			t.Fatal(err)
		}
		runner, err := agenttasks.NewRunner(proc, ledger, testInstallExecutor{}, clock)
		if err != nil {
			t.Fatal(err)
		}
		if err := runner.SetTrustedClock(trustedClock); err != nil {
			t.Fatal(err)
		}
		if err := runner.ConfigureXrayInstall(policy.InstallKey(), artifacts, executor); err != nil {
			t.Fatal(err)
		}
		return runner
	}
	runner := newRunner(nodeLedger)
	acks, err := runner.ProcessXrayInstall(t.Context(), leased.Task, leased.LeaseID, nil, 0, now)
	if err != nil || len(acks) != 4 || acks[3].Status != "SUCCEEDED" {
		t.Fatalf("Agent installation result = %+v, %v", acks, err)
	}
	if err := nodeLedger.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := taskledger.Open(agentLedgerPath)
	if err != nil {
		t.Fatal(err)
	}
	nodeLedger = reopened
	runner = newRunner(nodeLedger)
	advance(61 * time.Second)
	recovered := download("2")
	if recovered.LeaseID == leased.LeaseID {
		t.Fatal("expired delivery reused the old lease")
	}
	assertStatus(client.request(http.MethodPost, "/api/v1/helper/tasks/authorize", leased, true), http.StatusForbidden)
	assertStatus(client.request(http.MethodPost, artifacttrust.BackupEndpoint, backupReq, true), http.StatusForbidden)
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
	assertStatus(client.request(http.MethodGet, "/api/v1/agent/tasks/next?install=xray-manifest-v1&next_sequence=2", nil, true), http.StatusNoContent)

	advance(30 * time.Minute)
	assertStatus(request(http.MethodPost, acceptSigned, "test-session-token", client.csrf, issueBody), http.StatusConflict)
	changed.TaskID = "xray-install-0000000000002"
	assertStatus(request(http.MethodPost, base, "test-session-token", client.csrf, changed), http.StatusCreated)
	advance(30 * time.Minute)
	changed.TaskID = "xray-install-0000000000003"
	assertStatus(request(http.MethodPost, base, "test-session-token", client.csrf, changed), http.StatusConflict)
	assertStatus(client.request(http.MethodPost, "/api/v1/admin/tasks", status, false), http.StatusCreated)
}

type installTestCache func(string, string, string, string, int64) (*os.File, error)

func (c installTestCache) OpenExact(core, version, arch, digest string, length int64) (*os.File, error) {
	return c(core, version, arch, digest, length)
}

func (installTestCache) Snapshot() (corecatalog.BackupManifest, error) {
	return corecatalog.BackupManifest{}, nil
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
