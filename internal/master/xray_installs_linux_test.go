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
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
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
	t.Run("single-host", func(t *testing.T) { testXrayInstallReservationAndOperatorAuthorization(t, false) })
	t.Run("independent-checkpoint", func(t *testing.T) { testXrayInstallReservationAndOperatorAuthorization(t, true) })
}

func testXrayInstallReservationAndOperatorAuthorization(t *testing.T, independent bool) {
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
	var checkRevision func()
	if independent {
		_, authority, initial := enrollTestCheckpoint(t, client)
		checkRevision = func() {
			anchored, err := authority.Read(t.Context(), initial.Node, initial.Epoch, checkpoint.Challenge{1})
			if err != nil || anchored.Record.Revision < initial.Revision+2 {
				t.Fatalf("reservation and signed task were not independently anchored: %+v, %v", anchored, err)
			}
		}
	}
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
	if checkRevision != nil {
		checkRevision()
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
	const newVersion = "v26.11.9"
	newDigest := strings.Repeat("b", 64)
	if err := os.WriteFile(backupPath, []byte(backupPayload), 0600); err != nil {
		t.Fatal(err)
	}
	client.server.ConfigureCoreBackups(installTestCache(func(core, version, arch, digest string, size int64) (*os.File, error) {
		approved := (version == in.Version && digest == in.SHA256) || (version == newVersion && digest == newDigest)
		if core != "xray" || arch != in.Architecture || !approved || size != int64(len(backupPayload)) {
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
	var durableResult json.RawMessage
	var executor agenttasks.InstallExecutor = testInstallExecutor{
		install: func(raw []byte, lease string) (json.RawMessage, error) {
			calls.Add(1)
			assertStatus(client.request(http.MethodPost, "/api/v1/helper/tasks/authorize", helperAuthorizationRequest{LeaseID: lease, Task: raw}, true), http.StatusOK)
			task, err := policy.InstallKey().Verify(raw)
			if err != nil {
				return nil, err
			}
			durableResult, err = json.Marshal(lifecycleauth.InstallResult{Outcome: "SUCCEEDED", Version: task.Version, SHA256: task.SHA256})
			return durableResult, err
		},
		reconcile: func(raw []byte) (json.RawMessage, error) {
			if !bytes.Equal(raw, leased.Task) {
				return nil, lifecycleauth.ErrDenied
			}
			return durableResult, nil
		},
	}
	if os.Geteuid() == 0 {
		executor = rootInstallTestExecutor(t, client.server, client.nodeID, policy.InstallKey(), clock, &calls)
	}
	artifacts := testInstallArtifacts{
		in.Version: {Core: "xray", Version: in.Version, Architecture: in.Architecture, SHA256: in.SHA256, SignatureStatus: "not-provided"},
		newVersion: {Core: "xray", Version: newVersion, Architecture: in.Architecture, SHA256: newDigest, SignatureStatus: "not-provided"},
	}
	newRunner := func(ledger *taskledger.Ledger, executor agenttasks.InstallExecutor) *agenttasks.Runner {
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
	lostHelperResponse := testInstallExecutor{install: func(raw []byte, lease string) (json.RawMessage, error) {
		if _, err := executor.ExecuteInstall(t.Context(), raw, lease); err != nil {
			t.Fatalf("Helper execution failed: %v", err)
		}
		return nil, errors.New("lost Helper response after durable completion")
	}}
	runner := newRunner(nodeLedger, lostHelperResponse)
	acks, err := runner.ProcessXrayInstall(t.Context(), leased.Task, leased.LeaseID, nil, 0, now)
	if err != nil || len(acks) != 1 || acks[0].Status != "NEEDS_RECONCILIATION" {
		t.Fatalf("Agent uncertain installation result = %+v, %v", acks, err)
	}
	if err := nodeLedger.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := taskledger.Open(agentLedgerPath)
	if err != nil {
		t.Fatal(err)
	}
	nodeLedger = reopened
	runner = newRunner(nodeLedger, lostHelperResponse)
	advance(61 * time.Second)
	recovered := download("1")
	if recovered.LeaseID == leased.LeaseID {
		t.Fatal("expired delivery reused the old lease")
	}
	assertStatus(client.request(http.MethodPost, "/api/v1/helper/tasks/authorize", leased, true), http.StatusForbidden)
	assertStatus(client.request(http.MethodPost, artifacttrust.BackupEndpoint, backupReq, true), http.StatusForbidden)
	assertStatus(client.request(http.MethodPost, "/api/v1/helper/tasks/authorize", recovered, true), http.StatusOK)
	acks, err = runner.ProcessXrayInstall(t.Context(), recovered.Task, recovered.LeaseID, nil, 0, now)
	if err != nil || calls.Load() != 1 || len(acks) != 1 || acks[0].Status != "NEEDS_RECONCILIATION" {
		t.Fatalf("Agent retried the install or lost its pending state: calls=%d %+v %v", calls.Load(), acks, err)
	}
	const ackPath = "/api/v1/agent/tasks/ack"
	report := func(ack agenttasks.Ack) *httptest.ResponseRecorder {
		return client.request(http.MethodPost, ackPath, taskAckRequest{TaskID: in.TaskID, Sequence: 1, StatusVersion: ack.StatusVersion, Status: ack.Status, Result: ack.Result}, true)
	}
	assertStatus(report(acks[0]), http.StatusNoContent)
	assertStatus(client.request(http.MethodPost, "/api/v1/helper/tasks/authorize", recovered, true), http.StatusForbidden)
	assertStatus(client.request(http.MethodPost, "/api/v1/admin/tasks", status, false), http.StatusConflict)
	assertStatus(client.request(http.MethodGet, "/api/v1/agent/tasks/next?install=xray-manifest-v1&next_sequence=1", nil, true), http.StatusConflict)
	advance(11 * time.Minute)
	const reconcilePath = "/api/v1/agent/tasks/next?install=xray-manifest-v1&install_reconciliation=v1&next_sequence="
	getRecovery := func(expected string) {
		t.Helper()
		response := client.request(http.MethodGet, reconcilePath+expected, nil, true)
		assertStatus(response, http.StatusOK)
		var recovery struct {
			helperAuthorizationRequest
			ReconcileInstall  bool  `json:"reconcile_install"`
			LastStatusVersion int64 `json:"last_status_version"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &recovery); err != nil || recovery.LeaseID != "" ||
			!recovery.ReconcileInstall || recovery.LastStatusVersion != 1 || !bytes.Equal(recovery.Task, task) {
			t.Fatalf("unexpected reconciliation delivery: %s (%v)", response.Body, err)
		}
	}
	getRecovery("1")
	if acks, err := runner.ReconcileXrayInstall(t.Context(), task, 1); err != nil || len(acks) != 0 {
		t.Fatalf("reconciled without proof: %+v, %v", acks, err)
	}
	runner = newRunner(nodeLedger, executor)
	acks, err = runner.ReconcileXrayInstall(t.Context(), task, 1)
	if err != nil || calls.Load() != 1 || len(acks) != 1 || acks[0].Status != "SUCCEEDED" || acks[0].StatusVersion != 2 {
		t.Fatalf("Agent did not recover the durable result: calls=%d %+v %v", calls.Load(), acks, err)
	}
	if err := nodeLedger.Close(); err != nil {
		t.Fatal(err)
	}
	nodeLedger, err = taskledger.Open(agentLedgerPath)
	if err != nil {
		t.Fatal(err)
	}
	getRecovery("2")
	runner = newRunner(nodeLedger, executor)
	replayed, err := runner.ReconcileXrayInstall(t.Context(), task, 1)
	if err != nil || len(replayed) != 1 || replayed[0].StatusVersion != acks[0].StatusVersion || !bytes.Equal(replayed[0].Result, acks[0].Result) {
		t.Fatalf("result replay after Agent reopen: %+v, %v", replayed, err)
	}
	for range 2 {
		assertStatus(report(replayed[0]), http.StatusNoContent)
	}
	if err := client.server.ReconcileTaskRuntime(); err != nil {
		t.Fatalf("reconcile recorded installation: %v", err)
	}
	assertStatus(client.request(http.MethodGet, "/api/v1/agent/tasks/next?install=xray-manifest-v1&next_sequence=2", nil, true), http.StatusNoContent)

	for i, operation := range []string{"core.stop", "core.start", "core.upgrade", "core.downgrade", "core.uninstall"} {
		control := in
		control.TaskID = "xray-control-" + operation[5:] + "-000000000001"
		control.Operation, control.ManifestVersion = operation, 0
		schema, capability := lifecycleauth.ControlProposalVersion, "xray_control=v1"
		switch operation {
		case "core.upgrade":
			control.CurrentVersion, control.CurrentSHA256 = in.Version, in.SHA256
			control.Version, control.SHA256, control.ManifestVersion = newVersion, newDigest, in.ManifestVersion
		case "core.downgrade":
			control.CurrentVersion, control.CurrentSHA256, control.ManifestVersion = newVersion, newDigest, in.ManifestVersion
		}
		versionChange := lifecycleauth.IsVersionChange(operation)
		if versionChange || operation == "core.uninstall" {
			schema, capability = lifecycleauth.ChangeProposalVersion, "xray_change=v1"
		}
		res := request(http.MethodPost, base, "test-session-token", client.csrf, control)
		assertStatus(res, http.StatusCreated)
		var view xrayInstallView
		if err := json.Unmarshal(res.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		sequence := int64(i + 2)
		p, err := lifecycleauth.ParseProposal(view.Proposal)
		if err != nil || p.Operation != operation || p.Sequence != sequence || p.SchemaVersion != schema ||
			p.CurrentVersion != control.CurrentVersion || p.CurrentSHA256 != control.CurrentSHA256 {
			t.Fatalf("control proposal: %+v (%v)", p, err)
		}
		proof, err := policy.SignRequest(p, operatorPrivate, now)
		if err != nil {
			t.Fatal(err)
		}
		controlTask, err := policy.Issue(t.Context(), ledger, proof, signerPrivate, now)
		if err != nil {
			t.Fatal(err)
		}
		body := map[string]any{"request": proof, "task": json.RawMessage(controlTask)}
		assertStatus(request(http.MethodPost, base+"/"+control.TaskID+"/signed-task", "other-session", "other-csrf", body), http.StatusNotFound)
		assertStatus(request(http.MethodPost, base+"/"+control.TaskID+"/signed-task", "test-session-token", client.csrf, body), http.StatusOK)
		dispatchPath := base + "/" + control.TaskID + "/dispatch"
		confirmation := map[string]any{}
		if operation == "core.downgrade" || operation == "core.uninstall" {
			assertStatus(request(http.MethodPost, dispatchPath, "test-session-token", client.csrf, confirmation), http.StatusBadRequest)
			wrongOperation := "core.uninstall"
			if operation == wrongOperation {
				wrongOperation = "core.downgrade"
			}
			assertStatus(request(http.MethodPost, dispatchPath, "test-session-token", client.csrf, map[string]any{"confirm_operation": wrongOperation}), http.StatusBadRequest)
			confirmation["confirm_operation"] = operation
		}
		res = request(http.MethodPost, dispatchPath, "test-session-token", client.csrf, confirmation)
		assertStatus(res, http.StatusCreated)
		var dispatched taskView
		if err := json.Unmarshal(res.Body.Bytes(), &dispatched); err != nil || dispatched.Operation != operation {
			t.Fatalf("dispatched control: %+v (%v)", dispatched, err)
		}
		next := "/api/v1/agent/tasks/next?install=xray-manifest-v1&next_sequence=" + strconv.FormatInt(sequence, 10)
		assertStatus(client.request(http.MethodGet, next, nil, true), http.StatusNoContent)
		if schema == lifecycleauth.ChangeProposalVersion {
			assertStatus(client.request(http.MethodGet, next+"&xray_control=v1", nil, true), http.StatusNoContent)
		}
		if versionChange {
			legacy := strings.Replace(next, "xray-manifest-v1", "xray-v1", 1)
			assertStatus(client.request(http.MethodGet, legacy+"&"+capability, nil, true), http.StatusNoContent)
		}
		res = client.request(http.MethodGet, next+"&"+capability, nil, true)
		assertStatus(res, http.StatusOK)
		var delivery helperAuthorizationRequest
		if err := json.Unmarshal(res.Body.Bytes(), &delivery); err != nil || len(delivery.LeaseID) != 32 || !bytes.Equal(delivery.Task, controlTask) {
			t.Fatalf("invalid control delivery: %+v (%v)", delivery, err)
		}
		backupStatus := http.StatusForbidden
		if versionChange {
			backupStatus = http.StatusOK
		}
		assertStatus(client.request(http.MethodPost, artifacttrust.BackupEndpoint, artifacttrust.BackupRequest{
			Task: delivery.Task, LeaseID: delivery.LeaseID, Length: int64(len(backupPayload)),
		}, true), backupStatus)
		acks, err := runner.ProcessXrayInstall(t.Context(), delivery.Task, delivery.LeaseID, nil, 0, now)
		if err != nil || len(acks) != 4 || acks[3].Status != "SUCCEEDED" {
			t.Fatalf("control %s ACKs: %+v (%v)", operation, acks, err)
		}
		for _, ack := range acks {
			assertStatus(client.request(http.MethodPost, ackPath, taskAckRequest{
				TaskID: control.TaskID, Sequence: sequence, StatusVersion: ack.StatusVersion, Status: ack.Status, Result: ack.Result,
			}, true), http.StatusNoContent)
		}
		res = request(http.MethodGet, "/api/v1/admin/tasks/"+control.TaskID, "test-session-token", "", nil)
		assertStatus(res, http.StatusOK)
		if err := json.Unmarshal(res.Body.Bytes(), &dispatched); err != nil || dispatched.Operation != operation || dispatched.Status != "SUCCEEDED" {
			t.Fatalf("reported control: %+v (%v)", dispatched, err)
		}
	}
	if calls.Load() != 6 {
		t.Fatalf("unexpected Xray execution count: %d", calls.Load())
	}

	advance(30 * time.Minute)
	assertStatus(request(http.MethodPost, acceptSigned, "test-session-token", client.csrf, issueBody), http.StatusConflict)
	changed.TaskID = "xray-install-0000000000002"
	assertStatus(request(http.MethodPost, base, "test-session-token", client.csrf, changed), http.StatusCreated)
	advance(30 * time.Minute)
	changed.TaskID = "xray-install-0000000000003"
	assertStatus(request(http.MethodPost, base, "test-session-token", client.csrf, changed), http.StatusConflict)
	assertStatus(client.request(http.MethodPost, "/api/v1/admin/tasks", status, false), http.StatusCreated)
	res = client.request(http.MethodGet, reconcilePath+"7", nil, true)
	assertStatus(res, http.StatusOK)
	if !strings.Contains(res.Body.String(), status.RequestID) || strings.Contains(res.Body.String(), "reconcile_install") {
		t.Fatalf("next sequence did not resume normal delivery: %s", res.Body)
	}
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
		XrayInstall: &helper.XrayInstallConfig{Key: key, Apply: func(ctx context.Context, task lifecycleauth.InstallTask, _ string, authorize func(context.Context) error) (string, error) {
			if task.Operation == "core.install" {
				for range 2 {
					if err := authorize(ctx); err != nil {
						return "", err
					}
				}
			}
			calls.Add(1)
			return "SUCCEEDED", nil
		}, Reconcile: func(context.Context, lifecycleauth.InstallTask, string) (string, error) {
			return "", errors.New("Helper should replay its durable result")
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
	install   func([]byte, string) (json.RawMessage, error)
	reconcile func([]byte) (json.RawMessage, error)
}

func (e testInstallExecutor) ExecuteStatus(context.Context, []byte, string) (json.RawMessage, error) {
	return nil, lifecycleauth.ErrDenied
}

func (e testInstallExecutor) ExecuteInstall(_ context.Context, raw []byte, lease string) (json.RawMessage, error) {
	return e.install(raw, lease)
}

func (e testInstallExecutor) ReconcileInstall(_ context.Context, raw []byte) (json.RawMessage, error) {
	if e.reconcile == nil {
		return nil, lifecycleauth.ErrDenied
	}
	return e.reconcile(raw)
}

type testInstallArtifacts map[string]artifacttrust.Target

func (s testInstallArtifacts) LookupCoreManifest(_ context.Context, core, version string, manifest int64) (artifacttrust.Target, error) {
	target, ok := s[version]
	if !ok || manifest != 2 || core != target.Core {
		return artifacttrust.Target{}, lifecycleauth.ErrDenied
	}
	return target, nil
}

func (s testInstallArtifacts) Download(context.Context, artifacttrust.Target) (string, error) {
	return "test-only", nil
}
