package master

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/taskdispatch"
	"github.com/ACnoway/mcui/internal/tasksigner"
)

type taskTestClient struct {
	server *Server
	store  *store.Store
	csrf   string
	peer   *tls.ConnectionState
}

func newTaskTestClient(t *testing.T) taskTestClient {
	t.Helper()
	s, st := testServer(t)
	nodeID, err := security.NewNodeID()
	if err != nil {
		t.Fatal(err)
	}
	_, agentKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := security.NewCSR(agentKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := security.ParseCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	certificatePEM, serial, notAfter, err := s.nodeCA.IssueNodeCertificate(csr, nodeID, now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certificatePEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	peer := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, s.nodeCA.Certificate}, VerifiedChains: [][]*x509.Certificate{{leaf, s.nodeCA.Certificate}}}
	actorID, sessionToken, csrf := "operator-1", "test-session-token", "test-csrf-token"
	err = st.Update(func(state *store.State) error {
		state.Admins[actorID] = store.Admin{ID: actorID, Username: "operator", Role: "operator", NodeIDs: []string{nodeID}}
		state.Sessions[hash(sessionToken)] = store.Session{ID: hash(sessionToken), AdminID: actorID, CreatedAt: now.Unix(), LastSeen: now.Unix(), MFAAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), CSRFToken: csrf}
		state.Nodes[nodeID] = store.Node{ID: nodeID, Name: "test node", Group: "g1", CurrentSerial: serial, Certificates: map[string]store.NodeCertificate{serial: {NotAfter: notAfter}}, LastSeen: now.Unix()}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer, err := tasksigner.New("task-key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	tasks, err := taskdispatch.Init(filepath.Join(t.TempDir(), "tasks.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tasks.Close() })
	if err = s.ConfigureTaskRuntime(TaskRuntime{Store: tasks, Signer: signer, KeyID: "task-key-1", PublicKey: privateKey.Public().(ed25519.PublicKey), Now: time.Now}); err != nil {
		t.Fatal(err)
	}
	return taskTestClient{server: s, store: st, csrf: csrf, peer: peer}
}

func (c taskTestClient) request(method, path string, body any, useNodeCert bool) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, "http://example.com"+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if method != http.MethodGet {
		req.Header.Set("Origin", "http://example.com")
	}
	if strings.HasPrefix(req.URL.Path, "/api/v1/admin/tasks") {
		req.AddCookie(&http.Cookie{Name: "mcui_session", Value: "test-session-token"})
	}
	if method == http.MethodPost && req.URL.Path == "/api/v1/admin/tasks" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	if useNodeCert {
		req.TLS = c.peer
	}
	response := httptest.NewRecorder()
	c.server.Handler().ServeHTTP(response, req)
	return response
}

func TestStatusTaskAPIEnforcesScopeAndCompletesMtlSDelivery(t *testing.T) {
	client := newTaskTestClient(t)
	rawRequest := statusTaskRequest{RequestID: "request-1234567890123456", NodeID: client.peer.PeerCertificates[0].URIs[0].Opaque[len("mcui:node:"):], Core: "xray"}
	created := client.request(http.MethodPost, "/api/v1/admin/tasks", rawRequest, false)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status task HTTP %d: %s", created.Code, created.Body)
	}
	var createdTask taskView
	if err := json.Unmarshal(created.Body.Bytes(), &createdTask); err != nil || createdTask.Status != "QUEUED" || createdTask.Sequence != 1 || createdTask.Core != "xray" || createdTask.CreatedBy != "operator" || createdTask.Approval != "not-required" || createdTask.CreatedAt == "" {
		t.Fatalf("created task = %+v, %v", createdTask, err)
	}
	retry := client.request(http.MethodPost, "/api/v1/admin/tasks", rawRequest, false)
	var retriedTask taskView
	if err := json.Unmarshal(retry.Body.Bytes(), &retriedTask); err != nil || retry.Code != http.StatusCreated || retriedTask.TaskID != createdTask.TaskID {
		t.Fatalf("idempotent status-task retry HTTP %d: %+v err=%v", retry.Code, retriedTask, err)
	}
	changedIntent := rawRequest
	changedIntent.Core = "mita"
	if response := client.request(http.MethodPost, "/api/v1/admin/tasks", changedIntent, false); response.Code != http.StatusConflict {
		t.Fatalf("changed request intent returned HTTP %d", response.Code)
	}
	listed := client.request(http.MethodGet, "/api/v1/admin/tasks?node_id="+rawRequest.NodeID, nil, false)
	if listed.Code != http.StatusOK {
		t.Fatalf("list tasks HTTP %d: %s", listed.Code, listed.Body)
	}
	var tasks []taskView
	if err := json.Unmarshal(listed.Body.Bytes(), &tasks); err != nil || len(tasks) != 1 {
		t.Fatalf("task list = %+v, %v", tasks, err)
	}
	unauthorized := client.request(http.MethodGet, "/api/v1/agent/tasks/next", nil, false)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("task pull without mTLS returned HTTP %d", unauthorized.Code)
	}
	lease := client.request(http.MethodGet, "/api/v1/agent/tasks/next", nil, true)
	if lease.Code != http.StatusOK {
		t.Fatalf("task pull HTTP %d: %s", lease.Code, lease.Body)
	}
	var delivery struct {
		TaskID            string          `json:"task_id"`
		Sequence          int64           `json:"sequence"`
		Task              json.RawMessage `json:"task"`
		LeaseID           string          `json:"lease_id"`
		LastStatusVersion int64           `json:"last_status_version"`
		LeaseDeadline     string          `json:"lease_deadline"`
	}
	if err := json.Unmarshal(lease.Body.Bytes(), &delivery); err != nil || delivery.TaskID != createdTask.TaskID || delivery.Sequence != 1 || delivery.LeaseID == "" || len(delivery.Task) == 0 {
		t.Fatalf("delivery = %+v, %v", delivery, err)
	}
	checkpointDenied := client.request(http.MethodPost, "/api/v1/helper/tasks/authorize", helperAuthorizationRequest{LeaseID: delivery.LeaseID, Task: delivery.Task}, false)
	if checkpointDenied.Code != http.StatusUpgradeRequired {
		t.Fatalf("helper checkpoint without TLS returned HTTP %d", checkpointDenied.Code)
	}
	checkpoint := client.request(http.MethodPost, "/api/v1/helper/tasks/authorize", helperAuthorizationRequest{LeaseID: delivery.LeaseID, Task: delivery.Task}, true)
	var checkpointResult struct {
		PreviousSequence int64  `json:"previous_sequence"`
		ServerTime       string `json:"server_time"`
	}
	if err := json.Unmarshal(checkpoint.Body.Bytes(), &checkpointResult); err != nil || checkpoint.Code != http.StatusOK || checkpointResult.PreviousSequence != 0 || checkpointResult.ServerTime == "" {
		t.Fatalf("helper checkpoint HTTP %d: %+v err=%v", checkpoint.Code, checkpointResult, err)
	}
	for version, status := range []string{"ACK_ACCEPTED", "RUNNING", "VERIFYING"} {
		ack := taskAckRequest{TaskID: delivery.TaskID, Sequence: 1, StatusVersion: int64(version + 1), Status: status}
		response := client.request(http.MethodPost, "/api/v1/agent/tasks/ack", ack, true)
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s ACK HTTP %d: %s", status, response.Code, response.Body)
		}
	}
	result := json.RawMessage(`{"core":"xray","load_state":"loaded","active_state":"active","sub_state":"running","observed_at":"` + time.Now().UTC().Format(time.RFC3339) + `"}`)
	finalAck := taskAckRequest{TaskID: delivery.TaskID, Sequence: 1, StatusVersion: 4, Status: "SUCCEEDED", Result: result}
	if response := client.request(http.MethodPost, "/api/v1/agent/tasks/ack", finalAck, true); response.Code != http.StatusNoContent {
		t.Fatalf("SUCCEEDED ACK HTTP %d: %s", response.Code, response.Body)
	}
	final := client.request(http.MethodGet, "/api/v1/admin/tasks/"+delivery.TaskID, nil, false)
	var finalTask taskView
	if err := json.Unmarshal(final.Body.Bytes(), &finalTask); err != nil || final.Code != http.StatusOK || finalTask.Status != "SUCCEEDED" || len(finalTask.Acks) != 4 {
		t.Fatalf("final task HTTP %d = %+v, %v", final.Code, finalTask, err)
	}
	var audit []store.Audit
	if err := client.store.View(func(state store.State) error { audit = state.Audits; return nil }); err != nil {
		t.Fatal(err)
	}
	visible := false
	for _, event := range audit {
		if event.ResourceType == "task" && event.Resource == delivery.TaskID && event.NodeID == rawRequest.NodeID {
			visible = true
		}
	}
	if !visible {
		t.Fatal("task issue was not audited with its target node")
	}
}

func TestStatusTaskFailureClosesReadOnlySlotAndAuditorCannotCreate(t *testing.T) {
	client := newTaskTestClient(t)
	nodeID := client.peer.PeerCertificates[0].URIs[0].Opaque[len("mcui:node:"):]
	request := statusTaskRequest{RequestID: "request-3234567890123456", NodeID: nodeID, Core: "xray"}
	created := client.request(http.MethodPost, "/api/v1/admin/tasks", request, false)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status task HTTP %d: %s", created.Code, created.Body)
	}
	lease := client.request(http.MethodGet, "/api/v1/agent/tasks/next", nil, true)
	var delivery struct {
		TaskID   string `json:"task_id"`
		Sequence int64  `json:"sequence"`
	}
	if err := json.Unmarshal(lease.Body.Bytes(), &delivery); err != nil {
		t.Fatal(err)
	}
	for version, status := range []string{"ACK_ACCEPTED", "RUNNING", "FAILED"} {
		var result json.RawMessage
		if status == "FAILED" {
			result = json.RawMessage(`{"error_code":"helper_unavailable"}`)
		}
		ack := taskAckRequest{TaskID: delivery.TaskID, Sequence: delivery.Sequence, StatusVersion: int64(version + 1), Status: status, Result: result}
		if response := client.request(http.MethodPost, "/api/v1/agent/tasks/ack", ack, true); response.Code != http.StatusNoContent {
			t.Fatalf("%s ACK HTTP %d: %s", status, response.Code, response.Body)
		}
	}
	request.RequestID = "request-4234567890123456"
	second := client.request(http.MethodPost, "/api/v1/admin/tasks", request, false)
	var nextTask taskView
	if err := json.Unmarshal(second.Body.Bytes(), &nextTask); err != nil || second.Code != http.StatusCreated || nextTask.Sequence != 2 {
		t.Fatalf("next status task after failure HTTP %d: %+v err=%v", second.Code, nextTask, err)
	}
	if err := client.store.Update(func(state *store.State) error {
		admin := state.Admins["operator-1"]
		admin.Role = "auditor"
		state.Admins[admin.ID] = admin
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	request.RequestID = "request-5234567890123456"
	if response := client.request(http.MethodPost, "/api/v1/admin/tasks", request, false); response.Code != http.StatusNotFound {
		t.Fatalf("auditor create returned HTTP %d", response.Code)
	}
}

func TestStatusTaskAPIRejectsOutOfScopeNodeAndSecretBearingResults(t *testing.T) {
	client := newTaskTestClient(t)
	response := client.request(http.MethodPost, "/api/v1/admin/tasks", statusTaskRequest{RequestID: "request-1234567890123456", NodeID: "node-00000000000000000000000000000000", Core: "xray"}, false)
	if response.Code != http.StatusNotFound {
		t.Fatalf("out-of-scope issue returned HTTP %d", response.Code)
	}
	malformed := statusTaskRequest{RequestID: "request-2234567890123456", NodeID: client.peer.PeerCertificates[0].URIs[0].Opaque[len("mcui:node:"):], Core: "xray"}
	created := client.request(http.MethodPost, "/api/v1/admin/tasks", malformed, false)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status task HTTP %d: %s", created.Code, created.Body)
	}
	lease := client.request(http.MethodGet, "/api/v1/agent/tasks/next", nil, true)
	var delivery struct {
		TaskID   string `json:"task_id"`
		Sequence int64  `json:"sequence"`
	}
	if err := json.Unmarshal(lease.Body.Bytes(), &delivery); err != nil {
		t.Fatal(err)
	}
	badResult := json.RawMessage(`{"core":"xray","load_state":"loaded","active_state":"active","sub_state":"running","observed_at":"` + time.Now().UTC().Format(time.RFC3339) + `","secret":"must-reject"}`)
	ack := taskAckRequest{TaskID: delivery.TaskID, Sequence: delivery.Sequence, StatusVersion: 1, Status: "SUCCEEDED", Result: badResult}
	response = client.request(http.MethodPost, "/api/v1/agent/tasks/ack", ack, true)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("secret-bearing ACK returned HTTP %d: %s", response.Code, response.Body)
	}
}
