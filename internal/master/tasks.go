package master

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/taskdispatch"
	"github.com/ACnoway/mcui/internal/tasksigner"
)

const statusTaskLifetime = 5 * time.Minute

var statusTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

// TaskRuntime is configured by the Master process before it starts serving.
// The private key stays in a separate signer process; Master holds only its
// public key and a narrow status-signing client.
type TaskRuntime struct {
	Store     *taskdispatch.Store
	Signer    tasksigner.SignStatus
	KeyID     string
	PublicKey ed25519.PublicKey
	Now       func() time.Time
}

func (s *Server) ConfigureTaskRuntime(runtime TaskRuntime) error {
	if s == nil || runtime.Store == nil || runtime.Signer == nil || runtime.KeyID == "" || len(runtime.PublicKey) != ed25519.PublicKeySize || runtime.Now == nil {
		return errors.New("incomplete task runtime configuration")
	}
	copy := runtime
	copy.PublicKey = append(ed25519.PublicKey(nil), runtime.PublicKey...)
	s.taskRuntime = &copy
	return nil
}

type statusTaskRequest struct {
	RequestID string `json:"request_id"`
	NodeID    string `json:"node_id"`
	Core      string `json:"core"`
}

type unsignedStatusTask struct {
	SchemaVersion int    `json:"schema_version"`
	TaskID        string `json:"task_id"`
	NodeID        string `json:"node_id"`
	Sequence      int64  `json:"sequence"`
	Operation     string `json:"operation"`
	IssuedAt      string `json:"issued_at"`
	NotBefore     string `json:"not_before"`
	ExpiresAt     string `json:"expires_at"`
	Payload       struct {
		Core string `json:"core"`
	} `json:"payload"`
	Step struct {
		StepID     string `json:"step_id"`
		Parameters struct {
			Core string `json:"core"`
		} `json:"parameters"`
		ArtifactSHA256 string `json:"artifact_sha256"`
		Architecture   string `json:"architecture"`
		ExpectedState  string `json:"expected_state"`
	} `json:"step"`
	KeyID              string `json:"signing_key_id"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	Signature          string `json:"signature"`
}

type statusTaskEnvelope struct {
	TaskID    string `json:"task_id"`
	NodeID    string `json:"node_id"`
	Sequence  int64  `json:"sequence"`
	Operation string `json:"operation"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
	Payload   struct {
		Core string `json:"core"`
	} `json:"payload"`
}

type taskAckRequest struct {
	TaskID        string          `json:"task_id"`
	Sequence      int64           `json:"sequence"`
	StatusVersion int64           `json:"status_version"`
	Status        string          `json:"status"`
	Result        json.RawMessage `json:"result"`
}

type helperAuthorizationRequest struct {
	LeaseID string          `json:"lease_id"`
	Task    json.RawMessage `json:"task"`
}

type statusResult struct {
	Core        string `json:"core"`
	LoadState   string `json:"load_state"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
	ObservedAt  string `json:"observed_at"`
}

type statusFailure struct {
	ErrorCode string `json:"error_code"`
}

type taskAckView struct {
	StatusVersion int64           `json:"status_version"`
	Status        string          `json:"status"`
	Result        json.RawMessage `json:"result,omitempty"`
}

type taskView struct {
	TaskID        string        `json:"task_id"`
	NodeID        string        `json:"node_id"`
	Sequence      int64         `json:"sequence"`
	CreatedBy     string        `json:"created_by,omitempty"`
	CreatedAt     string        `json:"created_at,omitempty"`
	Approval      string        `json:"approval"`
	Operation     string        `json:"operation"`
	Core          string        `json:"core"`
	IssuedAt      string        `json:"issued_at"`
	ExpiresAt     string        `json:"expires_at"`
	Active        bool          `json:"active"`
	LeaseDeadline string        `json:"lease_deadline,omitempty"`
	Status        string        `json:"status"`
	Acks          []taskAckView `json:"acks"`
}

func (s *Server) createStatusTask(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.requireCSRF(w, r)
	if !ok {
		return
	}
	runtime := s.taskRuntime
	if runtime == nil {
		http.Error(w, "task runtime unavailable", http.StatusServiceUnavailable)
		return
	}
	var in statusTaskRequest
	if readJSON(r, &in) != nil || !validRequestID(in.RequestID) || in.NodeID == "" || !validCoreName(in.Core) {
		http.Error(w, "invalid status-task request", http.StatusBadRequest)
		return
	}
	node, allowed := s.authorizedStatusNode(ctx.Admin.ID, in.NodeID)
	if !allowed || (ctx.Admin.Role != "security_admin" && ctx.Admin.Role != "operator") {
		_ = s.recordAudit(ctx.Admin.ID, "task.status.create", "node", in.NodeID, "denied")
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if existing, existingErr := runtime.Store.GetRecord(in.RequestID); existingErr == nil {
		var envelope statusTaskEnvelope
		if existing.NodeID != node.ID || protocol.VerifyV2Task(existing.Raw, runtime.PublicKey) != nil || json.Unmarshal(existing.Raw, &envelope) != nil || envelope.NodeID != node.ID || envelope.TaskID != in.RequestID || envelope.Operation != "core.status" || envelope.Payload.Core != in.Core {
			http.Error(w, "task request conflicts with an earlier request", http.StatusConflict)
			return
		}
		writeJSON(w, http.StatusCreated, s.decorateTaskView(toTaskView(existing, runtime.PublicKey)))
		return
	} else if !errors.Is(existingErr, taskdispatch.ErrNotFound) {
		http.Error(w, "task history unavailable", http.StatusInternalServerError)
		return
	}
	now := runtime.Now().UTC().Truncate(time.Second)
	if now.IsZero() {
		http.Error(w, "task runtime clock unavailable", http.StatusServiceUnavailable)
		return
	}
	// Persist authorization and its audit before creating a deliverable task.
	// A failed signing call therefore cannot leave an entirely unaudited queue item.
	if err = s.store.Update(func(st *store.State) error {
		current, adminExists := st.Admins[ctx.Admin.ID]
		currentNode, nodeExists := st.Nodes[node.ID]
		if !adminExists || current.Disabled || (current.Role != "security_admin" && current.Role != "operator") || !nodeExists || currentNode.Disabled || !canQueryCoreStatus(current, currentNode) {
			return errors.New("task authorization changed")
		}
		for _, event := range st.Audits {
			if event.Action == "task.status.authorize" && event.Resource == in.RequestID {
				return errors.New("task request ID was already used")
			}
		}
		s.appendAudit(st, store.Audit{At: now.Unix(), Actor: current.ID, Action: "task.status.authorize", ResourceType: "task", Resource: in.RequestID, NodeID: node.ID, Outcome: "authorized"})
		return nil
	}); err != nil {
		http.Error(w, "task authorization changed or request ID already used", http.StatusConflict)
		return
	}
	delivery, err := runtime.Store.Issue(node.ID, in.RequestID, runtime.KeyID, runtime.PublicKey, func(sequence int64) ([]byte, error) {
		unsigned, err := makeUnsignedStatusTask(in, sequence, runtime.KeyID, now)
		if err != nil {
			return nil, err
		}
		signed, err := runtime.Signer.SignStatus(unsigned)
		if err != nil {
			return nil, err
		}
		var issued statusTaskEnvelope
		if protocol.VerifyV2Task(signed, runtime.PublicKey) != nil || json.Unmarshal(signed, &issued) != nil || issued.NodeID != node.ID || issued.TaskID != in.RequestID || issued.Sequence != sequence || issued.Operation != "core.status" || issued.Payload.Core != in.Core {
			return nil, taskdispatch.ErrIdentity
		}
		return signed, nil
	})
	if err != nil {
		if errors.Is(err, taskdispatch.ErrConflict) || errors.Is(err, taskdispatch.ErrSequence) {
			http.Error(w, "task request conflicts with current node state", http.StatusConflict)
			return
		}
		_ = s.recordTaskAudit(ctx.Admin.ID, "task.status.issue", in.RequestID, node.ID, "failed")
		http.Error(w, "task signing unavailable", http.StatusServiceUnavailable)
		return
	}
	var envelope statusTaskEnvelope
	if _, err = runtime.Store.GetRecord(delivery.TaskID); err != nil || protocol.VerifyV2Task(delivery.Raw, runtime.PublicKey) != nil || json.Unmarshal(delivery.Raw, &envelope) != nil || envelope.NodeID != node.ID || envelope.TaskID != in.RequestID || envelope.Operation != "core.status" || envelope.Payload.Core != in.Core {
		http.Error(w, "stored task request mismatch", http.StatusConflict)
		return
	}
	_ = s.recordTaskAudit(ctx.Admin.ID, "task.status.issue", delivery.TaskID, node.ID, "issued")
	record, err := runtime.Store.GetRecord(delivery.TaskID)
	if err != nil {
		http.Error(w, "task unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, s.decorateTaskView(toTaskView(record, runtime.PublicKey)))
}

func makeUnsignedStatusTask(in statusTaskRequest, sequence int64, keyID string, now time.Time) ([]byte, error) {
	if sequence < 1 || !validCoreName(in.Core) {
		return nil, taskdispatch.ErrInvalid
	}
	issued := now.Format(time.RFC3339)
	task := unsignedStatusTask{
		SchemaVersion:      2,
		TaskID:             in.RequestID,
		NodeID:             in.NodeID,
		Sequence:           sequence,
		Operation:          "core.status",
		IssuedAt:           issued,
		NotBefore:          issued,
		ExpiresAt:          now.Add(statusTaskLifetime).Format(time.RFC3339),
		KeyID:              keyID,
		SignatureAlgorithm: "Ed25519",
		Signature:          tasksigner.PlaceholderSignature,
	}
	task.Payload.Core = in.Core
	task.Step.StepID = "core.status"
	task.Step.Parameters.Core = in.Core
	task.Step.ArtifactSHA256 = "not-applicable"
	task.Step.Architecture = "not-applicable"
	task.Step.ExpectedState = "observe"
	return json.Marshal(task)
}

func validCoreName(core string) bool {
	return core == "xray" || core == "sing-box" || core == "mita"
}

func canQueryCoreStatus(admin store.Admin, node store.Node) bool {
	return node.ID != "" && !node.Disabled && canReadNode(admin, node)
}

func (s *Server) authorizedStatusNode(adminID, nodeID string) (store.Node, bool) {
	var node store.Node
	allowed := false
	err := s.store.View(func(st store.State) error {
		admin, adminExists := st.Admins[adminID]
		candidate, nodeExists := st.Nodes[nodeID]
		if adminExists && nodeExists && canQueryCoreStatus(admin, candidate) {
			node, allowed = candidate, true
		}
		return nil
	})
	return node, err == nil && allowed
}

func (s *Server) listTasks(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.adminAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	runtime := s.taskRuntime
	if runtime == nil {
		http.Error(w, "task runtime unavailable", http.StatusServiceUnavailable)
		return
	}
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		http.Error(w, "node_id is required", http.StatusBadRequest)
		return
	}
	if _, allowed := s.authorizedStatusNode(ctx.Admin.ID, nodeID); !allowed {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	records, err := runtime.Store.ListRecords(nodeID, 100)
	if err != nil {
		http.Error(w, "task history unavailable", http.StatusInternalServerError)
		return
	}
	metadata := s.taskAuditMetadata(nodeID)
	out := make([]taskView, 0, len(records))
	for _, record := range records {
		out = append(out, decorateTaskView(toTaskView(record, runtime.PublicKey), metadata[record.TaskID]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) taskDetail(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.adminAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	runtime := s.taskRuntime
	if runtime == nil {
		http.Error(w, "task runtime unavailable", http.StatusServiceUnavailable)
		return
	}
	record, err := runtime.Store.GetRecord(r.PathValue("id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if _, allowed := s.authorizedStatusNode(ctx.Admin.ID, record.NodeID); !allowed {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, s.decorateTaskView(toTaskView(record, runtime.PublicKey)))
}

type taskAuditInfo struct {
	Actor string
	At    string
}

func (s *Server) taskAuditMetadata(nodeID string) map[string]taskAuditInfo {
	metadata := map[string]taskAuditInfo{}
	if s == nil || s.store == nil || nodeID == "" {
		return metadata
	}
	_ = s.store.View(func(st store.State) error {
		for _, event := range st.Audits {
			if event.Action != "task.status.authorize" || event.ResourceType != "task" || event.NodeID != nodeID || event.Outcome != "authorized" {
				continue
			}
			actor := event.Actor
			if admin, ok := st.Admins[event.Actor]; ok && admin.Username != "" {
				actor = admin.Username
			}
			metadata[event.Resource] = taskAuditInfo{Actor: actor, At: time.Unix(event.At, 0).UTC().Format(time.RFC3339)}
		}
		return nil
	})
	return metadata
}

func decorateTaskView(view taskView, info taskAuditInfo) taskView {
	view.CreatedBy = info.Actor
	view.CreatedAt = info.At
	if view.Approval == "" {
		view.Approval = "not-required"
	}
	return view
}

func (s *Server) decorateTaskView(view taskView) taskView {
	return decorateTaskView(view, s.taskAuditMetadata(view.NodeID)[view.TaskID])
}

func (s *Server) recordTaskAudit(actor, action, taskID, nodeID, outcome string) error {
	now := time.Now().Unix()
	return s.store.Update(func(st *store.State) error {
		s.appendAudit(st, store.Audit{At: now, Actor: actor, Action: action, ResourceType: "task", Resource: taskID, NodeID: nodeID, Outcome: outcome})
		return nil
	})
}

func toTaskView(record taskdispatch.Record, publicKey ed25519.PublicKey) taskView {
	var envelope statusTaskEnvelope
	if protocol.VerifyV2Task(record.Raw, publicKey) != nil || json.Unmarshal(record.Raw, &envelope) != nil {
		return taskView{TaskID: record.TaskID, NodeID: record.NodeID, Sequence: record.Sequence, Active: record.Active, Status: "NEEDS_RECONCILIATION", Acks: []taskAckView{}}
	}
	out := taskView{
		TaskID: record.TaskID, NodeID: record.NodeID, Sequence: record.Sequence,
		Approval:  "not-required",
		Operation: envelope.Operation, Core: envelope.Payload.Core,
		IssuedAt: envelope.IssuedAt, ExpiresAt: envelope.ExpiresAt,
		Active: record.Active, Status: "QUEUED", Acks: make([]taskAckView, 0, len(record.Acks)),
	}
	if !record.LeaseDeadline.IsZero() {
		out.LeaseDeadline = record.LeaseDeadline.Format(time.RFC3339)
	}
	for _, ack := range record.Acks {
		view := taskAckView{StatusVersion: ack.StatusVersion, Status: ack.Status}
		if len(ack.Result) != 0 && json.Valid(ack.Result) {
			view.Result = append(json.RawMessage(nil), ack.Result...)
		}
		out.Acks = append(out.Acks, view)
		out.Status = ack.Status
	}
	return out
}

func (s *Server) nextTask(w http.ResponseWriter, r *http.Request) {
	node, _, ok := s.authenticateNode(r)
	if !ok {
		http.Error(w, "node certificate rejected", http.StatusUnauthorized)
		return
	}
	runtime := s.taskRuntime
	if runtime == nil {
		http.Error(w, "task runtime unavailable", http.StatusServiceUnavailable)
		return
	}
	now := runtime.Now().UTC()
	delivery, err := runtime.Store.Lease(node.ID, now, runtime.KeyID, runtime.PublicKey)
	if errors.Is(err, taskdispatch.ErrNotFound) || errors.Is(err, taskdispatch.ErrLeaseActive) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		if errors.Is(err, taskdispatch.ErrConflict) {
			http.Error(w, "task requires reconciliation", http.StatusConflict)
			return
		}
		http.Error(w, "task delivery unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"task_id": delivery.TaskID, "sequence": delivery.Sequence,
		"task": json.RawMessage(delivery.Raw), "lease_id": delivery.LeaseID,
		"last_status_version": delivery.LastStatusVersion,
		"lease_deadline":      delivery.Deadline.UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) acknowledgeTask(w http.ResponseWriter, r *http.Request) {
	node, _, ok := s.authenticateNode(r)
	if !ok {
		http.Error(w, "node certificate rejected", http.StatusUnauthorized)
		return
	}
	runtime := s.taskRuntime
	if runtime == nil {
		http.Error(w, "task runtime unavailable", http.StatusServiceUnavailable)
		return
	}
	var in taskAckRequest
	if readJSON(r, &in) != nil || in.TaskID == "" || in.Sequence < 1 || in.StatusVersion < 1 {
		http.Error(w, "invalid task ACK", http.StatusBadRequest)
		return
	}
	record, err := runtime.Store.GetRecord(in.TaskID)
	if err != nil || record.NodeID != node.ID || record.Sequence != in.Sequence {
		http.Error(w, "task ACK target rejected", http.StatusNotFound)
		return
	}
	var envelope statusTaskEnvelope
	if protocol.VerifyV2Task(record.Raw, runtime.PublicKey) != nil || json.Unmarshal(record.Raw, &envelope) != nil {
		http.Error(w, "stored task requires reconciliation", http.StatusConflict)
		return
	}
	if !validStatusAck(envelope.Payload.Core, in.Status, in.Result, runtime.Now()) {
		http.Error(w, "invalid task result", http.StatusBadRequest)
		return
	}
	if err = runtime.Store.Acknowledge(node.ID, taskdispatch.Ack{
		NodeID: node.ID, TaskID: in.TaskID, Sequence: in.Sequence,
		StatusVersion: in.StatusVersion, Status: in.Status, Result: []byte(in.Result),
	}); err != nil {
		http.Error(w, "task ACK rejected", http.StatusConflict)
		return
	}
	if err = s.store.Update(func(st *store.State) error {
		current, exists := st.Nodes[node.ID]
		if !exists || current.Disabled {
			return store.ErrNotFound
		}
		s.appendAudit(st, store.Audit{At: runtime.Now().Unix(), Actor: node.ID, Action: "task.status.ack", ResourceType: "task", Resource: in.TaskID, NodeID: node.ID, Outcome: in.Status})
		return nil
	}); err != nil {
		http.Error(w, "task ACK audit unavailable", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// authorizeHelperTask is a narrow, read-only checkpoint endpoint. Possession
// of the exact signed task and current node lease is the capability; the
// Helper still verifies the signature and fixed operation locally. HTTPS is
// mandatory because this endpoint supplies authoritative time and gap state.
func (s *Server) authorizeHelperTask(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "TLS required", http.StatusUpgradeRequired)
		return
	}
	runtime := s.taskRuntime
	if runtime == nil {
		http.Error(w, "task runtime unavailable", http.StatusServiceUnavailable)
		return
	}
	if !s.allowAttempt("helper-checkpoint:" + clientAddress(r)) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	var in helperAuthorizationRequest
	if readJSON(r, &in) != nil || len(in.Task) == 0 || len(in.Task) > 64*1024 || len(in.LeaseID) != 32 {
		http.Error(w, "invalid helper authorization", http.StatusBadRequest)
		return
	}
	var envelope statusTaskEnvelope
	if _, err := protocol.CanonicalV2TaskBytes(in.Task); err != nil || json.Unmarshal(in.Task, &envelope) != nil || envelope.Operation != "core.status" {
		http.Error(w, "helper authorization denied", http.StatusForbidden)
		return
	}
	now := runtime.Now().UTC()
	previous, err := runtime.Store.ValidateLease(envelope.NodeID, envelope.TaskID, envelope.Sequence, in.LeaseID, in.Task, now, runtime.KeyID, runtime.PublicKey)
	if err != nil {
		http.Error(w, "helper authorization denied", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"server_time": now.Format(time.RFC3339Nano), "previous_sequence": previous})
}

func validStatusAck(core, status string, result json.RawMessage, now time.Time) bool {
	switch status {
	case "ACK_ACCEPTED", "RUNNING", "VERIFYING":
		return len(result) == 0 || string(result) == "null"
	case "SUCCEEDED":
		var observed statusResult
		if !decodeExactResult(result, &observed) || observed.Core != core || !validStatusToken(observed.LoadState) || !validStatusToken(observed.ActiveState) || !validStatusToken(observed.SubState) {
			return false
		}
		at, err := time.Parse(time.RFC3339, observed.ObservedAt)
		return err == nil && !at.After(now.Add(30*time.Second))
	case "FAILED", "EXPIRED", "CANCELED", "NEEDS_RECONCILIATION":
		var failure statusFailure
		if !decodeExactResult(result, &failure) {
			return false
		}
		switch failure.ErrorCode {
		case "task_expired", "task_canceled", "helper_unavailable", "status_unavailable", "reconciliation_required":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func decodeExactResult(raw json.RawMessage, dst any) bool {
	if len(raw) == 0 || len(raw) > taskdispatch.MaxResultBytes || !json.Valid(raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return false
	}
	var trailing any
	return decoder.Decode(&trailing) == io.EOF
}

func validStatusToken(value string) bool {
	return len(value) > 0 && statusTokenPattern.MatchString(value)
}
