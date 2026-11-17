package master

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ACnoway/mcui/internal/protocol"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/taskdispatch"
)

var ErrTaskAuditReconciliation = errors.New("task and audit databases require reconciliation")

// ReconcileTaskRuntime checks the task database against the separately
// committed authorization/audit database before task APIs are served. A task
// without its authorization record, or an issued audit without its task, is a
// rollback or consistency failure and prevents startup. A task whose durable
// authorization exists but whose post-issue audit was interrupted gets a
// recovery audit entry.
func (s *Server) ReconcileTaskRuntime() error {
	if s == nil || s.store == nil || s.taskRuntime == nil || s.taskRuntime.Store == nil {
		return ErrTaskAuditReconciliation
	}
	refs, err := s.taskRuntime.Store.ListTaskReferences()
	if err != nil {
		return fmt.Errorf("%w: read task history: %v", ErrTaskAuditReconciliation, err)
	}
	var audits []store.Audit
	if err = s.store.View(func(state store.State) error {
		audits = append([]store.Audit(nil), state.Audits...)
		return nil
	}); err != nil {
		return fmt.Errorf("%w: read audit history: %v", ErrTaskAuditReconciliation, err)
	}

	authorizations := make(map[string]store.Audit)
	voidAuthorizations := make(map[string]store.Audit)
	issued := make(map[string]bool)
	issueFailed := make(map[string]bool)
	voidIssued := make(map[string]bool)
	voidIssueFailed := make(map[string]bool)
	for _, event := range audits {
		if event.ResourceType != "task" {
			continue
		}
		switch event.Action {
		case "task.status.authorize":
			if event.Outcome != "authorized" || event.Resource == "" {
				continue
			}
			if previous, ok := authorizations[event.Resource]; ok && (previous.Actor != event.Actor || previous.NodeID != event.NodeID || (previous.Detail != "" && event.Detail != "" && previous.Detail != event.Detail)) {
				return fmt.Errorf("%w: conflicting authorization for %q", ErrTaskAuditReconciliation, event.Resource)
			}
			authorizations[event.Resource] = event
		case "task.status.void.authorize":
			if event.Resource == "" || event.Actor == "" || event.NodeID == "" || event.Outcome == "" {
				continue
			}
			voidAuthorizations[event.Resource] = event
		case "task.status.issue":
			if event.Resource == "" {
				continue
			}
			if event.Outcome == "issued" || event.Outcome == "issued-recovered" {
				issued[event.Resource] = true
			} else if event.Outcome == "failed" {
				issueFailed[event.Resource] = true
			}
		case "task.status.void.issue":
			if event.Resource == "" {
				continue
			}
			if event.Outcome == "voided" || event.Outcome == "voided-recovered" {
				voidIssued[event.Resource] = true
			} else if event.Outcome == "failed" {
				voidIssueFailed[event.Resource] = true
			}
		}
	}

	seen := make(map[string]taskdispatch.TaskReference, len(refs))
	for _, ref := range refs {
		var body statusTaskEnvelope
		if ref.TaskID == "" || ref.NodeID == "" || ref.Sequence < 1 || protocol.VerifyV2Task(ref.Raw, s.taskRuntime.PublicKey) != nil || json.Unmarshal(ref.Raw, &body) != nil || body.TaskID != ref.TaskID || body.NodeID != ref.NodeID || body.Sequence != ref.Sequence || body.Operation != "core.status" {
			return fmt.Errorf("%w: invalid signed task record %q", ErrTaskAuditReconciliation, ref.TaskID)
		}
		auth, ok := authorizations[ref.TaskID]
		if !ok || auth.NodeID != ref.NodeID || (auth.Detail != "" && auth.Detail != body.Payload.Core) {
			return fmt.Errorf("%w: task %q has no matching authorization", ErrTaskAuditReconciliation, ref.TaskID)
		}
		seen[ref.TaskID] = ref
		if issueFailed[ref.TaskID] {
			return fmt.Errorf("%w: task %q has a failed issue audit", ErrTaskAuditReconciliation, ref.TaskID)
		}
		if !issued[ref.TaskID] {
			if err = s.recoverTaskIssueAudit(ref.TaskID, ref.NodeID, auth.Actor); err != nil {
				return err
			}
		}
		isVoidControl := false
		if ref.ControlKind == string(protocol.Skip) {
			var fields struct {
				NodeID    string `json:"node_id"`
				Sequence  uint64 `json:"sequence"`
				Reason    string `json:"reason"`
				KeyID     string `json:"signing_key_id"`
				ExpiresAt string `json:"expires_at"`
			}
			if protocol.Verify(protocol.Skip, ref.ControlRaw, s.taskRuntime.PublicKey) != nil || json.Unmarshal(ref.ControlRaw, &fields) != nil || fields.NodeID != ref.NodeID || fields.Sequence != uint64(ref.Sequence) || fields.KeyID != s.taskRuntime.KeyID || fields.ExpiresAt == "" || (fields.Reason != "VOID_UNISSUED" && fields.Reason != "EXPIRED") {
				return fmt.Errorf("%w: task %q has an invalid skip control", ErrTaskAuditReconciliation, ref.TaskID)
			}
			isVoidControl = fields.Reason == "VOID_UNISSUED"
		}
		if isVoidControl || voidIssued[ref.TaskID] {
			action, hasAction := voidAuthorizations[ref.TaskID]
			if !hasAction || action.NodeID != ref.NodeID {
				return fmt.Errorf("%w: voided task %q has no matching authorization", ErrTaskAuditReconciliation, ref.TaskID)
			}
			if voidIssueFailed[ref.TaskID] {
				return fmt.Errorf("%w: task %q has a failed void audit", ErrTaskAuditReconciliation, ref.TaskID)
			}
			if isVoidControl && (ref.Active || ref.LastStatus != "") {
				return fmt.Errorf("%w: task %q has an invalid unacknowledged void state", ErrTaskAuditReconciliation, ref.TaskID)
			}
			if !isVoidControl && ref.LastStatus != "CANCELED" {
				return fmt.Errorf("%w: task %q has no persisted void state", ErrTaskAuditReconciliation, ref.TaskID)
			}
			if !voidIssued[ref.TaskID] {
				if err = s.recoverTaskVoidAudit(ref.TaskID, ref.NodeID, action.Actor); err != nil {
					return err
				}
			}
		}
	}
	for taskID := range issued {
		if _, ok := seen[taskID]; !ok {
			return fmt.Errorf("%w: issued audit for %q has no task record", ErrTaskAuditReconciliation, taskID)
		}
	}
	for taskID := range voidIssued {
		if _, ok := seen[taskID]; !ok {
			return fmt.Errorf("%w: void audit for %q has no task record", ErrTaskAuditReconciliation, taskID)
		}
	}
	return nil
}

func (s *Server) recoverTaskIssueAudit(taskID, nodeID, actor string) error {
	now, err := s.taskRuntime.currentTime()
	if err != nil {
		return fmt.Errorf("%w: trusted clock unavailable during audit recovery", ErrTaskAuditReconciliation)
	}
	return s.store.Update(func(state *store.State) error {
		var authorization *store.Audit
		for i := range state.Audits {
			event := &state.Audits[i]
			if event.Action == "task.status.authorize" && event.ResourceType == "task" && event.Resource == taskID {
				if event.Actor != actor || event.NodeID != nodeID || event.Outcome != "authorized" {
					return ErrTaskAuditReconciliation
				}
				authorization = event
			}
			if event.Action == "task.status.issue" && event.ResourceType == "task" && event.Resource == taskID && event.Outcome == "issued" {
				return nil
			}
		}
		if authorization == nil {
			return ErrTaskAuditReconciliation
		}
		s.appendAudit(state, store.Audit{At: now.Unix(), Actor: actor, Action: "task.status.issue", ResourceType: "task", Resource: taskID, NodeID: nodeID, Outcome: "issued-recovered"})
		return nil
	})
}

func (s *Server) recoverTaskVoidAudit(taskID, nodeID, actor string) error {
	now, err := s.taskRuntime.currentTime()
	if err != nil {
		return fmt.Errorf("%w: trusted clock unavailable during void audit recovery", ErrTaskAuditReconciliation)
	}
	return s.store.Update(func(state *store.State) error {
		var authorization *store.Audit
		for i := range state.Audits {
			event := &state.Audits[i]
			if event.Action == "task.status.void.authorize" && event.ResourceType == "task" && event.Resource == taskID {
				if event.Actor == actor && event.NodeID == nodeID {
					authorization = event
				}
			}
			if event.Action == "task.status.void.issue" && event.ResourceType == "task" && event.Resource == taskID && (event.Outcome == "voided" || event.Outcome == "voided-recovered") {
				return nil
			}
		}
		if authorization == nil {
			return ErrTaskAuditReconciliation
		}
		s.appendAudit(state, store.Audit{At: now.Unix(), Actor: actor, Action: "task.status.void.issue", ResourceType: "task", Resource: taskID, NodeID: nodeID, Outcome: "voided-recovered"})
		return nil
	})
}
