package master

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/taskdispatch"
)

var errXrayInstallReserved = errors.New("Xray install sequence or task ID is reserved")
var errXrayInstallScope = errors.New("Xray install outside current scope")

type xrayInstallRequest struct {
	TaskID          string `json:"task_id"`
	NodeID          string `json:"node_id"`
	Operation       string `json:"operation"`
	Version         string `json:"version"`
	Architecture    string `json:"architecture"`
	SHA256          string `json:"sha256"`
	ManifestVersion int64  `json:"manifest_version"`
	CurrentVersion  string `json:"current_version"`
	CurrentSHA256   string `json:"current_sha256"`
	MFACode         string `json:"mfa_code"`
}

type xrayInstallView struct {
	Proposal json.RawMessage `json:"proposal"`
	Status   string          `json:"status"`
}

func xrayInstallState(record store.XrayInstall, p lifecycleauth.Proposal, now time.Time) xrayInstallView {
	view := xrayInstallView{Proposal: record.Proposal, Status: "AWAITING_SIGNATURE"}
	if p.SchemaVersion == 1 {
		view.Status = "LEGACY"
	} else if now.Unix() >= p.ExpiresAt {
		view.Status = "EXPIRED"
	} else if len(record.SignedTask) > 0 {
		view.Status = "SIGNED_TASK_VERIFIED"
	}
	return view
}

func (s *Server) xrayInstallAccess(w http.ResponseWriter, r *http.Request) (adminContext, *lifecycleauth.Policy, bool) {
	var ctx adminContext
	var ok bool
	if r.Method == http.MethodGet {
		ctx, ok = s.adminAuth(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return ctx, nil, false
		}
	} else {
		ctx, ok = s.requireCSRF(w, r)
		if !ok {
			return ctx, nil, false
		}
	}
	if ctx.Admin.Role != "operator" && !(r.Method == http.MethodGet && s.canManagePanelXray(ctx.Admin)) {
		http.NotFound(w, r)
		return ctx, nil, false
	}
	if !secureRequest(r) || s.taskRuntime == nil || s.taskRuntime.XrayInstallPolicy == nil {
		http.Error(w, "Xray install requires HTTPS and a configured task runtime and authorization policy", http.StatusServiceUnavailable)
		return ctx, nil, false
	}
	return ctx, s.taskRuntime.XrayInstallPolicy, true
}

func canPrepareXrayInstall(st *store.State, p lifecycleauth.Proposal) bool {
	node, ok := st.Nodes[p.NodeID]
	if !ok || node.Disabled || !node.Enrolled || node.TokenHash == "" {
		return false
	}
	operator := st.Admins[p.RequesterID]
	return operator.Role == "operator" && canReadNode(operator, node)
}

func (s *Server) createXrayInstall(w http.ResponseWriter, r *http.Request) {
	s.nodeAccess.RLock()
	defer s.nodeAccess.RUnlock()
	ctx, policy, ok := s.xrayInstallAccess(w, r)
	if !ok {
		return
	}
	var in xrayInstallRequest
	if readJSON(r, &in) != nil || !validRequestID(in.TaskID) {
		http.Error(w, "invalid Xray install proposal", http.StatusBadRequest)
		return
	}
	schema := lifecycleauth.OfficialReleaseProposalVersion
	switch in.Operation {
	case "", "core.install":
		in.Operation = "core.install"
	case "core.start", "core.stop":
		schema = lifecycleauth.ControlProposalVersion
		if in.ManifestVersion != 0 {
			http.Error(w, "Xray control does not use a manifest version", http.StatusBadRequest)
			return
		}
	case "core.upgrade", "core.downgrade":
		schema = lifecycleauth.OfficialReleaseProposalVersion
	case "core.uninstall":
		schema = lifecycleauth.ChangeProposalVersion
	default:
		http.Error(w, "invalid Xray lifecycle operation", http.StatusBadRequest)
		return
	}
	if !s.stepUp(ctx, in.MFACode) {
		http.Error(w, "MFA re-verification required", http.StatusPreconditionRequired)
		return
	}
	now, err := s.taskRuntime.currentTime()
	if err != nil {
		http.Error(w, "trusted task clock unavailable", http.StatusServiceUnavailable)
		return
	}
	proposal := lifecycleauth.Proposal{
		SchemaVersion: schema, Core: "xray", Operation: in.Operation,
		TaskID: in.TaskID, NodeID: in.NodeID, RequesterID: ctx.Admin.ID,
		Version: in.Version, Architecture: in.Architecture, SHA256: in.SHA256, ManifestVersion: in.ManifestVersion,
		CurrentVersion: in.CurrentVersion, CurrentSHA256: in.CurrentSHA256,
		SigningKeyID: policy.SigningKeyID(), CreatedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
	}
	var record store.XrayInstall
	err = s.store.Update(func(st *store.State) error {
		if !canPrepareXrayInstall(st, proposal) {
			return errXrayInstallScope
		}
		if prior, exists := st.XrayInstalls[in.TaskID]; exists {
			if prior.Panel {
				return errXrayInstallReserved
			}
			old, err := lifecycleauth.ParseProposal(prior.Proposal)
			if err != nil {
				return err
			}
			proposal.Sequence, proposal.CreatedAt, proposal.ExpiresAt = old.Sequence, old.CreatedAt, old.ExpiresAt
			if proposal != old || !policy.AllowsProposal(old) {
				return errXrayInstallReserved
			}
			record = prior
			return nil
		}
		if _, err := s.taskRuntime.Store.GetRecord(in.TaskID); err == nil {
			return errXrayInstallReserved
		} else if !errors.Is(err, taskdispatch.ErrNotFound) {
			return err
		}
		if runtimeUpdateReserved(st, in.NodeID, now) {
			return errRuntimeBusy
		}
		for _, event := range st.Audits {
			if event.ResourceType == "task" && event.Resource == in.TaskID {
				return errXrayInstallReserved
			}
		}
		sequence, err := s.taskRuntime.Store.NextIdleSequence(in.NodeID)
		if err != nil {
			return err
		}
		proposal.Sequence = sequence
		if !policy.AllowsProposal(proposal) {
			return lifecycleauth.ErrDenied
		}
		for _, existing := range st.XrayInstalls {
			old, err := lifecycleauth.ParseProposal(existing.Proposal)
			if err != nil {
				return err
			}
			// An independent signer may have consumed an expired reservation.
			// A normal status task must take that slot before proposing again.
			if old.NodeID == proposal.NodeID && old.Sequence == sequence {
				return errXrayInstallReserved
			}
		}
		record.Proposal, err = json.Marshal(proposal)
		if err != nil {
			return err
		}
		st.XrayInstalls[proposal.TaskID] = record
		s.appendAudit(st, store.Audit{At: now.Unix(), Actor: ctx.Admin.ID, Action: xrayTaskAudit(proposal.Operation, "reserve"), ResourceType: "task", Resource: proposal.TaskID, NodeID: proposal.NodeID, Outcome: "reserved"})
		return nil
	})
	if err != nil {
		writeXrayInstallError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, xrayInstallState(record, proposal, now))
}

func (s *Server) recordSignedXrayInstall(w http.ResponseWriter, r *http.Request) {
	s.nodeAccess.RLock()
	defer s.nodeAccess.RUnlock()
	ctx, policy, ok := s.xrayInstallAccess(w, r)
	if !ok {
		return
	}
	var in struct {
		Request json.RawMessage `json:"request"`
		Task    json.RawMessage `json:"task"`
		MFACode string          `json:"mfa_code"`
	}
	if readJSON(r, &in) != nil || len(in.Task) == 0 || len(in.Task) > 16<<10 {
		http.Error(w, "invalid signed Xray install", http.StatusBadRequest)
		return
	}
	request, err := lifecycleauth.ParseRequest(in.Request)
	if err != nil {
		http.Error(w, "invalid signed Xray request", http.StatusBadRequest)
		return
	}
	p := request.Proposal
	if p.SchemaVersion < lifecycleauth.SignedManifestProposalVersion || p.TaskID != r.PathValue("id") || p.RequesterID != ctx.Admin.ID {
		http.NotFound(w, r)
		return
	}
	if !s.stepUp(ctx, in.MFACode) {
		http.Error(w, "MFA re-verification required", http.StatusPreconditionRequired)
		return
	}
	now, err := s.taskRuntime.currentTime()
	if err != nil {
		http.Error(w, "trusted task clock unavailable", http.StatusServiceUnavailable)
		return
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, in.Task); err != nil {
		http.Error(w, "invalid signed Xray install", http.StatusBadRequest)
		return
	}
	requestID, err := policy.VerifyIssuedTask(in.Task, request, now)
	if err != nil {
		http.Error(w, "Xray request or task signature is invalid or expired", http.StatusConflict)
		return
	}
	var record store.XrayInstall
	err = s.store.Update(func(st *store.State) error {
		var exists bool
		record, exists = st.XrayInstalls[p.TaskID]
		if !exists || record.Panel || !canPrepareXrayInstall(st, p) {
			return errXrayInstallScope
		}
		saved, err := lifecycleauth.ParseProposal(record.Proposal)
		if err != nil {
			return err
		}
		if saved != p {
			return errXrayInstallReserved
		}
		if len(record.SignedTask) > 0 {
			if record.ApprovalID != requestID || !bytes.Equal(record.SignedTask, compact.Bytes()) {
				return errXrayInstallReserved
			}
			return nil
		}
		record.ApprovalID = requestID
		record.SignedTask = compact.Bytes()
		st.XrayInstalls[p.TaskID] = record
		s.appendAudit(st, store.Audit{At: now.Unix(), Actor: ctx.Admin.ID, Action: xrayTaskAudit(p.Operation, "verify"), ResourceType: "task", Resource: p.TaskID, NodeID: p.NodeID, Detail: record.ApprovalID, Outcome: "signature-verified"})
		return nil
	})
	if err != nil {
		writeXrayInstallError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, xrayInstallState(record, p, now))
}

func (s *Server) dispatchXrayInstall(w http.ResponseWriter, r *http.Request) {
	s.nodeAccess.RLock()
	defer s.nodeAccess.RUnlock()
	ctx, policy, ok := s.xrayInstallAccess(w, r)
	if !ok {
		return
	}
	var in struct {
		MFACode          string `json:"mfa_code"`
		ConfirmOperation string `json:"confirm_operation"`
	}
	if readJSON(r, &in) != nil {
		http.Error(w, "invalid Xray dispatch request", http.StatusBadRequest)
		return
	}
	if !s.stepUp(ctx, in.MFACode) {
		http.Error(w, "MFA re-verification required", http.StatusPreconditionRequired)
		return
	}
	id := r.PathValue("id")
	record, err := s.readXrayDispatch(id, ctx.Admin.ID, policy)
	if err != nil {
		writeXrayInstallError(w, r, err)
		return
	}
	now, err := s.taskRuntime.currentTime()
	if err != nil {
		http.Error(w, "trusted task clock unavailable", http.StatusServiceUnavailable)
		return
	}
	task, err := s.verifyStoredXrayTask(record.SignedTask, true)
	if err != nil {
		writeXrayInstallError(w, r, err)
		return
	}
	if (task.Operation == "core.downgrade" || task.Operation == "core.uninstall") && in.ConfirmOperation != task.Operation {
		http.Error(w, "confirm the specific Xray downgrade or uninstall operation before dispatch", http.StatusBadRequest)
		return
	}
	if existing, err := s.taskRuntime.Store.GetRecord(id); err == nil && bytes.Equal(existing.Raw, record.SignedTask) {
		writeJSON(w, http.StatusOK, s.taskRecordView(existing))
		return
	}
	if !task.ActiveAt(now) {
		http.Error(w, "signed Xray install task expired or not yet valid", http.StatusConflict)
		return
	}
	if err := s.store.View(func(st store.State) error {
		if runtimeUpdateReserved(&st, task.NodeID, now) {
			return errRuntimeBusy
		}
		return nil
	}); err != nil {
		writeXrayInstallError(w, r, err)
		return
	}
	if err := s.taskRuntime.Store.ProvisionInstall(record.SignedTask, policy.InstallKey(), now); err != nil {
		writeXrayInstallError(w, r, err)
		return
	}
	if err := s.recordTaskAudit(ctx.Admin.ID, xrayTaskAudit(task.Operation, "dispatch"), task.TaskID, task.NodeID, "queued"); err != nil {
		http.Error(w, "Xray task audit unavailable", http.StatusInternalServerError)
		return
	}
	dispatched, err := s.taskRuntime.Store.GetRecord(id)
	if err != nil {
		writeXrayInstallError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.taskRecordView(dispatched))
}

func xrayTaskAudit(operation, event string) string {
	return "task.xray." + strings.TrimPrefix(operation, "core.") + "." + event
}

func (s *Server) readXrayDispatch(id, requester string, policy *lifecycleauth.Policy) (store.XrayInstall, error) {
	var record store.XrayInstall
	err := s.store.View(func(st store.State) error {
		var ok bool
		record, ok = st.XrayInstalls[id]
		if !ok || record.Panel {
			return errXrayInstallScope
		}
		p, err := lifecycleauth.ParseProposal(record.Proposal)
		if err != nil {
			return err
		}
		if p.SchemaVersion < 2 || p.RequesterID != requester || !canPrepareXrayInstall(&st, p) || !policy.AllowsProposal(p) {
			return errXrayInstallScope
		}
		if len(record.SignedTask) == 0 {
			return errXrayInstallReserved
		}
		return nil
	})
	return record, err
}

func (s *Server) verifyStoredXrayTask(raw []byte, requireCurrentScope bool) (lifecycleauth.InstallTask, error) {
	policy := s.taskRuntime.XrayInstallPolicy
	task, err := policy.InstallKey().Verify(raw)
	if err != nil {
		return lifecycleauth.InstallTask{}, err
	}
	err = s.store.View(func(st store.State) error {
		record, ok := st.XrayInstalls[task.TaskID]
		if !ok || !bytes.Equal(raw, record.SignedTask) {
			return errXrayInstallReserved
		}
		p, err := lifecycleauth.ParseProposal(record.Proposal)
		if err != nil || !task.Matches(p, record.ApprovalID) {
			return errXrayInstallReserved
		}
		if record.Panel {
			if _, err := policy.VerifyPanelTask(p, raw); err != nil {
				return err
			}
			if requireCurrentScope && !s.panelXrayScope(&st, p) {
				return errXrayInstallScope
			}
			return nil
		}
		if requireCurrentScope && (!policy.AllowsProposal(p) || !canPrepareXrayInstall(&st, p)) {
			return errXrayInstallScope
		}
		return nil
	})
	return task, err
}

func (s *Server) renewXrayInstallLease(w http.ResponseWriter, r *http.Request) {
	s.nodeAccess.RLock()
	defer s.nodeAccess.RUnlock()
	node, ok := s.authenticateNode(r)
	if !ok {
		http.Error(w, "node credential rejected", http.StatusUnauthorized)
		return
	}
	if s.taskRuntime == nil || s.taskRuntime.XrayInstallPolicy == nil {
		http.Error(w, "task runtime unavailable", http.StatusServiceUnavailable)
		return
	}
	var in helperAuthorizationRequest
	if readJSON(r, &in) != nil || len(in.LeaseID) != 32 {
		http.Error(w, "invalid Xray install lease", http.StatusBadRequest)
		return
	}
	task, err := s.verifyStoredXrayTask(in.Task, true)
	if err != nil || task.NodeID != node.ID {
		http.Error(w, "Xray install lease rejected", http.StatusForbidden)
		return
	}
	now, err := s.taskRuntime.currentTime()
	if err != nil {
		http.Error(w, "trusted task clock unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := s.taskRuntime.Store.RenewInstallLease(task, in.LeaseID, in.Task, now); err != nil {
		http.Error(w, "Xray install lease no longer active", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listXrayInstalls(w http.ResponseWriter, r *http.Request) {
	ctx, _, ok := s.xrayInstallAccess(w, r)
	if !ok {
		return
	}
	now, err := s.taskRuntime.currentTime()
	if err != nil {
		http.Error(w, "trusted task clock unavailable", http.StatusServiceUnavailable)
		return
	}
	nodeID := r.URL.Query().Get("node_id")
	type listed struct {
		view xrayInstallView
		p    lifecycleauth.Proposal
	}
	var matches []listed
	err = s.store.View(func(st store.State) error {
		node, exists := st.Nodes[nodeID]
		if !exists || !canReadNode(st.Admins[ctx.Admin.ID], node) {
			return errXrayInstallScope
		}
		for _, record := range st.XrayInstalls {
			p, err := lifecycleauth.ParseProposal(record.Proposal)
			if err != nil {
				return err
			}
			if p.NodeID == nodeID && p.RequesterID == ctx.Admin.ID {
				matches = append(matches, listed{xrayInstallState(record, p, now), p})
			}
		}
		return nil
	})
	if err != nil {
		writeXrayInstallError(w, r, err)
		return
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].p.Sequence > matches[j].p.Sequence })
	out := make([]xrayInstallView, 0, min(100, len(matches)))
	for _, match := range matches[:min(100, len(matches))] {
		out = append(out, match.view)
	}
	writeJSON(w, http.StatusOK, out)
}

func checkXrayInstallReservation(st *store.State, taskID, nodeID string, now int64) error {
	if _, exists := st.XrayInstalls[taskID]; exists {
		return errXrayInstallReserved
	}
	for _, record := range st.XrayInstalls {
		if record.Panel && record.Dispatched {
			continue
		}
		p, err := lifecycleauth.ParseProposal(record.Proposal)
		if err != nil {
			return err
		}
		if p.NodeID == nodeID && now < p.ExpiresAt {
			return errXrayInstallReserved
		}
	}
	return nil
}

func writeXrayInstallError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errRuntimeBusy):
		http.Error(w, "a runtime update reserves this node", http.StatusConflict)
	case errors.Is(err, errXrayInstallScope):
		http.NotFound(w, r)
	case errors.Is(err, lifecycleauth.ErrDenied):
		http.Error(w, "proposal parameters or authorization policy rejected", http.StatusBadRequest)
	case errors.Is(err, errXrayInstallReserved), errors.Is(err, taskdispatch.ErrConflict), errors.Is(err, taskdispatch.ErrSequence):
		http.Error(w, "task ID or node sequence is unavailable", http.StatusConflict)
	default:
		http.Error(w, "Xray install proposal store unavailable", http.StatusInternalServerError)
	}
}
