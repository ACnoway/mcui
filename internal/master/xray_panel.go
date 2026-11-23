package master

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/taskdispatch"
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

type panelXraySigner interface {
	Manifest(context.Context) (artifacttrust.Manifest, error)
	Issue(context.Context, lifecycleauth.Proposal) ([]byte, error)
}

func (s *Server) ConfigurePanelXray(client panelXraySigner) error {
	if !s.singleAdmin || client == nil || s.taskRuntime == nil ||
		s.taskRuntime.TrustedNow == nil || !s.taskRuntime.XrayInstallPolicy.HasPanelScope() {
		return errors.New("panel Xray requires single-admin mode, trusted time and a configured lifecycle signer with panel scope")
	}
	s.xrayPanel = client
	return nil
}

func (s *Server) canManagePanelXray(a store.Admin) bool {
	return s.xrayPanel != nil && s.singleAdmin && a.Role == "security_admin" && a.AllNodes && !a.Disabled && !a.SetupPending
}

func (s *Server) panelXrayScope(st *store.State, p lifecycleauth.Proposal) bool {
	node, ok := st.Nodes[p.NodeID]
	admin := st.Admins[p.RequesterID]
	return ok && !node.Disabled && node.Enrolled && node.TokenHash != "" && s.canManagePanelXray(admin) &&
		canManageNode(admin, node) && s.taskRuntime.XrayInstallPolicy.AllowsPanelNode(node.ID)
}

type panelXrayRequest struct {
	TaskID         string `json:"task_id"`
	Operation      string `json:"operation"`
	Version        string `json:"version"`
	State          string `json:"state"`
	CatalogVersion int64  `json:"catalog_version"`
	Confirm        string `json:"confirm_operation"`
	MFACode        string `json:"mfa_code"`
}

func (in panelXrayRequest) intent() string {
	in.MFACode = ""
	raw, _ := json.Marshal(in)
	return hash(string(raw))
}

func (in panelXrayRequest) schema() int {
	switch in.Operation {
	case "core.install":
		return lifecycleauth.SignedManifestProposalVersion
	case "core.start", "core.stop":
		return lifecycleauth.ControlProposalVersion
	case "core.upgrade", "core.downgrade", "core.uninstall":
		return lifecycleauth.ChangeProposalVersion
	case xrayconfig.Operation:
		return lifecycleauth.ConfigProposalVersion
	default:
		return 0
	}
}

func (in panelXrayRequest) dangerous() bool {
	return in.Operation == "core.downgrade" || in.Operation == "core.uninstall" || in.Operation == xrayconfig.Operation
}

func (s *Server) panelXrayAuth(w http.ResponseWriter, r *http.Request, in *panelXrayRequest) (adminContext, bool) {
	if !secureRequest(r) || s.xrayPanel == nil {
		http.NotFound(w, r)
		return adminContext{}, false
	}
	ctx, ok := s.adminAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return ctx, false
	}
	if !s.canManagePanelXray(ctx.Admin) || !s.taskRuntime.XrayInstallPolicy.AllowsPanelNode(r.PathValue("node")) {
		http.NotFound(w, r)
		return ctx, false
	}
	if in != nil {
		if !csrfOK(r, ctx) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return ctx, false
		}
		if (in.dangerous() && !validTOTP(ctx.Admin.TOTPSecret, in.MFACode, time.Now())) || !s.stepUp(ctx, in.MFACode) {
			http.Error(w, "MFA re-verification required", http.StatusPreconditionRequired)
			return ctx, false
		}
	}
	return ctx, true
}

var errXrayInventory = errors.New("node Xray inventory is unavailable or has changed")

func panelInventory(node store.Node, now time.Time) (lifecycleauth.NodeInventory, string, error) {
	i := node.Inventory
	if node.LastSeen < now.Add(-90*time.Second).Unix() || node.LastSeen > now.Add(5*time.Second).Unix() ||
		i == nil || !i.Valid() || i.Xray == nil {
		return lifecycleauth.NodeInventory{}, "", errXrayInventory
	}
	raw, _ := json.Marshal(i)
	return *i, hash(node.ID + ":" + string(raw) + ":" + node.XrayDraft), nil
}

func xrayDraftPreviewed(i *lifecycleauth.XrayInventory, draft string) bool {
	return i.Catalog != nil && draft != "" && i.Preview == xrayconfig.PlanDigest(draft)
}

func xrayCandidate(i *lifecycleauth.XrayInventory, draft string) bool {
	return i.Candidate.Valid() && i.Candidate != i.Config && (i.Catalog == nil || xrayDraftPreviewed(i, draft))
}

func (s *Server) savePanelXrayDraft(w http.ResponseWriter, r *http.Request) {
	var in struct {
		State string          `json:"state"`
		Plan  xrayconfig.Plan `json:"plan"`
	}
	if readJSON(r, &in) != nil || len(in.State) != 64 || !in.Plan.Valid() {
		http.Error(w, "invalid Xray inbound draft", http.StatusBadRequest)
		return
	}
	s.withTaskHTTP(w, r, func(w http.ResponseWriter) {
		ctx, ok := s.panelXrayAuth(w, r, nil)
		if !ok {
			return
		}
		if !csrfOK(r, ctx) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		now, err := s.taskRuntime.currentTime()
		if err != nil {
			http.Error(w, "trusted task clock unavailable", http.StatusServiceUnavailable)
			return
		}
		err = s.store.Update(func(st *store.State) error {
			p := lifecycleauth.Proposal{NodeID: r.PathValue("node"), RequesterID: ctx.Admin.ID}
			if !s.panelXrayScope(st, p) {
				return errXrayInstallScope
			}
			node := st.Nodes[p.NodeID]
			inventory, fingerprint, err := panelInventory(node, now)
			if err != nil || inventory.Xray.Catalog == nil || !inventory.Xray.Catalog.Allows(in.Plan) {
				return errXrayInventory
			}
			draft := in.Plan.Encode()
			if draft == node.XrayDraft {
				return nil
			}
			if fingerprint != in.State {
				return errXrayInventory
			}
			for _, record := range st.XrayInstalls {
				if !record.Panel || record.Dispatched {
					continue
				}
				prior, err := lifecycleauth.ParseProposal(record.Proposal)
				if err != nil {
					return err
				}
				if prior.NodeID == p.NodeID && prior.Operation == xrayconfig.Operation && prior.ExpiresAt > now.Unix() {
					return errXrayInstallReserved
				}
			}
			node.XrayDraft = draft
			st.Nodes[p.NodeID] = node
			s.appendAudit(st, store.Audit{At: now.Unix(), Actor: p.RequesterID, Action: "xray.config.draft",
				ResourceType: "node", Resource: p.NodeID, NodeID: p.NodeID, Outcome: "saved"})
			return nil
		})
		if err != nil {
			writePanelXrayError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
	})
}

func (s *Server) panelXrayOptions(w http.ResponseWriter, r *http.Request) {
	var inventory lifecycleauth.NodeInventory
	var fingerprint string
	var draft string
	if !s.withTaskHTTP(w, r, func(w http.ResponseWriter) {
		ctx, ok := s.panelXrayAuth(w, r, nil)
		if !ok {
			return
		}
		now, err := s.taskRuntime.currentTime()
		if err != nil {
			http.Error(w, "trusted task clock unavailable", http.StatusServiceUnavailable)
			return
		}
		err = s.store.View(func(st store.State) error {
			p := lifecycleauth.Proposal{NodeID: r.PathValue("node"), RequesterID: ctx.Admin.ID}
			if !s.panelXrayScope(&st, p) {
				return errXrayInstallScope
			}
			var err error
			node := st.Nodes[p.NodeID]
			draft = node.XrayDraft
			inventory, fingerprint, err = panelInventory(node, now)
			return err
		})
		if err != nil {
			writePanelXrayError(w, r, err)
		}
	}) || fingerprint == "" {
		return
	}
	manifest, err := s.xrayPanel.Manifest(r.Context())
	versions := []string{}
	configReady := false
	if err == nil {
		for _, a := range manifest.Artifacts {
			if a.Component == "xray" && a.Architecture == inventory.Architecture {
				versions = append(versions, a.Version)
				if a.Version == inventory.Xray.Version && a.SHA256 == inventory.Xray.SHA256 && xrayCandidate(inventory.Xray, draft) {
					configReady = true
				}
			}
		}
		sort.Slice(versions, func(i, j int) bool { return corecatalog.CompareXrayVersions(versions[i], versions[j]) > 0 })
	}
	plan, _ := xrayconfig.ParsePlan(draft)
	writeJSON(w, http.StatusOK, map[string]any{
		"architecture": inventory.Architecture, "current": inventory.Xray, "state": fingerprint,
		"versions": versions, "catalog_version": manifest.ManifestVersion,
		"config_ready":    configReady,
		"draft":           plan,
		"draft_previewed": xrayDraftPreviewed(inventory.Xray, draft),
	})
}

func (s *Server) panelXrayOperation(w http.ResponseWriter, r *http.Request) {
	var in panelXrayRequest
	err := readJSON(r, &in)
	control := lifecycleauth.IsControlOperation(in.Operation)
	if err != nil || !validRequestID(in.TaskID) || len(in.State) != 64 || in.schema() == 0 ||
		(in.dangerous() && in.Confirm != in.Operation) ||
		(control && (in.Version != "" || in.CatalogVersion != 0)) ||
		(!control && (in.Version == "" || in.CatalogVersion < 1)) {
		http.Error(w, "invalid or unconfirmed Xray request", http.StatusBadRequest)
		return
	}
	var p lifecycleauth.Proposal
	var prior store.XrayInstall
	var ready bool
	if !s.withTaskHTTP(w, r, func(w http.ResponseWriter) {
		ctx, ok := s.panelXrayAuth(w, r, &in)
		if !ok {
			return
		}
		p = lifecycleauth.Proposal{NodeID: r.PathValue("node"), TaskID: in.TaskID, RequesterID: ctx.Admin.ID}
		err = s.store.View(func(st store.State) error {
			if !s.panelXrayScope(&st, p) {
				return errXrayInstallScope
			}
			prior = st.XrayInstalls[p.TaskID]
			if len(prior.Proposal) == 0 {
				return nil
			}
			old, err := lifecycleauth.ParseProposal(prior.Proposal)
			if err != nil || !prior.Panel || prior.Intent != in.intent() || old.NodeID != p.NodeID || old.RequesterID != p.RequesterID {
				return errXrayInstallReserved
			}
			p = old
			return nil
		})
		if err != nil {
			writePanelXrayError(w, r, err)
			return
		}
		if len(prior.SignedTask) > 0 {
			existing, err := s.taskRuntime.Store.GetRecord(p.TaskID)
			if err == nil && bytes.Equal(existing.Raw, prior.SignedTask) {
				if !prior.Dispatched {
					if err := s.markPanelXrayDispatched(p, time.Now()); err != nil {
						writePanelXrayError(w, r, err)
						return
					}
				}
				writeJSON(w, http.StatusOK, s.taskRecordView(existing))
				return
			}
			if !errors.Is(err, taskdispatch.ErrNotFound) {
				writePanelXrayError(w, r, errXrayInstallReserved)
				return
			}
		}
		ready = true
	}) || !ready {
		return
	}

	if len(prior.Proposal) == 0 {
		var manifest artifacttrust.Manifest
		if !control {
			manifest, err = s.xrayPanel.Manifest(r.Context())
			if err != nil || manifest.ManifestVersion != in.CatalogVersion {
				http.Error(w, "verified release list changed or is unavailable", http.StatusConflict)
				return
			}
		}
		ready = false
		if !s.withTaskHTTP(w, r, func(w http.ResponseWriter) {
			ctx, ok := s.panelXrayAuth(w, r, &in)
			if !ok {
				return
			}
			if ctx.Admin.ID != p.RequesterID {
				http.NotFound(w, r)
				return
			}
			if err := s.reservePanelXray(&p, in, manifest); err != nil {
				writePanelXrayError(w, r, err)
				return
			}
			ready = true
		}) || !ready {
			return
		}
	}

	raw := prior.SignedTask
	if len(raw) == 0 {
		raw, err = s.xrayPanel.Issue(r.Context(), p)
		if err != nil {
			http.Error(w, "Xray signing unavailable; retry the same request", http.StatusServiceUnavailable)
			return
		}
	}
	s.withTaskHTTP(w, r, func(w http.ResponseWriter) {
		ctx, ok := s.panelXrayAuth(w, r, &in)
		if !ok {
			return
		}
		if ctx.Admin.ID != p.RequesterID {
			http.NotFound(w, r)
			return
		}
		record, err := s.dispatchPanelXray(p, in, raw)
		if err != nil {
			writePanelXrayError(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, s.taskRecordView(record))
	})
}

func (s *Server) reservePanelXray(p *lifecycleauth.Proposal, in panelXrayRequest, manifest artifacttrust.Manifest) error {
	now, err := s.taskRuntime.currentTime()
	if err != nil {
		return err
	}
	return s.store.Update(func(st *store.State) error {
		if !s.panelXrayScope(st, *p) {
			return errXrayInstallScope
		}
		if saved, exists := st.XrayInstalls[p.TaskID]; exists {
			prior, err := lifecycleauth.ParseProposal(saved.Proposal)
			if err != nil || !saved.Panel || saved.Intent != in.intent() || prior.RequesterID != p.RequesterID || prior.NodeID != p.NodeID {
				return errXrayInstallReserved
			}
			*p = prior
			return nil
		}
		node := st.Nodes[p.NodeID]
		i, fingerprint, err := panelInventory(node, now)
		if err != nil || fingerprint != in.State {
			return errXrayInventory
		}
		if runtimeUpdateReserved(st, p.NodeID, now) {
			return errRuntimeBusy
		}
		if _, err := s.taskRuntime.Store.GetRecord(p.TaskID); !errors.Is(err, taskdispatch.ErrNotFound) {
			if err != nil {
				return err
			}
			return errXrayInstallReserved
		}
		p.Sequence, err = s.taskRuntime.Store.NextIdleSequence(p.NodeID)
		if err != nil {
			return err
		}
		for _, record := range st.XrayInstalls {
			prior, err := lifecycleauth.ParseProposal(record.Proposal)
			if err != nil {
				return err
			}
			if prior.NodeID == p.NodeID && prior.Sequence == p.Sequence {
				return errXrayInstallReserved
			}
		}
		p.Operation, p.Core, p.SchemaVersion = in.Operation, "xray", in.schema()
		p.Architecture = i.Architecture
		p.SigningKeyID = s.taskRuntime.XrayInstallPolicy.SigningKeyID()
		p.CreatedAt, p.ExpiresAt = now.Unix(), now.Add(10*time.Minute).Unix()
		installed := i.Xray.Version != ""
		if installed == (p.Operation == "core.install") {
			return errXrayInventory
		}
		if lifecycleauth.IsControlOperation(p.Operation) {
			p.Version, p.SHA256 = i.Xray.Version, i.Xray.SHA256
		} else {
			if !now.Before(manifest.ExpiresAt) {
				return lifecycleauth.ErrDenied
			}
			for _, a := range manifest.Artifacts {
				if a.Component == "xray" && a.Architecture == i.Architecture && a.Version == in.Version {
					p.Version, p.SHA256, p.ManifestVersion = a.Version, a.SHA256, manifest.ManifestVersion
					break
				}
			}
			if lifecycleauth.IsVersionChange(p.Operation) {
				p.CurrentVersion, p.CurrentSHA256 = i.Xray.Version, i.Xray.SHA256
			}
			if p.Operation == xrayconfig.Operation {
				if p.Version != i.Xray.Version || p.SHA256 != i.Xray.SHA256 || !xrayCandidate(i.Xray, node.XrayDraft) ||
					p.Sequence <= i.Xray.ConfigRevision {
					return errXrayInventory
				}
				p.Config = i.Xray.Candidate
				if i.Xray.Catalog != nil {
					p.Plan = node.XrayDraft
				}
			}
		}
		if _, _, err := s.taskRuntime.XrayInstallPolicy.PanelEvidence(*p); err != nil {
			return err
		}
		raw, err := json.Marshal(p)
		if err != nil {
			return err
		}
		st.XrayInstalls[p.TaskID] = store.XrayInstall{Proposal: raw, Panel: true, Intent: in.intent()}
		s.appendAudit(st, store.Audit{At: now.Unix(), Actor: p.RequesterID, Action: xrayTaskAudit(p.Operation, "reserve"),
			ResourceType: "task", Resource: p.TaskID, NodeID: p.NodeID, Outcome: "reserved"})
		return nil
	})
}

func (s *Server) dispatchPanelXray(p lifecycleauth.Proposal, in panelXrayRequest, raw []byte) (taskdispatch.Record, error) {
	policy := s.taskRuntime.XrayInstallPolicy
	task, err := policy.VerifyPanelTask(p, raw)
	if err != nil {
		return taskdispatch.Record{}, err
	}
	now, err := s.taskRuntime.currentTime()
	if err != nil {
		return taskdispatch.Record{}, err
	}
	err = s.store.Update(func(st *store.State) error {
		r := st.XrayInstalls[p.TaskID]
		old, err := lifecycleauth.ParseProposal(r.Proposal)
		if err != nil || !r.Panel || r.Intent != in.intent() || old != p || !s.panelXrayScope(st, p) {
			return errXrayInstallScope
		}
		if len(r.SignedTask) != 0 && !bytes.Equal(r.SignedTask, raw) {
			return errXrayInstallReserved
		}
		if r.Dispatched {
			return nil
		}
		if _, state, err := panelInventory(st.Nodes[p.NodeID], now); err != nil || state != in.State {
			return errXrayInventory
		}
		if runtimeUpdateReserved(st, p.NodeID, now) {
			return errRuntimeBusy
		}
		if !task.ActiveAt(now) {
			return errXrayInstallReserved
		}
		if len(r.SignedTask) == 0 {
			r.ApprovalID, r.SignedTask = task.ApprovalID, raw
			st.XrayInstalls[p.TaskID] = r
			s.appendAudit(st, store.Audit{At: now.Unix(), Actor: p.RequesterID, Action: xrayTaskAudit(p.Operation, "verify"),
				ResourceType: "task", Resource: p.TaskID, NodeID: p.NodeID, Detail: task.ApprovalID, Outcome: "signature-verified"})
		}
		return nil
	})
	if err != nil {
		return taskdispatch.Record{}, err
	}
	current, err := s.taskRuntime.Store.GetRecord(p.TaskID)
	if errors.Is(err, taskdispatch.ErrNotFound) {
		if err := s.taskRuntime.Store.ProvisionInstall(raw, policy.InstallKey(), now); err != nil {
			return taskdispatch.Record{}, err
		}
		current, err = s.taskRuntime.Store.GetRecord(p.TaskID)
	}
	if err != nil || !bytes.Equal(current.Raw, raw) {
		return taskdispatch.Record{}, errXrayInstallReserved
	}
	return current, s.markPanelXrayDispatched(p, now)
}

func (s *Server) markPanelXrayDispatched(p lifecycleauth.Proposal, now time.Time) error {
	return s.store.Update(func(st *store.State) error {
		record := st.XrayInstalls[p.TaskID]
		if !record.Dispatched {
			record.Dispatched = true
			st.XrayInstalls[p.TaskID] = record
			s.appendAudit(st, store.Audit{At: now.Unix(), Actor: p.RequesterID, Action: xrayTaskAudit(p.Operation, "dispatch"),
				ResourceType: "task", Resource: p.TaskID, NodeID: p.NodeID, Outcome: "queued"})
		}
		return nil
	})
}

func writePanelXrayError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errXrayInventory) {
		http.Error(w, errXrayInventory.Error(), http.StatusConflict)
		return
	}
	writeXrayInstallError(w, r, err)
}
