package master

import (
	"net/http"

	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

func (s *Server) deleteXrayClient(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.xrayClientAuth(w, r)
	if !ok {
		return
	}
	var in struct {
		Revision int64  `json:"revision"`
		MFACode  string `json:"mfa_code"`
	}
	username := r.PathValue("user")
	if readJSON(r, &in) != nil || !xrayconfig.ValidUsername(username) || in.Revision < 1 {
		http.Error(w, "invalid client deletion", http.StatusBadRequest)
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
	err = s.store.Update(func(st *store.State) error {
		client, exists := st.XrayClients[username]
		if !exists {
			return store.ErrNotFound
		}
		if client.Revision != in.Revision {
			return errClientRevision
		}
		removals := make(map[string][]store.XrayBinding)
		for _, binding := range client.Bindings {
			if _, exists := st.Nodes[binding.NodeID]; !exists {
				continue
			}
			if !s.panelXrayScope(st, lifecycleauth.Proposal{NodeID: binding.NodeID, RequesterID: ctx.Admin.ID}) {
				return store.ErrNotFound
			}
			removals[binding.NodeID] = append(removals[binding.NodeID], binding.XrayBinding)
		}
		for nodeID, bindings := range removals {
			if err := stageClientBindings(st, nodeID, nil, bindings, nil, now); err != nil {
				return err
			}
		}
		delete(st.XrayClients, username)
		s.auditXrayClient(st, ctx.Admin.ID, username, "delete", now)
		return nil
	})
	writeXrayClientResult(w, r, err, http.StatusOK)
}
