package master

import (
	"errors"
	"net/http"
	"time"

	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/xraytraffic"
)

func (s *Server) resetXrayTraffic(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Key       string            `json:"key"`
		Revision  int64             `json:"revision"`
		SampledAt int64             `json:"sampled_at"`
		Expected  xraytraffic.Bytes `json:"expected"`
		MFACode   string            `json:"mfa_code"`
	}
	if readJSON(r, &in) != nil || in.Revision <= 0 || in.SampledAt <= 0 || in.Expected == (xraytraffic.Bytes{}) ||
		!(xraytraffic.Sample{Revision: in.Revision, Epoch: hash("reset"), At: in.SampledAt,
			Counters: map[string]xraytraffic.Bytes{in.Key: in.Expected}}).Valid() {
		http.Error(w, "invalid traffic reset", http.StatusBadRequest)
		return
	}
	s.withTaskHTTP(w, r, func(w http.ResponseWriter) {
		admin, ok := s.panelXrayAuth(w, r, nil)
		if !ok {
			return
		}
		if !csrfOK(r, admin) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !s.stepUp(admin, in.MFACode) {
			http.Error(w, "MFA re-verification required", http.StatusPreconditionRequired)
			return
		}
		nodeID := r.PathValue("node")
		err := s.store.View(func(state store.State) error {
			if !s.panelXrayScope(&state, lifecycleauth.Proposal{NodeID: nodeID, RequesterID: admin.Admin.ID}) {
				return store.ErrNotFound
			}
			node := state.Nodes[nodeID]
			inventory, _, err := panelInventory(node, time.Now())
			if err != nil || !inventory.Xray.StatisticsActive || inventory.Xray.ConfigRevision != in.Revision {
				return store.ErrXrayTrafficChanged
			}
			return nil
		})
		if err == nil {
			err = s.store.ResetXrayTraffic(r.Context(), nodeID, admin.Admin.ID, in.Key, in.Revision, in.SampledAt, in.Expected)
		}
		switch {
		case errors.Is(err, store.ErrNotFound):
			http.NotFound(w, r)
		case errors.Is(err, store.ErrXrayTrafficChanged):
			http.Error(w, "traffic sample changed; refresh and retry", http.StatusConflict)
		case err != nil:
			http.Error(w, "could not reset Xray traffic", http.StatusServiceUnavailable)
		default:
			writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
		}
	})
}
