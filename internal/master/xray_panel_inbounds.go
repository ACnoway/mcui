package master

import (
	"net/http"
	"slices"
	"strconv"

	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

type panelInboundChange struct {
	State       string                    `json:"state"`
	Remove      bool                      `json:"remove,omitempty"`
	Protocol    string                    `json:"protocol,omitempty"`
	Username    string                    `json:"username,omitempty"`
	Credential  string                    `json:"credential,omitempty"`
	Destination xrayconfig.Destination    `json:"destination,omitzero"`
	Public      xrayconfig.PublicEndpoint `json:"public_endpoint,omitzero"`
	RotateTLS   bool                      `json:"rotate_tls,omitempty"`
}

type panelInbound struct {
	Inbound     xrayconfig.Inbound
	Credential  string
	Destination xrayconfig.Destination
}

func panelInbounds(draft xrayconfig.Configuration) []panelInbound {
	var entries []panelInbound
	for index, inbound := range draft.Inbounds {
		entry := panelInbound{Inbound: inbound, Credential: draft.Panel.Credentials[index]}
		for _, route := range draft.Network.Routes {
			if route.InboundPort != inbound.Port {
				continue
			}
			for _, outbound := range draft.Network.Outbounds {
				if outbound.Tag == route.OutboundTag {
					entry.Destination = outbound.Destination
				}
			}
		}
		entries = append(entries, entry)
	}
	return entries
}

func encodePanelInbounds(entries []panelInbound, identity *xrayconfig.PanelTLS) xrayconfig.Configuration {
	slices.SortFunc(entries, func(a, b panelInbound) int { return a.Inbound.Port - b.Inbound.Port })
	draft := xrayconfig.Configuration{
		Inbounds: xrayconfig.Plan{},
		Network:  &xrayconfig.Network{Outbounds: []xrayconfig.Outbound{}, Routes: []xrayconfig.Route{}},
		Panel:    &xrayconfig.PanelConfiguration{Credentials: []string{}},
	}
	tags := make(map[xrayconfig.Destination]string)
	for _, entry := range entries {
		if entry.Inbound.Protocol == xrayconfig.Trojan && identity != nil {
			draft.Panel.TLS = identity
			entry.Inbound.TLSCertSHA256 = identity.Trust.SHA256
		}
		draft.Inbounds = append(draft.Inbounds, entry.Inbound)
		draft.Panel.Credentials = append(draft.Panel.Credentials, entry.Credential)
		if entry.Destination == (xrayconfig.Destination{}) {
			continue
		}
		tag := tags[entry.Destination]
		if tag == "" {
			tag = "target-" + strconv.Itoa(entry.Inbound.Port)
			tags[entry.Destination] = tag
			draft.Network.Outbounds = append(draft.Network.Outbounds, xrayconfig.Outbound{Tag: tag, Destination: entry.Destination})
		}
		draft.Network.Routes = append(draft.Network.Routes, xrayconfig.Route{InboundPort: entry.Inbound.Port, OutboundTag: tag})
	}
	return draft
}

func (s *Server) savePanelXrayInbound(w http.ResponseWriter, r *http.Request) {
	var in panelInboundChange
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil || strconv.Itoa(port) != r.PathValue("port") || port < 1024 || port > 65535 ||
		readJSON(r, &in) != nil || len(in.State) != 64 ||
		(in.Remove && (in.Protocol != "" || in.Username != "" || in.Credential != "" || in.Destination != (xrayconfig.Destination{}))) ||
		(in.Protocol != xrayconfig.Trojan && (in.RotateTLS || in.Public != (xrayconfig.PublicEndpoint{}))) {
		http.Error(w, "invalid panel Xray inbound", http.StatusBadRequest)
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
		nodeID := r.PathValue("node")
		err = s.store.Update(func(st *store.State) error {
			p := lifecycleauth.Proposal{NodeID: nodeID, RequesterID: ctx.Admin.ID}
			if !s.panelXrayScope(st, p) {
				return errXrayInstallScope
			}
			node := st.Nodes[nodeID]
			inv, fingerprint, err := panelInventory(node, now)
			if err != nil || inv.Xray.PanelKey == "" || inv.Xray.Version != xrayconfig.Version || fingerprint != in.State {
				return errXrayInventory
			}
			if err := checkXrayDraftReservation(st, nodeID, now); err != nil {
				return err
			}
			if in.Protocol == xrayconfig.Trojan && (!inv.Xray.PanelTrojan ||
				(in.Public != (xrayconfig.PublicEndpoint{}) && (!in.Public.Valid() || !slices.Contains(inv.Xray.PanelAddresses, in.Public.Address)))) {
				return lifecycleauth.ErrDenied
			}
			var entries []panelInbound
			var identity *xrayconfig.PanelTLS
			if node.XrayDraft != "" {
				draft, err := xrayconfig.ParseConfiguration(node.XrayDraft)
				if err != nil || draft.Panel == nil {
					return errXrayInventory
				}
				entries = panelInbounds(draft)
				identity = draft.Panel.TLS
			}
			index := slices.IndexFunc(entries, func(entry panelInbound) bool { return entry.Inbound.Port == port })
			if index >= 0 && (in.Remove || in.Protocol != entries[index].Inbound.Protocol || in.Username != entries[index].Inbound.Users[0] || in.Credential != "") {
				for _, binding := range clientBindingsForNode(st, nodeID) {
					if binding.Port == port && binding.Credential == entries[index].Inbound.Users[0] {
						return errManagedClientBinding
					}
				}
			}
			if in.Remove {
				if index < 0 {
					return errXrayInventory
				}
				entries = slices.Delete(entries, index, index+1)
			} else {
				entry := panelInbound{Inbound: xrayconfig.Inbound{Port: port, Protocol: in.Protocol, Users: []string{in.Username}, PublicEndpoint: in.Public}, Destination: in.Destination}
				if in.Protocol == xrayconfig.Trojan {
					if identity == nil || in.RotateTLS {
						identity, err = xrayconfig.NewPanelTLS(inv.Xray.PanelKey, now)
						if err != nil {
							return lifecycleauth.ErrDenied
						}
					}
					entry.Inbound.TLSCertSHA256 = identity.Trust.SHA256
				}
				if index >= 0 && in.Credential == "" && entries[index].Inbound.Protocol == in.Protocol && entries[index].Inbound.Users[0] == in.Username {
					entry.Credential = entries[index].Credential
				} else {
					entry.Credential, err = xrayconfig.SealPanelCredential(inv.Xray.PanelKey, entry.Inbound, in.Credential)
					if err != nil {
						return lifecycleauth.ErrDenied
					}
				}
				if index < 0 {
					entries = append(entries, entry)
				} else {
					entries[index] = entry
				}
			}
			draft := encodePanelInbounds(entries, identity)
			encoded := draft.Encode()
			if !draft.Valid() || len(encoded) > xrayconfig.MaxConfigurationSize {
				return lifecycleauth.ErrDenied
			}
			if encoded == node.XrayDraft {
				return nil
			}
			node.XrayDraft = encoded
			node.XrayPanelKey = inv.Xray.PanelKey
			st.Nodes[nodeID] = node
			s.appendAudit(st, store.Audit{At: now.Unix(), Actor: ctx.Admin.ID, Action: "xray.config.draft",
				ResourceType: "node", Resource: nodeID, NodeID: nodeID, Outcome: "saved"})
			return nil
		})
		if err != nil {
			writePanelXrayError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
	})
}
