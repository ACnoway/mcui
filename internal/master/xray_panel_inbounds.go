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
	Inbound    xrayconfig.Inbound
	Credential string
}

func panelInbounds(draft xrayconfig.Configuration) []panelInbound {
	var entries []panelInbound
	for index, inbound := range draft.Inbounds {
		entries = append(entries, panelInbound{Inbound: inbound, Credential: draft.Panel.Credentials[index]})
	}
	return entries
}

func encodePanelInbounds(entries []panelInbound, identity *xrayconfig.PanelTLS, network *xrayconfig.Network) xrayconfig.Configuration {
	slices.SortFunc(entries, func(a, b panelInbound) int { return a.Inbound.Port - b.Inbound.Port })
	draft := xrayconfig.Configuration{
		Inbounds: xrayconfig.Plan{},
		Network:  network,
		Panel:    &xrayconfig.PanelConfiguration{Credentials: []string{}},
	}
	for _, entry := range entries {
		if entry.Inbound.Protocol == xrayconfig.Trojan && identity != nil {
			draft.Panel.TLS = identity
			entry.Inbound.TLSCertSHA256 = identity.Trust.SHA256
		}
		draft.Inbounds = append(draft.Inbounds, entry.Inbound)
		draft.Panel.Credentials = append(draft.Panel.Credentials, entry.Credential)
	}
	return draft
}

func updatePanelInboundRoute(network *xrayconfig.Network, port int, destination xrayconfig.Destination) {
	index := slices.IndexFunc(network.Routes, func(route xrayconfig.Route) bool { return route.InboundPort == port })
	previous := ""
	if index >= 0 {
		previous = network.Routes[index].OutboundTag
	}
	outbound := slices.IndexFunc(network.Outbounds, func(entry xrayconfig.Outbound) bool { return entry.Destination == destination })
	tag := ""
	if outbound >= 0 {
		tag = network.Outbounds[outbound].Tag
	}
	if tag == previous && (tag != "" || destination == (xrayconfig.Destination{})) {
		return
	}
	if index >= 0 {
		network.Routes = slices.Delete(network.Routes, index, index+1)
	}
	generatedTag := "target-" + strconv.Itoa(port)
	if previous == generatedTag && !slices.ContainsFunc(network.Routes, func(route xrayconfig.Route) bool { return route.OutboundTag == previous }) {
		network.Outbounds = slices.DeleteFunc(network.Outbounds, func(entry xrayconfig.Outbound) bool { return entry.Tag == previous })
	}
	if destination == (xrayconfig.Destination{}) {
		return
	}
	if tag == "" {
		tag = generatedTag
		for suffix := 1; slices.ContainsFunc(network.Outbounds, func(entry xrayconfig.Outbound) bool { return entry.Tag == tag }); suffix++ {
			tag = generatedTag + "-" + strconv.Itoa(suffix)
		}
		network.Outbounds = append(network.Outbounds, xrayconfig.Outbound{Tag: tag, Destination: destination})
	}
	network.Routes = append(network.Routes, xrayconfig.Route{InboundPort: port, OutboundTag: tag})
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
			if node.XrayPanelKey == "" && (inv.Xray.ConfigRevision != 0 || len(clientBindingsForNode(st, nodeID)) != 0) {
				return errXrayInventory
			}
			var entries []panelInbound
			var identity *xrayconfig.PanelTLS
			network := &xrayconfig.Network{Outbounds: []xrayconfig.Outbound{}, Routes: []xrayconfig.Route{}}
			if node.XrayDraft != "" {
				draft, err := xrayconfig.ParseConfiguration(node.XrayDraft)
				if err != nil {
					return errXrayInventory
				}
				if draft.Panel != nil {
					entries = panelInbounds(draft)
					identity = draft.Panel.TLS
					network = draft.Network
				} else if node.XrayPanelKey != "" || len(draft.Inbounds) != 0 {
					return errXrayInventory
				}
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
				entry := panelInbound{Inbound: xrayconfig.Inbound{Port: port, Protocol: in.Protocol, Users: []string{in.Username}, PublicEndpoint: in.Public}}
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
			updatePanelInboundRoute(network, port, in.Destination)
			draft := encodePanelInbounds(entries, identity, network)
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
