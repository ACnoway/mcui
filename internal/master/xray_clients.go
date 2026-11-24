package master

import (
	"cmp"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

const maxClientBindings = 64

var errManagedClientBinding = errors.New("change this inbound authorization in the Clients page")
var errClientRevision = errors.New("client bindings have changed; refresh and retry")
var errClientCredential = errors.New("the selected node credential is unavailable or assigned to another client")
var errClientExists = errors.New("client username already exists")

type clientBindingView struct {
	store.XrayBinding
	NodeName       string `json:"node_name"`
	Protocol       string `json:"protocol"`
	Applied        bool   `json:"applied"`
	ShareExpiresAt int64  `json:"share_expires_at,omitempty"`
	ShareID        string `json:"share_id,omitempty"`
}

type xrayClientView struct {
	Username  string              `json:"username"`
	Revision  int64               `json:"revision"`
	Bindings  []clientBindingView `json:"bindings"`
	ExpiresAt int64               `json:"expires_at,omitempty"`
	ShareID   string              `json:"share_id,omitempty"`
}

type clientNodeOption struct {
	ID       string             `json:"id"`
	Name     string             `json:"name"`
	Inbounds []clientPortOption `json:"inbounds"`
}

type clientPortOption struct {
	Port        int      `json:"port"`
	Protocol    string   `json:"protocol"`
	Credentials []string `json:"credentials"`
}

func (s *Server) xrayClientAuth(w http.ResponseWriter, r *http.Request) (adminContext, bool) {
	if !secureRequest(r) || s.xrayPanel == nil {
		http.NotFound(w, r)
		return adminContext{}, false
	}
	ctx, ok := s.adminAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return ctx, false
	}
	if !s.canManagePanelXray(ctx.Admin) {
		http.NotFound(w, r)
		return ctx, false
	}
	if r.Method != http.MethodGet && !csrfOK(r, ctx) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return ctx, false
	}
	return ctx, true
}

func (s *Server) listXrayClients(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.xrayClientAuth(w, r)
	if !ok {
		return
	}
	now, err := s.taskRuntime.currentTime()
	if err != nil {
		http.Error(w, "trusted task clock unavailable", http.StatusServiceUnavailable)
		return
	}
	result := struct {
		Clients []xrayClientView   `json:"clients"`
		Nodes   []clientNodeOption `json:"nodes"`
	}{Clients: []xrayClientView{}, Nodes: []clientNodeOption{}}
	err = s.store.View(func(st store.State) error {
		for id, node := range st.Nodes {
			if !s.panelXrayScope(&st, lifecycleauth.Proposal{NodeID: id, RequesterID: ctx.Admin.ID}) {
				continue
			}
			inventory, _, err := panelInventory(node, now)
			if err != nil || inventory.Xray.Catalog == nil {
				continue
			}
			catalog := inventory.Xray.Catalog
			option := clientNodeOption{ID: id, Name: node.Name}
			for _, port := range catalog.Ports {
				inbound, users, _ := catalog.Inbound(port)
				if len(users) > 0 {
					option.Inbounds = append(option.Inbounds, clientPortOption{port, inbound.Protocol, users})
				}
			}
			if len(option.Inbounds) > 0 {
				result.Nodes = append(result.Nodes, option)
			}
		}
		grants := make(map[string]subscriptionGrant)
		for username, client := range st.XrayClients {
			row := xrayClientView{Username: username, Revision: client.Revision, Bindings: []clientBindingView{},
				ExpiresAt: client.Subscription.ExpiresAt, ShareID: clientShareID(client.Subscription)}
			for _, binding := range client.Bindings {
				grant, err := s.clientNodeGrant(r.Context(), st.Nodes[binding.NodeID], now, grants)
				if err != nil {
					return err
				}
				protocol := grant.allowedPorts(binding.Credential, binding.Port).protocols[binding.Port]
				applied := hasClientBinding(grant.plan, binding.XrayBinding)
				node := st.Nodes[binding.NodeID]
				if !applied && node.Inventory != nil && node.Inventory.Xray != nil && node.Inventory.Xray.Catalog != nil {
					inbound, _, _ := node.Inventory.Xray.Catalog.Inbound(binding.Port)
					protocol = inbound.Protocol
				}
				row.Bindings = append(row.Bindings, clientBindingView{
					XrayBinding: binding.XrayBinding, NodeName: node.Name, Protocol: protocol, Applied: applied,
					ShareExpiresAt: binding.Share.ExpiresAt, ShareID: clientShareID(binding.Share),
				})
			}
			result.Clients = append(result.Clients, row)
		}
		return nil
	})
	if err != nil {
		http.Error(w, "could not read Xray clients", http.StatusServiceUnavailable)
		return
	}
	slices.SortFunc(result.Clients, func(a, b xrayClientView) int { return cmp.Compare(a.Username, b.Username) })
	slices.SortFunc(result.Nodes, func(a, b clientNodeOption) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
	})
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) createXrayClient(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.xrayClientAuth(w, r)
	if !ok {
		return
	}
	var in struct {
		Username string `json:"username"`
		MFACode  string `json:"mfa_code"`
	}
	if readJSON(r, &in) != nil || !xrayconfig.ValidUsername(in.Username) {
		http.Error(w, "invalid client username", http.StatusBadRequest)
		return
	}
	if !s.stepUp(ctx, in.MFACode) {
		http.Error(w, "MFA re-verification required", http.StatusPreconditionRequired)
		return
	}
	err := s.store.Update(func(st *store.State) error {
		if _, found := st.XrayClients[in.Username]; found {
			return errClientExists
		}
		st.XrayClients[in.Username] = store.XrayClient{Revision: 1, Bindings: []store.XrayClientBinding{}}
		s.auditXrayClient(st, ctx.Admin.ID, in.Username, "create", time.Now())
		return nil
	})
	writeXrayClientResult(w, r, err, http.StatusCreated)
}

func (s *Server) saveXrayClientBindings(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.xrayClientAuth(w, r)
	if !ok {
		return
	}
	var in struct {
		Revision int64               `json:"revision"`
		Bindings []store.XrayBinding `json:"bindings"`
		MFACode  string              `json:"mfa_code"`
	}
	username := r.PathValue("user")
	if readJSON(r, &in) != nil || !xrayconfig.ValidUsername(username) || in.Revision < 1 || !validClientBindings(in.Bindings) {
		http.Error(w, "invalid client bindings", http.StatusBadRequest)
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
	slices.SortFunc(in.Bindings, func(a, b store.XrayBinding) int {
		return cmp.Or(cmp.Compare(a.NodeID, b.NodeID), cmp.Compare(a.Port, b.Port))
	})
	err = s.store.Update(func(st *store.State) error {
		client, found := st.XrayClients[username]
		if !found {
			return store.ErrNotFound
		}
		previous := make(map[store.XrayBinding]store.XrayClientBinding, len(client.Bindings))
		for _, binding := range client.Bindings {
			previous[binding.XrayBinding] = binding
		}
		if slices.EqualFunc(client.Bindings, in.Bindings, func(a store.XrayClientBinding, b store.XrayBinding) bool {
			return a.XrayBinding == b
		}) {
			return nil
		}
		if client.Revision != in.Revision {
			return errClientRevision
		}
		added := make(map[string][]store.XrayBinding)
		removed := make(map[string][]store.XrayBinding)
		next := make([]store.XrayClientBinding, 0, len(in.Bindings))
		for _, binding := range in.Bindings {
			if old, exists := previous[binding]; exists {
				next = append(next, old)
				delete(previous, binding)
				continue
			}
			added[binding.NodeID] = append(added[binding.NodeID], binding)
			next = append(next, store.XrayClientBinding{XrayBinding: binding})
		}
		for binding := range previous {
			removed[binding.NodeID] = append(removed[binding.NodeID], binding)
		}
		for id, additions := range added {
			if !s.panelXrayScope(st, lifecycleauth.Proposal{NodeID: id, RequesterID: ctx.Admin.ID}) {
				return store.ErrNotFound
			}
			for other, record := range st.XrayClients {
				if other != username && slices.ContainsFunc(record.Bindings, func(binding store.XrayClientBinding) bool {
					return binding.NodeID == id && binding.Credential == additions[0].Credential
				}) {
					return errClientCredential
				}
			}
			if err := stageClientBindings(st, id, additions, removed[id], now); err != nil {
				return err
			}
			delete(removed, id)
		}
		for id, removals := range removed {
			if _, exists := st.Nodes[id]; exists {
				if err := stageClientBindings(st, id, nil, removals, now); err != nil {
					return err
				}
			}
		}
		client.Bindings = next
		client.Revision++
		st.XrayClients[username] = client
		s.auditXrayClient(st, ctx.Admin.ID, username, "bindings", now)
		return nil
	})
	writeXrayClientResult(w, r, err, http.StatusOK)
}

func validClientBindings(bindings []store.XrayBinding) bool {
	if bindings == nil || len(bindings) > maxClientBindings {
		return false
	}
	credentials := make(map[string]string)
	ports := make(map[string]map[int]bool)
	for _, binding := range bindings {
		if !security.ValidNodeID(binding.NodeID) || binding.Port < 1024 || binding.Port > 65535 ||
			!xrayconfig.ValidUsername(binding.Credential) {
			return false
		}
		if credential, exists := credentials[binding.NodeID]; exists && credential != binding.Credential {
			return false
		}
		credentials[binding.NodeID] = binding.Credential
		if ports[binding.NodeID] == nil {
			ports[binding.NodeID] = make(map[int]bool)
		}
		if ports[binding.NodeID][binding.Port] {
			return false
		}
		ports[binding.NodeID][binding.Port] = true
	}
	return true
}

func stageClientBindings(st *store.State, id string, additions, removals []store.XrayBinding, now time.Time) error {
	if err := checkXrayDraftReservation(st, id, now); err != nil {
		return err
	}
	node := st.Nodes[id]
	var catalog *xrayconfig.Catalog
	if len(additions) > 0 {
		inventory, _, err := panelInventory(node, now)
		if err != nil || inventory.Xray.Catalog == nil {
			return errXrayInventory
		}
		catalog = inventory.Xray.Catalog
	}
	encoded := node.XrayDraft
	if encoded == "" {
		encoded = "[]"
		if node.Inventory != nil && node.Inventory.Xray != nil && node.Inventory.Xray.Applied != nil {
			encoded = node.Inventory.Xray.AppliedConfiguration().Encode()
		} else if node.Inventory != nil && node.Inventory.Xray != nil && node.Inventory.Xray.ConfigRevision > 0 {
			return errXrayInventory
		}
	}
	draft, err := xrayconfig.ParseConfiguration(encoded)
	if err != nil {
		return errXrayInventory
	}
	for _, binding := range removals {
		if index := inboundIndex(draft.Inbounds, binding.Port); index >= 0 {
			in := &draft.Inbounds[index]
			in.Users = slices.DeleteFunc(in.Users, func(user string) bool { return user == binding.Credential })
		}
	}
	for _, binding := range additions {
		in, users, ok := catalog.Inbound(binding.Port)
		if !ok || !slices.Contains(users, binding.Credential) {
			return errClientCredential
		}
		index := inboundIndex(draft.Inbounds, binding.Port)
		if index >= 0 {
			in.Users = draft.Inbounds[index].Users
		}
		if !slices.Contains(in.Users, binding.Credential) {
			in.Users = append(in.Users, binding.Credential)
			slices.Sort(in.Users)
		}
		if index >= 0 {
			draft.Inbounds[index] = in
		} else {
			draft.Inbounds = append(draft.Inbounds, in)
		}
	}
	draft.Inbounds = slices.DeleteFunc(draft.Inbounds, func(in xrayconfig.Inbound) bool { return len(in.Users) == 0 })
	slices.SortFunc(draft.Inbounds, func(a, b xrayconfig.Inbound) int { return cmp.Compare(a.Port, b.Port) })
	if draft.Network != nil {
		draft.Network.Routes = slices.DeleteFunc(draft.Network.Routes, func(route xrayconfig.Route) bool {
			return inboundIndex(draft.Inbounds, route.InboundPort) < 0
		})
	}
	encoded = draft.Encode()
	if !draft.Valid() || len(encoded) > xrayconfig.MaxConfigurationSize || (catalog != nil && !catalog.AllowsConfiguration(draft)) {
		return errXrayInventory
	}
	node.XrayDraft = encoded
	st.Nodes[id] = node
	return nil
}

func inboundIndex(plan xrayconfig.Plan, port int) int {
	return slices.IndexFunc(plan, func(in xrayconfig.Inbound) bool { return in.Port == port })
}

func hasClientBinding(plan xrayconfig.Plan, binding store.XrayBinding) bool {
	index := inboundIndex(plan, binding.Port)
	return index >= 0 && slices.Contains(plan[index].Users, binding.Credential)
}

func clientBindingsForNode(st *store.State, nodeID string) []store.XrayBinding {
	var bindings []store.XrayBinding
	for _, record := range st.XrayClients {
		for _, binding := range record.Bindings {
			if binding.NodeID == nodeID {
				bindings = append(bindings, binding.XrayBinding)
			}
		}
	}
	slices.SortFunc(bindings, func(a, b store.XrayBinding) int {
		return cmp.Or(cmp.Compare(a.Port, b.Port), cmp.Compare(a.Credential, b.Credential))
	})
	return bindings
}

func (s *Server) auditXrayClient(st *store.State, actor, user, action string, now time.Time) {
	s.appendAudit(st, store.Audit{At: now.Unix(), Actor: actor, Action: "xray.client." + action,
		ResourceType: "xray_client", Resource: user, Outcome: "success"})
}

func writeXrayClientResult(w http.ResponseWriter, r *http.Request, err error, success int) {
	switch {
	case err == nil:
		writeJSON(w, success, map[string]string{"status": "saved"})
	case errors.Is(err, store.ErrNotFound):
		http.NotFound(w, r)
	case errors.Is(err, errXrayInventory), errors.Is(err, errXrayInstallReserved), errors.Is(err, errClientRevision),
		errors.Is(err, errClientCredential), errors.Is(err, errClientExists), errors.Is(err, errSubscriptionUnavailable):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		http.Error(w, "could not save Xray client", http.StatusServiceUnavailable)
	}
}
