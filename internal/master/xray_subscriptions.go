package master

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/taskdispatch"
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

const xraySubscriptionLifetime = 30 * 24 * time.Hour

var errSubscriptionUnavailable = errors.New("an applied Xray authorization is unavailable")

type subscriptionGrant struct {
	plan     xrayconfig.Plan
	revision int64
	sha256   string
}

func (g subscriptionGrant) ports(user string) []int {
	var ports []int
	for _, inbound := range g.plan {
		if slices.Contains(inbound.Users, user) {
			ports = append(ports, inbound.Port)
		}
	}
	return ports
}

func (g subscriptionGrant) matches(token store.XraySubscription, now time.Time) bool {
	return g.revision > 0 && token.TokenHash != "" && token.Revision == g.revision &&
		token.SHA256 == g.sha256 && token.ExpiresAt > now.Unix()
}

func (s *Server) xraySubscriptionGrant(ctx context.Context, node store.Node, now time.Time) (subscriptionGrant, error) {
	i, _, err := panelInventory(node, now)
	if err != nil || node.Disabled || !node.Enrolled || node.TokenHash == "" || i.Architecture != xrayconfig.Architecture ||
		!i.Xray.Running || i.Xray.Catalog == nil || i.Xray.Applied == nil || !i.Xray.Catalog.Allows(*i.Xray.Applied) {
		return subscriptionGrant{}, errSubscriptionUnavailable
	}
	raw, err := s.taskRuntime.Store.XrayConfigForSubscription(ctx, node.ID)
	if errors.Is(err, taskdispatch.ErrNotFound) {
		return subscriptionGrant{}, errSubscriptionUnavailable
	}
	if err != nil {
		return subscriptionGrant{}, err
	}
	task, err := s.taskRuntime.XrayInstallPolicy.InstallKey().Verify(raw)
	if err != nil || task.NodeID != node.ID || task.Operation != xrayconfig.Operation ||
		task.Architecture != i.Architecture || task.Version != i.Xray.Version || task.SHA256 != i.Xray.SHA256 ||
		task.Sequence != i.Xray.ConfigRevision || task.Config != i.Xray.Config || task.Plan != i.Xray.Applied.Encode() {
		return subscriptionGrant{}, errSubscriptionUnavailable
	}
	return subscriptionGrant{plan: *i.Xray.Applied, revision: task.Sequence, sha256: task.Config.SHA256}, nil
}

type xraySubscriptionView struct {
	Username  string `json:"username"`
	Eligible  bool   `json:"eligible"`
	Active    bool   `json:"active"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

func (s *Server) listXraySubscriptions(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.panelXrayAuth(w, r, nil)
	if !ok {
		return
	}
	node, err := s.store.NodeByID(r.Context(), r.PathValue("node"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && !canManageNode(ctx.Admin, node)) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "subscription service unavailable", http.StatusServiceUnavailable)
		return
	}
	var grant subscriptionGrant
	now, err := s.taskRuntime.currentTime()
	if err == nil {
		grant, err = s.xraySubscriptionGrant(r.Context(), node, now)
		if err != nil && !errors.Is(err, errSubscriptionUnavailable) {
			http.Error(w, "subscription service unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	users := make(map[string]bool)
	for user := range node.XraySubscriptions {
		users[user] = false
	}
	for _, inbound := range grant.plan {
		for _, user := range inbound.Users {
			users[user] = true
		}
	}
	rows := make([]xraySubscriptionView, 0, len(users))
	for user, eligible := range users {
		record := node.XraySubscriptions[user]
		rows = append(rows, xraySubscriptionView{
			Username: user, Eligible: eligible, ExpiresAt: record.ExpiresAt, Active: eligible && grant.matches(record, now),
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Username < rows[j].Username })
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) changeXraySubscription(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.panelXrayAuth(w, r, nil)
	if !ok {
		return
	}
	if !csrfOK(r, ctx) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var in struct {
		Action   string `json:"action"`
		Username string `json:"username"`
		MFACode  string `json:"mfa_code"`
	}
	if readJSON(r, &in) != nil || !xrayconfig.ValidUsername(in.Username) ||
		(in.Action != "issue" && in.Action != "revoke") {
		http.Error(w, "invalid subscription request", http.StatusBadRequest)
		return
	}
	if !s.stepUp(ctx, in.MFACode) {
		http.Error(w, "MFA re-verification required", http.StatusPreconditionRequired)
		return
	}
	nodeID := r.PathValue("node")
	now := time.Now()
	var token string
	if in.Action == "issue" {
		var err error
		now, err = s.taskRuntime.currentTime()
		if err != nil {
			http.Error(w, "trusted task clock unavailable", http.StatusServiceUnavailable)
			return
		}
		random, err := randomToken(32)
		if err != nil {
			http.Error(w, "subscription service unavailable", http.StatusServiceUnavailable)
			return
		}
		token = nodeID + "." + random
	}
	var expiresAt int64
	err := s.store.Update(func(st *store.State) error {
		node, exists := st.Nodes[nodeID]
		actor := st.Admins[ctx.Admin.ID]
		if !exists || !s.canManagePanelXray(actor) || !canManageNode(actor, node) {
			return store.ErrNotFound
		}
		auditAction := "xray.subscription.revoke"
		if in.Action == "revoke" {
			if _, exists := node.XraySubscriptions[in.Username]; !exists {
				return nil
			}
			delete(node.XraySubscriptions, in.Username)
		} else {
			grant, err := s.xraySubscriptionGrant(r.Context(), node, now)
			if err != nil {
				return err
			}
			if len(grant.ports(in.Username)) == 0 {
				return errSubscriptionUnavailable
			}
			auditAction = "xray.subscription.issue"
			if node.XraySubscriptions == nil {
				node.XraySubscriptions = make(map[string]store.XraySubscription)
			}
			for user, previous := range node.XraySubscriptions {
				if !grant.matches(previous, now) {
					delete(node.XraySubscriptions, user)
				}
			}
			if _, exists := node.XraySubscriptions[in.Username]; exists {
				auditAction = "xray.subscription.rotate"
			}
			expiresAt = now.Add(xraySubscriptionLifetime).Unix()
			node.XraySubscriptions[in.Username] = store.XraySubscription{
				TokenHash: hash(token), Revision: grant.revision, SHA256: grant.sha256, ExpiresAt: expiresAt,
			}
		}
		st.Nodes[nodeID] = node
		s.appendAudit(st, store.Audit{At: now.Unix(), Actor: actor.ID, Action: auditAction,
			ResourceType: "xray_subscription", Resource: in.Username, NodeID: nodeID, Outcome: "success"})
		return nil
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.NotFound(w, r)
	case errors.Is(err, errSubscriptionUnavailable):
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		http.Error(w, "subscription service unavailable", http.StatusServiceUnavailable)
	default:
		writeJSON(w, http.StatusOK, struct {
			Token     string `json:"token,omitempty"`
			ExpiresAt int64  `json:"expires_at,omitempty"`
		}{token, expiresAt})
	}
}

func subscriptionBearer(r *http.Request) (nodeID, token string, valid bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", "", false
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	last := strings.LastIndexByte(token, '.')
	if !ok || !strings.EqualFold(scheme, "Bearer") || last < 1 ||
		!security.ValidNodeID(token[:last]) || !security.ValidNodeSecret(token[last+1:]) {
		return "", "", false
	}
	return token[:last], token, true
}

func (s *Server) fetchXraySubscription(w http.ResponseWriter, r *http.Request) {
	nodeID, token, ok := subscriptionBearer(r)
	if !ok || !secureRequest(r) || r.URL.RawQuery != "" || s.xrayPanel == nil ||
		!s.taskRuntime.XrayInstallPolicy.AllowsPanelNode(nodeID) {
		http.NotFound(w, r)
		return
	}
	if !s.allowAttempt("xray-subscription:" + clientAddress(r)) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	s.withTaskHTTP(w, r, func(w http.ResponseWriter) {
		node, err := s.store.NodeByID(r.Context(), nodeID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			http.Error(w, "subscription service unavailable", http.StatusServiceUnavailable)
			return
		}
		digest := hash(token)
		var username string
		var record store.XraySubscription
		for user, entry := range node.XraySubscriptions {
			if subtle.ConstantTimeCompare([]byte(entry.TokenHash), []byte(digest)) == 1 {
				username, record = user, entry
				break
			}
		}
		if username == "" {
			http.NotFound(w, r)
			return
		}
		now, err := s.taskRuntime.currentTime()
		if err != nil {
			http.Error(w, "subscription service unavailable", http.StatusServiceUnavailable)
			return
		}
		grant, err := s.xraySubscriptionGrant(r.Context(), node, now)
		if err != nil && !errors.Is(err, errSubscriptionUnavailable) {
			http.Error(w, "subscription service unavailable", http.StatusServiceUnavailable)
			return
		}
		ports := grant.ports(username)
		if err != nil || !grant.matches(record, now) || len(ports) == 0 {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": 1, "username": username, "address": "127.0.0.1", "ports": ports,
			"revision": grant.revision, "expires_at": record.ExpiresAt,
		})
	})
}
