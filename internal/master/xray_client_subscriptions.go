package master

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

func (s *Server) clientNodeGrant(ctx context.Context, node store.Node, now time.Time, cache map[string]subscriptionGrant) (subscriptionGrant, error) {
	if grant, exists := cache[node.ID]; exists {
		return grant, nil
	}
	var grant subscriptionGrant
	if node.ID != "" && s.taskRuntime.XrayInstallPolicy.AllowsPanelNode(node.ID) {
		var err error
		grant, err = s.xraySubscriptionGrant(ctx, node, now)
		if err != nil && !errors.Is(err, errSubscriptionUnavailable) {
			return subscriptionGrant{}, err
		}
	}
	cache[node.ID] = grant
	return grant, nil
}

type issuedClientShare struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	ID        string `json:"id"`
}

type issuedBindingShare struct {
	store.XrayBinding
	issuedClientShare
}

type clientShareResult struct {
	Subscription *issuedClientShare   `json:"subscription,omitempty"`
	Inbounds     []issuedBindingShare `json:"inbounds"`
}

func issueClientShare(username string, now time.Time) (store.ClientShare, issuedClientShare, error) {
	secret, err := randomToken(32)
	if err != nil {
		return store.ClientShare{}, issuedClientShare{}, err
	}
	issued := issuedClientShare{Token: username + "." + secret, ExpiresAt: now.Add(xraySubscriptionLifetime).Unix()}
	stored := store.ClientShare{TokenHash: hash(issued.Token), ExpiresAt: issued.ExpiresAt}
	issued.ID = clientShareID(stored)
	return stored, issued, nil
}

func clientShareID(share store.ClientShare) string {
	return share.TokenHash[:min(16, len(share.TokenHash))]
}

func (s *Server) changeXrayClientShare(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.xrayClientAuth(w, r)
	if !ok {
		return
	}
	var in struct {
		Action  string `json:"action"`
		NodeID  string `json:"node_id"`
		Port    int    `json:"port"`
		MFACode string `json:"mfa_code"`
	}
	username := r.PathValue("user")
	if readJSON(r, &in) != nil || !xrayconfig.ValidUsername(username) || (in.Action != "issue" && in.Action != "revoke") ||
		(in.NodeID != "" && (!security.ValidNodeID(in.NodeID) || in.Port < 1024 || in.Port > 65535)) || (in.NodeID == "" && in.Port != 0) {
		http.Error(w, "invalid client share request", http.StatusBadRequest)
		return
	}
	if !s.stepUp(ctx, in.MFACode) {
		http.Error(w, "MFA re-verification required", http.StatusPreconditionRequired)
		return
	}
	now := time.Now()
	if in.Action == "issue" {
		var err error
		now, err = s.taskRuntime.currentTime()
		if err != nil {
			http.Error(w, "trusted task clock unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	result := clientShareResult{Inbounds: []issuedBindingShare{}}
	err := s.store.Update(func(st *store.State) error {
		client, found := st.XrayClients[username]
		if !found {
			return store.ErrNotFound
		}
		var indexes []int
		if in.NodeID != "" {
			index := slices.IndexFunc(client.Bindings, func(binding store.XrayClientBinding) bool {
				return binding.NodeID == in.NodeID && binding.Port == in.Port
			})
			if index < 0 {
				return store.ErrNotFound
			}
			indexes = append(indexes, index)
		} else {
			for index := range client.Bindings {
				indexes = append(indexes, index)
			}
		}
		if in.Action == "revoke" {
			for _, index := range indexes {
				client.Bindings[index].Share = store.ClientShare{}
				client.Bindings[index].Delivery = store.CredentialDelivery{}
			}
			if in.NodeID == "" {
				client.Subscription = store.ClientShare{}
			}
		} else {
			grants := make(map[string]subscriptionGrant)
			for _, index := range indexes {
				binding := &client.Bindings[index]
				grant, err := s.clientNodeGrant(r.Context(), st.Nodes[binding.NodeID], now, grants)
				if err != nil {
					return err
				}
				if !hasClientBinding(grant.plan, binding.XrayBinding) {
					if in.NodeID == "" {
						binding.Share = store.ClientShare{}
					}
					continue
				}
				stored, issued, err := issueClientShare(username, now)
				if err != nil {
					return err
				}
				binding.Share = stored
				result.Inbounds = append(result.Inbounds, issuedBindingShare{XrayBinding: binding.XrayBinding, issuedClientShare: issued})
			}
			if len(result.Inbounds) == 0 {
				return errSubscriptionUnavailable
			}
			if in.NodeID == "" {
				stored, issued, err := issueClientShare(username, now)
				if err != nil {
					return err
				}
				client.Subscription, result.Subscription = stored, &issued
			}
		}
		st.XrayClients[username] = client
		s.auditXrayClient(st, ctx.Admin.ID, username, "share."+in.Action, now)
		return nil
	})
	if err != nil {
		writeXrayClientResult(w, r, err, http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type clientSubscriptionEntry struct {
	NodeID   string         `json:"node_id"`
	NodeName string         `json:"node_name"`
	Config   map[string]any `json:"config"`
}

func (s *Server) fetchXrayClientSubscription(w http.ResponseWriter, r *http.Request) {
	username, token, valid := subscriptionBearer(r)
	if !valid || !xrayconfig.ValidUsername(username) || !secureRequest(r) || r.URL.RawQuery != "" || s.xrayPanel == nil {
		http.NotFound(w, r)
		return
	}
	if !s.allowAttempt("xray-subscription:" + clientAddress(r)) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	s.withTaskHTTP(w, r, func(w http.ResponseWriter) {
		now, err := s.taskRuntime.currentTime()
		if err != nil {
			http.Error(w, "subscription service unavailable", http.StatusServiceUnavailable)
			return
		}
		digest := hash(token)
		var expiresAt int64
		var credential string
		var entries []clientSubscriptionEntry
		err = s.store.View(func(st store.State) error {
			client, ok := st.XrayClients[username]
			if !ok {
				return nil
			}
			bindings, expiry := matchClientShare(client, digest, now)
			var delivery store.CredentialDelivery
			if expiry == 0 {
				for _, binding := range client.Bindings {
					link := binding.Delivery.Link
					if link.ExpiresAt > now.Unix() && subtle.ConstantTimeCompare([]byte(link.TokenHash), []byte(digest)) == 1 {
						bindings, expiry, delivery = []store.XrayClientBinding{binding}, link.ExpiresAt, binding.Delivery
						break
					}
				}
			}
			expiresAt = expiry
			grants := make(map[string]subscriptionGrant)
			for _, binding := range bindings {
				node := st.Nodes[binding.NodeID]
				grant, err := s.clientNodeGrant(r.Context(), node, now, grants)
				if err != nil {
					return err
				}
				ports := grant.allowedPorts(binding.Credential, binding.Port)
				if len(ports.ports) != 1 {
					continue
				}
				if delivery.CredentialHash != "" {
					if grant.credentialHashes[binding.Port] != delivery.CredentialHash {
						continue
					}
					aead, err := xrayCredentialEnvelope(token)
					if err != nil {
						return err
					}
					clear, err := aead.Open(nil, nil, delivery.Envelope, []byte(delivery.CredentialHash))
					if err != nil {
						return err
					}
					credential = string(clear)
				}
				entries = append(entries, clientSubscriptionEntry{
					NodeID: node.ID, NodeName: node.Name, Config: grant.payload(binding.Credential, ports, expiresAt),
				})
			}
			return nil
		})
		if err != nil {
			http.Error(w, "subscription service unavailable", http.StatusServiceUnavailable)
			return
		}
		if len(entries) == 0 {
			http.NotFound(w, r)
			return
		}
		response := map[string]any{
			"schema_version": 1, "username": username, "expires_at": expiresAt, "entries": entries,
		}
		if credential != "" {
			response["credential"] = credential
		}
		writeJSON(w, http.StatusOK, response)
	})
}

func matchClientShare(client store.XrayClient, digest string, now time.Time) ([]store.XrayClientBinding, int64) {
	if client.Subscription.ExpiresAt > now.Unix() && subtle.ConstantTimeCompare([]byte(client.Subscription.TokenHash), []byte(digest)) == 1 {
		return client.Bindings, client.Subscription.ExpiresAt
	}
	for i, binding := range client.Bindings {
		if binding.Share.ExpiresAt > now.Unix() && subtle.ConstantTimeCompare([]byte(binding.Share.TokenHash), []byte(digest)) == 1 {
			return client.Bindings[i : i+1], binding.Share.ExpiresAt
		}
	}
	return nil, 0
}
