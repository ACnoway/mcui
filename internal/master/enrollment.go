package master

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/store"
)

const installCodeLifetime = 10 * time.Minute

type agentInstaller struct {
	masterURL string
	url       string
	sha256    string
}

// ConfigureAgentInstaller takes release metadata verified by the panel operator.
func (s *Server) ConfigureAgentInstaller(masterURL, installerURL, digest string) error {
	origin, err := security.MasterOrigin(masterURL)
	if err != nil {
		return err
	}
	u, err := url.Parse(installerURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path == "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(installerURL, "#") {
		return errors.New("Agent installer must have an HTTPS download URL")
	}
	rawDigest, err := hex.DecodeString(digest)
	if err != nil || len(rawDigest) != 32 {
		return errors.New("Agent installer requires an approved SHA-256 digest")
	}
	s.installer = &agentInstaller{masterURL: origin, url: u.String(), sha256: hex.EncodeToString(rawDigest)}
	return nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func (i agentInstaller) command(nodeID, installCode string, preserve bool) string {
	stateFlag := ""
	if preserve {
		stateFlag = " --preserve-state"
	}
	return fmt.Sprintf(`(
  set +x
  set -eu
  umask 077
  tmp=$(mktemp -d)
  trap 'rm -rf -- "$tmp"' EXIT
  curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-time 180 --output "$tmp/install.sh" -- %s
  printf '%%s  %%s\n' %s "$tmp/install.sh" | sha256sum --check --status
  printf '%%s\n' %s | sudo -- /bin/bash "$tmp/install.sh" --master %s --node-id %s%s
)`, shellQuote(i.url), shellQuote(i.sha256), shellQuote(installCode), shellQuote(i.masterURL), shellQuote(nodeID), stateFlag)
}

func (s *Server) createNode(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.requireCSRF(w, r)
	if !ok {
		return
	}
	var in struct {
		Name  string `json:"name"`
		Group string `json:"node_group"`
	}
	if readJSON(r, &in) != nil || !namePattern.MatchString(in.Name) || !groupPattern.MatchString(in.Group) {
		http.Error(w, "invalid node", http.StatusBadRequest)
		return
	}
	id, err := security.NewNodeID()
	if err != nil {
		http.Error(w, "node creation unavailable", http.StatusInternalServerError)
		return
	}
	// Keep the format used by the existing node inventory and task records.
	node := store.Node{ID: id, Name: strings.TrimSpace(in.Name), Group: in.Group}
	err = s.store.Update(func(st *store.State) error {
		if !canManageGroup(st.Admins[ctx.Admin.ID], node.Group) {
			return store.ErrNotFound
		}
		if _, exists := st.Nodes[node.ID]; exists {
			return errors.New("node ID collision")
		}
		st.Nodes[node.ID] = node
		s.appendAudit(st, store.Audit{At: time.Now().Unix(), Actor: ctx.Admin.ID, Action: "node.create", ResourceType: "node", Resource: node.ID, Outcome: "success"})
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "node creation unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, nodeView(node))
}

func (s *Server) createInstallCommand(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.requireCSRF(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	var node store.Node
	_ = s.store.View(func(st store.State) error { node = st.Nodes[id]; return nil })
	if node.ID == "" || node.Disabled || !canManageNode(ctx.Admin, node) {
		_ = s.recordAudit(ctx.Admin.ID, "node.install_code.generate", "node", node.ID, "denied")
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !security.ValidNodeID(node.ID) || r.TLS == nil || s.installer == nil {
		http.Error(w, "Agent installer unavailable", http.StatusServiceUnavailable)
		return
	}
	var in struct {
		MFACode string `json:"mfa_code"`
	}
	if readJSON(r, &in) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !s.stepUp(ctx, in.MFACode) {
		_ = s.recordAudit(ctx.Admin.ID, "node.install_code.generate", "node", id, "mfa_required")
		http.Error(w, "MFA re-verification required", http.StatusPreconditionRequired)
		return
	}
	code, err := randomToken(32)
	if err != nil {
		http.Error(w, "Agent installer unavailable", http.StatusInternalServerError)
		return
	}
	var expires int64
	var preserve bool
	err = s.store.Update(func(st *store.State) error {
		n := st.Nodes[id]
		if n.ID == "" || n.Disabled || !canManageNode(st.Admins[ctx.Admin.ID], n) {
			return store.ErrNotFound
		}
		now := time.Now()
		expires = now.Add(installCodeLifetime).Unix()
		preserve = n.Enrolled
		n.InstallCodeHash, n.InstallCodeExpiresAt = hash(code), expires
		st.Nodes[id] = n
		s.appendAudit(st, store.Audit{At: now.Unix(), Actor: ctx.Admin.ID, Action: "node.install_code.generate", ResourceType: "node", Resource: id, Outcome: "success"})
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Agent installer unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"command": s.installer.command(id, code, preserve), "expires_at": expires})
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "HTTPS required", http.StatusUpgradeRequired)
		return
	}
	if !s.allowAttempt("enroll:" + clientAddress(r)) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	var in struct {
		InstallCode string `json:"install_code"`
	}
	if readJSON(r, &in) != nil || !security.ValidNodeSecret(in.InstallCode) {
		_ = s.recordAudit("anonymous", "node.enroll", "node", "", "denied")
		http.Error(w, "invalid installation request", http.StatusBadRequest)
		return
	}
	token, err := randomToken(32)
	if err != nil {
		http.Error(w, "enrollment unavailable", http.StatusInternalServerError)
		return
	}
	codeHash := hash(in.InstallCode)
	var nodeID string
	s.nodeAccess.Lock()
	defer s.nodeAccess.Unlock()
	err = s.store.Update(func(st *store.State) error {
		now := time.Now().Unix()
		var node store.Node
		for _, candidate := range st.Nodes {
			if subtle.ConstantTimeCompare([]byte(candidate.InstallCodeHash), []byte(codeHash)) == 1 {
				node = candidate
				break
			}
		}
		if node.ID == "" || node.Disabled || node.InstallCodeExpiresAt <= now {
			s.appendAudit(st, store.Audit{At: now, Actor: "anonymous", Action: "node.enroll", ResourceType: "node", Resource: node.ID, Outcome: "denied"})
			return nil
		}
		action := "node.enroll"
		if node.TokenHash != "" {
			action = "node.token.rotate"
		}
		node.InstallCodeHash, node.InstallCodeExpiresAt = "", 0
		node.Enrolled = true
		node.TokenHash, node.LastSeen = hash(token), 0
		nodeID = node.ID
		st.Nodes[nodeID] = node
		s.appendAudit(st, store.Audit{At: now, Actor: nodeID, Action: action, ResourceType: "node", Resource: nodeID, Outcome: "success"})
		return nil
	})
	if err != nil {
		http.Error(w, "enrollment unavailable", http.StatusInternalServerError)
		return
	}
	if nodeID == "" {
		http.Error(w, "installation code rejected", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"node_id": nodeID, "node_token": token})
}

func (s *Server) authenticateNode(r *http.Request) (store.Node, bool) {
	var node store.Node
	auth := r.Header.Values("Authorization")
	if r.TLS == nil || len(auth) != 1 {
		return node, false
	}
	scheme, token, ok := strings.Cut(auth[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || !security.ValidNodeSecret(token) {
		return node, false
	}
	digest := hash(token)
	err := s.store.View(func(st store.State) error {
		for _, candidate := range st.Nodes {
			if subtle.ConstantTimeCompare([]byte(candidate.TokenHash), []byte(digest)) == 1 && !candidate.Disabled {
				if node.ID != "" {
					return errors.New("duplicate node credential")
				}
				node = candidate
			}
		}
		return nil
	})
	return node, err == nil && node.ID != ""
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	s.nodeAccess.RLock()
	defer s.nodeAccess.RUnlock()
	node, ok := s.authenticateNode(r)
	if !ok {
		http.Error(w, "node credential rejected", http.StatusUnauthorized)
		return
	}
	var in struct {
		NodeID string `json:"node_id"`
	}
	if readJSON(r, &in) != nil {
		http.Error(w, "invalid heartbeat", http.StatusBadRequest)
		return
	}
	if in.NodeID != "" && in.NodeID != node.ID {
		http.Error(w, "heartbeat target rejected", http.StatusForbidden)
		return
	}
	err := s.store.Update(func(st *store.State) error {
		current := st.Nodes[node.ID]
		if current.Disabled || current.TokenHash != node.TokenHash {
			return store.ErrNotFound
		}
		current.LastSeen = time.Now().Unix()
		st.Nodes[node.ID] = current
		return nil
	})
	if err != nil {
		http.Error(w, "heartbeat unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "node_id": node.ID})
}
