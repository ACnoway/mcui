package master

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/xraytraffic"
)

const installCodeLifetime = 10 * time.Minute

type agentInstaller struct {
	masterURL string
	url       string
	sha256    string
	taskKeyID string
	taskKey   ed25519.PublicKey
	coreKeyID string
	coreKey   ed25519.PublicKey
	caPEM     []byte
}

// ConfigureAgentInstaller takes release metadata verified by the panel operator.
func (s *Server) ConfigureAgentInstaller(masterURL, installerURL, digest string) error {
	origin, err := security.MasterOrigin(masterURL)
	if err != nil {
		return err
	}
	return s.configureAgentInstaller(origin, installerURL, digest)
}

func (s *Server) configureAgentInstaller(origin, installerURL, digest string) error {
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

var installerKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var installerReleaseTag = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func (s *Server) ConfigureGitHubAgentInstaller(masterURL, tag, digest, taskID string, taskKey ed25519.PublicKey, coreID string, coreKey ed25519.PublicKey, ca []byte) error {
	if !installerReleaseTag.MatchString(tag) || !installerKeyIDPattern.MatchString(coreID) ||
		len(coreKey) != ed25519.PublicKeySize || coreID == taskID || bytes.Equal(coreKey, taskKey) {
		return errors.New("invalid GitHub Agent release tag or Core management key")
	}
	origin := ""
	if masterURL != "" {
		var err error
		origin, err = security.MasterOrigin(masterURL)
		if err != nil {
			return err
		}
	}
	releaseURL := "https://github.com/ACnoway/mcui/releases/download/" + tag + "/install-mcui-agent.sh"
	if err := s.configureAgentInstaller(origin, releaseURL, digest); err != nil {
		return err
	}
	if err := s.ConfigureAgentInstallerTrust(taskID, taskKey, ca); err != nil {
		s.installer = nil
		return err
	}
	s.installer.coreKeyID = coreID
	s.installer.coreKey = bytes.Clone(coreKey)
	return nil
}

func (s *Server) ConfigureAgentInstallerTrust(keyID string, key ed25519.PublicKey, caPEM []byte) error {
	if s.installer == nil || !installerKeyIDPattern.MatchString(keyID) || len(key) != ed25519.PublicKeySize {
		return errors.New("Agent installer trust requires approved installer metadata and a valid task key")
	}
	if runtime := s.taskRuntime; runtime != nil && (runtime.KeyID != keyID || !bytes.Equal(runtime.PublicKey, key)) {
		return errors.New("Agent installer task key differs from the Master task runtime key")
	}
	if len(caPEM) > 0 {
		canonical, err := security.CanonicalEnrollmentCA(caPEM)
		if err != nil {
			return err
		}
		caPEM = canonical
	}
	s.installer.taskKeyID = keyID
	s.installer.taskKey = append(ed25519.PublicKey(nil), key...)
	s.installer.caPEM = caPEM
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
	trustFlags := ""
	if i.taskKeyID != "" {
		trustFlags = " --task-key-id " + shellQuote(i.taskKeyID) + " --task-public-key " + shellQuote(base64.StdEncoding.EncodeToString(i.taskKey))
		if len(i.caPEM) > 0 {
			trustFlags += " --master-ca-base64 " + shellQuote(base64.StdEncoding.EncodeToString(i.caPEM))
		}
	}
	if i.coreKeyID != "" {
		trustFlags += " --core-key-id " + shellQuote(i.coreKeyID) + " --core-public-key " + shellQuote(base64.StdEncoding.EncodeToString(i.coreKey))
	}
	return fmt.Sprintf(`(
  set +x
  set -eu
  umask 077
  as_root() {
    if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo -- "$@"; fi
  }
  if [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
    printf 'Run this command as root or install sudo.\n' >&2
    exit 1
  fi
  if ! command -v curl >/dev/null 2>&1 || [ ! -s /etc/ssl/certs/ca-certificates.crt ]; then
    if [ ! -f /etc/debian_version ] || ! command -v apt-get >/dev/null 2>&1; then
      printf 'Install curl and the system CA certificates first.\n' >&2
      exit 1
    fi
    as_root apt-get update
    as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ca-certificates
  fi
  tmp=$(mktemp -d)
  trap 'rm -rf -- "$tmp"' EXIT
  curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-time 180 --output "$tmp/install.sh" -- %s
  printf '%%s  %%s\n' %s "$tmp/install.sh" | sha256sum --check --status
  printf '%%s\n' %s | as_root /bin/bash "$tmp/install.sh" --master %s --node-id %s%s%s
)`, shellQuote(i.url), shellQuote(i.sha256), shellQuote(installCode), shellQuote(i.masterURL), shellQuote(nodeID), stateFlag, trustFlags)
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
	if !security.ValidNodeID(node.ID) || !secureRequest(r) || s.installer == nil {
		http.Error(w, "Agent installer unavailable", http.StatusServiceUnavailable)
		return
	}
	installer := *s.installer
	if installer.masterURL == "" {
		// Use the origin that passed the authenticated request's CSRF check.
		origin := "https://" + r.Host
		if proxy, ok := proxyRequest(r); ok {
			origin = proxy.origin
		}
		var err error
		installer.masterURL, err = security.MasterOrigin(origin)
		if err != nil {
			http.Error(w, "Agent installer unavailable", http.StatusServiceUnavailable)
			return
		}
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
	writeJSON(w, http.StatusCreated, map[string]any{"command": installer.command(id, code, preserve), "expires_at": expires})
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	if !secureRequest(r) {
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
		node.Inventory = nil
		node.XraySubscriptions = nil
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
	if !secureRequest(r) || len(auth) != 1 {
		return node, false
	}
	scheme, token, ok := strings.Cut(auth[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || !security.ValidNodeSecret(token) {
		return node, false
	}
	node, err := s.store.NodeByTokenHash(r.Context(), hash(token))
	return node, err == nil && node.ID != ""
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	node, ok := s.authenticateNode(r)
	if !ok {
		http.Error(w, "node credential rejected", http.StatusUnauthorized)
		return
	}
	var in struct {
		NodeID    string                       `json:"node_id"`
		Inventory *lifecycleauth.NodeInventory `json:"inventory"`
		Traffic   *xraytraffic.Sample          `json:"xray_traffic,omitempty"`
	}
	if readJSON(r, &in) != nil || (in.Inventory != nil && !in.Inventory.Valid()) {
		http.Error(w, "invalid heartbeat", http.StatusBadRequest)
		return
	}
	if in.NodeID != "" && in.NodeID != node.ID {
		http.Error(w, "heartbeat target rejected", http.StatusForbidden)
		return
	}
	if in.Inventory != nil && in.Inventory.Xray != nil && in.Inventory.Xray.Traffic != nil {
		http.Error(w, "invalid heartbeat traffic field", http.StatusBadRequest)
		return
	}
	if in.Traffic != nil {
		now := time.Now()
		if in.Inventory == nil || in.Inventory.Xray == nil || in.Traffic.At < now.Add(-90*time.Second).UnixMilli() ||
			in.Traffic.At > now.Add(5*time.Second).UnixMilli() {
			http.Error(w, "invalid heartbeat traffic sample", http.StatusBadRequest)
			return
		}
		check := *in.Inventory.Xray
		check.Traffic = in.Traffic
		if !check.Valid() {
			http.Error(w, "invalid heartbeat traffic sample", http.StatusBadRequest)
			return
		}
	}
	err := s.store.RecordNodeHeartbeat(r.Context(), node.ID, node.TokenHash, time.Now().Unix(), in.Inventory)
	if err != nil {
		http.Error(w, "heartbeat unavailable", http.StatusServiceUnavailable)
		return
	}
	if in.Traffic != nil {
		if err := s.store.RecordXrayTraffic(r.Context(), node.ID, node.TokenHash, *in.Traffic); err != nil {
			http.Error(w, "heartbeat traffic unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok", "node_id": node.ID, "inventory": "v1",
		"xray_plan": "v1", "xray_draft": node.XrayDraft,
	})
}
