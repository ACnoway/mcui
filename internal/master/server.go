package master

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/store"
	"golang.org/x/crypto/argon2"
)

const (
	maxBody              = 1 << 20
	sessionIdleLimit     = 15 * time.Minute
	sessionAbsoluteLimit = 8 * time.Hour
	sensitiveMFALimit    = 10 * time.Minute
	certificateOverlap   = 24 * time.Hour
)

var (
	groupPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	namePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$`)
	usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$`)
	requestPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)
)

type Server struct {
	store          *store.Store
	bootstrapToken string
	nodeCA         *security.CertificateAuthority
	mux            *http.ServeMux
	rateMu         sync.Mutex
	attempts       map[string]attempt
}

type attempt struct {
	count       int
	start       time.Time
	lockedUntil time.Time
}

type adminContext struct {
	Admin   store.Admin
	Session store.Session
	Token   string
}

type NodeView struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Group             string `json:"group"`
	LastSeen          int64  `json:"last_seen"`
	Disabled          bool   `json:"disabled"`
	NeedsReenrollment bool   `json:"needs_reenrollment,omitempty"`
}

func New(s *store.Store, bootstrapToken, webDir string) *Server {
	return NewWithNodeCA(s, bootstrapToken, webDir, nil)
}

func NewWithNodeCA(s *store.Store, bootstrapToken, webDir string, nodeCA *security.CertificateAuthority) *Server {
	x := &Server{store: s, bootstrapToken: bootstrapToken, nodeCA: nodeCA, mux: http.NewServeMux(), attempts: map[string]attempt{}}
	x.mux.HandleFunc("GET /healthz", x.health)
	x.mux.HandleFunc("POST /api/v1/bootstrap", x.bootstrap)
	x.mux.HandleFunc("POST /api/v1/admin/login", x.login)
	x.mux.HandleFunc("POST /api/v1/admin/logout", x.logout)
	x.mux.HandleFunc("GET /api/v1/admin/me", x.me)
	x.mux.HandleFunc("POST /api/v1/admin/invites", x.createInvite)
	x.mux.HandleFunc("GET /api/v1/admin/nodes", x.nodes)
	x.mux.HandleFunc("GET /api/v1/admin/nodes/{id}", x.nodeDetail)
	x.mux.HandleFunc("GET /api/v1/admin/audit", x.audit)
	x.mux.HandleFunc("POST /api/v1/admin/nodes/disable", x.disableNode)
	x.mux.HandleFunc("POST /api/v1/agent/enroll", x.enroll)
	x.mux.HandleFunc("POST /api/v1/agent/cert/rotate", x.rotateCertificate)
	x.mux.HandleFunc("POST /api/v1/agent/heartbeat", x.heartbeat)
	if webDir != "" {
		x.mux.Handle("/", x.staticHandler(webDir))
	}
	return x
}

func (s *Server) Handler() http.Handler { return securityHeaders(s.mux) }

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Vary", "Origin")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func readJSON(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBody)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return errors.New("invalid trailing JSON")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hash(v string) string {
	b := sha256.Sum256([]byte(v))
	return hex.EncodeToString(b[:])
}

func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	if !s.allowAttempt("bootstrap:" + clientAddress(r)) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	if !sameOriginRequest(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if s.bootstrapToken == "" {
		http.Error(w, "bootstrap disabled", http.StatusForbidden)
		return
	}
	var in struct {
		Token      string `json:"token"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		TOTPSecret string `json:"totp_secret"`
	}
	if readJSON(r, &in) != nil || subtle.ConstantTimeCompare([]byte(in.Token), []byte(s.bootstrapToken)) != 1 || !usernamePattern.MatchString(in.Username) || len(in.Password) < 12 || len(in.Password) > 1024 {
		http.Error(w, "invalid bootstrap request", http.StatusBadRequest)
		return
	}
	if _, err := base32Decode(strings.ToUpper(strings.TrimRight(in.TOTPSecret, "="))); err != nil {
		http.Error(w, "invalid TOTP secret", http.StatusBadRequest)
		return
	}
	id, err := randomToken(16)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	saltBytes := make([]byte, 16)
	if _, err = rand.Read(saltBytes); err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	salt := base64.RawStdEncoding.EncodeToString(saltBytes)
	err = s.store.Update(func(st *store.State) error {
		if len(st.Admins) > 0 {
			return errors.New("initialized")
		}
		for _, a := range st.Admins {
			if a.Username == in.Username {
				return errors.New("username already exists")
			}
		}
		st.Admins[id] = store.Admin{ID: id, Username: in.Username, PasswordHash: salt + ":" + passwordHash(in.Password, salt), TOTPSecret: strings.ToUpper(strings.TrimRight(in.TOTPSecret, "=")), Role: "security_admin", AllNodes: true}
		s.appendAudit(st, store.Audit{At: time.Now().Unix(), Actor: id, Action: "bootstrap.admin.create", ResourceType: "admin", Resource: id, Outcome: "success"})
		return nil
	})
	if err != nil {
		http.Error(w, "bootstrap unavailable", http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"admin_id": id})
}

func passwordHash(password, saltEncoded string) string {
	salt, err := base64.RawStdEncoding.DecodeString(saltEncoded)
	if err != nil {
		return ""
	}
	h := argon2.IDKey([]byte(password), salt, 2, 64*1024, 2, 32)
	return base64.RawStdEncoding.EncodeToString(h)
}

func (s *Server) allowAttempt(key string) bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	now := time.Now()
	if len(s.attempts) >= 10000 {
		for k, a := range s.attempts {
			if now.Sub(a.start) > 10*time.Minute && !now.Before(a.lockedUntil) {
				delete(s.attempts, k)
			}
		}
		if _, known := s.attempts[key]; !known && len(s.attempts) >= 10000 {
			return false
		}
	}
	a := s.attempts[key]
	if now.Before(a.lockedUntil) {
		return false
	}
	if a.start.IsZero() || now.Sub(a.start) > time.Minute {
		a = attempt{start: now}
	}
	a.count++
	if a.count > 10 {
		a.lockedUntil = now.Add(5 * time.Minute)
		s.attempts[key] = a
		return false
	}
	s.attempts[key] = a
	return true
}

func clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if readJSON(r, &in) != nil || !sameOriginRequest(r) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !usernamePattern.MatchString(in.Username) || len(in.Password) == 0 || len(in.Password) > 1024 || len(in.Code) != 6 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !s.allowAttempt("login-ip:"+clientAddress(r)) || !s.allowAttempt("login-user:"+hash(strings.ToLower(in.Username))) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	var a store.Admin
	_ = s.store.View(func(st store.State) error {
		for _, candidate := range st.Admins {
			if candidate.Username == in.Username {
				a = candidate
				break
			}
		}
		return nil
	})
	parts := strings.SplitN(a.PasswordHash, ":", 2)
	passwordOK := false
	if len(parts) == 2 {
		passwordOK = subtle.ConstantTimeCompare([]byte(parts[1]), []byte(passwordHash(in.Password, parts[0]))) == 1
	} else {
		// Keep the unknown-user path close to the real password-verification cost.
		_ = passwordHash(in.Password, "AAECAwQFBgcICQoLDA0ODw")
	}
	if !passwordOK || !validTOTP(a.TOTPSecret, in.Code, time.Now()) || a.Disabled {
		_ = s.recordAudit("anonymous", "admin.login", "admin", in.Username, "denied")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token, err := randomToken(32)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	csrfToken, err := randomToken(32)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	now := time.Now().Unix()
	session := store.Session{ID: hash(token), AdminID: a.ID, CreatedAt: now, LastSeen: now, MFAAt: now, ExpiresAt: now + int64(sessionAbsoluteLimit.Seconds()), CSRFToken: csrfToken}
	err = s.store.Update(func(st *store.State) error {
		st.Sessions[session.ID] = session
		s.appendAudit(st, store.Audit{At: now, Actor: a.ID, Action: "admin.login", ResourceType: "admin", Resource: a.ID, Outcome: "success"})
		return nil
	})
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "mcui_session", Value: token, Path: "/", Secure: r.TLS != nil, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionAbsoluteLimit.Seconds())})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "csrf_token": csrfToken})
}

func (s *Server) adminAuth(r *http.Request) (adminContext, bool) {
	cookie, err := r.Cookie("mcui_session")
	if err != nil || cookie.Value == "" {
		return adminContext{}, false
	}
	var a store.Admin
	var session store.Session
	valid := false
	now := time.Now().Unix()
	err = s.store.Update(func(st *store.State) error {
		id := hash(cookie.Value)
		ss, ok := st.Sessions[id]
		if !ok {
			return nil
		}
		admin, ok := st.Admins[ss.AdminID]
		if !ok || admin.Disabled || ss.ExpiresAt <= now || ss.LastSeen <= 0 || now-ss.LastSeen > int64(sessionIdleLimit.Seconds()) {
			delete(st.Sessions, id)
			return nil
		}
		ss.LastSeen = now
		st.Sessions[id] = ss
		a, session, valid = admin, ss, true
		return nil
	})
	if err != nil || !valid {
		return adminContext{}, false
	}
	return adminContext{Admin: a, Session: session, Token: cookie.Value}, true
}

func sameOriginRequest(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin != "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		return origin == scheme+"://"+r.Host
	}
	site := r.Header.Get("Sec-Fetch-Site")
	return site == "same-origin" || site == "none"
}

func csrfOK(r *http.Request, ctx adminContext) bool {
	provided := r.Header.Get("X-CSRF-Token")
	return sameOriginRequest(r) && provided != "" && len(provided) == len(ctx.Session.CSRFToken) && subtle.ConstantTimeCompare([]byte(provided), []byte(ctx.Session.CSRFToken)) == 1
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.adminAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": ctx.Admin.ID, "username": ctx.Admin.Username, "role": ctx.Admin.Role,
		"all_nodes": ctx.Admin.AllNodes, "node_ids": ctx.Admin.NodeIDs, "node_groups": ctx.Admin.NodeGroups,
		"can_create_invites": ctx.Admin.Role == "security_admin" && (ctx.Admin.AllNodes || len(ctx.Admin.NodeGroups) > 0),
		"can_disable_nodes":  ctx.Admin.Role == "security_admin" && (ctx.Admin.AllNodes || len(ctx.Admin.NodeGroups) > 0 || len(ctx.Admin.NodeIDs) > 0),
		"csrf_token":         ctx.Session.CSRFToken, "mfa_recent": time.Now().Unix()-ctx.Session.MFAAt <= int64(sensitiveMFALimit.Seconds()),
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.adminAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !csrfOK(r, ctx) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = s.store.Update(func(st *store.State) error {
		delete(st.Sessions, ctx.Session.ID)
		s.appendAudit(st, store.Audit{At: time.Now().Unix(), Actor: ctx.Admin.ID, Action: "admin.logout", ResourceType: "admin", Resource: ctx.Admin.ID, Outcome: "success"})
		return nil
	})
	http.SetCookie(w, &http.Cookie{Name: "mcui_session", Value: "", Path: "/", Secure: r.TLS != nil, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func hasValue(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func canReadNode(a store.Admin, n store.Node) bool {
	if a.Disabled || (a.Role != "security_admin" && a.Role != "operator" && a.Role != "auditor") {
		return false
	}
	return a.AllNodes || hasValue(a.NodeIDs, n.ID) || hasValue(a.NodeGroups, n.Group)
}

func canManageGroup(a store.Admin, group string) bool {
	return !a.Disabled && a.Role == "security_admin" && (a.AllNodes || hasValue(a.NodeGroups, group))
}

func canDisableNode(a store.Admin, n store.Node) bool {
	return a.Role == "security_admin" && canReadNode(a, n)
}

func (s *Server) requireCSRF(w http.ResponseWriter, r *http.Request) (adminContext, bool) {
	ctx, ok := s.adminAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return adminContext{}, false
	}
	if !csrfOK(r, ctx) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return adminContext{}, false
	}
	return ctx, true
}

func (s *Server) stepUp(ctx adminContext, code string) bool {
	now := time.Now()
	if now.Unix()-ctx.Session.MFAAt <= int64(sensitiveMFALimit.Seconds()) {
		return true
	}
	if !validTOTP(ctx.Admin.TOTPSecret, code, now) {
		return false
	}
	return s.store.Update(func(st *store.State) error {
		ss, ok := st.Sessions[ctx.Session.ID]
		if !ok || ss.AdminID != ctx.Admin.ID || ss.ExpiresAt <= now.Unix() {
			return errors.New("session expired")
		}
		ss.MFAAt = now.Unix()
		st.Sessions[ctx.Session.ID] = ss
		s.appendAudit(st, store.Audit{At: now.Unix(), Actor: ctx.Admin.ID, Action: "admin.mfa.step_up", ResourceType: "admin", Resource: ctx.Admin.ID, Outcome: "success"})
		return nil
	}) == nil
}

func (s *Server) createInvite(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.requireCSRF(w, r)
	if !ok {
		return
	}
	var in struct {
		NodeGroup  string `json:"node_group"`
		TTLSeconds int64  `json:"ttl_seconds"`
		MFACode    string `json:"mfa_code"`
	}
	if readJSON(r, &in) != nil || !groupPattern.MatchString(in.NodeGroup) || in.TTLSeconds < 60 || in.TTLSeconds > 86400 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !canManageGroup(ctx.Admin, in.NodeGroup) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !s.stepUp(ctx, in.MFACode) {
		http.Error(w, "MFA re-verification required", http.StatusPreconditionRequired)
		return
	}
	token, err := randomToken(32)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	expires := time.Now().Unix() + in.TTLSeconds
	err = s.store.Update(func(st *store.State) error {
		st.Invites[hash(token)] = store.Invite{Hash: hash(token), NodeGroup: in.NodeGroup, ExpiresAt: expires}
		s.appendAudit(st, store.Audit{At: time.Now().Unix(), Actor: ctx.Admin.ID, Action: "node.invite.create", ResourceType: "node_group", Resource: in.NodeGroup, Outcome: "success"})
		return nil
	})
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"invite": token, "expires_at": expires})
}

func validRequestID(value string) bool { return requestPattern.MatchString(value) }

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "HTTPS required", http.StatusUpgradeRequired)
		return
	}
	if s.nodeCA == nil {
		http.Error(w, "node CA unavailable", http.StatusServiceUnavailable)
		return
	}
	if !s.allowAttempt("enroll:" + clientAddress(r)) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	var in struct {
		Invite    string `json:"invite"`
		Name      string `json:"name"`
		RequestID string `json:"request_id"`
		CSR       string `json:"csr_pem"`
	}
	if readJSON(r, &in) != nil || in.Invite == "" || !namePattern.MatchString(in.Name) || !validRequestID(in.RequestID) || in.CSR == "" {
		http.Error(w, "invalid registration request", http.StatusBadRequest)
		return
	}
	csrPEM, err := base64.RawStdEncoding.DecodeString(in.CSR)
	if err != nil || len(csrPEM) > 16*1024 {
		http.Error(w, "invalid CSR", http.StatusBadRequest)
		return
	}
	csr, err := security.ParseCSR(csrPEM)
	if err != nil {
		http.Error(w, "invalid CSR", http.StatusBadRequest)
		return
	}
	csrHash := hash(in.CSR)
	inviteHash := hash(in.Invite)
	requestHash := hash(in.Name + "\x00" + csrHash + "\x00" + inviteHash)
	nodeID, err := security.NewNodeID()
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	var result store.Enrollment
	now := time.Now()
	err = s.store.Update(func(st *store.State) error {
		if old, exists := st.Enrollments[in.RequestID]; exists {
			if old.RequestHash != requestHash {
				return errors.New("registration request ID reused")
			}
			result = old
			return nil
		}
		iv, exists := st.Invites[inviteHash]
		if !exists || iv.Used || iv.ExpiresAt <= now.Unix() {
			return errors.New("invalid invitation")
		}
		certPEM, serial, notAfter, err := s.nodeCA.IssueNodeCertificate(csr, nodeID, now)
		if err != nil {
			return err
		}
		pubDER, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
		node := store.Node{
			ID: nodeID, Name: in.Name, Group: iv.NodeGroup,
			PublicKey: base64.RawStdEncoding.EncodeToString(pubDER), LastSeen: now.Unix(), CurrentSerial: serial,
			Certificates: map[string]store.NodeCertificate{serial: {NotAfter: notAfter}},
			CertRequests: map[string]store.CertificateIssue{},
		}
		iv.Used = true
		st.Invites[inviteHash] = iv
		st.Nodes[nodeID] = node
		result = store.Enrollment{RequestID: in.RequestID, RequestHash: requestHash, InviteHash: inviteHash, CSRHash: csrHash, NodeID: nodeID, CertificatePEM: string(certPEM), Serial: serial, NotAfter: notAfter, CreatedAt: now.Unix()}
		st.Enrollments[in.RequestID] = result
		s.appendAudit(st, store.Audit{At: now.Unix(), Actor: nodeID, Action: "node.enroll", ResourceType: "node", Resource: nodeID, Outcome: "success"})
		return nil
	})
	if err != nil {
		_ = s.recordAudit("anonymous", "node.enroll", "node_group", inviteHash, "denied")
		http.Error(w, "registration denied", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"node_id": result.NodeID, "certificate_pem": result.CertificatePEM, "serial": result.Serial, "expires_at": time.Unix(result.NotAfter, 0).UTC().Format(time.RFC3339)})
}

func (s *Server) rotateCertificate(w http.ResponseWriter, r *http.Request) {
	node, serial, ok := s.authenticateNode(r)
	if !ok {
		http.Error(w, "node certificate rejected", http.StatusUnauthorized)
		return
	}
	if !s.allowAttempt("rotate:" + node.ID) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	if s.nodeCA == nil {
		http.Error(w, "node CA unavailable", http.StatusServiceUnavailable)
		return
	}
	var in struct {
		RequestID string `json:"request_id"`
		CSR       string `json:"csr_pem"`
	}
	if readJSON(r, &in) != nil || !validRequestID(in.RequestID) || in.CSR == "" {
		http.Error(w, "invalid rotation request", http.StatusBadRequest)
		return
	}
	csrPEM, err := base64.RawStdEncoding.DecodeString(in.CSR)
	if err != nil || len(csrPEM) > 16*1024 {
		http.Error(w, "invalid CSR", http.StatusBadRequest)
		return
	}
	csr, err := security.ParseCSR(csrPEM)
	if err != nil {
		http.Error(w, "invalid CSR", http.StatusBadRequest)
		return
	}
	csrHash := hash(in.CSR)
	now := time.Now()
	var issue store.CertificateIssue
	err = s.store.Update(func(st *store.State) error {
		n, exists := st.Nodes[node.ID]
		if !exists || n.Disabled {
			return store.ErrNotFound
		}
		if previous, exists := n.CertRequests[in.RequestID]; exists {
			if previous.CSRHash != csrHash {
				return errors.New("rotation request ID reused")
			}
			issue = previous
			return nil
		}
		if n.CurrentSerial != serial {
			return errors.New("rotation requires the current certificate")
		}
		newPEM, newSerial, notAfter, err := s.nodeCA.IssueNodeCertificate(csr, n.ID, now)
		if err != nil {
			return err
		}
		old := n.Certificates[serial]
		old.ValidUntil = now.Add(certificateOverlap).Unix()
		if old.ValidUntil > old.NotAfter {
			old.ValidUntil = old.NotAfter
		}
		n.Certificates[serial] = old
		n.Certificates[newSerial] = store.NodeCertificate{NotAfter: notAfter}
		n.CurrentSerial = newSerial
		if n.CertRequests == nil {
			n.CertRequests = map[string]store.CertificateIssue{}
		}
		issue = store.CertificateIssue{CSRHash: csrHash, CertificatePEM: string(newPEM), Serial: newSerial, NotAfter: notAfter}
		n.CertRequests[in.RequestID] = issue
		st.Nodes[n.ID] = n
		s.appendAudit(st, store.Audit{At: now.Unix(), Actor: n.ID, Action: "node.certificate.rotate", ResourceType: "node", Resource: n.ID, Outcome: "success"})
		return nil
	})
	if err != nil {
		http.Error(w, "rotation rejected", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"certificate_pem": issue.CertificatePEM, "serial": issue.Serial, "expires_at": time.Unix(issue.NotAfter, 0).UTC().Format(time.RFC3339)})
}

func (s *Server) authenticateNode(r *http.Request) (store.Node, string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return store.Node{}, "", false
	}
	cert := r.TLS.PeerCertificates[0]
	nodeID, err := security.NodeIDFromCertificate(cert)
	if err != nil || cert.NotBefore.After(time.Now()) || !cert.NotAfter.After(time.Now()) {
		return store.Node{}, "", false
	}
	serial := cert.SerialNumber.String()
	var node store.Node
	valid := false
	_ = s.store.View(func(st store.State) error {
		n, exists := st.Nodes[nodeID]
		if !exists || n.Disabled {
			return nil
		}
		issued, exists := n.Certificates[serial]
		if !exists || issued.Revoked || issued.NotAfter <= time.Now().Unix() || (issued.ValidUntil != 0 && issued.ValidUntil <= time.Now().Unix()) {
			return nil
		}
		node, valid = n, true
		return nil
	})
	return node, serial, valid
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	node, _, ok := s.authenticateNode(r)
	if !ok {
		http.Error(w, "node certificate rejected", http.StatusUnauthorized)
		return
	}
	now := time.Now().Unix()
	err := s.store.Update(func(st *store.State) error {
		current, exists := st.Nodes[node.ID]
		if !exists || current.Disabled {
			return store.ErrNotFound
		}
		current.LastSeen = now
		st.Nodes[node.ID] = current
		return nil
	})
	if err != nil {
		http.Error(w, "node unavailable", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "node_id": node.ID})
}

func (s *Server) disableNode(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.requireCSRF(w, r)
	if !ok {
		return
	}
	var in struct {
		NodeID  string `json:"node_id"`
		MFACode string `json:"mfa_code"`
	}
	if readJSON(r, &in) != nil || in.NodeID == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var target store.Node
	_ = s.store.View(func(st store.State) error { target = st.Nodes[in.NodeID]; return nil })
	if target.ID == "" || !canDisableNode(ctx.Admin, target) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !s.stepUp(ctx, in.MFACode) {
		http.Error(w, "MFA re-verification required", http.StatusPreconditionRequired)
		return
	}
	err := s.store.Update(func(st *store.State) error {
		n, exists := st.Nodes[in.NodeID]
		if !exists || !canDisableNode(ctx.Admin, n) {
			return store.ErrNotFound
		}
		n.Disabled = true
		for serial, cert := range n.Certificates {
			cert.Revoked = true
			n.Certificates[serial] = cert
		}
		st.Nodes[in.NodeID] = n
		s.appendAudit(st, store.Audit{At: time.Now().Unix(), Actor: ctx.Admin.ID, Action: "node.disable", ResourceType: "node", Resource: n.ID, Outcome: "success"})
		return nil
	})
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
}

func nodeView(n store.Node) NodeView {
	return NodeView{ID: n.ID, Name: n.Name, Group: n.Group, LastSeen: n.LastSeen, Disabled: n.Disabled, NeedsReenrollment: n.NeedsReenrollment}
}

func (s *Server) nodes(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.adminAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var out []NodeView
	_ = s.store.View(func(st store.State) error {
		for _, n := range st.Nodes {
			if canReadNode(ctx.Admin, n) {
				out = append(out, nodeView(n))
			}
		}
		return nil
	})
	if out == nil {
		out = []NodeView{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) nodeDetail(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.adminAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var node store.Node
	_ = s.store.View(func(st store.State) error { node = st.Nodes[r.PathValue("id")]; return nil })
	if node.ID == "" || !canReadNode(ctx.Admin, node) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, nodeView(node))
}

func auditVisible(a store.Admin, st store.State, event store.Audit) bool {
	if a.AllNodes {
		return true
	}
	switch event.ResourceType {
	case "node":
		node, ok := st.Nodes[event.Resource]
		return ok && canReadNode(a, node)
	case "node_group":
		return a.Role == "security_admin" && hasValue(a.NodeGroups, event.Resource)
	case "admin":
		return event.Resource == a.ID || event.Actor == a.ID
	default:
		return false
	}
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.adminAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var out []store.Audit
	_ = s.store.View(func(st store.State) error {
		for _, event := range st.Audits {
			if auditVisible(ctx.Admin, st, event) {
				out = append(out, event)
			}
		}
		return nil
	})
	if out == nil {
		out = []store.Audit{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) appendAudit(st *store.State, event store.Audit) {
	st.Audits = append(st.Audits, event)
	if len(st.Audits) > 10000 {
		st.Audits = append([]store.Audit(nil), st.Audits[len(st.Audits)-10000:]...)
	}
}

func (s *Server) recordAudit(actor, action, resourceType, resource, outcome string) error {
	return s.store.Update(func(st *store.State) error {
		s.appendAudit(st, store.Audit{At: time.Now().Unix(), Actor: actor, Action: action, ResourceType: resourceType, Resource: resource, Outcome: outcome})
		return nil
	})
}
