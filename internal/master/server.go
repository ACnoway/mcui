package master

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/ACnoway/mcui/internal/store"
	"golang.org/x/crypto/argon2"
)

const (
	maxBody              = 1 << 20
	sessionIdleLimit     = 15 * time.Minute
	sessionAbsoluteLimit = 8 * time.Hour
	sensitiveMFALimit    = 10 * time.Minute
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
	installer      *agentInstaller
	nodeAccess     sync.RWMutex
	taskRuntime    *TaskRuntime
	taskCheckpoint *taskCheckpoint
	coreCatalog    corecatalog.Source
	coreBackups    corecatalog.BackupSnapshotter
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
	ID       string `json:"id"`
	Name     string `json:"name"`
	Group    string `json:"group"`
	LastSeen int64  `json:"last_seen"`
	Disabled bool   `json:"disabled"`
	Pending  bool   `json:"pending"`
}

func New(s *store.Store, bootstrapToken, webDir string) *Server {
	x := &Server{store: s, bootstrapToken: bootstrapToken, coreCatalog: corecatalog.NewClient(), mux: http.NewServeMux(), attempts: map[string]attempt{}}
	x.mux.HandleFunc("GET /healthz", x.health)
	x.handleAPI("POST /api/v1/bootstrap", x.bootstrap)
	x.handleAPI("POST /api/v1/admin/login", x.login)
	x.handleAPI("POST /api/v1/admin/logout", x.logout)
	x.handleAPI("GET /api/v1/admin/me", x.me)
	x.handleAPI("GET /api/v1/admin/admins", x.admins)
	x.handleAPI("POST /api/v1/admin/admins", x.createAdmin)
	x.handleAPI("POST /api/v1/admin/admins/disable", x.disableAdmin)
	x.handleAPI("POST /api/v1/admin/nodes", x.createNode)
	x.handleAPI("POST /api/v1/admin/nodes/{id}/install-command", x.createInstallCommand)
	x.handleAPI("GET /api/v1/admin/nodes", x.nodes)
	x.handleAPI("GET /api/v1/admin/nodes/{id}", x.nodeDetail)
	x.handleAPI("GET /api/v1/admin/audit", x.audit)
	x.handleAPI("POST /api/v1/admin/tasks", x.createStatusTask)
	x.handleAPI("POST /api/v1/admin/tasks/{id}/cancel", x.cancelStatusTask)
	x.handleAPI("POST /api/v1/admin/tasks/{id}/skip", x.skipExpiredStatusTask)
	x.handleAPI("POST /api/v1/admin/tasks/{id}/void", x.voidUnissuedStatusTask)
	x.handleAPI("GET /api/v1/admin/tasks", x.listTasks)
	x.handleAPI("GET /api/v1/admin/tasks/{id}", x.taskDetail)
	x.handleAPI("GET /api/v1/admin/xray-installs", x.listXrayInstalls)
	x.handleAPI("POST /api/v1/admin/xray-installs", x.createXrayInstall)
	x.handleAPI("POST /api/v1/admin/xray-installs/{id}/signed-task", x.recordSignedXrayInstall)
	x.handleAPI("POST /api/v1/admin/xray-installs/{id}/dispatch", x.dispatchXrayInstall)
	x.handleAPI("GET /api/v1/admin/cores/releases", x.coreReleases)
	x.handleAPI("GET /api/v1/admin/cores/backups", x.coreBackupsSnapshot)
	x.handleAPI("POST /api/v1/admin/nodes/disable", x.disableNode)
	x.handleAPI("POST /api/v1/agent/enroll", x.enroll)
	x.handleAPI("POST /api/v1/agent/heartbeat", x.heartbeat)
	x.handleAPI("GET /api/v1/agent/tasks/next", x.nextTask)
	x.handleAPI("POST /api/v1/agent/tasks/ack", x.acknowledgeTask)
	x.handleAPI("POST /api/v1/agent/tasks/renew-install", x.renewXrayInstallLease)
	x.handleAPI("POST /api/v1/helper/tasks/authorize", x.authorizeHelperTask)
	if webDir != "" {
		x.mux.Handle("/", x.staticHandler(webDir))
	}
	return x
}

func (s *Server) Handler() http.Handler { return securityHeaders(s.mux) }

func (s *Server) ConfigureCoreCatalog(source corecatalog.Source) {
	if source != nil {
		s.coreCatalog = source
	}
}

func (s *Server) ConfigureCoreBackups(source corecatalog.BackupSnapshotter) {
	s.coreBackups = source
}

func (s *Server) coreBackupsSnapshot(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminAuth(r); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.coreBackups == nil {
		http.Error(w, "Core backup store unavailable", http.StatusServiceUnavailable)
		return
	}
	snapshot, err := s.coreBackups.Snapshot()
	if err != nil {
		http.Error(w, "Core backup metadata unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) coreReleases(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminAuth(r); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.coreCatalog == nil {
		http.Error(w, "release catalog unavailable", http.StatusServiceUnavailable)
		return
	}
	page := 1
	if raw := r.URL.Query().Get("page"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > corecatalog.MaxPage {
			http.Error(w, "invalid release catalog page", http.StatusBadRequest)
			return
		}
		page = parsed
	}
	var snapshot corecatalog.Snapshot
	var err error
	if page == 1 {
		snapshot, err = s.coreCatalog.List(r.Context())
	} else if paged, ok := s.coreCatalog.(interface {
		ListPage(context.Context, int) (corecatalog.Snapshot, error)
	}); ok {
		snapshot, err = paged.ListPage(r.Context(), page)
	} else {
		http.Error(w, "release catalog page unavailable", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		http.Error(w, "official release catalog unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

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
			if strings.EqualFold(a.Username, in.Username) {
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
		"can_prepare_xray_installs": r.TLS != nil && s.taskRuntime != nil && s.taskRuntime.XrayInstallPolicy != nil && ctx.Admin.Role == "operator",
		"all_nodes":                 ctx.Admin.AllNodes, "node_ids": ctx.Admin.NodeIDs, "node_groups": ctx.Admin.NodeGroups,
		"can_create_nodes":   ctx.Admin.Role == "security_admin" && (ctx.Admin.AllNodes || len(ctx.Admin.NodeGroups) > 0),
		"can_install_agents": r.TLS != nil && s.installer != nil && ctx.Admin.Role == "security_admin",
		"can_disable_nodes":  ctx.Admin.Role == "security_admin" && (ctx.Admin.AllNodes || len(ctx.Admin.NodeGroups) > 0 || len(ctx.Admin.NodeIDs) > 0),
		"csrf_token":         ctx.Session.CSRFToken, "mfa_recent": time.Now().Unix()-ctx.Session.MFAAt <= int64(sensitiveMFALimit.Seconds()),
	})
}

type AdminView struct {
	ID         string   `json:"id"`
	Username   string   `json:"username"`
	Role       string   `json:"role"`
	NodeIDs    []string `json:"node_ids"`
	NodeGroups []string `json:"node_groups"`
	Disabled   bool     `json:"disabled"`
}

func adminView(a store.Admin) AdminView {
	return AdminView{ID: a.ID, Username: a.Username, Role: a.Role, NodeIDs: append([]string{}, a.NodeIDs...), NodeGroups: append([]string{}, a.NodeGroups...), Disabled: a.Disabled}
}

func adminScopeWithin(actor, target store.Admin, st store.State) bool {
	if target.AllNodes {
		return actor.AllNodes
	}
	if len(target.NodeIDs)+len(target.NodeGroups) == 0 {
		return false
	}
	for _, id := range target.NodeIDs {
		node, ok := st.Nodes[id]
		if !ok || !canReadNode(actor, node) {
			return false
		}
	}
	for _, group := range target.NodeGroups {
		if !groupPattern.MatchString(group) || !canManageGroup(actor, group) {
			return false
		}
	}
	return true
}

func (s *Server) admins(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.adminAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if ctx.Admin.Role != "security_admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var out []AdminView
	if err := s.store.View(func(st store.State) error {
		actor, exists := st.Admins[ctx.Admin.ID]
		if !exists || actor.Disabled || actor.Role != "security_admin" {
			return errors.New("administrator unavailable")
		}
		for _, candidate := range st.Admins {
			if candidate.ID == actor.ID || (candidate.Role != "security_admin" && adminScopeWithin(actor, candidate, st)) {
				out = append(out, adminView(candidate))
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
		return nil
	}); err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	if out == nil {
		out = []AdminView{}
	}
	writeJSON(w, http.StatusOK, out)
}

func generateTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

func normalizeUnique(values []string, valid func(string) bool) ([]string, bool) {
	if len(values) > 200 {
		return nil, false
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !valid(value) {
			return nil, false
		}
		if _, exists := seen[value]; exists {
			return nil, false
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, true
}

func (s *Server) createAdmin(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.requireCSRF(w, r)
	if !ok {
		return
	}
	var in struct {
		Username   string   `json:"username"`
		Password   string   `json:"password"`
		Role       string   `json:"role"`
		NodeIDs    []string `json:"node_ids"`
		NodeGroups []string `json:"node_groups"`
		MFACode    string   `json:"mfa_code"`
	}
	if readJSON(r, &in) != nil || !usernamePattern.MatchString(in.Username) || len(in.Password) < 12 || len(in.Password) > 1024 || (in.Role != "auditor" && in.Role != "operator") {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	ids, idsOK := normalizeUnique(in.NodeIDs, func(v string) bool { return v != "" && len(v) <= 128 })
	groups, groupsOK := normalizeUnique(in.NodeGroups, func(v string) bool { return groupPattern.MatchString(v) })
	if !idsOK || !groupsOK || len(ids)+len(groups) == 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !s.stepUp(ctx, in.MFACode) {
		http.Error(w, "MFA re-verification required", http.StatusPreconditionRequired)
		return
	}
	secret, err := generateTOTPSecret()
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
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
	now := time.Now().Unix()
	err = s.store.Update(func(st *store.State) error {
		actor, exists := st.Admins[ctx.Admin.ID]
		if !exists || actor.Disabled || actor.Role != "security_admin" || !adminScopeWithin(actor, store.Admin{NodeIDs: ids, NodeGroups: groups}, *st) {
			return store.ErrNotFound
		}
		for _, candidate := range st.Admins {
			if strings.EqualFold(candidate.Username, in.Username) {
				return errors.New("username already exists")
			}
		}
		st.Admins[id] = store.Admin{ID: id, Username: in.Username, PasswordHash: salt + ":" + passwordHash(in.Password, salt), TOTPSecret: secret, Role: in.Role, NodeIDs: ids, NodeGroups: groups}
		s.appendAudit(st, store.Audit{At: now, Actor: actor.ID, Action: "admin.create", ResourceType: "admin", Resource: id, Outcome: "success"})
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "scope not permitted", http.StatusForbidden)
		return
	}
	if err != nil {
		http.Error(w, "administrator creation unavailable", http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"admin": AdminView{ID: id, Username: in.Username, Role: in.Role, NodeIDs: ids, NodeGroups: groups}, "totp_secret": secret})
}

func (s *Server) disableAdmin(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.requireCSRF(w, r)
	if !ok {
		return
	}
	var in struct {
		AdminID string `json:"admin_id"`
		MFACode string `json:"mfa_code"`
	}
	if readJSON(r, &in) != nil || in.AdminID == "" || in.AdminID == ctx.Admin.ID {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !s.stepUp(ctx, in.MFACode) {
		http.Error(w, "MFA re-verification required", http.StatusPreconditionRequired)
		return
	}
	now := time.Now().Unix()
	err := s.store.Update(func(st *store.State) error {
		actor, actorOK := st.Admins[ctx.Admin.ID]
		target, targetOK := st.Admins[in.AdminID]
		if !actorOK || actor.Disabled || actor.Role != "security_admin" || !targetOK || target.Role == "security_admin" || !adminScopeWithin(actor, target, *st) {
			return store.ErrNotFound
		}
		if target.Disabled {
			return nil
		}
		target.Disabled = true
		st.Admins[target.ID] = target
		for sessionID, session := range st.Sessions {
			if session.AdminID == target.ID {
				delete(st.Sessions, sessionID)
			}
		}
		s.appendAudit(st, store.Audit{At: now, Actor: actor.ID, Action: "admin.disable", ResourceType: "admin", Resource: target.ID, Outcome: "success"})
		return nil
	})
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
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

func canManageNode(a store.Admin, n store.Node) bool {
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

func validRequestID(value string) bool { return requestPattern.MatchString(value) }

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
	if target.ID == "" || !canManageNode(ctx.Admin, target) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !s.stepUp(ctx, in.MFACode) {
		http.Error(w, "MFA re-verification required", http.StatusPreconditionRequired)
		return
	}
	s.nodeAccess.Lock()
	defer s.nodeAccess.Unlock()
	err := s.store.Update(func(st *store.State) error {
		n, exists := st.Nodes[in.NodeID]
		if !exists || !canManageNode(st.Admins[ctx.Admin.ID], n) {
			return store.ErrNotFound
		}
		n.Disabled = true
		n.TokenHash, n.InstallCodeHash, n.InstallCodeExpiresAt = "", "", 0
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
	return NodeView{ID: n.ID, Name: n.Name, Group: n.Group, LastSeen: n.LastSeen, Disabled: n.Disabled, Pending: !n.Disabled && (n.TokenHash == "" || n.LastSeen == 0)}
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
	case "task":
		node, ok := st.Nodes[event.NodeID]
		return ok && canReadNode(a, node)
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
