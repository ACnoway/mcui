package master

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ACnoway/mcui/internal/store"
	"golang.org/x/crypto/argon2"
)

const maxBody = 1 << 20

type Server struct {
	store          *store.Store
	bootstrapToken string
	mux            *http.ServeMux
	rateMu         sync.Mutex
	attempts       map[string]attempt
}
type attempt struct {
	count       int
	start       time.Time
	lockedUntil time.Time
}

func New(s *store.Store, bootstrapToken, webDir string) *Server {
	x := &Server{store: s, bootstrapToken: bootstrapToken, mux: http.NewServeMux(), attempts: map[string]attempt{}}
	x.mux.HandleFunc("GET /healthz", x.health)
	x.mux.HandleFunc("POST /api/v1/bootstrap", x.bootstrap)
	x.mux.HandleFunc("POST /api/v1/admin/login", x.login)
	x.mux.HandleFunc("POST /api/v1/admin/logout", x.logout)
	x.mux.HandleFunc("POST /api/v1/admin/invites", x.createInvite)
	x.mux.HandleFunc("GET /api/v1/admin/nodes", x.nodes)
	x.mux.HandleFunc("GET /api/v1/admin/audit", x.audit)
	x.mux.HandleFunc("POST /api/v1/admin/nodes/disable", x.disableNode)
	x.mux.HandleFunc("POST /api/v1/agent/enroll", x.enroll)
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
func readJSON(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBody)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(dst); e != nil {
		return e
	}
	var x any
	if d.Decode(&x) != io.EOF {
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
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func hash(v string) string { b := sha256.Sum256([]byte(v)); return hex.EncodeToString(b[:]) }
func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	if s.bootstrapToken == "" {
		http.Error(w, "bootstrap disabled", 403)
		return
	}
	var in struct {
		Token      string `json:"token"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		TOTPSecret string `json:"totp_secret"`
	}
	if readJSON(r, &in) != nil || subtle.ConstantTimeCompare([]byte(in.Token), []byte(s.bootstrapToken)) != 1 || len(in.Username) < 3 || len(in.Password) < 12 {
		http.Error(w, "invalid bootstrap request", 400)
		return
	}
	if _, err := base32Decode(strings.ToUpper(strings.TrimRight(in.TOTPSecret, "="))); err != nil {
		http.Error(w, "invalid TOTP secret", 400)
		return
	}
	id, err := randomToken(16)
	if err != nil {
		http.Error(w, "unavailable", 500)
		return
	}
	saltBytes := make([]byte, 16)
	if _, err = rand.Read(saltBytes); err != nil {
		http.Error(w, "unavailable", 500)
		return
	}
	salt := base64.RawStdEncoding.EncodeToString(saltBytes)
	e := s.store.Update(func(st *store.State) error {
		if len(st.Admins) > 0 {
			return errors.New("initialized")
		}
		st.Admins[id] = store.Admin{ID: id, Username: in.Username, PasswordHash: salt + ":" + passwordHash(in.Password, salt), TOTPSecret: strings.ToUpper(strings.TrimRight(in.TOTPSecret, "=")), Role: "security_admin"}
		st.Audits = append(st.Audits, store.Audit{At: time.Now().Unix(), Actor: id, Action: "bootstrap.admin.create", Outcome: "success"})
		return nil
	})
	if e != nil {
		http.Error(w, "bootstrap unavailable", 409)
		return
	}
	writeJSON(w, 201, map[string]string{"admin_id": id})
}
func passwordHash(p, s string) string {
	salt, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	h := argon2.IDKey([]byte(p), salt, 2, 64*1024, 2, 32)
	return base64.RawStdEncoding.EncodeToString(h)
}
func (s *Server) allowAttempt(key string) bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	now := time.Now()
	a := s.attempts[key]
	if now.Before(a.lockedUntil) {
		return false
	}
	if now.Sub(a.start) > time.Minute {
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
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.allowAttempt(r.RemoteAddr) {
		http.Error(w, "too many attempts", 429)
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if readJSON(r, &in) != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	var a store.Admin
	_ = s.store.View(func(st store.State) error {
		for _, v := range st.Admins {
			if v.Username == in.Username {
				a = v
			}
		}
		return nil
	})
	parts := strings.SplitN(a.PasswordHash, ":", 2)
	if len(parts) != 2 || subtle.ConstantTimeCompare([]byte(parts[1]), []byte(passwordHash(in.Password, parts[0]))) != 1 || !validTOTP(a.TOTPSecret, in.Code, time.Now()) || a.Disabled {
		_ = s.recordAudit("anonymous", "admin.login", "", "denied")
		http.Error(w, "unauthorized", 401)
		return
	}
	token, e := randomToken(32)
	if e != nil {
		http.Error(w, "unavailable", 500)
		return
	}
	now := time.Now().Unix()
	e = s.store.Update(func(st *store.State) error {
		st.Sessions[hash(token)] = store.Session{ID: hash(token), AdminID: a.ID, CreatedAt: now, ExpiresAt: now + 8*3600}
		st.Audits = append(st.Audits, store.Audit{At: now, Actor: a.ID, Action: "admin.login", Outcome: "success"})
		return nil
	})
	if e != nil {
		http.Error(w, "unavailable", 500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "mcui_session", Value: token, Path: "/", Secure: r.TLS != nil, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600})
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	if !csrfOK(r) {
		http.Error(w, "forbidden", 403)
		return
	}
	c, _ := r.Cookie("mcui_session")
	_ = s.store.Update(func(st *store.State) error {
		delete(st.Sessions, hash(c.Value))
		st.Audits = append(st.Audits, store.Audit{At: time.Now().Unix(), Actor: a.ID, Action: "admin.logout", Outcome: "success"})
		return nil
	})
	http.SetCookie(w, &http.Cookie{Name: "mcui_session", Value: "", Path: "/", Secure: r.TLS != nil, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
func (s *Server) authenticate(r *http.Request) (store.Admin, bool) {
	c, e := r.Cookie("mcui_session")
	if e != nil {
		return store.Admin{}, false
	}
	var a store.Admin
	ok := false
	now := time.Now().Unix()
	_ = s.store.View(func(st store.State) error {
		ss, yes := st.Sessions[hash(c.Value)]
		a, yesA := st.Admins[ss.AdminID]
		ok = yes && yesA && !a.Disabled && ss.ExpiresAt > now
		return nil
	})
	return a, ok
}
func csrfOK(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin != "" {
		return origin == "http://"+r.Host || origin == "https://"+r.Host
	}
	return r.Header.Get("Sec-Fetch-Site") == "same-origin" || r.Header.Get("Sec-Fetch-Site") == "none"
}
func (s *Server) createInvite(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	if !csrfOK(r) {
		http.Error(w, "forbidden", 403)
		return
	}
	var in struct {
		NodeGroup  string `json:"node_group"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	if readJSON(r, &in) != nil || in.NodeGroup == "" || in.TTLSeconds < 60 || in.TTLSeconds > 86400 {
		http.Error(w, "invalid request", 400)
		return
	}
	token, e := randomToken(32)
	if e != nil {
		http.Error(w, "unavailable", 500)
		return
	}
	exp := time.Now().Unix() + in.TTLSeconds
	e = s.store.Update(func(st *store.State) error {
		st.Invites[hash(token)] = store.Invite{Hash: hash(token), NodeGroup: in.NodeGroup, ExpiresAt: exp}
		st.Audits = append(st.Audits, store.Audit{At: time.Now().Unix(), Actor: a.ID, Action: "node.invite.create", Resource: in.NodeGroup, Outcome: "success"})
		return nil
	})
	if e != nil {
		http.Error(w, "unavailable", 500)
		return
	}
	writeJSON(w, 201, map[string]any{"invite": token, "expires_at": exp})
}
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Invite    string `json:"invite"`
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}
	if readJSON(r, &in) != nil || in.Invite == "" || in.Name == "" || in.PublicKey == "" {
		http.Error(w, "invalid request", 400)
		return
	}
	pub, e := base64.StdEncoding.DecodeString(in.PublicKey)
	if e != nil || len(pub) != 32 {
		http.Error(w, "invalid public key", 400)
		return
	}
	id, e := randomToken(16)
	if e != nil {
		http.Error(w, "unavailable", 500)
		return
	}
	token, e := randomToken(32)
	if e != nil {
		http.Error(w, "unavailable", 500)
		return
	}
	now := time.Now().Unix()
	e = s.store.Update(func(st *store.State) error {
		ih := hash(in.Invite)
		iv, ok := st.Invites[ih]
		if !ok || iv.Used || iv.ExpiresAt <= now {
			return errors.New("invalid invite")
		}
		iv.Used = true
		st.Invites[ih] = iv
		st.Nodes[id] = store.Node{ID: id, Name: in.Name, Group: iv.NodeGroup, PublicKey: in.PublicKey, TokenHash: hash(token), LastSeen: now}
		st.Audits = append(st.Audits, store.Audit{At: now, Actor: id, Action: "node.enroll", Resource: id, Outcome: "success"})
		return nil
	})
	if e != nil {
		http.Error(w, "registration denied", 403)
		return
	}
	writeJSON(w, 201, map[string]string{"node_id": id, "node_token": token, "transport": "http-development-only"})
}
func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	p := strings.Fields(r.Header.Get("Authorization"))
	if len(p) != 2 || p[0] != "Bearer" {
		http.Error(w, "node token required", 401)
		return
	}
	th := hash(p[1])
	var id string
	e := s.store.Update(func(st *store.State) error {
		for k, n := range st.Nodes {
			if n.TokenHash != "" && subtle.ConstantTimeCompare([]byte(n.TokenHash), []byte(th)) == 1 {
				if n.Disabled {
					return errors.New("disabled")
				}
				n.LastSeen = time.Now().Unix()
				st.Nodes[k] = n
				id = k
				return nil
			}
		}
		return errors.New("unknown")
	})
	if e != nil {
		http.Error(w, "node unavailable", 403)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok", "node_id": id})
}
func (s *Server) disableNode(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	if !csrfOK(r) {
		http.Error(w, "forbidden", 403)
		return
	}
	var in struct {
		NodeID string `json:"node_id"`
	}
	if readJSON(r, &in) != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	e := s.store.Update(func(st *store.State) error {
		n, ok := st.Nodes[in.NodeID]
		if !ok {
			return store.ErrNotFound
		}
		n.Disabled = true
		st.Nodes[in.NodeID] = n
		st.Audits = append(st.Audits, store.Audit{At: time.Now().Unix(), Actor: a.ID, Action: "node.disable", Resource: n.ID, Outcome: "success"})
		return nil
	})
	if e != nil {
		http.Error(w, "not found", 404)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "disabled"})
}
func (s *Server) nodes(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	if a.Role != "security_admin" && a.Role != "operator" && a.Role != "auditor" {
		http.Error(w, "forbidden", 403)
		return
	}
	var out []store.Node
	_ = s.store.View(func(st store.State) error {
		for _, n := range st.Nodes {
			n.PublicKey = ""
			n.TokenHash = ""
			n.Certificate = ""
			n.RevokedSerial = ""
			out = append(out, n)
		}
		return nil
	})
	writeJSON(w, 200, out)
}
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authenticate(r); !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	var out []store.Audit
	_ = s.store.View(func(st store.State) error { out = append(out, st.Audits...); return nil })
	writeJSON(w, 200, out)
}
func (s *Server) appendAudit(st *store.State, event store.Audit) {
	st.Audits = append(st.Audits, event)
	if len(st.Audits) > 10000 {
		st.Audits = append([]store.Audit(nil), st.Audits[len(st.Audits)-10000:]...)
	}
}
func (s *Server) recordAudit(actor, action, resource, outcome string) error {
	return s.store.Update(func(st *store.State) error {
		s.appendAudit(st, store.Audit{At: time.Now().Unix(), Actor: actor, Action: action, Resource: resource, Outcome: outcome})
		return nil
	})
}
