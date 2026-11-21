package master

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSingleAdminFirstLoginThroughTrustedProxy(t *testing.T) {
	s, db := testServer(t)
	s.EnableSingleAdmin()
	if err := s.ConfigureHTTPSProxy("https://PANEL.example.test:443", "10.20.0.1"); err != nil {
		t.Fatal(err)
	}
	username, initial, err := PrepareSingleAdmin(db, false)
	if err != nil || username == "" || initial == "" {
		t.Fatalf("initialize administrator: %v", err)
	}
	if user, pass, err := PrepareSingleAdmin(db, false); user != "" || pass != "" || err != nil {
		t.Fatalf("repeat initialization returned credentials or failed: %v", err)
	}
	_, rotated, err := PrepareSingleAdmin(db, true)
	if err != nil || rotated == "" || initial == rotated {
		t.Fatalf("recover pending administrator: %v", err)
	}

	h := s.Handler()
	request := func(method, path, remote, origin string, data map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, "http://panel.example.test"+path, strings.NewReader(string(raw)))
		r.RemoteAddr = remote
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-For", "203.0.113.10")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	const (
		peer   = "10.20.0.1:45678"
		origin = "https://panel.example.test"
		login  = "/api/v1/admin/login"
		setup  = "/api/v1/admin/setup"
	)
	body := map[string]string{"username": username, "password": rotated}
	if w := request(http.MethodPost, login, "10.20.0.2:45678", origin, body); w.Code != http.StatusForbidden {
		t.Fatalf("accepted forged proxy request: %d", w.Code)
	}
	if w := request(http.MethodPost, login, peer, "http://panel.example.test", body); w.Code != http.StatusBadRequest {
		t.Fatalf("accepted wrong Origin: %d", w.Code)
	}
	if w := request(http.MethodPost, login, peer, origin, map[string]string{"username": username, "password": initial}); w.Code != http.StatusUnauthorized {
		t.Fatalf("accepted previous initial password: %d", w.Code)
	}
	w := request(http.MethodPost, login, peer, origin, body)
	var first map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil || w.Code != http.StatusOK ||
		first["status"] != "setup_required" || first["csrf_token"] != "" || len(w.Result().Cookies()) != 0 {
		t.Fatalf("pending login created a session or failed: %d, %v", w.Code, err)
	}
	if w := request(http.MethodGet, "/api/v1/admin/nodes", peer, origin, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("pending account reached management: %d", w.Code)
	}
	key, err := base32Decode(first["totp_secret"])
	if err != nil || len(key) != 20 {
		t.Fatal("valid MFA enrollment secret was not provided")
	}
	const newPassword = "new-stronger-test-password"
	setupBody := map[string]string{
		"username": username, "initial_password": rotated, "new_password": newPassword,
		"totp_secret": first["totp_secret"], "code": fmtCode(totpAt(key, time.Now().Unix()/30)),
	}
	if w := request(http.MethodPost, setup, peer, origin, setupBody); w.Code != http.StatusOK {
		t.Fatalf("complete MFA and password change: %d %s", w.Code, w.Body)
	}
	if w := request(http.MethodPost, setup, peer, origin, setupBody); w.Code != http.StatusUnauthorized {
		t.Fatalf("first login setup could be replayed: %d", w.Code)
	}
	if _, _, err := PrepareSingleAdmin(db, true); err == nil {
		t.Fatal("offline initial recovery accepted an enrolled administrator")
	}
	if w := request(http.MethodPost, login, peer, origin, body); w.Code != http.StatusUnauthorized {
		t.Fatalf("accepted initial password after setup: %d", w.Code)
	}
	body["password"] = newPassword
	body["code"] = fmtCode(totpAt(key, time.Now().Unix()/30))
	w = request(http.MethodPost, login, peer, origin, body)
	cookies := w.Result().Cookies()
	if w.Code != http.StatusOK || len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected secure session through proxy: %d", w.Code)
	}
}
