package master

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/store"
)

func testServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, e := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st, "", ""), st
}
func requestJSON(t *testing.T, h http.Handler, path string, v any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(v)
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(b)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestInviteEnrollmentOneTimeAndTokenHeartbeat(t *testing.T) {
	s, st := testServer(t)
	invite := "enrollment-secret"
	_ = st.Update(func(x *store.State) error {
		x.Invites[hash(invite)] = store.Invite{Hash: hash(invite), NodeGroup: "group-a", ExpiresAt: time.Now().Add(time.Hour).Unix()}
		return nil
	})
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	body := map[string]string{"invite": invite, "name": "node-a", "public_key": base64.StdEncoding.EncodeToString(pub)}
	w := requestJSON(t, s.Handler(), "/api/v1/agent/enroll", body)
	if w.Code != 201 {
		t.Fatalf("enroll=%d %s", w.Code, w.Body)
	}
	var result map[string]string
	if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if result["node_token"] == "" {
		t.Fatal("node token missing")
	}
	if again := requestJSON(t, s.Handler(), "/api/v1/agent/enroll", body); again.Code != 403 {
		t.Fatalf("reused invite status=%d", again.Code)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer "+result["node_token"])
	hb := httptest.NewRecorder()
	s.Handler().ServeHTTP(hb, r)
	if hb.Code != 200 {
		t.Fatalf("heartbeat=%d %s", hb.Code, hb.Body)
	}
}
func TestDisabledNodeCannotHeartbeat(t *testing.T) {
	s, st := testServer(t)
	token := "node-token"
	_ = st.Update(func(x *store.State) error {
		x.Nodes["n1"] = store.Node{ID: "n1", TokenHash: hash(token), Disabled: true}
		return nil
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("heartbeat status=%d", w.Code)
	}
}
