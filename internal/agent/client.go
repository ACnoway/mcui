package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Client struct {
	masterURL, name, group, invite string
	key                            ed25519.PrivateKey
	http                           *http.Client
	statePath                      string
}
type localState struct {
	PrivateKey string `json:"private_key"`
	NodeID     string `json:"node_id,omitempty"`
	NodeToken  string `json:"node_token,omitempty"`
}

func New(masterURL, name, group, invite string) (*Client, error) {
	u, e := url.Parse(masterURL)
	if e != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname()))) {
		return nil, errors.New("master must use HTTPS; HTTP is allowed only for loopback development")
	}
	if name == "" || invite == "" {
		return nil, errors.New("name and invite are required")
	}
	state := filepath.Join("/var/lib/mcui-agent", "identity.json")
	if p := os.Getenv("MCUI_AGENT_STATE"); p != "" {
		state = p
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	c := &Client{masterURL: strings.TrimRight(masterURL, "/"), name: name, group: group, invite: invite, statePath: state, http: &http.Client{Timeout: 15 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if e = c.loadOrCreate(); e != nil {
		return nil, e
	}
	return c, nil
}
func isLoopback(host string) bool { return host == "localhost" || host == "127.0.0.1" || host == "::1" }
func (c *Client) loadOrCreate() error {
	b, e := os.ReadFile(c.statePath)
	if e == nil {
		if e = os.Chmod(c.statePath, 0600); e != nil {
			return e
		}
		var s localState
		if e = json.Unmarshal(b, &s); e != nil {
			return e
		}
		raw, e := base64.RawStdEncoding.DecodeString(s.PrivateKey)
		if e != nil || len(raw) != ed25519.PrivateKeySize {
			return errors.New("invalid agent identity")
		}
		c.key = ed25519.PrivateKey(raw)
		return nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(c.statePath), 0700); e != nil {
		return e
	}
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	c.key = key
	return c.save(localState{PrivateKey: base64.RawStdEncoding.EncodeToString(key)})
}
func (c *Client) save(s localState) error {
	if e := os.MkdirAll(filepath.Dir(c.statePath), 0700); e != nil {
		return e
	}
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(c.statePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if e != nil {
		return e
	}
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	return closeErr
}
func (c *Client) RunOnce() error {
	if e := c.enrollIfNeeded(); e != nil {
		return e
	}
	b, e := os.ReadFile(c.statePath)
	if e != nil {
		return e
	}
	var s localState
	if e = json.Unmarshal(b, &s); e != nil {
		return e
	}
	if s.NodeToken == "" || s.NodeID == "" {
		return errors.New("incomplete agent identity")
	}
	req, e := http.NewRequest(http.MethodPost, c.masterURL+"/api/v1/agent/heartbeat", strings.NewReader(`{}`))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+s.NodeToken)
	req.Header.Set("Content-Type", "application/json")
	resp, e := c.http.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("heartbeat rejected")
	}
	return nil
}
func (c *Client) enrollIfNeeded() error {
	b, e := os.ReadFile(c.statePath)
	if e != nil {
		return e
	}
	var s localState
	if e = json.Unmarshal(b, &s); e != nil {
		return e
	}
	if s.NodeID != "" && s.NodeToken != "" {
		return nil
	}
	pub := c.key.Public().(ed25519.PublicKey)
	body, _ := json.Marshal(map[string]string{"invite": c.invite, "name": c.name, "public_key": base64.StdEncoding.EncodeToString(pub)})
	req, e := http.NewRequest(http.MethodPost, c.masterURL+"/api/v1/agent/enroll", strings.NewReader(string(body)))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	resp, e := c.http.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		return errors.New("registration rejected")
	}
	var result struct {
		NodeID    string `json:"node_id"`
		NodeToken string `json:"node_token"`
	}
	if e = json.NewDecoder(resp.Body).Decode(&result); e != nil {
		return e
	}
	if result.NodeID == "" || result.NodeToken == "" {
		return errors.New("invalid registration response")
	}
	s.NodeID = result.NodeID
	s.NodeToken = result.NodeToken
	return c.save(s)
}
func (c *Client) NextDelay() time.Duration { return 15 * time.Second }
