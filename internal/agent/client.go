package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
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
	PrivateKey     string `json:"private_key"`
	NodeID         string `json:"node_id,omitempty"`
	NodeToken      string `json:"node_token,omitempty"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
}

func New(masterURL, name, group, invite string) (*Client, error) {
	if masterURL == "" || name == "" || invite == "" {
		return nil, errors.New("master URL, name, and invite are required")
	}
	path := filepath.Join("/var/lib/mcui-agent", "identity.json")
	if p := os.Getenv("MCUI_AGENT_STATE"); p != "" {
		path = p
	}
	c := &Client{masterURL: masterURL, name: name, group: group, invite: invite, statePath: path, http: &http.Client{Timeout: 15 * time.Second}}
	if err := c.loadOrCreate(); err != nil {
		return nil, err
	}
	return c, nil
}
func (c *Client) loadOrCreate() error {
	b, e := os.ReadFile(c.statePath)
	if e == nil {
		var st localState
		if e = json.Unmarshal(b, &st); e != nil {
			return e
		}
		raw, e := base64.RawStdEncoding.DecodeString(st.PrivateKey)
		if e != nil || len(raw) != ed25519.PrivateKeySize {
			return errors.New("invalid agent identity")
		}
		c.key = ed25519.PrivateKey(raw)
		return nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	c.key = key
	return c.save(localState{PrivateKey: base64.RawStdEncoding.EncodeToString(key)})
}
func (c *Client) save(st localState) error {
	if err := os.MkdirAll(filepath.Dir(c.statePath), 0700); err != nil {
		return err
	}
	b, e := json.Marshal(st)
	if e != nil {
		return e
	}
	return os.WriteFile(c.statePath, b, 0600)
}
func (c *Client) RunOnce() error {
	if err := c.enrollIfNeeded(); err != nil {
		return err
	}
	if err := c.loadOrCreate(); err != nil {
		return err
	}
	b, err := os.ReadFile(c.statePath)
	if err != nil {
		return err
	}
	var st localState
	if err = json.Unmarshal(b, &st); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.masterURL+"/api/v1/agent/heartbeat", strings.NewReader(`{}`))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+st.NodeToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("heartbeat rejected")
	}
	return nil
}
func (c *Client) enrollIfNeeded() error {
	b, e := os.ReadFile(c.statePath)
	if e != nil {
		return e
	}
	var st localState
	if e = json.Unmarshal(b, &st); e != nil {
		return e
	}
	if st.NodeID != "" && st.NodeToken != "" {
		return nil
	}
	pub := c.key.Public().(ed25519.PublicKey)
	body, _ := json.Marshal(map[string]string{"invite": c.invite, "name": c.name, "group": c.group, "public_key": base64.StdEncoding.EncodeToString(pub)})
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
	if resp.StatusCode != http.StatusCreated {
		return errors.New("registration rejected")
	}
	var result struct {
		NodeID    string `json:"node_id"`
		NodeToken string `json:"node_token"`
	}
	if e = json.NewDecoder(resp.Body).Decode(&result); e != nil {
		return e
	}
	st.NodeID = result.NodeID
	st.NodeToken = result.NodeToken
	return c.save(st)
}
func (c *Client) NextDelay() time.Duration { return 15 * time.Second }
