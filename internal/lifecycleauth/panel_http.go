package lifecycleauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type PanelSignerClient struct {
	origin string
	token  string
	http   *http.Client
}

func NewPanelSignerClient(origin string, token []byte) (*PanelSignerClient, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || u.Port() == "" || len(token) < 32 {
		return nil, errors.New("Xray signer requires a loopback HTTP origin and bearer token")
	}
	return &PanelSignerClient{origin: u.String(), token: string(token), http: &http.Client{
		Timeout:       15 * time.Second,
		Transport:     &http.Transport{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (c *PanelSignerClient) exchange(ctx context.Context, method, path string, body []byte, limit int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Xray signer rejected the request")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil || len(raw) > limit {
		return nil, errors.New("invalid Xray signer response")
	}
	return raw, nil
}

func (c *PanelSignerClient) Issue(ctx context.Context, proposal Proposal) ([]byte, error) {
	raw, err := json.Marshal(proposal)
	if err != nil {
		return nil, err
	}
	return c.exchange(ctx, http.MethodPost, "/v1/xray/issue", raw, maxProofBytes)
}

func NewPanelSignerHandler(policy *Policy, ledger *Ledger, key ed25519.PrivateKey, token []byte, now func() (time.Time, error)) (http.Handler, error) {
	if !policy.HasPanelScope() || ledger == nil || !matchesPrivate(key, policy.signingKey) || len(token) < 32 || now == nil {
		return nil, errors.New("incomplete panel Xray signer configuration")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/xray/issue", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxProofBytes))
		var p Proposal
		if err != nil || jsonv2.Unmarshal(raw, &p, jsonv2.RejectUnknownMembers(true)) != nil {
			http.Error(w, "invalid proposal", http.StatusBadRequest)
			return
		}
		if _, _, err := policy.PanelEvidence(p); err != nil {
			http.Error(w, "invalid proposal", http.StatusForbidden)
			return
		}
		at, err := now()
		if err != nil {
			http.Error(w, "trusted time unavailable", http.StatusServiceUnavailable)
			return
		}
		task, err := policy.IssuePanel(r.Context(), ledger, p, key, at)
		if err != nil {
			http.Error(w, "signing rejected", http.StatusConflict)
			return
		}
		_, _ = w.Write(task)
	})
	secret := bytes.Clone(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("Authorization")
		if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") ||
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(values[0], "Bearer ")), secret) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		mux.ServeHTTP(w, r)
	}), nil
}
