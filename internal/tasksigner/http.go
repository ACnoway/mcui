package tasksigner

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxSignRequestBytes = 64 * 1024

type SignStatus interface {
	SignStatus(raw []byte) ([]byte, error)
}

type signRequest struct {
	Task string `json:"task"`
}

type signResponse struct {
	Task string `json:"task"`
}

// NewHTTPHandler exposes only the status-task signing operation. The caller
// must bind it to loopback and protect the bearer token file with mode 0600.
func NewHTTPHandler(s SignStatus, token []byte) (http.Handler, error) {
	if s == nil || len(token) < 32 {
		return nil, errors.New("signer and a 32-byte token are required")
	}
	secret := append([]byte(nil), token...)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sign/status", func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		provided := strings.TrimPrefix(authorization, "Bearer ")
		if len(provided) != len(secret) || subtle.ConstantTimeCompare([]byte(provided), secret) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.ContentLength > maxSignRequestBytes {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxSignRequestBytes+1))
		if err != nil || len(body) > maxSignRequestBytes {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var request signRequest
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&request); err != nil || request.Task == "" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		raw, err := base64.RawStdEncoding.DecodeString(request.Task)
		if err != nil || len(raw) > maxSignRequestBytes {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		signed, err := s.SignStatus(raw)
		if err != nil {
			http.Error(w, "signing rejected", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(signResponse{Task: base64.RawStdEncoding.EncodeToString(signed)})
	})
	return mux, nil
}

// NewHTTPClient creates a narrow client for a loopback-only signing daemon.
// Redirects are disabled so the token cannot be forwarded to another host.
func NewHTTPClient(endpoint string, token []byte) (*HTTPClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("signer endpoint must be a loopback HTTP URL")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, errors.New("signer endpoint must use loopback")
	}
	if len(token) < 32 {
		return nil, errors.New("signer token must contain at least 32 bytes")
	}
	return &HTTPClient{
		endpoint: strings.TrimRight(endpoint, "/"),
		token:    append([]byte(nil), token...),
		http: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

type HTTPClient struct {
	endpoint string
	token    []byte
	http     *http.Client
}

func (c *HTTPClient) SignStatus(raw []byte) ([]byte, error) {
	if c == nil || c.http == nil || len(raw) == 0 || len(raw) > maxSignRequestBytes {
		return nil, errors.New("invalid signer request")
	}
	body, err := json.Marshal(signRequest{Task: base64.RawStdEncoding.EncodeToString(raw)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.endpoint+"/v1/sign/status", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(c.token))
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return nil, errors.New("status-task signer rejected request")
	}
	encoded, err := io.ReadAll(io.LimitReader(resp.Body, maxSignRequestBytes+1))
	if err != nil || len(encoded) > maxSignRequestBytes {
		return nil, errors.New("invalid signer response")
	}
	var result signResponse
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&result); err != nil || result.Task == "" {
		return nil, errors.New("invalid signer response")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errors.New("invalid signer response")
	}
	signed, err := base64.RawStdEncoding.DecodeString(result.Task)
	if err != nil || len(signed) == 0 || len(signed) > maxSignRequestBytes {
		return nil, errors.New("invalid signer response")
	}
	return signed, nil
}
