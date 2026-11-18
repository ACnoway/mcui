// Package checkpointhttp transports checkpoint observations over mutually
// authenticated TLS. The server authorizes one enrolled client public key.
package checkpointhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ACnoway/mcui/internal/checkpoint"
	"github.com/ACnoway/mcui/internal/security"
)

const (
	readPath = "/v1/checkpoint/read"
	swapPath = "/v1/checkpoint/compare-and-swap"
	maxBody  = 4096
)

type readRequest struct {
	Node      string               `json:"node"`
	Epoch     uint64               `json:"epoch"`
	Challenge checkpoint.Challenge `json:"challenge"`
}

type swapRequest struct {
	Previous  checkpoint.Record    `json:"previous"`
	Next      checkpoint.Record    `json:"next"`
	Challenge checkpoint.Challenge `json:"challenge"`
}

// NewHandler requires TLS 1.3, a verified client chain, and a matching
// SHA-256 fingerprint of the enrolled client's SubjectPublicKeyInfo.
func NewHandler(authority checkpoint.Authority, clientKey [32]byte) (http.Handler, error) {
	if authority == nil || clientKey == ([32]byte{}) {
		return nil, errors.New("checkpoint authority and enrolled client key are required")
	}
	mux := http.NewServeMux()
	mux.Handle("POST "+readPath, serve(func(ctx context.Context, in readRequest) (checkpoint.Observation, error) {
		if !security.ValidNodeID(in.Node) || in.Epoch == 0 || in.Challenge == (checkpoint.Challenge{}) {
			return checkpoint.Observation{}, checkpoint.ErrDenied
		}
		return authority.Read(ctx, in.Node, in.Epoch, in.Challenge)
	}))
	mux.Handle("POST "+swapPath, serve(func(ctx context.Context, in swapRequest) (checkpoint.Observation, error) {
		if !security.ValidNodeID(in.Previous.Node) || in.Challenge == (checkpoint.Challenge{}) {
			return checkpoint.Observation{}, checkpoint.ErrDenied
		}
		return authority.CompareAndSwap(ctx, in.Previous, in.Next, in.Challenge)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 ||
			sha256.Sum256(r.TLS.VerifiedChains[0][0].RawSubjectPublicKeyInfo) != clientKey {
			http.Error(w, "checkpoint client is unauthorized", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	}), nil
}

func serve[T any](operation func(context.Context, T) (checkpoint.Observation, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in T
		if err := decode(r.Body, &in); err != nil {
			http.Error(w, "invalid checkpoint request", http.StatusBadRequest)
			return
		}
		observed, err := operation(r.Context(), in)
		if err != nil {
			http.Error(w, "checkpoint operation failed", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(observed)
	})
}

func decode(body io.Reader, destination any) error {
	raw, err := io.ReadAll(io.LimitReader(body, maxBody+1))
	if err != nil || len(raw) > maxBody {
		return errors.New("checkpoint message exceeds size limit or could not be read")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing checkpoint message data")
	}
	return nil
}

type Client struct {
	origin string
	http   *http.Client
}

var _ checkpoint.Authority = (*Client)(nil)

// NewClient uses only the supplied CA, validates the HTTPS hostname, and
// presents the enrolled client certificate. It never proxies or redirects.
func NewClient(origin string, caPEM []byte, certificate tls.Certificate) (*Client, error) {
	origin, err := security.MasterOrigin(origin)
	if err != nil {
		return nil, fmt.Errorf("invalid checkpoint origin: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) || len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return nil, errors.New("checkpoint server CA and client certificate are required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		Certificates: []tls.Certificate{certificate},
	}
	return &Client{origin: origin, http: &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}, nil
}

func (c *Client) Read(ctx context.Context, node string, epoch uint64, challenge checkpoint.Challenge) (checkpoint.Observation, error) {
	in := readRequest{Node: node, Epoch: epoch, Challenge: challenge}
	return c.call(ctx, readPath, in, node, epoch, challenge)
}

func (c *Client) CompareAndSwap(ctx context.Context, previous, next checkpoint.Record, challenge checkpoint.Challenge) (checkpoint.Observation, error) {
	in := swapRequest{Previous: previous, Next: next, Challenge: challenge}
	return c.call(ctx, swapPath, in, previous.Node, previous.Epoch, challenge)
}

func (c *Client) call(ctx context.Context, path string, input any, node string, epoch uint64, challenge checkpoint.Challenge) (checkpoint.Observation, error) {
	var observed checkpoint.Observation
	raw, err := json.Marshal(input)
	if err != nil {
		return observed, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+path, bytes.NewReader(raw))
	if err != nil {
		return observed, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return observed, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return observed, fmt.Errorf("checkpoint authority returned HTTP %d", resp.StatusCode)
	}
	if err = decode(resp.Body, &observed); err != nil {
		return checkpoint.Observation{}, err
	}
	if observed.Challenge != challenge || observed.Record.Node != node || observed.Record.Epoch != epoch || observed.Record.Digest == ([32]byte{}) {
		return checkpoint.Observation{}, checkpoint.ErrDenied
	}
	return observed, nil
}
