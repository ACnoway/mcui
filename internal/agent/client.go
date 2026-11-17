package agent

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/security"
)

const maxResponseBytes = 64 * 1024

type Client struct {
	masterURL, name, group, invite string
	serverRoots                    *x509.CertPool
	statePath                      string
	failures                       int
	taskHandler                    TaskHandler
	taskHandlerFactory             func(nodeID string) (TaskHandler, error)
	taskSequenceProvider           func() (int64, error)
}

type localState struct {
	PrivateKey        string `json:"private_key"`
	NodeID            string `json:"node_id,omitempty"`
	CertificatePEM    string `json:"certificate_pem,omitempty"`
	CertificateSerial string `json:"certificate_serial,omitempty"`
	EnrollmentID      string `json:"enrollment_request_id,omitempty"`
	PendingKey        string `json:"pending_private_key,omitempty"`
	PendingCSR        string `json:"pending_csr_pem,omitempty"`
	RotationID        string `json:"rotation_request_id,omitempty"`
}

func New(masterURL, name, group, invite, serverCAPath string) (*Client, error) {
	u, err := url.Parse(masterURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("Master must use HTTPS with a valid host")
	}
	if name == "" {
		return nil, errors.New("node name is required")
	}
	if serverCAPath == "" {
		return nil, errors.New("a pre-trusted Master CA file is required")
	}
	caPEM, err := os.ReadFile(serverCAPath)
	if err != nil {
		return nil, fmt.Errorf("read Master CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("Master CA file contains no certificates")
	}
	statePath := filepath.Join("/var/lib/mcui-agent", "identity.json")
	if p := os.Getenv("MCUI_AGENT_STATE"); p != "" {
		statePath = p
	}
	c := &Client{masterURL: strings.TrimRight(masterURL, "/"), name: name, group: group, invite: invite, serverRoots: roots, statePath: statePath}
	state, err := c.loadOrCreate()
	if err != nil {
		return nil, err
	}
	if state.CertificatePEM == "" && invite == "" {
		return nil, errors.New("a one-time enrollment invitation is required for an unregistered Agent")
	}
	if state.CertificatePEM != "" {
		if _, err := parseClientCertificate(state.CertificatePEM, state.PrivateKey, state.NodeID); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Client) NodeID() (string, error) {
	if c == nil {
		return "", errors.New("Agent client is unavailable")
	}
	state, err := c.loadOrCreate()
	if err != nil {
		return "", err
	}
	return state.NodeID, nil
}

func (c *Client) loadOrCreate() (localState, error) {
	stateDir := filepath.Dir(c.statePath)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return localState{}, err
	}
	if runtime.GOOS != "windows" {
		info, err := os.Lstat(stateDir)
		if err != nil {
			return localState{}, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return localState{}, errors.New("Agent identity directory must be a real directory")
		}
		if err := os.Chmod(stateDir, 0700); err != nil {
			return localState{}, err
		}
	}
	info, statErr := os.Lstat(c.statePath)
	if statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return localState{}, errors.New("Agent identity path must be a regular file")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
			return localState{}, errors.New("Agent identity file permissions must exclude group and other access")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return localState{}, statErr
	}
	b, err := os.ReadFile(c.statePath)
	if err == nil {
		var state localState
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err = dec.Decode(&state); err != nil {
			return localState{}, err
		}
		var trailing any
		if dec.Decode(&trailing) != io.EOF {
			return localState{}, errors.New("invalid Agent identity file")
		}
		if _, err = decodePrivateKey(state.PrivateKey); err != nil {
			return localState{}, errors.New("invalid Agent identity")
		}
		return state, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return localState{}, err
	}
	_, key, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		return localState{}, err
	}
	state := localState{PrivateKey: base64.RawStdEncoding.EncodeToString(key)}
	if err := c.save(state); err != nil {
		return localState{}, err
	}
	return state, nil
}

func decodePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	return ed25519.PrivateKey(raw), nil
}

func (c *Client) save(state localState) error {
	if err := os.MkdirAll(filepath.Dir(c.statePath), 0700); err != nil {
		return err
	}
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	// The Windows branch supports local development; Linux uses temp-file replacement plus directory fsync.
	if runtime.GOOS == "windows" {
		f, err := os.OpenFile(c.statePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		if err = f.Chmod(0600); err == nil {
			_, err = f.Write(b)
		}
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		return closeErr
	}
	f, err := os.CreateTemp(filepath.Dir(c.statePath), ".mcui-identity-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(tmp, c.statePath); err != nil {
		return err
	}
	if dir, openErr := os.Open(filepath.Dir(c.statePath)); openErr == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func privateKeyPEM(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parseClientCertificate(certificatePEM, privateKeyEncoded, nodeID string) (tls.Certificate, error) {
	key, err := decodePrivateKey(privateKeyEncoded)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := privateKeyPEM(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair([]byte(certificatePEM), keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("invalid Agent certificate: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, errors.New("Agent certificate is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	cert.Leaf = leaf
	certID, err := security.NodeIDFromCertificate(leaf)
	if err != nil || certID != nodeID {
		return tls.Certificate{}, errors.New("Agent certificate identity does not match local state")
	}
	return cert, nil
}

func (c *Client) httpClient(state localState) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.serverRoots}
	if state.CertificatePEM != "" {
		cert, err := parseClientCertificate(state.CertificatePEM, state.PrivateKey, state.NodeID)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Timeout: 15 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func (c *Client) post(state localState, path string, body any) ([]byte, int, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	client, err := c.httpClient(state)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest(http.MethodPost, c.masterURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(response) > maxResponseBytes {
		return nil, resp.StatusCode, errors.New("Master response too large")
	}
	return response, resp.StatusCode, nil
}

func (c *Client) RunOnce() error {
	err := c.runOnce()
	if err != nil {
		c.failures++
	} else {
		c.failures = 0
	}
	return err
}

func (c *Client) runOnce() error {
	state, err := c.loadOrCreate()
	if err != nil {
		return err
	}
	if state.CertificatePEM == "" {
		state, err = c.enroll(state)
		if err != nil {
			return err
		}
	}
	cert, err := parseClientCertificate(state.CertificatePEM, state.PrivateKey, state.NodeID)
	if err != nil {
		return err
	}
	if time.Until(cert.Leaf.NotAfter) <= 7*24*time.Hour {
		state, err = c.rotate(state)
		if err != nil {
			return err
		}
	}
	_, status, err := c.post(state, "/api/v1/agent/heartbeat", map[string]string{})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("heartbeat rejected (HTTP %d)", status)
	}
	if c.taskHandlerFactory != nil && c.taskHandler == nil {
		c.taskHandler, err = c.taskHandlerFactory(state.NodeID)
		if err != nil {
			return fmt.Errorf("initialize status-task handler: %w", err)
		}
	}
	if c.taskHandler != nil {
		if err = c.processStatusTask(state); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) enroll(state localState) (localState, error) {
	if c.invite == "" {
		return state, errors.New("enrollment invitation required")
	}
	if state.EnrollmentID == "" {
		requestID, err := randomRequestID()
		if err != nil {
			return state, err
		}
		state.EnrollmentID = requestID
		if err = c.save(state); err != nil {
			return state, err
		}
	}
	key, err := decodePrivateKey(state.PrivateKey)
	if err != nil {
		return state, err
	}
	csr, err := security.NewCSR(key)
	if err != nil {
		return state, err
	}
	body := map[string]string{
		"invite": c.invite, "name": c.name, "request_id": state.EnrollmentID,
		"csr_pem": base64.RawStdEncoding.EncodeToString(csr),
	}
	response, status, err := c.post(state, "/api/v1/agent/enroll", body)
	if err != nil {
		return state, err
	}
	if status != http.StatusCreated {
		return state, fmt.Errorf("registration rejected (HTTP %d)", status)
	}
	var result struct {
		NodeID         string `json:"node_id"`
		CertificatePEM string `json:"certificate_pem"`
		Serial         string `json:"serial"`
	}
	if err := json.Unmarshal(response, &result); err != nil || result.NodeID == "" || result.CertificatePEM == "" || result.Serial == "" {
		return state, errors.New("invalid registration response")
	}
	cert, err := parseClientCertificate(result.CertificatePEM, state.PrivateKey, result.NodeID)
	if err != nil || cert.Leaf.SerialNumber.String() != result.Serial || !cert.Leaf.NotAfter.After(time.Now()) {
		return state, errors.New("Master returned an invalid node certificate")
	}
	state.NodeID, state.CertificatePEM, state.CertificateSerial = result.NodeID, result.CertificatePEM, result.Serial
	if err := c.save(state); err != nil {
		return state, err
	}
	return state, nil
}

func randomRequestID() (string, error) {
	b := make([]byte, 24)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (c *Client) rotate(state localState) (localState, error) {
	if state.PendingKey == "" {
		_, key, err := ed25519.GenerateKey(crand.Reader)
		if err != nil {
			return state, err
		}
		csr, err := security.NewCSR(key)
		if err != nil {
			return state, err
		}
		requestID, err := randomRequestID()
		if err != nil {
			return state, err
		}
		state.PendingKey = base64.RawStdEncoding.EncodeToString(key)
		state.PendingCSR = base64.RawStdEncoding.EncodeToString(csr)
		state.RotationID = requestID
		if err := c.save(state); err != nil {
			return state, err
		}
	}
	csr, err := base64.RawStdEncoding.DecodeString(state.PendingCSR)
	if err != nil {
		return state, errors.New("invalid pending certificate request")
	}
	response, status, err := c.post(state, "/api/v1/agent/cert/rotate", map[string]string{
		"request_id": state.RotationID, "csr_pem": base64.RawStdEncoding.EncodeToString(csr),
	})
	if err != nil {
		return state, err
	}
	if status != http.StatusOK {
		return state, fmt.Errorf("certificate rotation rejected (HTTP %d)", status)
	}
	var result struct {
		CertificatePEM string `json:"certificate_pem"`
		Serial         string `json:"serial"`
	}
	if err := json.Unmarshal(response, &result); err != nil || result.CertificatePEM == "" || result.Serial == "" {
		return state, errors.New("invalid certificate rotation response")
	}
	newCert, err := parseClientCertificate(result.CertificatePEM, state.PendingKey, state.NodeID)
	if err != nil || newCert.Leaf.SerialNumber.String() != result.Serial || !newCert.Leaf.NotAfter.After(time.Now()) {
		return state, errors.New("Master returned an invalid rotated certificate")
	}
	state.PrivateKey, state.CertificatePEM, state.CertificateSerial = state.PendingKey, result.CertificatePEM, result.Serial
	state.PendingKey, state.PendingCSR, state.RotationID = "", "", ""
	if err := c.save(state); err != nil {
		return state, err
	}
	return state, nil
}

func (c *Client) NextDelay() time.Duration {
	base := 15 * time.Second
	if c.failures > 0 {
		shift := c.failures - 1
		if shift > 5 {
			shift = 5
		}
		base *= time.Duration(1 << shift)
		if base > 5*time.Minute {
			base = 5 * time.Minute
		}
	}
	jitter := time.Duration(mrand.Int64N(int64(base/5)+1)) - base/10
	return base + jitter
}
