package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ACnoway/mcui/internal/security"
)

const maxResponseBytes = 64 * 1024

type Client struct {
	masterURL            string
	http                 *http.Client
	statePath            string
	failures             int
	taskFailures         int
	nextTaskAttempt      time.Time
	taskHandler          TaskHandler
	taskHandlerFactory   StatusTaskHandlerFactory
	taskSequenceProvider func() (int64, error)
	xrayInstallMode      string
}

type localState struct {
	NodeID    string `json:"node_id"`
	NodeToken string `json:"node_token"`
	MasterURL string `json:"master_url"`
}

func New(masterURL, serverCAPath string) (*Client, error) {
	origin, err := security.MasterOrigin(masterURL)
	if err != nil {
		return nil, err
	}
	var caPEM []byte
	if serverCAPath != "" {
		caPEM, err = os.ReadFile(serverCAPath)
		if err != nil {
			return nil, fmt.Errorf("read Master CA: %w", err)
		}
	}
	client, err := security.NewMasterHTTPClient(caPEM, 15*time.Second)
	if err != nil {
		return nil, err
	}
	statePath := os.Getenv("MCUI_AGENT_STATE")
	if statePath == "" {
		statePath = filepath.Join("/var/lib/mcui-agent", "identity.json")
	}
	return &Client{masterURL: origin, http: client, statePath: statePath}, nil
}

func (c *Client) NodeID() (string, error) {
	state, err := c.load()
	return state.NodeID, err
}

// CheckRuntimeIdentity validates the stored enrollment without changing it.
func (c *Client) CheckRuntimeIdentity() error {
	state, err := c.load()
	if err != nil {
		return err
	}
	if state.NodeToken == "" {
		return errors.New("runtime requires an enrolled Agent identity")
	}
	return nil
}

func (c *Client) load() (localState, error) {
	var state localState
	dir, err := os.Lstat(filepath.Dir(c.statePath))
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if !dir.IsDir() || (runtime.GOOS != "windows" && dir.Mode().Perm() != 0700) {
		return state, errors.New("Agent identity directory must be a private 0700 directory")
	}
	info, err := os.Lstat(c.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) || info.Size() > maxResponseBytes {
		return state, errors.New("Agent identity file must be a private 0600 regular file")
	}
	data, err := os.ReadFile(c.statePath)
	if err != nil {
		return state, err
	}
	// For a legacy certificate identity, only node_id is read and used.
	if err = json.Unmarshal(data, &state); err != nil || (state.NodeID != "" && !security.ValidNodeID(state.NodeID)) {
		return localState{}, errors.New("invalid Agent identity file")
	}
	if state.NodeToken != "" && (state.NodeID == "" || !security.ValidNodeSecret(state.NodeToken) || state.MasterURL != c.masterURL) {
		return localState{}, errors.New("Agent identity is invalid or bound to another Master")
	}
	return state, nil
}

func (c *Client) CheckEnrollment(expectedID string) error {
	if !security.ValidNodeID(expectedID) {
		return errors.New("a valid expected node ID is required")
	}
	state, err := c.load()
	if err != nil {
		return err
	}
	if state.NodeID != "" && state.NodeID != expectedID {
		return errors.New("installation command is for a different node")
	}
	return nil
}

func (c *Client) Enroll(expectedID, code string) error {
	if err := c.CheckEnrollment(expectedID); err != nil {
		return err
	}
	if !security.ValidNodeSecret(code) {
		return errors.New("invalid installation code")
	}
	if err := os.MkdirAll(filepath.Dir(c.statePath), 0700); err != nil {
		return err
	}
	body := map[string]string{"install_code": code}
	raw, status, err := c.post(localState{}, "/api/v1/agent/enroll", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("enrollment rejected (HTTP %d)", status)
	}
	var state localState
	if json.Unmarshal(raw, &state) != nil || state.NodeID != expectedID || !security.ValidNodeSecret(state.NodeToken) {
		return errors.New("Master returned invalid or mismatched enrollment credentials")
	}
	state.MasterURL = c.masterURL
	return c.save(state)
}

func (c *Client) save(state localState) error {
	dirPath := filepath.Dir(c.statePath)
	file, err := os.CreateTemp(dirPath, ".mcui-identity-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	err = json.NewEncoder(file).Encode(state)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(file.Name(), c.statePath); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(dirPath)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (c *Client) post(state localState, path string, body any) ([]byte, int, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest(http.MethodPost, c.masterURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if state.NodeToken != "" {
		req.Header.Set("Authorization", "Bearer "+state.NodeToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return nil, resp.StatusCode, nil
	}
	response, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(response) > maxResponseBytes {
		return nil, resp.StatusCode, errors.New("invalid Master response size")
	}
	return response, resp.StatusCode, nil
}

func (c *Client) RunOnce() error {
	state, err := c.heartbeat()
	if err != nil {
		c.failures++
		return err
	}
	c.failures = 0
	if time.Now().Before(c.nextTaskAttempt) {
		return nil
	}
	if err = c.pollTasks(state); err != nil {
		c.taskFailures++
		c.nextTaskAttempt = time.Now().Add(retryDelay(c.taskFailures))
		return fmt.Errorf("status-task polling failed: %w", err)
	}
	c.taskFailures = 0
	c.nextTaskAttempt = time.Time{}
	return nil
}

func (c *Client) heartbeat() (localState, error) {
	state, err := c.load()
	if err != nil {
		return localState{}, err
	}
	if state.NodeToken == "" {
		return localState{}, errors.New("Agent must redeem an installation code before connecting")
	}
	raw, status, err := c.post(state, "/api/v1/agent/heartbeat", map[string]string{"node_id": state.NodeID})
	if err != nil {
		return localState{}, err
	}
	if status != http.StatusOK {
		return localState{}, fmt.Errorf("heartbeat rejected (HTTP %d)", status)
	}
	var reply struct {
		NodeID string `json:"node_id"`
	}
	if json.Unmarshal(raw, &reply) != nil || reply.NodeID != state.NodeID {
		return localState{}, errors.New("Master returned a mismatched heartbeat identity")
	}
	return state, nil
}

func (c *Client) pollTasks(state localState) error {
	if c.taskHandlerFactory != nil && c.taskHandler == nil {
		handler, err := c.taskHandlerFactory(state.NodeID)
		if err != nil {
			return fmt.Errorf("initialize status-task handler: %w", err)
		}
		c.taskHandler = handler
	}
	if c.taskHandler != nil {
		return c.processStatusTask(state)
	}
	return nil
}

func (c *Client) NextDelay() time.Duration {
	return retryDelay(c.failures)
}

func retryDelay(failures int) time.Duration {
	base := 15 * time.Second
	if failures > 0 {
		shift := min(failures-1, 5)
		base = min(base*time.Duration(1<<shift), 5*time.Minute)
	}
	jitter := time.Duration(mrand.Int64N(int64(base/5)+1)) - base/10
	return base + jitter
}
