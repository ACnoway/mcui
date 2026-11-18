//go:build linux

package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/ACnoway/mcui/internal/security"
)

type HTTPCheckpoint struct {
	endpoint string
	client   *http.Client
}

type checkpointRequest struct {
	LeaseID string          `json:"lease_id"`
	Task    json.RawMessage `json:"task"`
}

type checkpointResponse struct {
	ServerTime       string `json:"server_time"`
	PreviousSequence int64  `json:"previous_sequence"`
}

// NewHTTPCheckpoint creates a server-authenticated HTTPS client for the Master-side status
// task checkpoint. The endpoint is read-only and authorizes only the exact
// signed envelope under its current delivery lease.
func NewHTTPCheckpoint(masterURL string, caPEM []byte) (*HTTPCheckpoint, error) {
	origin, err := security.MasterOrigin(masterURL)
	if err != nil {
		return nil, err
	}
	client, err := security.NewMasterHTTPClient(caPEM, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return &HTTPCheckpoint{endpoint: origin, client: client}, nil
}

func (c *HTTPCheckpoint) AuthorizeStatus(ctx context.Context, raw []byte, leaseID string) (time.Time, int64, error) {
	if c == nil || c.client == nil || ctx == nil || leaseID == "" || len(raw) == 0 || len(raw) > 64*1024 {
		return time.Time{}, 0, ErrReconciliation
	}
	body, err := json.Marshal(checkpointRequest{LeaseID: leaseID, Task: append(json.RawMessage(nil), raw...)})
	if err != nil {
		return time.Time{}, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/api/v1/helper/tasks/authorize", bytes.NewReader(body))
	if err != nil {
		return time.Time{}, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return time.Time{}, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return time.Time{}, 0, ErrReconciliation
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(data) > 4096 {
		return time.Time{}, 0, ErrReconciliation
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var response checkpointResponse
	if err = decoder.Decode(&response); err != nil {
		return time.Time{}, 0, ErrReconciliation
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || response.PreviousSequence < 0 {
		return time.Time{}, 0, ErrReconciliation
	}
	serverTime, err := time.Parse(time.RFC3339Nano, response.ServerTime)
	if err != nil || serverTime.IsZero() {
		return time.Time{}, 0, ErrReconciliation
	}
	return serverTime.UTC(), response.PreviousSequence, nil
}
