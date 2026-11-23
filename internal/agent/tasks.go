package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
)

type TaskAck struct {
	StatusVersion int64           `json:"status_version"`
	Status        string          `json:"status"`
	Result        json.RawMessage `json:"result,omitempty"`
}

type TaskHandler interface {
	ProcessStatusTask(ctx context.Context, raw []byte, leaseID string, lastStatusVersion int64, serverNow time.Time) ([]TaskAck, error)
	ProcessControlTask(ctx context.Context, taskRaw []byte, controlKind string, controlRaw []byte, leaseID string, lastStatusVersion int64, serverNow time.Time) ([]TaskAck, error)
	ProcessSequenceSkip(ctx context.Context, controlRaw []byte, sequence int64, lastStatusVersion int64, serverNow time.Time) ([]TaskAck, error)
}

type InstallTaskHandler interface {
	ProcessXrayInstall(context.Context, []byte, string, []byte, int64, time.Time) ([]TaskAck, error)
}

type installReconciliationHandler interface {
	ReconcileXrayInstall(context.Context, []byte, int64) ([]TaskAck, error)
}

func (c *Client) EnableXrayInstalls(signedManifest bool) {
	c.xrayInstallMode = "xray-v1"
	if signedManifest {
		c.xrayInstallMode = "xray-manifest-v1"
	}
}

type StatusExecutor interface {
	ExecuteStatus(ctx context.Context, raw []byte, leaseID string) (json.RawMessage, error)
}

type StatusExecutionError struct{ Code string }

func (e StatusExecutionError) Error() string           { return "status Helper rejected the query" }
func (e StatusExecutionError) StatusErrorCode() string { return e.Code }

type StatusTaskHandlerFactory func(nodeID string) (TaskHandler, error)

type taskDelivery struct {
	TaskID            string          `json:"task_id"`
	Sequence          int64           `json:"sequence"`
	Task              json.RawMessage `json:"task"`
	LeaseID           string          `json:"lease_id"`
	LastStatusVersion int64           `json:"last_status_version"`
	LeaseDeadline     string          `json:"lease_deadline"`
	ServerTime        string          `json:"server_time"`
	ControlKind       string          `json:"control_kind,omitempty"`
	Control           json.RawMessage `json:"control,omitempty"`
	SequenceRecovery  bool            `json:"sequence_recovery,omitempty"`
	SequenceSkip      bool            `json:"sequence_skip,omitempty"`
	ReconcileInstall  bool            `json:"reconcile_install,omitempty"`
}

type taskDeliveryIdentity struct {
	TaskID   string `json:"task_id"`
	NodeID   string `json:"node_id"`
	Sequence int64  `json:"sequence"`
}

var leaseIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (c *Client) SetTaskHandlerFactory(factory StatusTaskHandlerFactory) error {
	if c == nil || factory == nil || c.taskHandlerFactory != nil || c.taskHandler != nil {
		return errors.New("invalid or duplicate status-task handler factory")
	}
	c.taskHandlerFactory = factory
	return nil
}

func (c *Client) SetTaskSequenceProvider(provider func() (int64, error)) error {
	if c == nil || provider == nil || c.taskSequenceProvider != nil {
		return errors.New("invalid or duplicate task sequence provider")
	}
	c.taskSequenceProvider = provider
	return nil
}

func (c *Client) processStatusTask(state localState) error {
	endpoint := c.masterURL + "/api/v1/agent/tasks/next"
	if c.taskSequenceProvider != nil {
		next, sequenceErr := c.taskSequenceProvider()
		if sequenceErr != nil || next < 1 {
			return errors.New("Agent task sequence is unavailable")
		}
		endpoint += "?next_sequence=" + strconv.FormatInt(next, 10)
		if c.xrayInstallMode != "" {
			endpoint += "&install=" + c.xrayInstallMode
			if _, ok := c.taskHandler.(installReconciliationHandler); ok {
				endpoint += "&install_reconciliation=v1"
			}
			endpoint += "&xray_control=v1&xray_change=v1&xray_config=v1"
			if c.xrayInstallMode == "xray-manifest-v1" {
				endpoint += "&xray_plan=v1&xray_http=v1&xray_protocols=v1&xray_trojan_tls=v1"
			}
		}
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+state.NodeToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return err
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("task pull rejected (HTTP %d)", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(body) > maxResponseBytes {
		return errors.New("invalid task delivery size")
	}
	var delivery taskDelivery
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&delivery); err != nil || delivery.TaskID == "" || delivery.Sequence < 1 || delivery.LastStatusVersion < 0 ||
		(len(delivery.Task) == 0 && !delivery.SequenceSkip) ||
		(delivery.SequenceSkip && (len(delivery.Task) != 0 || delivery.ControlKind != string(protocol.Skip))) ||
		(delivery.SequenceRecovery && (len(delivery.Task) == 0 || delivery.ControlKind != string(protocol.Skip))) {
		return errors.New("invalid task delivery")
	}
	if delivery.ReconcileInstall {
		if delivery.LeaseID != "" || delivery.LeaseDeadline != "" || delivery.ControlKind != "" || delivery.LastStatusVersion < 1 {
			return errors.New("invalid Xray reconciliation delivery")
		}
	} else if !leaseIDPattern.MatchString(delivery.LeaseID) {
		return errors.New("invalid task lease")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return errors.New("invalid task delivery")
	}
	serverNow, err := time.Parse(time.RFC3339Nano, delivery.ServerTime)
	if err != nil || serverNow.IsZero() {
		return errors.New("invalid task delivery server time")
	}
	install := false
	if len(delivery.Task) > 0 {
		if _, err = protocol.CanonicalV2TaskBytes(delivery.Task); err != nil {
			if _, v1Err := protocol.CanonicalSignedBytes(protocol.Task, delivery.Task); c.xrayInstallMode == "" || v1Err != nil {
				return fmt.Errorf("invalid signed task envelope: %w", err)
			}
			install = true
		}
		var identity taskDeliveryIdentity
		if err = json.Unmarshal(delivery.Task, &identity); err != nil || identity.TaskID != delivery.TaskID || identity.NodeID != state.NodeID || identity.Sequence != delivery.Sequence {
			return errors.New("task delivery identity mismatch")
		}
	}
	if (delivery.ControlKind == "") != (len(delivery.Control) == 0) {
		return errors.New("incomplete task control delivery")
	}
	if delivery.ControlKind != "" {
		kind := protocol.Kind(delivery.ControlKind)
		if kind != protocol.Cancel && kind != protocol.Skip {
			return errors.New("unsupported task control kind")
		}
		if _, err = protocol.CanonicalSignedBytes(kind, delivery.Control); err != nil {
			return fmt.Errorf("invalid signed task control: %w", err)
		}
	}
	timeout := 30 * time.Second
	if install {
		timeout = 9 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var acks []TaskAck
	if delivery.ReconcileInstall {
		handler, ok := c.taskHandler.(installReconciliationHandler)
		if !install || !ok {
			return errors.New("unsupported Xray reconciliation delivery")
		}
		acks, err = handler.ReconcileXrayInstall(ctx, delivery.Task, delivery.LastStatusVersion)
	} else if delivery.SequenceSkip {
		acks, err = c.taskHandler.ProcessSequenceSkip(ctx, append([]byte(nil), delivery.Control...), delivery.Sequence, delivery.LastStatusVersion, serverNow)
	} else if install {
		handler, ok := c.taskHandler.(InstallTaskHandler)
		if !ok || (delivery.ControlKind != "" && !delivery.SequenceRecovery) {
			return errors.New("unsupported Xray install delivery")
		}
		done := make(chan struct{})
		if !delivery.SequenceRecovery {
			go c.renewXrayInstall(ctx, state, delivery, done)
		} else {
			close(done)
		}
		acks, err = handler.ProcessXrayInstall(ctx, delivery.Task, delivery.LeaseID, delivery.Control, delivery.LastStatusVersion, serverNow)
		cancel()
		<-done
	} else if delivery.ControlKind == "" {
		acks, err = c.taskHandler.ProcessStatusTask(ctx, append([]byte(nil), delivery.Task...), delivery.LeaseID, delivery.LastStatusVersion, serverNow)
	} else {
		acks, err = c.taskHandler.ProcessControlTask(ctx, append([]byte(nil), delivery.Task...), delivery.ControlKind, append([]byte(nil), delivery.Control...), delivery.LeaseID, delivery.LastStatusVersion, serverNow)
	}
	cancel()
	if err != nil {
		return fmt.Errorf("status-task processing failed: %w", err)
	}
	if delivery.ReconcileInstall && len(acks) == 0 {
		return nil
	}
	if len(acks) == 0 || len(acks) > 9 {
		return errors.New("status-task processor returned invalid ACK history")
	}
	if delivery.SequenceRecovery {
		// The historical task already has a terminal Master ACK. Advancing the
		// Agent ledger is the receipt; posting another ACK would reopen history.
		return nil
	}
	baseVersion := int64(0)
	if delivery.ReconcileInstall {
		if len(acks) != 1 || (acks[0].Status != "SUCCEEDED" && acks[0].Status != "ROLLED_BACK") {
			return errors.New("invalid Xray reconciliation result")
		}
		baseVersion = delivery.LastStatusVersion
	} else if len(acks) == 1 && acks[0].StatusVersion > 1 && (acks[0].Status == "EXPIRED" || acks[0].Status == "CANCELED" || acks[0].Status == "NEEDS_RECONCILIATION") {
		baseVersion = delivery.LastStatusVersion
	}
	for i, ack := range acks {
		if ack.StatusVersion != baseVersion+int64(i+1) || ack.Status == "" || (len(ack.Result) != 0 && !json.Valid(ack.Result)) {
			return errors.New("status-task processor returned invalid ACK history")
		}
		requestBody := struct {
			TaskID        string          `json:"task_id"`
			Sequence      int64           `json:"sequence"`
			StatusVersion int64           `json:"status_version"`
			Status        string          `json:"status"`
			Result        json.RawMessage `json:"result,omitempty"`
		}{delivery.TaskID, delivery.Sequence, ack.StatusVersion, ack.Status, ack.Result}
		_, status, postErr := c.post(state, "/api/v1/agent/tasks/ack", requestBody)
		if postErr != nil {
			return postErr
		}
		if status != http.StatusNoContent {
			return fmt.Errorf("task ACK rejected (HTTP %d)", status)
		}
	}
	return nil
}

func (c *Client) renewXrayInstall(ctx context.Context, state localState, delivery taskDelivery, done chan<- struct{}) {
	defer close(done)
	body, err := json.Marshal(struct {
		Task    json.RawMessage `json:"task"`
		LeaseID string          `json:"lease_id"`
	}{delivery.Task, delivery.LeaseID})
	if err != nil {
		return
	}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.masterURL+"/api/v1/agent/tasks/renew-install", bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+state.NodeToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusConflict {
				return
			}
		}
	}
}
