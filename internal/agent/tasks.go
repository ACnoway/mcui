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
	client, err := c.httpClient(state)
	if err != nil {
		return err
	}
	endpoint := c.masterURL + "/api/v1/agent/tasks/next"
	if c.taskSequenceProvider != nil {
		next, sequenceErr := c.taskSequenceProvider()
		if sequenceErr != nil || next < 1 {
			return errors.New("Agent task sequence is unavailable")
		}
		endpoint += "?next_sequence=" + strconv.FormatInt(next, 10)
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
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
	if err = decoder.Decode(&delivery); err != nil || delivery.TaskID == "" || delivery.Sequence < 1 || !leaseIDPattern.MatchString(delivery.LeaseID) || delivery.LastStatusVersion < 0 || (len(delivery.Task) == 0 && !delivery.SequenceSkip) || (delivery.SequenceSkip && (len(delivery.Task) != 0 || delivery.ControlKind != string(protocol.Skip))) || (delivery.SequenceRecovery && (len(delivery.Task) == 0 || delivery.ControlKind != string(protocol.Skip))) {
		return errors.New("invalid task delivery")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return errors.New("invalid task delivery")
	}
	serverNow, err := time.Parse(time.RFC3339Nano, delivery.ServerTime)
	if err != nil || serverNow.IsZero() {
		return errors.New("invalid task delivery server time")
	}
	if len(delivery.Task) > 0 {
		if _, err = protocol.CanonicalV2TaskBytes(delivery.Task); err != nil {
			return fmt.Errorf("invalid signed task envelope: %w", err)
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	var acks []TaskAck
	if delivery.SequenceSkip {
		acks, err = c.taskHandler.ProcessSequenceSkip(ctx, append([]byte(nil), delivery.Control...), delivery.Sequence, delivery.LastStatusVersion, serverNow)
	} else if delivery.ControlKind == "" {
		acks, err = c.taskHandler.ProcessStatusTask(ctx, append([]byte(nil), delivery.Task...), delivery.LeaseID, delivery.LastStatusVersion, serverNow)
	} else {
		acks, err = c.taskHandler.ProcessControlTask(ctx, append([]byte(nil), delivery.Task...), delivery.ControlKind, append([]byte(nil), delivery.Control...), delivery.LeaseID, delivery.LastStatusVersion, serverNow)
	}
	cancel()
	if err != nil {
		return fmt.Errorf("status-task processing failed: %w", err)
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
	if len(acks) == 1 && acks[0].StatusVersion > 1 && (acks[0].Status == "EXPIRED" || acks[0].Status == "CANCELED" || acks[0].Status == "NEEDS_RECONCILIATION") {
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
