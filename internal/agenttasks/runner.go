package agenttasks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
	"github.com/ACnoway/mcui/internal/taskledger"
)

type StatusExecutor interface {
	ExecuteStatus(ctx context.Context, raw []byte, leaseID string) (json.RawMessage, error)
}

type Ack struct {
	StatusVersion int64
	Status        string
	Result        json.RawMessage
}

type Runner struct {
	processor *Processor
	ledger    *taskledger.Ledger
	executor  StatusExecutor
	now       func() time.Time
}

var statusValuePattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

type statusTaskBody struct {
	Payload struct {
		Core string `json:"core"`
	} `json:"payload"`
}

type statusObservation struct {
	Core        string `json:"core"`
	LoadState   string `json:"load_state"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
	ObservedAt  string `json:"observed_at"`
}

type statusFailure struct {
	ErrorCode string `json:"error_code"`
}

// NewRunner connects durable Agent intake to the fixed, read-only status
// executor. The ledger must be exclusively owned by this Runner. Its clock
// callback is the local wall clock, not an independent trusted time source.
func NewRunner(processor *Processor, ledger *taskledger.Ledger, executor StatusExecutor, now func() time.Time) (*Runner, error) {
	if processor == nil || ledger == nil || executor == nil || now == nil {
		return nil, errors.New("incomplete Agent task runner")
	}
	return &Runner{processor: processor, ledger: ledger, executor: executor, now: now}, nil
}

// ProcessStatusTask accepts and persists the exact signed envelope before any
// Helper call. ACKs are reproducible from ledger state so a lost HTTP response
// can be retried byte-for-byte after restart.
func (r *Runner) ProcessStatusTask(ctx context.Context, raw []byte, leaseID string, lastStatusVersion int64) ([]Ack, error) {
	if r == nil {
		return nil, errors.New("invalid status-task delivery")
	}
	return r.ProcessStatusTaskAt(ctx, raw, leaseID, lastStatusVersion, r.now())
}

// ProcessStatusTaskAt accepts the task using server time included in the
// authenticated Master delivery. It still relies on the caller to establish
// time freshness and rollback protection.
func (r *Runner) ProcessStatusTaskAt(ctx context.Context, raw []byte, leaseID string, lastStatusVersion int64, serverNow time.Time) ([]Ack, error) {
	if r == nil || ctx == nil || leaseID == "" || lastStatusVersion < 0 || serverNow.IsZero() {
		return nil, errors.New("invalid status-task delivery")
	}
	task, err := r.processor.ReceiveAt(ctx, raw, serverNow)
	if err != nil {
		return nil, err
	}
	var envelope statusTaskBody
	if err = json.Unmarshal(task.Envelope, &envelope); err != nil || !statusValuePattern.MatchString(envelope.Payload.Core) {
		return nil, errors.New("invalid persisted status task")
	}
	if task.State == taskledger.Pending {
		started, startErr := r.ledger.Start(task.Sequence, serverNow)
		if errors.Is(startErr, taskledger.ErrNotYet) {
			return acknowledgments(task, lastStatusVersion), nil
		}
		if startErr != nil {
			return nil, startErr
		}
		task = started
	}
	if task.State == taskledger.Running {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, executeErr := r.executor.ExecuteStatus(ctx, task.Envelope, leaseID)
		if executeErr != nil {
			code := "helper_unavailable"
			var coded interface{ StatusErrorCode() string }
			if errors.As(executeErr, &coded) && statusValuePattern.MatchString(coded.StatusErrorCode()) {
				code = coded.StatusErrorCode()
			}
			failure, _ := json.Marshal(statusFailure{ErrorCode: code})
			var finishErr error
			if code == "reconciliation_required" {
				finishErr = r.ledger.RequireReconciliation(task.Sequence, failure)
			} else {
				finishErr = r.ledger.Finish(task.Sequence, taskledger.Failed, failure)
			}
			if finishErr != nil {
				return nil, finishErr
			}
		} else if !validStatusObservation(result, envelope.Payload.Core) {
			failure, _ := json.Marshal(statusFailure{ErrorCode: "status_unavailable"})
			if finishErr := r.ledger.Finish(task.Sequence, taskledger.Failed, failure); finishErr != nil {
				return nil, finishErr
			}
		} else if finishErr := r.ledger.Finish(task.Sequence, taskledger.Succeeded, result); finishErr != nil {
			return nil, finishErr
		}
		task, err = r.ledger.Get(task.Sequence)
		if err != nil {
			return nil, err
		}
	}
	return acknowledgments(task, lastStatusVersion), nil
}

// ProcessControlTask durably receives the original signed task before applying
// its separately signed V1 control. Cancel can only tombstone a pending task;
// EXPIRED skip only acknowledges a task already durably expired in the ledger.
func (r *Runner) ProcessControlTask(ctx context.Context, taskRaw []byte, controlKind string, controlRaw []byte, leaseID string, lastStatusVersion int64, serverNow time.Time) ([]Ack, error) {
	if r == nil || ctx == nil || leaseID == "" || lastStatusVersion < 0 || serverNow.IsZero() || len(controlRaw) == 0 {
		return nil, errors.New("invalid controlled task delivery")
	}
	task, err := r.processor.ReceiveAt(ctx, taskRaw, serverNow)
	if err != nil {
		return nil, err
	}
	switch controlKind {
	case string(protocol.Cancel):
		err = r.processor.ApplyCancel(ctx, controlRaw, serverNow, task.ID, task.Sequence)
		if err != nil && !errors.Is(err, taskledger.ErrTooLate) {
			return nil, err
		}
		task, err = r.ledger.Get(task.Sequence)
		if err != nil {
			return nil, err
		}
	case string(protocol.Skip):
		taskID, sequence := task.ID, task.Sequence
		skipped, skipErr := r.processor.ApplySkip(ctx, controlRaw, serverNow, taskID, sequence)
		if errors.Is(skipErr, taskledger.ErrTooLate) {
			task, err = r.ledger.Get(sequence)
		} else if skipErr != nil {
			return nil, skipErr
		} else {
			task = skipped
		}
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported task control kind")
	}
	acks := acknowledgments(task, lastStatusVersion)
	if len(acks) == 0 {
		return nil, errors.New("task control did not produce an ACK state")
	}
	return acks, nil
}

func validStatusObservation(raw []byte, core string) bool {
	if len(raw) == 0 || len(raw) > 4096 || !json.Valid(raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var result statusObservation
	if decoder.Decode(&result) != nil || result.Core != core || !statusValuePattern.MatchString(result.LoadState) || !statusValuePattern.MatchString(result.ActiveState) || !statusValuePattern.MatchString(result.SubState) {
		return false
	}
	var trailing any
	if decoder.Decode(&trailing) == nil {
		return false
	}
	_, err := time.Parse(time.RFC3339, result.ObservedAt)
	return err == nil
}

func acknowledgments(task taskledger.Task, lastStatusVersion int64) []Ack {
	accepted := Ack{StatusVersion: 1, Status: "ACK_ACCEPTED"}
	running := Ack{StatusVersion: 2, Status: "RUNNING"}
	verifying := Ack{StatusVersion: 3, Status: "VERIFYING"}
	switch task.State {
	case taskledger.Pending:
		return []Ack{accepted}
	case taskledger.Running:
		return []Ack{accepted, running}
	case taskledger.Succeeded:
		return []Ack{accepted, running, verifying, {StatusVersion: 4, Status: "SUCCEEDED", Result: append(json.RawMessage(nil), task.Result...)}}
	case taskledger.Failed:
		return []Ack{accepted, running, {StatusVersion: 3, Status: "FAILED", Result: append(json.RawMessage(nil), task.Result...)}}
	case taskledger.Expired:
		result, _ := json.Marshal(statusFailure{ErrorCode: "task_expired"})
		return []Ack{{StatusVersion: lastStatusVersion + 1, Status: "EXPIRED", Result: result}}
	case taskledger.Canceled:
		result, _ := json.Marshal(statusFailure{ErrorCode: "task_canceled"})
		return []Ack{{StatusVersion: lastStatusVersion + 1, Status: "CANCELED", Result: result}}
	case taskledger.Reconciliation:
		result, _ := json.Marshal(statusFailure{ErrorCode: "reconciliation_required"})
		return []Ack{{StatusVersion: lastStatusVersion + 1, Status: "NEEDS_RECONCILIATION", Result: result}}
	default:
		return nil
	}
}
