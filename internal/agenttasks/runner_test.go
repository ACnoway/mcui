package agenttasks_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/agent"
	"github.com/ACnoway/mcui/internal/agenttasks"
	"github.com/ACnoway/mcui/internal/taskauth"
	"github.com/ACnoway/mcui/internal/taskledger"
	"github.com/ACnoway/mcui/internal/tasksigner"
)

type fakeStatusExecutor struct {
	result json.RawMessage
	err    error
	calls  int
}

func (e *fakeStatusExecutor) ExecuteStatus(_ context.Context, _ []byte, _ string) (json.RawMessage, error) {
	e.calls++
	return append(json.RawMessage(nil), e.result...), e.err
}

func TestRunnerPersistsBeforeExecutionAndReplaysFinalAcks(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ledger, err := taskledger.Initialize(filepath.Join(dir, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer, err := tasksigner.New("test-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signer.SignStatus([]byte(unsigned))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 16, 0, 1, 0, 0, time.UTC)
	processor, err := agenttasks.New(agenttasks.Config{
		NodeID: "node-001",
		Keys:   map[string]taskauth.Key{"test-key": {PublicKey: privateKey.Public().(ed25519.PublicKey), Active: true, Purpose: taskauth.PurposeTask}},
		Now:    func() time.Time { return now }, Ledger: ledger,
	})
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeStatusExecutor{result: json.RawMessage(`{"core":"xray","load_state":"loaded","active_state":"active","sub_state":"running","observed_at":"2026-11-16T00:01:00Z"}`)}
	runner, err := agenttasks.NewRunner(processor, ledger, executor, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	acks, err := runner.ProcessStatusTask(context.Background(), raw, "lease-001", 0)
	if err != nil || len(acks) != 4 || acks[0].Status != "ACK_ACCEPTED" || acks[1].Status != "RUNNING" || acks[2].Status != "VERIFYING" || acks[3].Status != "SUCCEEDED" || executor.calls != 1 {
		t.Fatalf("ACKs=%+v calls=%d err=%v", acks, executor.calls, err)
	}
	acks, err = runner.ProcessStatusTask(context.Background(), raw, "lease-002", 4)
	if err != nil || len(acks) != 4 || acks[3].Status != "SUCCEEDED" || executor.calls != 1 {
		t.Fatalf("duplicate ACKs=%+v calls=%d err=%v", acks, executor.calls, err)
	}
	task, err := ledger.Get(1)
	if err != nil || task.State != taskledger.Succeeded {
		t.Fatalf("durable task state=%+v err=%v", task, err)
	}
}

func TestRunnerRejectsSecretBearingHelperResult(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ledger, err := taskledger.Initialize(filepath.Join(dir, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer, _ := tasksigner.New("test-key", privateKey)
	raw, err := signer.SignStatus([]byte(unsigned))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 16, 0, 1, 0, 0, time.UTC)
	processor, err := agenttasks.New(agenttasks.Config{NodeID: "node-001", Keys: map[string]taskauth.Key{"test-key": {PublicKey: privateKey.Public().(ed25519.PublicKey), Active: true, Purpose: taskauth.PurposeTask}}, Now: func() time.Time { return now }, Ledger: ledger})
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeStatusExecutor{result: json.RawMessage(`{"core":"xray","load_state":"loaded","active_state":"active","sub_state":"running","observed_at":"2026-11-16T00:01:00Z","secret":"reject"}`)}
	runner, err := agenttasks.NewRunner(processor, ledger, executor, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	acks, err := runner.ProcessStatusTask(context.Background(), raw, "lease-001", 0)
	if err != nil || len(acks) != 3 || acks[2].Status != "FAILED" {
		t.Fatalf("ACKs=%+v err=%v", acks, err)
	}
	var result map[string]string
	if err := json.Unmarshal(acks[2].Result, &result); err != nil || result["error_code"] != "status_unavailable" || result["secret"] != "" {
		t.Fatalf("failure result leaked output: %s err=%v", acks[2].Result, err)
	}
}

func TestRunnerPersistsExpiredEnvelopeWithoutCallingHelper(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ledger, err := taskledger.Initialize(filepath.Join(dir, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer, err := tasksigner.New("test-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signer.SignStatus([]byte(unsigned))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 16, 0, 11, 0, 0, time.UTC)
	processor, err := agenttasks.New(agenttasks.Config{NodeID: "node-001", Keys: map[string]taskauth.Key{"test-key": {PublicKey: privateKey.Public().(ed25519.PublicKey), Active: true, Purpose: taskauth.PurposeTask}}, Now: func() time.Time { return now }, Ledger: ledger})
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeStatusExecutor{}
	runner, err := agenttasks.NewRunner(processor, ledger, executor, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	acks, err := runner.ProcessStatusTask(context.Background(), raw, "lease-001", 0)
	if err != nil || len(acks) != 1 || acks[0].Status != "EXPIRED" || acks[0].StatusVersion != 1 || executor.calls != 0 {
		t.Fatalf("expired ACKs=%+v calls=%d err=%v", acks, executor.calls, err)
	}
	task, err := ledger.Get(1)
	if err != nil || task.State != taskledger.Expired {
		t.Fatalf("expired ledger state=%+v err=%v", task, err)
	}
}

func TestRunnerFencesUncertainHelperOutcomeAtServerVersion(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ledger, err := taskledger.Initialize(filepath.Join(dir, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer, _ := tasksigner.New("test-key", privateKey)
	raw, err := signer.SignStatus([]byte(unsigned))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 16, 0, 1, 0, 0, time.UTC)
	processor, err := agenttasks.New(agenttasks.Config{NodeID: "node-001", Keys: map[string]taskauth.Key{"test-key": {PublicKey: privateKey.Public().(ed25519.PublicKey), Active: true, Purpose: taskauth.PurposeTask}}, Now: func() time.Time { return now }, Ledger: ledger})
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeStatusExecutor{err: agent.StatusExecutionError{Code: "reconciliation_required"}}
	runner, err := agenttasks.NewRunner(processor, ledger, executor, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	acks, err := runner.ProcessStatusTask(context.Background(), raw, "lease-001", 2)
	if err != nil || len(acks) != 1 || acks[0].Status != "NEEDS_RECONCILIATION" || acks[0].StatusVersion != 3 || executor.calls != 1 {
		t.Fatalf("reconciliation ACKs=%+v calls=%d err=%v", acks, executor.calls, err)
	}
	task, err := ledger.Get(1)
	if err != nil || task.State != taskledger.Reconciliation {
		t.Fatalf("uncertain task state=%+v err=%v", task, err)
	}
	if next, err := ledger.Next(); err != nil || next != 1 {
		t.Fatalf("uncertain task advanced sequence: next=%d err=%v", next, err)
	}
}
