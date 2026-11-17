package taskdispatch

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
	"github.com/ACnoway/mcui/internal/tasksigner"
)

func TestIssueIsAtomicIdempotentAndAuditable(t *testing.T) {
	store, err := Init(filepath.Join(t.TempDir(), "tasks.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signer, err := tasksigner.New("test-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 11, 17, 1, 0, 0, 0, time.UTC)
	build := func(taskID, nodeID, core string) func(int64) ([]byte, error) {
		return func(sequence int64) ([]byte, error) {
			body := map[string]any{
				"schema_version": 2, "task_id": taskID, "node_id": nodeID,
				"sequence": sequence, "operation": "core.status",
				"issued_at": issued.Format(time.RFC3339), "not_before": issued.Format(time.RFC3339),
				"expires_at":     issued.Add(5 * time.Minute).Format(time.RFC3339),
				"payload":        map[string]any{"core": core},
				"step":           map[string]any{"step_id": "core.status", "parameters": map[string]any{"core": core}, "artifact_sha256": "not-applicable", "architecture": "not-applicable", "expected_state": "observe"},
				"signing_key_id": "test-key", "signature_algorithm": "Ed25519", "signature": tasksigner.PlaceholderSignature,
			}
			unsigned, marshalErr := json.Marshal(body)
			if marshalErr != nil {
				return nil, marshalErr
			}
			return signer.SignStatus(unsigned)
		}
	}
	requestID := "request-1234567890123456"
	created, err := store.Issue("node-001", requestID, "test-key", publicKey, build(requestID, "node-001", "xray"))
	if err != nil || created.Sequence != 1 || created.TaskID != requestID {
		t.Fatalf("first issue = %+v, %v", created, err)
	}
	called := false
	retry, err := store.Issue("node-001", requestID, "test-key", publicKey, func(int64) ([]byte, error) {
		called = true
		return nil, errors.New("retry should reuse persisted task")
	})
	if err != nil || called || retry.Sequence != created.Sequence || string(retry.Raw) != string(created.Raw) {
		t.Fatalf("idempotent retry = %+v, called=%v, err=%v", retry, called, err)
	}
	if _, err = store.Issue("node-001", "request-2234567890123456", "test-key", publicKey, build("request-2234567890123456", "node-001", "xray")); !errors.Is(err, ErrConflict) {
		t.Fatalf("concurrent active task was not rejected: %v", err)
	}
	if err = store.Acknowledge("node-001", Ack{NodeID: "node-001", TaskID: requestID, Sequence: 1, StatusVersion: 1, Status: "SUCCEEDED", Result: []byte(`{"core":"xray","load_state":"loaded","active_state":"active","sub_state":"running","observed_at":"2026-11-17T01:00:00Z"}`)}); err != nil {
		t.Fatal(err)
	}
	secondID := "request-3234567890123456"
	second, err := store.Issue("node-001", secondID, "test-key", publicKey, build(secondID, "node-001", "sing-box"))
	if err != nil || second.Sequence != 2 {
		t.Fatalf("second issue = %+v, %v", second, err)
	}
	records, err := store.ListRecords("node-001", 10)
	if err != nil || len(records) != 2 || records[0].TaskID != secondID || records[1].TaskID != requestID || len(records[1].Acks) != 1 {
		t.Fatalf("task history = %+v, %v", records, err)
	}
}

func TestIssueRejectsSignerReturningWrongTargetOrSignature(t *testing.T) {
	store, err := Init(filepath.Join(t.TempDir(), "tasks.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	wrongSigner, err := tasksigner.New("other-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(taskInput)
	_, err = store.Issue("node-001", "task-001", "test-key", publicKey, func(int64) ([]byte, error) {
		return wrongSigner.SignStatus(raw)
	})
	if err == nil {
		t.Fatal("accepted a task signed under a different key ID")
	}
	var count int
	if err = store.db.QueryRow(`SELECT COUNT(*) FROM tasks`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed issue left a task row: count=%d err=%v", count, err)
	}
}

func TestFailedStatusTaskIsTerminalAndReleasesNextSequence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tasks.db")
	store, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signer, err := tasksigner.New("test-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 11, 17, 1, 0, 0, 0, time.UTC)
	build := func(taskID string, sequence int64) ([]byte, error) {
		body := map[string]any{
			"schema_version": 2, "task_id": taskID, "node_id": "node-001", "sequence": sequence,
			"operation": "core.status", "issued_at": issued.Format(time.RFC3339),
			"not_before": issued.Format(time.RFC3339), "expires_at": issued.Add(5 * time.Minute).Format(time.RFC3339),
			"payload":        map[string]any{"core": "xray"},
			"step":           map[string]any{"step_id": "core.status", "parameters": map[string]any{"core": "xray"}, "artifact_sha256": "not-applicable", "architecture": "not-applicable", "expected_state": "observe"},
			"signing_key_id": "test-key", "signature_algorithm": "Ed25519", "signature": tasksigner.PlaceholderSignature,
		}
		unsigned, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			return nil, marshalErr
		}
		return signer.SignStatus(unsigned)
	}
	firstID, secondID := "request-1234567890123456", "request-2234567890123456"
	first, err := store.Issue("node-001", firstID, "test-key", publicKey, func(seq int64) ([]byte, error) { return build(firstID, seq) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Lease("node-001", issued, "test-key", publicKey); err != nil {
		t.Fatal(err)
	}
	if err = store.Acknowledge("node-001", Ack{NodeID: "node-001", TaskID: first.TaskID, Sequence: first.Sequence, StatusVersion: 1, Status: "FAILED", Result: []byte(`{"error_code":"helper_unavailable"}`)}); err != nil {
		t.Fatal(err)
	}
	record, err := store.GetRecord(firstID)
	if err != nil || record.Active {
		t.Fatalf("failed status task remained active: %+v err=%v", record, err)
	}
	second, err := store.Issue("node-001", secondID, "test-key", publicKey, func(seq int64) ([]byte, error) { return build(secondID, seq) })
	if err != nil || second.Sequence != 2 {
		t.Fatalf("next status sequence after failure = %+v err=%v", second, err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("failed status task did not reopen as terminal: %v", err)
	}
	defer reopened.Close()
}

func TestValidateLeaseProvidesIndependentFreshnessGate(t *testing.T) {
	store, err := Init(filepath.Join(t.TempDir(), "tasks.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	raw, publicKey := signed(t)
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	delivery, err := store.Issue("node-001", "task-001", "test-key", publicKey, func(int64) ([]byte, error) { return raw, nil })
	if err != nil {
		t.Fatal(err)
	}
	delivery, err = store.Lease("node-001", now, "test-key", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := store.ValidateLease("node-001", delivery.TaskID, delivery.Sequence, delivery.LeaseID, delivery.Raw, now, "test-key", publicKey)
	if err != nil || previous != 0 {
		t.Fatalf("valid lease authorization previous=%d err=%v", previous, err)
	}
	if _, err = store.ValidateLease("node-001", delivery.TaskID, delivery.Sequence, "wrong-lease-id-000000000000000", delivery.Raw, now, "test-key", publicKey); !errors.Is(err, ErrLeaseActive) {
		t.Fatalf("wrong lease was authorized: %v", err)
	}
	if _, err = store.ValidateLease("node-001", delivery.TaskID, delivery.Sequence, delivery.LeaseID, delivery.Raw, delivery.Deadline, "test-key", publicKey); !errors.Is(err, ErrLeaseActive) {
		t.Fatalf("expired lease was authorized: %v", err)
	}
	if err = store.Acknowledge("node-001", Ack{NodeID: "node-001", TaskID: delivery.TaskID, Sequence: delivery.Sequence, StatusVersion: 1, Status: "SUCCEEDED", Result: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ValidateLease("node-001", delivery.TaskID, delivery.Sequence, delivery.LeaseID, delivery.Raw, now, "test-key", publicKey); !errors.Is(err, ErrLeaseActive) {
		t.Fatalf("terminal task remained checkpoint-authorized: %v", err)
	}
}

func TestControlDeliveryPersistsAndClosesWithTerminalAck(t *testing.T) {
	store, err := Init(filepath.Join(t.TempDir(), "tasks.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	raw, publicKey := signed(t)
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer, err := tasksigner.New("test-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Issue("node-001", "task-001", "test-key", publicKey, func(int64) ([]byte, error) { return raw, nil }); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 16, 0, 1, 0, 0, time.UTC)
	control := signedControlForTest(t, signer, protocol.Cancel, map[string]any{
		"schema_version": 1, "node_id": "node-001", "task_id": "task-001", "sequence": 1,
		"issued_at": now.Format(time.RFC3339), "not_before": now.Format(time.RFC3339), "expires_at": now.Add(5 * time.Minute).Format(time.RFC3339),
		"signing_key_id": "test-key", "signature_algorithm": "Ed25519", "signature": tasksigner.PlaceholderSignature,
	})
	if err = store.SetControl("node-001", "task-001", protocol.Cancel, control, now, "test-key", publicKey); err != nil {
		t.Fatal(err)
	}
	record, err := store.GetRecord("task-001")
	if err != nil || record.ControlKind != string(protocol.Cancel) || string(record.ControlRaw) != string(control) {
		t.Fatalf("persisted cancel=%+v err=%v", record, err)
	}
	delivery, err := store.Lease("node-001", now.Add(time.Second), "test-key", publicKey)
	if err != nil || delivery.ControlKind != string(protocol.Cancel) || string(delivery.ControlRaw) != string(control) {
		t.Fatalf("cancel delivery=%+v err=%v", delivery, err)
	}
	if err = store.Acknowledge("node-001", Ack{NodeID: "node-001", TaskID: "task-001", Sequence: 1, StatusVersion: 1, Status: "CANCELED", Result: []byte(`{"error_code":"task_canceled"}`)}); err != nil {
		t.Fatal(err)
	}
	record, err = store.GetRecord("task-001")
	if err != nil || record.Active || record.ControlKind != "" || len(record.ControlRaw) != 0 || len(record.Acks) != 1 {
		t.Fatalf("terminal cancel record=%+v err=%v", record, err)
	}
}

func TestExpiredSkipControlDeliveryAndRejectStartedTask(t *testing.T) {
	store, err := Init(filepath.Join(t.TempDir(), "tasks.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	raw, publicKey := signed(t)
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer, err := tasksigner.New("test-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Issue("node-001", "task-001", "test-key", publicKey, func(int64) ([]byte, error) { return raw, nil }); err != nil {
		t.Fatal(err)
	}
	startedAt := time.Date(2026, 11, 16, 0, 1, 0, 0, time.UTC)
	if err = store.Acknowledge("node-001", Ack{NodeID: "node-001", TaskID: "task-001", Sequence: 1, StatusVersion: 1, Status: "ACK_ACCEPTED"}); err != nil {
		t.Fatal(err)
	}
	if err = store.Acknowledge("node-001", Ack{NodeID: "node-001", TaskID: "task-001", Sequence: 1, StatusVersion: 2, Status: "RUNNING"}); err != nil {
		t.Fatal(err)
	}
	expired := startedAt.Add(10 * time.Minute)
	skip := signedControlForTest(t, signer, protocol.Skip, map[string]any{
		"schema_version": 1, "node_id": "node-001", "sequence": 1, "reason": "EXPIRED",
		"issued_at": expired.Format(time.RFC3339), "not_before": expired.Format(time.RFC3339), "expires_at": expired.Add(5 * time.Minute).Format(time.RFC3339),
		"signing_key_id": "test-key", "signature_algorithm": "Ed25519", "signature": tasksigner.PlaceholderSignature,
	})
	if err = store.SetControl("node-001", "task-001", protocol.Skip, skip, expired, "test-key", publicKey); !errors.Is(err, ErrConflict) {
		t.Fatalf("skip replaced a started task: %v", err)
	}
}

func TestOpenAddsControlTableWithoutChangingLegacyTasks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tasks.db")
	store, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, publicKey := signed(t)
	if _, err = store.Issue("node-001", "task-001", "test-key", publicKey, func(int64) ([]byte, error) { return raw, nil }); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DROP TABLE task_controls`); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("legacy database migration failed: %v", err)
	}
	defer reopened.Close()
	record, err := reopened.GetRecord("task-001")
	if err != nil || record.TaskID != "task-001" || record.Sequence != 1 || !record.Active {
		t.Fatalf("legacy task changed during migration: %+v err=%v", record, err)
	}
	var controls int
	if err = reopened.db.QueryRow(`SELECT COUNT(*) FROM task_controls`).Scan(&controls); err != nil || controls != 0 {
		t.Fatalf("unexpected migrated controls=%d err=%v", controls, err)
	}
}

func signedControlForTest(t *testing.T, signer *tasksigner.Signer, kind protocol.Kind, fields map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignControl(kind, raw)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
