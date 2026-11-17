// Package taskintegration exercises the existing component boundary only. It is
// not a runtime, a trusted-clock implementation, or an authorization service.
package taskintegration_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
	"github.com/ACnoway/mcui/internal/taskauth"
	"github.com/ACnoway/mcui/internal/taskcontrol"
	"github.com/ACnoway/mcui/internal/taskledger"
	"github.com/ACnoway/mcui/internal/tasksigner"
)

var now = time.Date(2026, 11, 16, 0, 1, 0, 0, time.UTC)

const unsignedTask = `{"schema_version":2,"task_id":"task-1","node_id":"node-1","sequence":1,"operation":"core.status","issued_at":"2026-11-16T00:00:00Z","not_before":"2026-11-16T00:00:00Z","expires_at":"2026-11-16T00:10:00Z","payload":{"core":"xray"},"step":{"step_id":"core.status","parameters":{"core":"xray"},"artifact_sha256":"not-applicable","architecture":"not-applicable","expected_state":"observe"},"signing_key_id":"key-1","signature_algorithm":"Ed25519","signature":"` + tasksigner.PlaceholderSignature + `"}`

type fixture struct {
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	trust  taskcontrol.Trust
	task   []byte
	cancel []byte
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := tasksigner.New("key-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	task, err := signer.SignStatus([]byte(unsignedTask))
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{pub: pub, priv: priv, task: task, trust: taskcontrol.Trust{NodeID: "node-1", KeyID: "key-1", Purpose: taskcontrol.PurposeTask, PublicKey: pub, Now: now}}
	f.cancel = signCancel(t, priv, "2026-11-16T00:09:00Z")
	return f
}

func signCancel(t *testing.T, key ed25519.PrivateKey, expiry string) []byte {
	t.Helper()
	fields := map[string]any{"schema_version": 1, "node_id": "node-1", "task_id": "task-1", "sequence": 1, "issued_at": "2026-11-16T00:00:00Z", "not_before": "2026-11-16T00:00:00Z", "expires_at": expiry, "signing_key_id": "key-1", "signature_algorithm": "Ed25519", "signature": tasksigner.PlaceholderSignature}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := protocol.CanonicalSignedBytes(protocol.Cancel, raw)
	if err != nil {
		t.Fatal(err)
	}
	fields["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(key, msg))
	raw, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	// Preserve non-canonical whitespace to check that stored evidence is exact.
	return append([]byte(" \n"), raw...)
}

// authenticateTask uses the actual verifier but this test still supplies its
// own trust and clock; neither is a production authorization or clock service.
func authenticateTask(raw []byte, trust taskcontrol.Trust) (taskledger.Task, error) {
	verified, err := taskauth.Verify(raw, taskauth.Trust{
		NodeID: trust.NodeID,
		Keys: map[string]taskauth.Key{trust.KeyID: {
			PublicKey: trust.PublicKey, Active: true, Purpose: trust.Purpose,
		}},
		Now: trust.Now,
	})
	if err != nil {
		return taskledger.Task{}, err
	}
	return taskledger.Task{ID: verified.TaskID, Sequence: int64(verified.Sequence), Envelope: verified.Raw, NotBefore: verified.NotBefore, ExpiresAt: verified.ExpiresAt}, nil
}

// Verify immediately before application and derive every ledger argument from
// that freshly verified snapshot; this does not make trust or time production-safe.
func applyCancel(l *taskledger.Ledger, raw []byte, trust taskcontrol.Trust) error {
	v, err := taskcontrol.Verify(protocol.Cancel, raw, trust)
	if err != nil {
		return err
	}
	return l.AcceptCancel(int64(v.Sequence), v.TaskID, v.Raw)
}

func newLedger(t *testing.T) (*taskledger.Ledger, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ledger.db")
	l, err := taskledger.Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	return l, path
}
func reopen(t *testing.T, l *taskledger.Ledger, path string) *taskledger.Ledger {
	t.Helper()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err := taskledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return l
}
func acceptedTask(t *testing.T, f fixture) taskledger.Task {
	t.Helper()
	task, err := authenticateTask(f.task, f.trust)
	if err != nil {
		t.Fatal(err)
	}
	return task
}
func assertState(t *testing.T, l *taskledger.Ledger, state taskledger.State, task, cancel []byte, next int64) {
	t.Helper()
	got, err := l.Get(1)
	if err != nil || got.ID != "task-1" || got.State != state || !bytes.Equal(got.Envelope, task) {
		t.Fatalf("task = %+v, error %v", got, err)
	}
	id, evidence, err := l.GetCancel(1)
	if cancel == nil {
		if !errors.Is(err, taskledger.ErrNotFound) {
			t.Fatalf("unexpected cancellation %q %q: %v", id, evidence, err)
		}
	} else if err != nil || id != "task-1" || !bytes.Equal(evidence, cancel) {
		t.Fatalf("cancellation %q %q: %v", id, evidence, err)
	}
	n, err := l.Next()
	if err != nil || n != next {
		t.Fatalf("next = %d: %v", n, err)
	}
}

func TestDelayedSignedCancellationSurvivesReopen(t *testing.T) {
	f := newFixture(t)
	l, path := newLedger(t)
	if err := applyCancel(l, f.cancel, f.trust); err != nil {
		t.Fatal(err)
	}
	if err := applyCancel(l, f.cancel, f.trust); err != nil {
		t.Fatalf("duplicate cancel: %v", err)
	}
	id, evidence, err := l.GetCancel(1)
	if err != nil || id != "task-1" || !bytes.Equal(evidence, f.cancel) {
		t.Fatalf("tombstone %q %q: %v", id, evidence, err)
	}
	l = reopen(t, l, path)
	defer func() { _ = l.Close() }()
	got, err := l.Accept(acceptedTask(t, f), now)
	if err != nil || got.State != taskledger.Canceled {
		t.Fatalf("delayed task: %+v: %v", got, err)
	}
	if _, err := l.Start(1, now); !errors.Is(err, taskledger.ErrState) {
		t.Fatalf("canceled task started: %v", err)
	}
	if _, err := l.Accept(acceptedTask(t, f), now); err != nil {
		t.Fatalf("duplicate task: %v", err)
	}
	assertState(t, l, taskledger.Canceled, f.task, f.cancel, 2)
	l = reopen(t, l, path)
	assertState(t, l, taskledger.Canceled, f.task, f.cancel, 2)
}

func TestTamperedAndUntrustedMessagesLeaveLedgerUnchanged(t *testing.T) {
	f := newFixture(t)
	l, path := newLedger(t)
	defer func() { _ = l.Close() }()
	if _, err := l.Accept(acceptedTask(t, f), now); err != nil {
		t.Fatal(err)
	}
	original, err := l.Get(1)
	if err != nil {
		t.Fatal(err)
	}
	tamperedTask := bytes.Replace(f.task, []byte(`"task_id":"task-1"`), []byte(`"task_id":"task-2"`), 1)
	if bytes.Equal(tamperedTask, f.task) {
		t.Fatal("task tamper failed")
	}
	if _, err := authenticateTask(tamperedTask, f.trust); err == nil || !strings.Contains(err.Error(), "signature:") {
		t.Fatalf("task signature tamper: %v", err)
	}
	tampered := bytes.Replace(f.cancel, []byte(`"task_id":"task-1"`), []byte(`"task_id":"task-2"`), 1)
	if bytes.Equal(tampered, f.cancel) {
		t.Fatal("cancel tamper failed")
	}
	if err := applyCancel(l, tampered, f.trust); !errors.Is(err, taskcontrol.ErrSignature) {
		t.Fatalf("cancel signature tamper: %v", err)
	}
	wrongNode := f.trust
	wrongNode.NodeID = "node-2"
	if err := applyCancel(l, f.cancel, wrongNode); !errors.Is(err, taskcontrol.ErrTarget) {
		t.Fatalf("node binding: %v", err)
	}
	wrongKey := f.trust
	wrongKey.KeyID = "key-2"
	if err := applyCancel(l, f.cancel, wrongKey); !errors.Is(err, taskcontrol.ErrKey) {
		t.Fatalf("key binding: %v", err)
	}
	expired := f.trust
	expired.Now = time.Date(2026, 11, 16, 0, 9, 0, 0, time.UTC)
	if err := applyCancel(l, f.cancel, expired); !errors.Is(err, taskcontrol.ErrTime) {
		t.Fatalf("time binding: %v", err)
	}
	assertState(t, l, taskledger.Pending, f.task, nil, 1)
	l = reopen(t, l, path)
	after, err := l.Get(1)
	if err != nil || !reflect.DeepEqual(original, after) {
		t.Fatalf("task changed: %+v: %v", after, err)
	}
	assertState(t, l, taskledger.Pending, f.task, nil, 1)
}

func TestStartRacesAuthenticatedCancellation(t *testing.T) {
	for i := 0; i < 20; i++ {
		f := newFixture(t)
		l, path := newLedger(t)
		if _, err := l.Accept(acceptedTask(t, f), now); err != nil {
			t.Fatal(err)
		}
		gate := make(chan struct{})
		startResult, cancelResult := make(chan error, 1), make(chan error, 1)
		go func() { <-gate; _, err := l.Start(1, now); startResult <- err }()
		go func() { <-gate; cancelResult <- applyCancel(l, f.cancel, f.trust) }()
		close(gate)
		startErr, cancelErr := <-startResult, <-cancelResult
		switch {
		case startErr == nil && errors.Is(cancelErr, taskledger.ErrTooLate):
			assertState(t, l, taskledger.Running, f.task, nil, 1)
			l = reopen(t, l, path)
			assertState(t, l, taskledger.Reconciliation, f.task, nil, 1)
		case errors.Is(startErr, taskledger.ErrState) && cancelErr == nil:
			assertState(t, l, taskledger.Canceled, f.task, f.cancel, 2)
			l = reopen(t, l, path)
			assertState(t, l, taskledger.Canceled, f.task, f.cancel, 2)
		default:
			t.Fatalf("start=%v cancel=%v", startErr, cancelErr)
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAuthenticatedDifferentDuplicateQuarantines(t *testing.T) {
	for _, kind := range []string{"task", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			l, path := newLedger(t)
			if _, err := l.Accept(acceptedTask(t, f), now); err != nil {
				t.Fatal(err)
			}
			if kind == "task" {
				// Whitespace is cryptographically equivalent but not byte-identical delivery.
				alt := append([]byte(" "), f.task...)
				task, err := authenticateTask(alt, f.trust)
				if err != nil {
					t.Fatal(err)
				}
				_, err = l.Accept(task, now)
				if !errors.Is(err, taskledger.ErrConflict) {
					t.Fatalf("task conflict: %v", err)
				}
			} else {
				if err := applyCancel(l, f.cancel, f.trust); err != nil {
					t.Fatal(err)
				}
				alt := signCancel(t, f.priv, "2026-11-16T00:08:00Z")
				if bytes.Equal(alt, f.cancel) {
					t.Fatal("identical alternate")
				}
				if err := applyCancel(l, alt, f.trust); !errors.Is(err, taskledger.ErrConflict) {
					t.Fatalf("cancel conflict: %v", err)
				}
			}
			if _, err := l.Get(1); !errors.Is(err, taskledger.ErrQuarantined) {
				t.Fatalf("not quarantined: %v", err)
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := taskledger.Open(path)
			if err == nil {
				reopened.Close()
				t.Fatal("quarantine did not survive reopen")
			}
		})
	}
}
