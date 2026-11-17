package agenttasks_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/agenttasks"
	"github.com/ACnoway/mcui/internal/taskauth"
	"github.com/ACnoway/mcui/internal/taskledger"
	"github.com/ACnoway/mcui/internal/tasksigner"
)

const unsigned = `{"schema_version":2,"task_id":"task-001","node_id":"node-001","sequence":1,"operation":"core.status","issued_at":"2026-11-16T00:00:00Z","not_before":"2026-11-16T00:00:00Z","expires_at":"2026-11-16T00:10:00Z","payload":{"core":"xray"},"step":{"step_id":"core.status","parameters":{"core":"xray"},"artifact_sha256":"not-applicable","architecture":"not-applicable","expected_state":"observe"},"signing_key_id":"test-key","signature_algorithm":"Ed25519","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}`

func TestReceivePersistsSignedTask(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	l, err := taskledger.Initialize(filepath.Join(dir, "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer, err := tasksigner.New("test-key", key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signer.SignStatus([]byte(unsigned))
	if err != nil {
		t.Fatal(err)
	}
	p, err := agenttasks.New(agenttasks.Config{NodeID: "node-001", Keys: map[string]taskauth.Key{"test-key": {PublicKey: key.Public().(ed25519.PublicKey), Active: true, Purpose: taskauth.PurposeTask}}, Now: func() time.Time { return time.Date(2026, 11, 16, 0, 1, 0, 0, time.UTC) }, Ledger: l})
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Receive(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "task-001" || got.State != taskledger.Pending || !bytes.Equal(got.Envelope, raw) {
		t.Fatalf("unexpected task: %+v", got)
	}
}

func TestRejectionsAndRecovery(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ledger")
	l, err := taskledger.Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if l != nil {
			_ = l.Close()
		}
	}()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer, err := tasksigner.New("test-key", key)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(input string) []byte {
		t.Helper()
		raw, e := signer.SignStatus([]byte(input))
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	now := time.Date(2026, 11, 16, 0, 1, 0, 0, time.UTC)
	config := agenttasks.Config{NodeID: "node-001", Keys: map[string]taskauth.Key{"test-key": {PublicKey: key.Public().(ed25519.PublicKey), Active: true, Purpose: taskauth.PurposeTask}}, Now: func() time.Time { return now }, Ledger: l}
	p, err := agenttasks.New(config)
	if err != nil {
		t.Fatal(err)
	}
	good := sign(unsigned)
	cases := []struct {
		name     string
		raw      []byte
		expected error
	}{
		{"tampered", bytes.Replace(good, []byte("task-001"), []byte("task-002"), 1), taskauth.ErrSignature},
		{"wrong node", sign(strings.Replace(unsigned, "node-001", "node-002", 1)), taskauth.ErrTarget},
		{"gap", sign(strings.Replace(unsigned, `"sequence":1`, `"sequence":2`, 1)), taskledger.ErrGap},
		{"unsupported operation", bytes.Replace(good, []byte("core.status"), []byte("core.start"), 1), taskauth.ErrSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, e := p.Receive(context.Background(), tc.raw)
			if !errors.Is(e, tc.expected) {
				t.Fatalf("got %v, want %v", e, tc.expected)
			}
			if _, e = l.Get(1); !errors.Is(e, taskledger.ErrNotFound) {
				t.Fatalf("ledger changed: %v", e)
			}
			n, e := l.Next()
			if e != nil || n != 1 {
				t.Fatalf("next=%d err=%v", n, e)
			}
		})
	}
	now = time.Date(2026, 11, 16, 0, 10, 0, 0, time.UTC)
	if _, err = p.Receive(context.Background(), good); !errors.Is(err, taskauth.ErrTime) {
		t.Fatalf("expired: %v", err)
	}
	now = time.Date(2026, 11, 15, 23, 59, 59, 0, time.UTC)
	if _, err = p.Receive(context.Background(), good); !errors.Is(err, taskauth.ErrTime) {
		t.Fatalf("early: %v", err)
	}
	now = time.Date(2026, 11, 16, 0, 1, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = p.Receive(ctx, good); !errors.Is(err, context.Canceled) {
		t.Fatalf("context: %v", err)
	}
	if _, err = p.Receive(context.Background(), good); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Receive(context.Background(), good); err != nil {
		t.Fatalf("duplicate: %v", err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	l = nil
	l, err = taskledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := l.Get(1)
	if err != nil || got.State != taskledger.Pending || !bytes.Equal(got.Envelope, good) {
		t.Fatalf("reopen: %+v %v", got, err)
	}
	config.Ledger = l
	p, err = agenttasks.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Receive(context.Background(), good); err != nil {
		t.Fatalf("reboot duplicate: %v", err)
	}
}
