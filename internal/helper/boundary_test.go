//go:build linux

package helper

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"

	"errors"
	"fmt"
	"github.com/ACnoway/mcui/internal/protocol"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Helper, []byte, ed25519.PrivateKey, *int32) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	var calls int32
	c := Config{TrustedTimeHealthy: func() bool { return true }, NodeID: "node-001", AllowedUID: uint32(os.Getuid()), Keys: map[string]TrustedKey{"key-1": {PublicKey: pub, Purpose: "task"}}, Now: func() time.Time { return time.Date(2026, 11, 17, 0, 1, 0, 0, time.UTC) }, ReadStatus: func(string) (string, error) { atomic.AddInt32(&calls, 1); return "active", nil }}
	h, e := Initialize(dir, c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { h.Close() })
	return h, signed(t, priv, "node-001", 1), priv, &calls
}
func TestDenialsDoNotConsume(t *testing.T) {
	h, raw, priv, calls := fixture(t)
	uid := uint32(os.Getuid())
	for _, tc := range []struct {
		name   string
		data   []byte
		uid    uint32
		mutate func()
	}{
		{"peer", raw, uid + 1, nil}, {"node", signed(t, priv, "node-other", 1), uid, nil},
		{"signature", []byte(strings.Replace(string(raw), "xray", "mita", 2)), uid, nil},
		{"extra argument", []byte(strings.Replace(string(raw), `"payload":{`, `"payload":{"unit":"sshd.service",`, 1)), uid, nil},
		{"key", raw, uid, func() { h.cfg.Keys["key-1"] = TrustedKey{PublicKey: h.cfg.Keys["key-1"].PublicKey, Purpose: "other"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := h.cfg.Keys["key-1"]
			if tc.mutate != nil {
				tc.mutate()
			}
			defer func() { h.cfg.Keys["key-1"] = original }()
			if _, e := h.executeUID(tc.uid, tc.data); !errors.Is(e, ErrDenied) {
				t.Fatalf("got %v", e)
			}
		})
	}
	if *calls != 0 {
		t.Fatal("read on denial")
	}
	if _, e := h.executeUID(uid, raw); e != nil {
		t.Fatal(e)
	}
}
func TestPendingNeverReexecutes(t *testing.T) {
	h, raw, _, calls := fixture(t)
	h.cfg.ReadStatus = func(string) (string, error) { atomic.AddInt32(calls, 1); return "", errors.New("crash") }
	if _, e := h.executeUID(uint32(os.Getuid()), raw); !errors.Is(e, ErrReconciliation) {
		t.Fatal(e)
	}
	if _, e := h.executeUID(uint32(os.Getuid()), raw); !errors.Is(e, ErrReconciliation) || *calls != 1 {
		t.Fatalf("%v calls %d", e, *calls)
	}
}
func TestConcurrentReplay(t *testing.T) {
	h, raw, _, calls := fixture(t)
	var wg sync.WaitGroup
	errs := make(chan error, 24)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := h.executeUID(uint32(os.Getuid()), raw)
			if e != nil || r != "active" {
				errs <- fmt.Errorf("%q %v", r, e)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if *calls != 1 {
		t.Fatalf("calls %d", *calls)
	}
}
func TestTimeAndKeyBoundaries(t *testing.T) {
	h, raw, priv, calls := fixture(t)
	signEdit := func(edits map[string]any) []byte {
		var o map[string]any
		if e := json.Unmarshal(raw, &o); e != nil {
			t.Fatal(e)
		}
		for k, v := range edits {
			o[k] = v
		}
		b, _ := json.Marshal(o)
		msg, e := protocol.CanonicalV2TaskBytes(b)
		if e != nil {
			t.Fatal(e)
		}
		o["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
		b, _ = json.Marshal(o)
		return b
	}
	now := time.Date(2026, 11, 17, 0, 1, 0, 0, time.UTC)
	cases := []struct {
		name  string
		data  []byte
		clock time.Time
	}{
		{"not before", raw, now.Add(-time.Minute - time.Second)},
		{"expiry", raw, now.Add(9 * time.Minute)},
		{"future issued", signEdit(map[string]any{"issued_at": "2026-11-17T00:01:31Z", "not_before": "2026-11-17T00:01:31Z"}), now},
		{"unknown key", signEdit(map[string]any{"signing_key_id": "unknown"}), now},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h.cfg.Now = func() time.Time { return tc.clock }
			if _, e := h.executeUID(uint32(os.Getuid()), tc.data); !errors.Is(e, ErrDenied) && !errors.Is(e, ErrReconciliation) {
				t.Fatalf("%v", e)
			}
		})
	}
	if *calls != 0 {
		t.Fatal(*calls)
	}
}

func TestTimeAfterLockWait(t *testing.T) {
	h, raw, _, calls := fixture(t)
	h.cfg.Now = func() time.Time { return time.Date(2026, 11, 17, 0, 1, 0, 0, time.UTC) }
	// A caller can block on the ledger lock while the task expires.
	other, e := Open(h.dir.Name(), h.cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if e = unix.Flock(int(other.dir.Fd()), unix.LOCK_EX); e != nil {
		t.Fatal(e)
	}
	clockCalled := make(chan struct{}, 1)
	var expired atomic.Bool
	h.cfg.Now = func() time.Time {
		select {
		case clockCalled <- struct{}{}:
		default:
		}
		if expired.Load() {
			return time.Date(2026, 11, 17, 0, 10, 0, 0, time.UTC)
		}
		return time.Date(2026, 11, 17, 0, 1, 0, 0, time.UTC)
	}
	done := make(chan error, 1)
	go func() { _, e := h.executeUID(uint32(os.Getuid()), raw); done <- e }()
	select {
	case <-clockCalled:
	case <-time.After(100 * time.Millisecond):
	}
	expired.Store(true)
	unix.Flock(int(other.dir.Fd()), unix.LOCK_UN)
	if e = <-done; !errors.Is(e, ErrDenied) {
		t.Fatalf("expired while waiting: %v, calls=%d", e, *calls)
	}
}

func TestSequenceConflict(t *testing.T) {
	h, raw, priv, calls := fixture(t)
	if _, e := h.executeUID(uint32(os.Getuid()), raw); e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	json.Unmarshal(raw, &v)
	v["task_id"] = "task-other"
	raw2, _ := json.Marshal(v)
	if _, e := h.executeUID(uint32(os.Getuid()), raw2); !errors.Is(e, ErrDenied) {
		t.Fatal(e)
	}
	_ = priv
	if *calls != 1 {
		t.Fatal(*calls)
	}
}
func TestActualSocketPeer(t *testing.T) {
	h, raw, _, calls := fixture(t)
	sock := filepath.Join(t.TempDir(), "s")
	ln, e := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	client, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server, e := ln.AcceptUnix()
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	h.cfg.AllowedUID = uint32(os.Getuid()) + 1
	if _, e = h.Execute(server, raw); !errors.Is(e, ErrDenied) {
		t.Fatal(e)
	}
	h.cfg.AllowedUID = uint32(os.Getuid())
	if _, e = h.Execute(server, raw); !errors.Is(e, ErrReconciliation) || *calls != 0 {
		t.Fatalf("socket runtime should be disabled: %v calls=%d", e, *calls)
	}
}
