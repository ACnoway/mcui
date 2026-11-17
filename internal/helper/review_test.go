//go:build linux

package helper

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestUnhealthyTrustedTimeDeniesExecution(t *testing.T) {
	h, raw, _, calls := fixture(t)
	field := reflect.ValueOf(&h.cfg).Elem().FieldByName("TrustedTimeHealthy")
	if !field.IsValid() {
		t.Fatal("missing trusted-time health interface")
	}
	field.Set(reflect.ValueOf(func() bool { return false }))
	if _, err := h.executeUID(uint32(os.Getuid()), raw); !errors.Is(err, ErrReconciliation) {
		t.Fatalf("unhealthy clock accepted: %v", err)
	}
	if *calls != 0 {
		t.Fatal(*calls)
	}
}

func TestRuntimeSocketFailsClosedWithoutIndependentCheckpoint(t *testing.T) {
	h, raw, _, calls := fixture(t)
	sock := filepath.Join(t.TempDir(), "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if _, err = h.Execute(server, raw); !errors.Is(err, ErrReconciliation) {
		t.Fatalf("runtime enabled without independent checkpoint: %v", err)
	}
	if *calls != 0 {
		t.Fatalf("status called %d times", *calls)
	}
}

func TestClockRollbackAfterRestartDenied(t *testing.T) {
	h, raw, _, calls := fixture(t)
	if _, err := h.executeUID(uint32(os.Getuid()), raw); err != nil {
		t.Fatal(err)
	}
	cfg := h.cfg
	cfg.Now = func() time.Time { return time.Date(2026, 11, 17, 0, 0, 30, 0, time.UTC) }
	reopened, err := Open(h.dir.Name(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = reopened.executeUID(uint32(os.Getuid()), raw); !errors.Is(err, ErrReconciliation) {
		t.Fatalf("rollback accepted: %v", err)
	}
	if *calls != 1 {
		t.Fatal(*calls)
	}
}

func TestCachedResultDoesNotHideLaterPending(t *testing.T) {
	h, raw, _, _ := fixture(t)
	uid := uint32(os.Getuid())
	if _, err := h.executeUID(uid, raw); err != nil {
		t.Fatal(err)
	}
	l, err := h.load()
	if err != nil {
		t.Fatal(err)
	}
	l.Records = append(l.Records, record{TaskID: "task-002", Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Pending: true})
	if err = h.save(l); err != nil {
		t.Fatal(err)
	}
	if _, err = h.executeUID(uid, raw); !errors.Is(err, ErrReconciliation) {
		t.Fatalf("pending masked by cached replay: %v", err)
	}
}
