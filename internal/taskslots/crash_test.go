package taskslots

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The child exits after commit without Close. This tests process-exit recovery,
// not power loss: it does not discard the OS page cache or simulate storage faults.
func TestAbruptExitPreservesReservation(t *testing.T) {
	if path := os.Getenv("TASKSLOTS_CRASH_DB"); path != "" {
		s, err := Open(path)
		if err != nil {
			os.Exit(2)
		}
		if _, err = s.Reserve("node", "task", []byte("exact")); err != nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
	path := filepath.Join(t.TempDir(), "db")
	s, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAbruptExitPreservesReservation$")
	cmd.Env = append(os.Environ(), "TASKSLOTS_CRASH_DB="+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v %s", err, out)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Reserve("node", "task", []byte("exact"))
	if err != nil || got.Sequence != 1 {
		t.Fatalf("recovery: %+v %v", got, err)
	}
}
