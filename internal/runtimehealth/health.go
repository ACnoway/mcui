package runtimehealth

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"
)

const Protocol = 1
const StateDir = "/var/lib/mcui-runtime"
const TrialFile = "trial"

func Managed() bool { return os.Getenv("MCUI_RUNTIME_TRIAL_FILE") != "" }

// Trial reports whether the root supervisor is testing a candidate. The path
// is supplied by the locally installed systemd unit.
func Trial() (bool, error) {
	path := os.Getenv("MCUI_RUNTIME_TRIAL_FILE")
	if path == "" {
		return false, nil
	}
	if !filepath.IsAbs(path) {
		return false, errors.New("runtime trial marker path must be absolute")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0022 != 0 {
		return false, errors.New("runtime trial directory is unavailable or writable")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0444 || info.Size() != 0 {
		return false, errors.New("invalid runtime trial marker")
	}
	return true, nil
}

func NotifyReady() error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return errors.New("managed runtime requires a systemd notification socket")
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	_, err = conn.Write([]byte("READY=1"))
	return err
}

// WaitForCommit prevents the candidate Agent from polling until the supervisor
// has durably committed the pair.
func WaitForCommit() error {
	deadline := time.NewTimer(90 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		trial, err := Trial()
		if err != nil || !trial {
			return err
		}
		select {
		case <-deadline.C:
			return errors.New("runtime pair was not committed")
		case <-ticker.C:
		}
	}
}
