//go:build linux

package runtimeupdate

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type systemdPair struct {
	dir        string
	agentUnit  string
	helperUnit string
}

func (s systemdPair) Stop(ctx context.Context) error {
	if _, err := systemctl(ctx, 50*time.Second, "stop", s.agentUnit, s.helperUnit); err != nil {
		return err
	}
	for _, unit := range []string{s.agentUnit, s.helperUnit} {
		props, err := s.properties(ctx, unit)
		if err != nil {
			return err
		}
		state := props["ActiveState"]
		if (state != "inactive" && state != "failed") || props["MainPID"] != "0" || props["ControlPID"] != "0" {
			return fmt.Errorf("%s did not stop", unit)
		}
		// A failed trial may reach the systemd start limit. A known stopped
		// service can clear it before the committed executable is restarted.
		if state == "failed" {
			if _, err := systemctl(ctx, 5*time.Second, "reset-failed", unit); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s systemdPair) Start(ctx context.Context) error {
	_, err := systemctl(ctx, 45*time.Second, "start", s.helperUnit, s.agentUnit)
	return err
}

func (s systemdPair) Healthy(ctx context.Context) error {
	pids, err := s.pids(ctx)
	if err != nil {
		return err
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return s.checkPIDs(ctx, pids)
		case <-ticker.C:
			if err := s.checkPIDs(ctx, pids); err != nil {
				return err
			}
		}
	}
}

func (s systemdPair) checkPIDs(ctx context.Context, expected [2]int) error {
	actual, err := s.pids(ctx)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("the runtime pair restarted during the health observation")
	}
	return nil
}

func (s systemdPair) pids(ctx context.Context) ([2]int, error) {
	var pids [2]int
	for i, unit := range []string{s.agentUnit, s.helperUnit} {
		props, err := s.properties(ctx, unit)
		if err != nil {
			return pids, err
		}
		path := filepath.Join(s.dir, "current", binaries[i])
		pid, err := strconv.Atoi(props["MainPID"])
		if err != nil || pid <= 1 || props["ActiveState"] != "active" || props["SubState"] != "running" ||
			props["Type"] != "notify" || props["NotifyAccess"] != "main" ||
			!strings.HasPrefix(props["ExecStart"], "{ path="+path+" ;") {
			return pids, fmt.Errorf("%s is not ready with the managed executable", unit)
		}
		pids[i] = pid
	}
	return pids, nil
}

func (s systemdPair) properties(ctx context.Context, unit string) (map[string]string, error) {
	out, err := systemctl(ctx, 3*time.Second, "show", "--property=Type,NotifyAccess,ExecStart,ActiveState,SubState,MainPID,ControlPID", unit)
	if err != nil {
		return nil, err
	}
	props := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			props[key] = value
		}
	}
	return props, nil
}

func systemctl(ctx context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", append([]string{"--no-pager", "--no-ask-password"}, args...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0"}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl %s: %w", args[0], err)
	}
	return out, nil
}
