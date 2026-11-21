//go:build linux

package xrayruntime

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const serviceUnit = "mcui-xray.service"
const preflightUnit = "mcui-xray-preflight.service"

type systemdService struct{}

func (systemdService) preflight(ctx context.Context) error {
	if err := systemctl(ctx, 20*time.Second, "stop", preflightUnit); err != nil {
		return err
	}
	return systemctl(ctx, 20*time.Second, "start", preflightUnit)
}

func (systemdService) start(ctx context.Context) error {
	if err := systemctl(ctx, 20*time.Second, "start", serviceUnit); err != nil {
		return err
	}
	pid, err := runningPID(ctx)
	if err != nil {
		return err
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return checkPID(ctx, pid)
		case <-ticker.C:
			if err := checkPID(ctx, pid); err != nil {
				return err
			}
		}
	}
}

func (systemdService) stop(ctx context.Context) error {
	if err := systemctl(ctx, 20*time.Second, "stop", serviceUnit); err != nil {
		return err
	}
	state, err := serviceState(ctx)
	if err != nil {
		return err
	}
	if state["MainPID"] != "0" || state["ActiveState"] != "inactive" || state["SubState"] != "dead" {
		return errors.New("Xray systemd service is not stopped")
	}
	return nil
}

func checkPID(ctx context.Context, expected int) error {
	actual, err := runningPID(ctx)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("Xray process changed during startup confirmation")
	}
	return nil
}

func runningPID(ctx context.Context) (int, error) {
	values, err := serviceState(ctx)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(values["MainPID"])
	if err != nil || pid <= 1 || values["ActiveState"] != "active" || values["SubState"] != "running" {
		return 0, errors.New("Xray systemd process is not running")
	}
	return pid, nil
}

func serviceState(ctx context.Context) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := systemctlCommand(ctx, "show", "--property=ActiveState,SubState,MainPID", serviceUnit)
	data, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("read Xray systemd status: %w", err)
	}
	values := make(map[string]string, 3)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if ok {
			values[name] = value
		}
	}
	return values, nil
}

func systemctl(ctx context.Context, timeout time.Duration, action string, unit string) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := systemctlCommand(ctx, action, unit).Run(); err != nil {
		return fmt.Errorf("systemd %s %s: %w", action, unit, err)
	}
	return nil
}

func systemctlCommand(ctx context.Context, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", append([]string{"--no-pager", "--no-ask-password"}, args...)...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0"}
	return command
}
