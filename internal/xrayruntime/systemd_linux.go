//go:build linux

package xrayruntime

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const serviceUnit = "mcui-xray.service"
const preflightUnit = "mcui-xray-preflight.service"
const networkNamespace = "/run/netns/mcui-xray"

type systemdService struct{}

func (systemdService) checkConfigUnits(ctx context.Context, destination string) error {
	ns, err := os.Lstat(networkNamespace)
	if err != nil {
		return errors.New("Xray requires a dedicated network namespace")
	}
	host, err := os.Stat("/proc/self/ns/net")
	var fs unix.Statfs_t
	if err != nil || !ns.Mode().IsRegular() || os.SameFile(ns, host) ||
		unix.Statfs(networkNamespace, &fs) != nil || fs.Type != unix.NSFS_MAGIC {
		return errors.New("invalid dedicated Xray network namespace")
	}
	if err := checkConfigUnit(ctx, preflightUnit, "candidate", "candidate-config.json", "-test ", "", ""); err != nil {
		return err
	}
	return checkConfigUnit(ctx, serviceUnit, "current", "runtime-config.json", "", networkNamespace, destination)
}

func checkConfigUnit(ctx context.Context, unit, bundle, config, flag, namespace, destination string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := systemctlCommand(ctx, "show", "--property=ExecStart,StandardInput,NeedDaemonReload,PrivateNetwork,NetworkNamespacePath,DynamicUser,NoNewPrivileges,IPAddressDeny,IPAddressAllow", unit)
	raw, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("read Xray configuration sandbox for %s: %w", unit, err)
	}
	values := systemdProperties(raw)
	argv := "argv[]=" + StateDir + "/" + bundle + "/xray run " + flag + "-config stdin: ;"
	deny := strings.Fields(values["IPAddressDeny"])
	if values["PrivateNetwork"] != "yes" || values["NetworkNamespacePath"] != namespace ||
		values["DynamicUser"] != "yes" || values["NoNewPrivileges"] != "yes" ||
		values["StandardInput"] != "file" || values["NeedDaemonReload"] != "no" || !strings.Contains(values["ExecStart"], argv) ||
		len(deny) != 2 || !strings.Contains(values["IPAddressDeny"], "0.0.0.0/0") || !strings.Contains(values["IPAddressDeny"], "::/0") ||
		(namespace == "" && values["IPAddressAllow"] != "") {
		return fmt.Errorf("Xray configuration sandbox does not match the required settings for %s", unit)
	}
	if namespace != "" {
		allow := strings.Fields(values["IPAddressAllow"])
		var loopback, endpoint bool
		for _, entry := range allow {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 {
				return errors.New("Xray service IP allowances must be individual IPv4 addresses")
			}
			loopback = loopback || entry == "127.0.0.1/32"
			endpoint = endpoint || entry == destination
		}
		if !loopback || (destination != "" && !endpoint) {
			return errors.New("Xray service lacks IP allowances for the approved route")
		}
	}
	// systemd exposes the input type through D-Bus, but omits the file path.
	// Read the unit and its drop-ins after checking that they match the loaded unit.
	raw, err = systemctlCommand(ctx, "cat", unit).Output()
	if err != nil || unitStandardInput(raw) != "file:"+StateDir+"/control/"+config {
		return fmt.Errorf("Xray unit %s does not use the required private configuration", unit)
	}
	return nil
}

func unitStandardInput(raw []byte) string {
	var section, input string
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\\\n", " "), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
		}
		if name, value, ok := strings.Cut(line, "="); ok && section == "[Service]" && strings.TrimSpace(name) == "StandardInput" {
			input = strings.TrimSpace(value)
		}
	}
	return input
}

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
	// A failed start can leave the unit failed even after systemd finishes
	// stopping it. Clear that state before restoring the previous selection.
	if state["MainPID"] == "0" && state["ActiveState"] == "failed" && state["SubState"] == "failed" {
		if err := systemctl(ctx, 20*time.Second, "reset-failed", serviceUnit); err != nil {
			return err
		}
		state, err = serviceState(ctx)
		if err != nil {
			return err
		}
	}
	if state["MainPID"] != "0" || state["ActiveState"] != "inactive" || state["SubState"] != "dead" {
		return fmt.Errorf("Xray systemd service is not stopped (%s/%s, PID %s)", state["ActiveState"], state["SubState"], state["MainPID"])
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
	return systemdProperties(data), nil
}

func systemdProperties(data []byte) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if ok {
			values[name] = value
		}
	}
	return values
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
