//go:build linux

package xrayruntime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/xrayconfig"
	"golang.org/x/sys/unix"
)

const serviceUnit = "mcui-xray.service"
const preflightUnit = "mcui-xray-preflight.service"
const networkNamespace = "/run/netns/mcui-xray"

type networkPolicy uint8

const (
	networkPolicyBase networkPolicy = iota
	networkPolicyRestricted
	networkPolicyPanel
	networkPolicyPreflight
)

var panelNetworkAllow = []string{xrayconfig.PanelDNSAddress + "/32", "127.0.0.0/8"}
var panelNetworkDeny = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
	"fc00::/7", "fe80::/10", "ff00::/8",
}

type systemdService struct{}

type publishedInbound struct {
	port     int
	endpoint xrayconfig.PublicEndpoint
}

type panelNetworkService interface {
	panelAddresses() ([]string, error)
	setPanelDestinations(context.Context, []string, bool, bool) error
	startPanelIngress(context.Context, []publishedInbound) error
}

func (systemdService) panelAddresses() ([]string, error) {
	local, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var addresses []string
	for _, addr := range local {
		ip, _, _ := strings.Cut(addr.String(), "/")
		if (xrayconfig.PublicEndpoint{Address: ip, Port: 1}).Valid() {
			addresses = append(addresses, ip)
		}
	}
	slices.Sort(addresses)
	addresses = slices.Compact(addresses)
	return addresses[:min(16, len(addresses))], nil
}

func validatePanelAddresses(service panelNetworkService, published []publishedInbound) error {
	if len(published) == 0 {
		return nil
	}
	addresses, err := service.panelAddresses()
	if err != nil {
		return err
	}
	for _, inbound := range published {
		if !slices.Contains(addresses, inbound.endpoint.Address) {
			return errors.New("Xray public listener address is not bound to this node")
		}
	}
	return nil
}

func (systemdService) setPanelDestinations(ctx context.Context, destinations []string, published, direct bool) error {
	local, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, addr := range local {
		ip, _, _ := strings.Cut(addr.String(), "/")
		if slices.Contains(destinations, ip+"/32") {
			return errors.New("Xray panel route targets an address of this node")
		}
	}
	if err := systemctl(ctx, 22*time.Second, "start", "mcui-xray-network.service"); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	allow := append([]string{"127.0.0.1/32"}, destinations...)
	deny := []string{"0.0.0.0/0", "::/0"}
	if published {
		allow = append(allow, xrayconfig.PublicListenAddress+"/32")
	}
	if direct {
		allow = slices.Clone(panelNetworkAllow)
		deny = slices.Clone(panelNetworkDeny)
	}
	cmd := systemctlCommand(ctx, "set-property", "--runtime", serviceUnit,
		"IPAddressDeny=", "IPAddressDeny="+strings.Join(deny, " "),
		"IPAddressAllow=", "IPAddressAllow="+strings.Join(allow, " "))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("apply Xray direct-outbound address policy: %w", err)
	}
	raw, err := systemctlCommand(ctx, "show", "--property=IPAddressAllow,IPAddressDeny", serviceUnit).Output()
	values := systemdProperties(raw)
	gotAllow, gotDeny := strings.Fields(values["IPAddressAllow"]), strings.Fields(values["IPAddressDeny"])
	slices.Sort(gotAllow)
	slices.Sort(gotDeny)
	slices.Sort(allow)
	slices.Sort(deny)
	if err != nil || !slices.Equal(gotAllow, allow) || !slices.Equal(gotDeny, deny) {
		return errors.New("Xray direct-outbound address policy differs")
	}
	return nil
}

func (systemdService) startPanelIngress(ctx context.Context, published []publishedInbound) error {
	for _, inbound := range published {
		if err := startPanelSocket(ctx, inbound); err != nil {
			return err
		}
	}
	return nil
}

func startPanelSocket(ctx context.Context, inbound publishedInbound) error {
	name := fmt.Sprintf("mcui-xray-panel-publish-%d-%s-%d", inbound.port, inbound.endpoint.Address, inbound.endpoint.Port)
	socket := name + ".socket"
	if err := checkPublishUnits(ctx, inbound, name, true); err != nil {
		ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--quiet", "--no-ask-password", "--collect", "--unit="+name,
			"--socket-property=ListenStream="+inbound.endpoint.String(), "--socket-property=Accept=no",
			"--socket-property=BindsTo="+serviceUnit, "--socket-property=After="+serviceUnit,
			"--socket-property=CollectMode=inactive-or-failed",
			"--property=BindsTo="+socket, "--property=After="+socket+" "+serviceUnit,
			"--property=DynamicUser=yes", "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=",
			"--property=PrivateNetwork=yes", "--property=NetworkNamespacePath="+networkNamespace,
			"--property=RestrictAddressFamilies=AF_INET", "--property=IPAddressDeny=any",
			"--property=IPAddressAllow=127.0.0.1/32 "+xrayconfig.PublicListenAddress+"/32",
			"--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
			"--property=PrivateDevices=yes", "--property=ProtectControlGroups=yes", "--property=ProtectKernelTunables=yes",
			"--property=InaccessiblePaths=-/etc/mcui -/etc/mcui-agent -/etc/mcui-xray -/var/lib/mcui -/var/lib/mcui-agent -/var/lib/mcui-xray -/run/mcui",
			"--", "/usr/lib/systemd/systemd-socket-proxyd", "--connections-max=128",
			xrayconfig.PublicListenAddress+":"+strconv.Itoa(inbound.port))
		cmd.Env = systemdCommandEnv
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("open Xray public TCP listener %s: %w", inbound.endpoint, err)
		}
	}
	if err := checkPublishUnits(ctx, inbound, name, true); err != nil {
		return err
	}
	return systemctl(ctx, 7*time.Second, "start", socket)
}

func (systemdService) checkConfigUnits(ctx context.Context, destinations []string, published []publishedInbound, checkSockets bool, policy networkPolicy) error {
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
	if err := checkConfigUnit(ctx, preflightUnit, "candidate", "candidate-config.json", "-test ", "", nil, false, networkPolicyPreflight); err != nil {
		return err
	}
	if err := checkConfigUnit(ctx, serviceUnit, "current", "runtime-config.json", "", networkNamespace, destinations, len(published) > 0, policy); err != nil {
		return err
	}
	if checkSockets {
		for _, inbound := range published {
			if err := checkPublishUnit(ctx, inbound); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkConfigUnit(ctx context.Context, unit, bundle, config, flag, namespace string, destinations []string, published bool, policy networkPolicy) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := systemctlCommand(ctx, "show", "--property=ExecStart,StandardInput,NeedDaemonReload,PrivateNetwork,NetworkNamespacePath,DynamicUser,NoNewPrivileges,IPAddressDeny,IPAddressAllow", unit)
	raw, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("read Xray configuration sandbox for %s: %w", unit, err)
	}
	values := systemdProperties(raw)
	argv := "argv[]=" + StateDir + "/" + bundle + "/xray run " + flag + "-config stdin: ;"
	if values["PrivateNetwork"] != "yes" || values["NetworkNamespacePath"] != namespace ||
		values["DynamicUser"] != "yes" || values["NoNewPrivileges"] != "yes" ||
		values["StandardInput"] != "file" || values["NeedDaemonReload"] != "no" || !strings.Contains(values["ExecStart"], argv) ||
		(policy == networkPolicyPreflight && (!deniesAllIP(values) || values["IPAddressAllow"] != "")) ||
		(policy == networkPolicyBase && !validCurrentNetworkPolicy(values)) ||
		(policy == networkPolicyRestricted && !deniesAllIP(values)) {
		return fmt.Errorf("Xray configuration sandbox does not match the required settings for %s", unit)
	}
	if policy == networkPolicyPanel {
		if !panelNetworkPolicyMatches(values) {
			return errors.New("Xray panel service direct-outbound policy differs")
		}
	}
	if namespace != "" && policy == networkPolicyRestricted {
		allow := strings.Fields(values["IPAddressAllow"])
		for _, entry := range allow {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 ||
				(prefix.Addr().IsLoopback() && entry != "127.0.0.1/32" && entry != xrayconfig.PublicListenAddress+"/32") ||
				(!prefix.Addr().IsLoopback() && !(xrayconfig.PublicEndpoint{Address: prefix.Addr().String(), Port: 1}).Valid()) {
				return errors.New("Xray service IP allowances must be individual IPv4 addresses")
			}
		}
		if !slices.Contains(allow, "127.0.0.1/32") {
			return errors.New("Xray service lacks IP allowances for the approved route")
		}
		for _, destination := range destinations {
			if !slices.Contains(allow, destination) {
				return errors.New("Xray service lacks IP allowances for the approved route")
			}
		}
		if published && !slices.Contains(allow, xrayconfig.PublicListenAddress+"/32") {
			return errors.New("Xray service lacks the public ingress loopback allowance")
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

func deniesAllIP(values map[string]string) bool {
	deny := strings.Fields(values["IPAddressDeny"])
	return len(deny) == 2 && slices.Contains(deny, "0.0.0.0/0") && slices.Contains(deny, "::/0")
}

func panelNetworkPolicyMatches(values map[string]string) bool {
	allow, deny := strings.Fields(values["IPAddressAllow"]), strings.Fields(values["IPAddressDeny"])
	slices.Sort(allow)
	slices.Sort(deny)
	wantAllow, wantDeny := slices.Clone(panelNetworkAllow), slices.Clone(panelNetworkDeny)
	slices.Sort(wantAllow)
	slices.Sort(wantDeny)
	return slices.Equal(allow, wantAllow) && slices.Equal(deny, wantDeny)
}

func validCurrentNetworkPolicy(values map[string]string) bool {
	if panelNetworkPolicyMatches(values) {
		return true
	}
	if !deniesAllIP(values) {
		return false
	}
	for _, entry := range strings.Fields(values["IPAddressAllow"]) {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 ||
			(prefix.Addr().IsLoopback() && entry != "127.0.0.1/32" && entry != xrayconfig.PublicListenAddress+"/32") ||
			(!prefix.Addr().IsLoopback() && !(xrayconfig.PublicEndpoint{Address: prefix.Addr().String(), Port: 1}).Valid()) {
			return false
		}
	}
	return true
}

func checkPublishUnit(ctx context.Context, inbound publishedInbound) error {
	return checkPublishUnits(ctx, inbound, "mcui-xray-publish@"+strconv.Itoa(inbound.port), false)
}

func checkPublishUnits(ctx context.Context, inbound publishedInbound, name string, managed bool) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	port := strconv.Itoa(inbound.port)
	socket, service := name+".socket", name+".service"
	raw, err := systemctlCommand(ctx, "show", "--property=LoadState,NeedDaemonReload,Listen,Accept,Triggers,NetworkNamespacePath,PrivateNetwork,Transient,BindsTo", socket).Output()
	values := systemdProperties(raw)
	if err != nil || values["LoadState"] != "loaded" || values["NeedDaemonReload"] != "no" || values["Accept"] != "no" ||
		values["Listen"] != inbound.endpoint.String()+" (Stream)" || values["Triggers"] != service ||
		values["PrivateNetwork"] == "yes" || values["NetworkNamespacePath"] != "" ||
		(managed && (values["Transient"] != "yes" || values["BindsTo"] != serviceUnit)) {
		return fmt.Errorf("Xray public socket %s does not match the approved endpoint", socket)
	}
	raw, err = systemctlCommand(ctx, "show", "--property=LoadState,NeedDaemonReload,ExecStart,PrivateNetwork,NetworkNamespacePath,DynamicUser,NoNewPrivileges,IPAddressDeny,IPAddressAllow,BindsTo,Transient", service).Output()
	values = systemdProperties(raw)
	argv := "argv[]=/usr/lib/systemd/systemd-socket-proxyd --connections-max=128 " + xrayconfig.PublicListenAddress + ":" + port + " ;"
	allow := strings.Fields(values["IPAddressAllow"])
	if err != nil || values["LoadState"] != "loaded" || values["NeedDaemonReload"] != "no" || values["BindsTo"] != socket ||
		values["PrivateNetwork"] != "yes" || values["NetworkNamespacePath"] != networkNamespace || values["DynamicUser"] != "yes" ||
		values["NoNewPrivileges"] != "yes" || !strings.Contains(values["ExecStart"], argv) || !deniesAllIP(values) ||
		len(allow) != 2 || !slices.Contains(allow, "127.0.0.1/32") || !slices.Contains(allow, xrayconfig.PublicListenAddress+"/32") ||
		(managed && values["Transient"] != "yes") {
		return fmt.Errorf("Xray public ingress service %s does not use the required isolated relay", service)
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
	command.Env = systemdCommandEnv
	return command
}

var systemdCommandEnv = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0"}
