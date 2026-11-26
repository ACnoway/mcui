//go:build linux

package xrayruntime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"
)

func hostUnitProperties(ctx context.Context, unit, properties string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, err := systemctlCommand(ctx, "show", "--property="+properties, unit).Output()
	if err != nil {
		return nil, fmt.Errorf("read Xray host unit %s: %w", unit, err)
	}
	return systemdProperties(raw), nil
}

func (s *systemdService) checkHostUnits(ctx context.Context) error {
	directory, err := os.Lstat("/usr/local/libexec")
	if err != nil || !directory.IsDir() || directory.Mode().Perm()&0022 != 0 || !owned(directory) {
		return errors.New("Xray host firewall helper directory is not securely owned")
	}
	info, err := os.Lstat("/usr/local/libexec/mcui-xray-host-network")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0755 || !owned(info) {
		return errors.New("Xray host firewall helper is not root-owned and immutable to other users")
	}
	info, err = os.Lstat("/usr/sbin/nft")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 || !owned(info) {
		return errors.New("Xray host firewall executable is unavailable or writable by other users")
	}
	p, err := hostUnitProperties(ctx, hostServiceUnit, "ExecStart,StandardInput,NeedDaemonReload,PrivateNetwork,NetworkNamespacePath,DynamicUser,NoNewPrivileges,User,Group,CapabilityBoundingSet,AmbientCapabilities,RestrictAddressFamilies,ProtectSystem,BindsTo,Requires,After,IPAddressDeny,IPAddressAllow")
	if err != nil {
		return err
	}
	argv := "argv[]=" + StateDir + "/current/xray run -config stdin: ;"
	if !strings.Contains(p["ExecStart"], argv) || p["StandardInput"] != "file" || p["NeedDaemonReload"] != "no" ||
		p["PrivateNetwork"] != "no" || p["NetworkNamespacePath"] != "" || p["DynamicUser"] != "no" ||
		p["NoNewPrivileges"] != "yes" || p["User"] != "mcui-xray-host" || p["Group"] != "mcui-xray-stats" ||
		p["CapabilityBoundingSet"] != "cap_net_bind_service" || p["AmbientCapabilities"] != "cap_net_bind_service" ||
		p["ProtectSystem"] != "strict" || !slices.Contains(strings.Fields(p["BindsTo"]), hostGuardUnit) ||
		!slices.Contains(strings.Fields(p["Requires"]), hostGuardUnit) || !slices.Contains(strings.Fields(p["After"]), hostGuardUnit) ||
		p["IPAddressDeny"] != "" || p["IPAddressAllow"] != "" {
		return errors.New("Xray host service sandbox differs from required settings")
	}
	families := strings.Fields(p["RestrictAddressFamilies"])
	slices.Sort(families)
	if !slices.Equal(families, []string{"AF_INET", "AF_INET6", "AF_UNIX"}) {
		return errors.New("Xray host service address families differ")
	}
	raw, err := systemctlCommand(ctx, "cat", hostServiceUnit).Output()
	if err != nil || unitStandardInput(raw) != "file:"+StateDir+"/control/runtime-config.json" {
		return errors.New("Xray host service does not use the private configuration")
	}
	for _, item := range []struct{ unit, argument string }{{hostGuardUnit, "start"}, {hostCheckUnit, "verify"}} {
		p, err := hostUnitProperties(ctx, item.unit, "ExecStart,ExecStop,Type,RemainAfterExit,NoNewPrivileges,CapabilityBoundingSet,User,ProtectSystem,NeedDaemonReload")
		if err != nil || p["Type"] != "oneshot" || p["User"] != "root" || p["NoNewPrivileges"] != "yes" ||
			p["CapabilityBoundingSet"] != "cap_net_admin" || p["ProtectSystem"] != "strict" || p["NeedDaemonReload"] != "no" ||
			!strings.Contains(p["ExecStart"], "argv[]=/usr/local/libexec/mcui-xray-host-network "+item.argument+" ;") ||
			(item.unit == hostGuardUnit && (p["RemainAfterExit"] != "yes" ||
				!strings.Contains(p["ExecStop"], "argv[]=/usr/local/libexec/mcui-xray-host-network stop ;"))) {
			return errors.New("Xray host firewall unit differs from required settings")
		}
	}
	return nil
}

func (s *systemdService) checkHostCandidate(destinations []string, published []publishedInbound) error {
	local, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	addresses := make(map[netip.Addr]bool, len(local))
	for _, addr := range local {
		prefix, err := netip.ParsePrefix(addr.String())
		if err == nil {
			addresses[prefix.Addr().Unmap()] = true
		}
	}
	for _, destination := range destinations {
		prefix, err := netip.ParsePrefix(destination)
		if err != nil || addresses[prefix.Addr().Unmap()] {
			return errors.New("Xray target is an address of this node")
		}
	}
	for _, inbound := range published {
		address, err := netip.ParseAddr(inbound.listen.Address)
		if !inbound.host || err != nil || (!address.IsUnspecified() && !addresses[address]) {
			return errors.New("Xray host listener address is not bound to this node")
		}
	}
	return nil
}

func (s *systemdService) prepareHost(ctx context.Context, destinations []string, published []publishedInbound) error {
	if err := s.checkHostUnits(ctx); err != nil {
		return err
	}
	if err := s.checkHostCandidate(destinations, published); err != nil {
		return err
	}
	if err := systemctl(ctx, 22*time.Second, "start", hostGuardUnit); err != nil {
		return err
	}
	return systemctl(ctx, 10*time.Second, "start", hostCheckUnit)
}
