package master

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/ACnoway/mcui/internal/xrayconfig"
)

// pinRealityTarget resolves once before signing. REALITY's own dialer bypasses
// Xray's routing and Freedom rules, so it must never receive a mutable hostname.
func pinRealityTarget(ctx context.Context, target string) (string, error) {
	return pinRealityTargetWithResolver(ctx, target, net.DefaultResolver)
}

func pinRealityTargetWithResolver(ctx context.Context, target string, resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}) (string, error) {
	if !xrayconfig.ValidRealityTargetInput(target) {
		return "", errors.New("invalid REALITY target")
	}
	host, port, _ := net.SplitHostPort(target)
	if ip, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(ip.String(), port), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := resolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return "", errors.New("REALITY target DNS unavailable")
	}
	for _, ip := range ips {
		if !(xrayconfig.PublicEndpoint{Address: ip.String(), Port: 1}).Valid() {
			return "", errors.New("REALITY target DNS returned a non-public address")
		}
	}
	slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
	return net.JoinHostPort(ips[0].String(), port), nil
}
