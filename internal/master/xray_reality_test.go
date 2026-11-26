package master

import (
	"context"
	"net/netip"
	"testing"
)

type realityTestResolver []netip.Addr

func (r realityTestResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r, nil
}

func TestPinRealityTargetRejectsPrivateAddresses(t *testing.T) {
	target, err := pinRealityTarget(context.Background(), "93.184.216.34:443")
	if err != nil || target != "93.184.216.34:443" {
		t.Fatalf("valid target: %q %v", target, err)
	}
	for _, target := range []string{"127.0.0.1:443", "169.254.169.254:80", "10.0.0.1:443", "localhost:443", "93.184.216.34:0"} {
		if _, err := pinRealityTarget(context.Background(), target); err == nil {
			t.Errorf("accepted protected target %q", target)
		}
	}
}

func TestPinRealityTargetRejectsMixedDNSAnswers(t *testing.T) {
	resolver := realityTestResolver{netip.MustParseAddr("93.184.216.35"), netip.MustParseAddr("93.184.216.34")}
	got, err := pinRealityTargetWithResolver(context.Background(), "example.com:443", resolver)
	if err != nil || got != "93.184.216.34:443" {
		t.Fatalf("unexpected pin: %q %v", got, err)
	}
	resolver = append(resolver, netip.MustParseAddr("169.254.169.254"))
	if _, err := pinRealityTargetWithResolver(context.Background(), "example.com:443", resolver); err == nil {
		t.Fatal("accepted mixed public and protected DNS answers")
	}
}
