package xrayconfig

import (
	"strings"
	"testing"
)

func TestManagedNetworkRoundTripAndPolicy(t *testing.T) {
	release := strings.Repeat("a", 64)
	first := Destination{Address: "93.184.216.34", Port: 443}
	second := Destination{Address: "93.184.216.35", Port: 8443}
	catalog := LocalCatalog{
		ReleaseSHA256: release, Ports: []int{1080, 1081}, DestinationIP: first.Address, DestinationPort: first.Port,
		Credentials: map[string]string{"alice": strings.Repeat("A", 43)}, RoutingDestinations: []Destination{first, second},
	}
	plan := Plan{{Port: 1080, Users: []string{"alice"}}, {Port: 1081, Users: []string{"alice"}}}
	network := &Network{
		Outbounds: []Outbound{{Tag: "first", Destination: first}, {Tag: "second", Destination: second}},
		Routes:    []Route{{InboundPort: 1081, OutboundTag: "second"}, {InboundPort: 1080, OutboundTag: "first"}},
	}
	draft := Configuration{Inbounds: plan, Network: network}
	encoded := draft.Encode()
	decoded, err := ParseConfiguration(encoded)
	if err != nil || decoded.Encode() != encoded {
		t.Fatalf("configuration draft round-trip failed: %v", err)
	}
	raw, ref, err := catalog.RenderConfiguration(release, draft)
	if err != nil || !ref.Matches(raw) || !strings.Contains(string(raw), `"outbounds":[{"protocol":"blackhole","tag":"deny"}`) {
		t.Fatalf("managed configuration must have a default-deny outbound: %s, %v", raw, err)
	}
	ports := map[string]int{"socks-1080": 1080, "socks-1081": 1081}
	applied, err := AppliedNetwork(raw, ports)
	if err != nil || (Configuration{Inbounds: plan, Network: applied}).Encode() != encoded {
		t.Fatalf("committed configuration did not retain the signed network draft: %v", err)
	}
	legacy, legacyRef, err := catalog.Render(release, plan)
	if err != nil || legacyRef == ref {
		t.Fatalf("legacy configuration must have a different digest: %v", err)
	}
	legacyNetwork, err := AppliedNetwork(legacy, ports)
	if err != nil || legacyNetwork != nil {
		t.Fatalf("legacy config must remain inbound-only: %v", err)
	}
	if _, err := ParseConfiguration(strings.Replace(encoded, `"port":443`, `"port":443,"port":8443`, 1)); err == nil {
		t.Fatal("accepted a duplicate configuration field")
	}
	catalog.RoutingDestinations = []Destination{first}
	if _, _, err := catalog.RenderConfiguration(release, draft); err == nil {
		t.Fatal("rendered a previously approved but now revoked destination")
	}
	network.Outbounds[1].Destination = Destination{Address: "169.254.169.254", Port: 80}
	if _, err := ParseConfiguration(draft.Encode()); err == nil {
		t.Fatal("accepted a service metadata destination")
	}
	network.Outbounds = network.Outbounds[:1]
	if draft.Valid() {
		t.Fatal("accepted a routing rule referencing a deleted outbound")
	}
}
