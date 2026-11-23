package xrayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRealityPlanBindsPublicKeyAndLimitsHandshakeTarget(t *testing.T) {
	release := strings.Repeat("a", 64)
	privateKey := strings.Repeat("Q", 43)
	credential := "cc2f34e1-8197-4751-b505-c27f9e2d841b:0123456789abcdef"
	catalog := LocalCatalog{
		ReleaseSHA256: release, Ports: []int{1080}, DestinationIP: "93.184.216.34", DestinationPort: 8080,
		PortProtocols: map[int]string{1080: VLESSReality}, ProtocolCredentials: map[string]map[string]string{VLESSReality: {"alice": credential}},
		RealityPrivateKey: privateKey,
	}
	view, err := catalog.Public(release)
	if err != nil || view.RealityPublicKey == "" || view.RealityPublicKey == privateKey {
		t.Fatalf("REALITY public identity unavailable: %v", err)
	}
	wire, err := json.Marshal(view)
	if err != nil || strings.Contains(string(wire), "0123456789abcdef") || strings.Contains(string(wire), privateKey) ||
		strings.Contains(string(wire), "cc2f34e1-") {
		t.Fatal("REALITY inventory includes private handshake or user credentials")
	}
	plan := Plan{{Port: 1080, Protocol: VLESSReality, RealityPublicKey: view.RealityPublicKey, Users: []string{"alice"}}}
	if parsed, err := ParsePlan(plan.Encode()); err != nil || !view.Allows(parsed) {
		t.Fatalf("approved REALITY plan rejected: %v", err)
	}
	raw, ref, err := catalog.Render(release, plan)
	if err != nil || !ref.Matches(raw) || !strings.Contains(string(raw), `"target":"127.0.0.1:10443"`) ||
		!strings.Contains(string(raw), `"protocol":"vless"`) || !strings.Contains(string(raw), `"shortIds":["0123456789abcdef"]`) {
		t.Fatalf("invalid REALITY config or handshake target: %v", err)
	}
	catalog.RealityPrivateKey = strings.Repeat("M", 43)
	if _, _, err := catalog.Render(release, plan); err == nil {
		t.Fatal("old REALITY public key was accepted after rotation")
	}
	catalog.Ports = []int{1080, realityTargetPort}
	if _, err := catalog.Public(release); err == nil {
		t.Fatal("managed port could take the REALITY handshake target")
	}
	catalog.Ports = []int{1080}
	catalog.ProtocolCredentials[VLESS] = map[string]string{"bob": strings.SplitN(credential, ":", 2)[0]}
	if _, err := catalog.Public(release); err == nil {
		t.Fatal("reused a VLESS identity across security profiles")
	}
	delete(catalog.ProtocolCredentials, VLESS)
	catalog.ProtocolCredentials[VLESSReality]["bob"] = "d631da39-7a6d-4ac4-8b3e-a0a39ec02f38:0123456789abcdef"
	if _, err := catalog.Public(release); err == nil {
		t.Fatal("reused a REALITY short ID")
	}
}
