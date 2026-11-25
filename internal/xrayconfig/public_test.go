package xrayconfig

import (
	"strings"
	"testing"
)

func TestPublicEndpointBindsEncryptedPlanToDedicatedLoopback(t *testing.T) {
	release := strings.Repeat("a", 64)
	key := strings.Repeat("Q", 43)
	endpoint := PublicEndpoint{Address: "93.184.216.35", Port: 443}
	catalog := LocalCatalog{
		ReleaseSHA256: release, Ports: []int{1080, 1081}, DestinationIP: "93.184.216.34", DestinationPort: 8080,
		PortProtocols: map[int]string{1080: VLESSReality}, PublicEndpoints: map[int]PublicEndpoint{1080: endpoint},
		Credentials: map[string]string{"bob": strings.Repeat("I", 43)},
		ProtocolCredentials: map[string]map[string]string{
			VLESSReality: {"alice": "cc2f34e1-8197-4751-b505-c27f9e2d841b:0123456789abcdef"},
		},
		RealityPrivateKey: key,
	}
	view, err := catalog.Public(release)
	if err != nil || view.PublicEndpoints[1080] != endpoint {
		t.Fatalf("approved public endpoint not reported: %v", err)
	}
	plan := Plan{
		{Port: 1080, Protocol: VLESSReality, RealityPublicKey: view.RealityPublicKey, PublicEndpoint: endpoint, Users: []string{"alice"}},
		{Port: 1081, Users: []string{"bob"}},
	}
	got, err := ParsePlan(plan.Encode())
	if err != nil || !view.Allows(got) {
		t.Fatalf("approved public plan rejected: %v", err)
	}
	encoded := plan.Encode()
	if strings.Count(encoded, `"public_endpoint"`) != 1 {
		t.Fatal("local-only port lost its original encoding")
	}
	raw, ref, err := catalog.Render(release, plan)
	if err != nil || !ref.Matches(raw) || !strings.Contains(string(raw), `"listen":"127.0.0.2","port":1080`) ||
		!strings.Contains(string(raw), `"listen":"127.0.0.1","port":1081`) ||
		!strings.Contains(string(raw), `"tag":"published-93.184.216.35:443"`) {
		t.Fatalf("render did not isolate the published service or bind the endpoint: %v", err)
	}
	if decoded, ok := PublishedEndpoint("published-93.184.216.35:443"); !ok || decoded != endpoint {
		t.Fatal("committed tag did not bind the public endpoint")
	}
	plan[0].PublicEndpoint.Port = 8443
	if view.Allows(plan) {
		t.Fatal("accepted endpoint outside the current node policy")
	}
	plan[1].PublicEndpoint = endpoint
	if plan.Valid() {
		t.Fatal("accepted a public endpoint for a plaintext protocol")
	}
	for _, address := range []string{"0.0.0.0", "127.0.0.1", "10.1.2.3", "203.0.113.9", "localhost", "::1"} {
		if (PublicEndpoint{Address: address, Port: 443}).Valid() {
			t.Errorf("accepted non-public endpoint %q", address)
		}
	}
}

func TestPublicVLESSPlan(t *testing.T) {
	endpoint := PublicEndpoint{Address: "93.184.216.35", Port: 443}
	plan := Plan{{Port: 1080, Protocol: VLESS, PublicEndpoint: endpoint, Users: []string{"alice"}}}
	if !plan.Valid() {
		t.Fatal("public VLESS plan was rejected")
	}
}
