package xrayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPolicyRejectsDuplicateAndUnknownFields(t *testing.T) {
	valid := `{"release_sha256":"example","listen_port":1080,"password":"password","destination_ip":"93.184.216.34","destination_port":8080}`
	for _, extra := range []string{`"listen_port":1081`, `"unknown":true`} {
		raw := strings.TrimSuffix(valid, "}") + "," + extra + "}"
		var policy Policy
		if json.Unmarshal([]byte(raw), &policy) == nil {
			t.Fatalf("accepted invalid policy field %s", extra)
		}
	}
}

func TestControlledInboundPolicy(t *testing.T) {
	release := strings.Repeat("a", 64)
	policy := Policy{ReleaseSHA256: release, ListenPort: 1080, Password: strings.Repeat("A", 43), DestinationIP: "93.184.216.34", DestinationPort: 8080}
	data, ref, err := policy.Render(release)
	if err != nil || ref.Port != 1080 || !ref.Matches(data) || ref.Matches(append(data, '\n')) {
		t.Fatal("rendered configuration does not bind the exact bytes and port")
	}
	if repeat, _, err := policy.Render(release); err != nil || string(data) != string(repeat) {
		t.Fatal("configuration is not deterministic")
	}
	if _, _, err := policy.Render(strings.Repeat("b", 64)); err == nil {
		t.Fatal("rendered configuration for a different release")
	}
	for _, ip := range []string{
		"localhost", "::ffff:93.184.216.34", "2001:4860:4860::8888", "127.0.0.1", "10.1.2.3", "172.16.1.1",
		"192.168.0.1", "169.254.169.254", "168.63.129.16", "100.100.100.200", "192.0.2.1", "198.19.0.1", "224.0.0.1",
	} {
		policy.DestinationIP = ip
		if _, _, err := policy.Render(release); err == nil {
			t.Errorf("accepted forbidden destination %s", ip)
		}
	}
	policy.DestinationIP, policy.Password = "93.184.216.34", "weak"
	if _, _, err := policy.Render(release); err == nil {
		t.Fatal("accepted an incorrectly encoded password")
	}
}

func TestManagedInboundsBindGrantsAndCredentialRotation(t *testing.T) {
	release := strings.Repeat("a", 64)
	catalog := LocalCatalog{
		ReleaseSHA256: release, Ports: []int{1081, 1080}, DestinationIP: "93.184.216.34", DestinationPort: 8080,
		Credentials: map[string]string{"alice": strings.Repeat("A", 43), "bob": strings.Repeat("E", 43)},
	}
	plan := Plan{{Port: 1080, Users: []string{"alice", "bob"}}, {Port: 1081, Users: []string{"bob"}}}
	const legacyPlan = `[{"port":1080,"users":["alice","bob"]},{"port":1081,"users":["bob"]}]`
	if plan.Encode() != legacyPlan {
		t.Fatal("existing authorization encoding changed")
	}
	if got, err := ParsePlan(plan.Encode()); err != nil || got.Encode() != plan.Encode() {
		t.Fatalf("canonical plan rejected: %v", err)
	}
	raw, ref, err := catalog.Render(release, plan)
	if err != nil || ref.Port != 1080 || !ref.Matches(raw) || !strings.Contains(string(raw), `"inboundTag":["socks-1080","socks-1081"]`) {
		t.Fatalf("managed grants failed to render: %v", err)
	}
	catalog.HTTPPorts = []int{1081}
	if _, _, err := catalog.Render(release, plan); err == nil {
		t.Fatal("rendered the SOCKS template on an HTTP-only port")
	}
	plan[1].Protocol = HTTP
	if got, err := ParsePlan(plan.Encode()); err != nil || !got.UsesHTTP() {
		t.Fatalf("HTTP-only authorization did not round trip: %v", err)
	}
	data, mixed, err := catalog.Render(release, plan)
	if err != nil || mixed == ref || !mixed.Matches(data) ||
		!strings.Contains(string(data), `"inboundTag":["socks-1080","http-1081"]`) ||
		!strings.Contains(string(data), `"protocol":"http","settings":{"allowTransparent":false,"users":[{"pass":"`+catalog.Credentials["bob"]+`","user":"bob"}]}`) {
		t.Fatalf("HTTP-only grant did not bind its template and users: %v", err)
	}
	ref = mixed
	for _, ports := range [][]int{{1082}, {1081, 1081}} {
		invalid := catalog
		invalid.HTTPPorts = ports
		if _, err := invalid.Public(release); err == nil {
			t.Fatal("accepted invalid HTTP port catalog")
		}
	}
	public, err := catalog.Public(release)
	view, _ := json.Marshal(public)
	if err != nil || strings.Contains(string(view), catalog.Credentials["alice"]) || strings.Contains(string(view), catalog.DestinationIP) {
		t.Fatalf("unexpected public catalog: %s", view)
	}
	delete(catalog.Credentials, "alice")
	if _, _, err := catalog.Render(release, plan); err == nil {
		t.Fatal("rendered a removed credential")
	}
	catalog.Credentials["alice"] = strings.Repeat("I", 43)
	if _, rotated, err := catalog.Render(release, plan); err != nil || rotated == ref {
		t.Fatal("credential rotation did not change the approved content")
	}
	raw, ref, err = catalog.Render(release, Plan{})
	if err != nil || !ref.Matches(raw) || !strings.Contains(string(raw), `"inbounds":[]`) || strings.Contains(string(raw), `"routing"`) {
		t.Fatalf("empty plan must remove listeners and allow rules: %v", err)
	}
	for _, bad := range []string{
		`null`, `[{"port":1080,"users":[]}]`, `[{"port":1080,"users":["alice","alice"]}]`,
		`[{"port":1080,"users":["bob","alice"]}]`, `[{"port":1080,"port":1081,"users":["alice"]}]`,
		`[{"port":1080,"users":["alice"],"destination":"1.2.3.4"}]`,
		`[{"port":1080,"protocol":"socks","users":["alice"]}]`, `[{"port":1080,"protocol":"vless","users":["alice"]}]`,
	} {
		if _, err := ParsePlan(bad); err == nil {
			t.Errorf("accepted invalid plan %s", bad)
		}
	}
	unknown := Plan{{Port: 1082, Users: []string{"alice"}}}
	if _, _, err := catalog.Render(release, unknown); err == nil {
		t.Fatal("rendered an unapproved listen port")
	}
}
