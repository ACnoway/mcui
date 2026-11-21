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
