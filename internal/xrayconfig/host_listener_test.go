package xrayconfig

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestHostListenerAndTag(t *testing.T) {
	for _, listener := range []HostListener{{"0.0.0.0", 443}, {"127.0.0.1", 1080}, {"::", 443}, {"2001:4860:4860::8888", 443}} {
		if !listener.Valid() {
			t.Errorf("valid host listener rejected: %+v", listener)
		}
	}
	for _, listener := range []HostListener{{"localhost", 443}, {"::ffff:127.0.0.1", 443}, {"224.0.0.1", 443}, {"fe80::1%eth0", 443}, {"0.0.0.0", 0}} {
		if listener.Valid() {
			t.Errorf("invalid host listener accepted: %+v", listener)
		}
	}
	endpoint := PublicEndpoint{Address: "93.184.216.34", Port: 443}
	tag := HostInboundTag(1080, endpoint)
	port, got, ok := ParseHostInboundTag(tag)
	if !ok || port != 1080 || got != endpoint {
		t.Fatal("host tag did not round-trip")
	}
	if _, _, ok := ParseHostInboundTag(tag + "="); ok {
		t.Fatal("non-canonical host tag accepted")
	}
}

func TestPanelHostListenerRendersAndReconstructs(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := PublicEndpoint{Address: "93.184.216.34", Port: 8443}
	in := Inbound{Port: 1080, Protocol: VLESS, Users: []string{"alice"}, PublicEndpoint: endpoint,
		HostListen: &HostListener{Address: "0.0.0.0", Port: 443}}
	box, err := SealPanelCredential(base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), in, "00000000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	draft := Configuration{Inbounds: Plan{in}, Network: &Network{Outbounds: []Outbound{}, Routes: []Route{}, Host: true},
		Panel: &PanelConfiguration{Credentials: []string{box}, DirectPorts: []int{1080}}}
	data, ref, err := draft.RenderPanel(key)
	if err != nil || !ref.Matches(data) {
		t.Fatalf("host render failed: %v", err)
	}
	var config struct {
		Inbounds []struct {
			Listen string `json:"listen"`
			Port   int    `json:"port"`
			Tag    string `json:"tag"`
		} `json:"inbounds"`
		DNS struct {
			Tag     string   `json:"tag"`
			Servers []string `json:"servers"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(data, &config); err != nil || len(config.Inbounds) != 1 {
		t.Fatal("invalid rendered host config", err)
	}
	entry := config.Inbounds[0]
	if entry.Listen != "0.0.0.0" || entry.Port != 443 || config.DNS.Tag != PanelHostDNSTag || len(config.DNS.Servers) != 1 || config.DNS.Servers[0] != "localhost" {
		t.Fatalf("host listener or DNS differs: %s", data)
	}
	port, advertised, ok := ParseHostInboundTag(entry.Tag)
	if !ok || port != in.Port || advertised != endpoint {
		t.Fatal("host tag lost logical inbound or endpoint")
	}
	applied, err := AppliedNetwork(data, map[string]int{entry.Tag: in.Port})
	if err != nil || applied == nil || !applied.Host {
		t.Fatalf("host mode not reconstructed: %+v %v", applied, err)
	}
	withoutMode := draft
	withoutMode.Network = &Network{Outbounds: []Outbound{}, Routes: []Route{}}
	if withoutMode.Valid() {
		t.Fatal("host listener accepted without host mode")
	}
}
