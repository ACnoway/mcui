package xrayconfig

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPanelCredentialsAreBoundToNodeAndInbound(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "00000000-0000-4000-8000-000000000001"
	inbound := Inbound{Port: 1080, Protocol: VLESS, Users: []string{"alice"}}
	sealed, err := SealPanelCredential(base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), inbound, secret)
	if err != nil {
		t.Fatal(err)
	}
	draft := Configuration{
		Inbounds: Plan{inbound},
		Network: &Network{
			Outbounds: []Outbound{{Tag: "target-1080", Destination: Destination{Address: "93.184.216.34", Port: 443}}},
			Routes:    []Route{{InboundPort: 1080, OutboundTag: "target-1080"}},
		},
		Panel: &PanelConfiguration{Credentials: []string{sealed}},
	}
	encoded := draft.Encode()
	if bytes.Contains([]byte(encoded), []byte(secret)) {
		t.Fatal("draft contains an unencrypted credential")
	}
	parsed, err := ParseConfiguration(encoded)
	if err != nil {
		t.Fatal(err)
	}
	data, ref, err := parsed.RenderPanel(key)
	if err != nil || !ref.Matches(data) || !bytes.Contains(data, []byte(secret)) || !bytes.Contains(data, []byte(`"listen":"127.0.0.1"`)) {
		t.Fatalf("panel draft did not render locally: %v", err)
	}
	if _, _, err := parsed.RenderPanel(other); err == nil {
		t.Fatal("accepted a draft for another node")
	}
	parsed.Inbounds[0].Users[0] = "bob"
	if _, _, err := parsed.RenderPanel(key); err == nil {
		t.Fatal("accepted a credential assigned to another user")
	}
	parsed = draft
	parsed.Network.Outbounds[0].Destination.Address = "127.0.0.1"
	if parsed.Valid() {
		t.Fatal("allowed a route to a local management destination")
	}
}

func TestPanelSocksInboundUsesProtectedDirectOutbound(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	inbound := Inbound{
		Port: 1080, PublicEndpoint: PublicEndpoint{Address: "93.184.216.35", Port: 443}, Users: []string{"alice"},
	}
	sealed, err := SealPanelCredential(public, inbound, strings.Repeat("A", 43))
	if err != nil {
		t.Fatal(err)
	}
	draft := Configuration{
		Inbounds: Plan{inbound}, Network: &Network{Outbounds: []Outbound{}, Routes: []Route{}},
		Panel: &PanelConfiguration{Credentials: []string{sealed}, DirectPorts: []int{1080}},
	}
	withoutDirect := draft
	withoutDirect.Panel = &PanelConfiguration{Credentials: draft.Panel.Credentials}
	if withoutDirect.Valid() {
		t.Fatal("accepted a panel SOCKS inbound without its protected direct route")
	}
	raw, ref, err := draft.RenderPanel(key)
	if err != nil || !ref.Matches(raw) {
		t.Fatalf("failed to render SOCKS5 inbound: %v", err)
	}
	var config struct {
		DNS struct {
			Tag           string   `json:"tag"`
			Servers       []string `json:"servers"`
			QueryStrategy string   `json:"queryStrategy"`
		} `json:"dns"`
		Inbounds []struct {
			Listen   string `json:"listen"`
			Protocol string `json:"protocol"`
			Settings struct {
				Auth string `json:"auth"`
				UDP  bool   `json:"udp"`
			} `json:"settings"`
		} `json:"inbounds"`
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Tag      string `json:"tag"`
			Settings struct {
				DomainStrategy string `json:"domainStrategy"`
				FinalRules     []struct {
					Action string   `json:"action"`
					IP     []string `json:"ip"`
				} `json:"finalRules"`
			} `json:"settings"`
		} `json:"outbounds"`
		Routing struct {
			Rules []struct {
				InboundTags []string `json:"inboundTag"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 1 || config.Inbounds[0].Listen != PublicListenAddress ||
		config.Inbounds[0].Protocol != "socks" || config.Inbounds[0].Settings.Auth != "password" || config.Inbounds[0].Settings.UDP {
		t.Fatalf("unexpected rendered SOCKS5 inbound: %s", raw)
	}
	if len(config.Outbounds) != 3 || config.Outbounds[0].Tag != denyTag || config.Outbounds[2].Tag != PanelDNSTag ||
		config.Outbounds[1].Tag != "direct" || config.Outbounds[1].Protocol != "freedom" ||
		config.Outbounds[1].Settings.DomainStrategy != "UseIPv4" || len(config.Outbounds[1].Settings.FinalRules) != 1 ||
		config.DNS.Tag != PanelDNSTag || !slices.Equal(config.DNS.Servers, []string{PanelDNSAddress}) || config.DNS.QueryStrategy != "UseIPv4" {
		t.Fatalf("SOCKS5 inbound does not use the expected direct outbound: %s", raw)
	}
	blocked := config.Outbounds[1].Settings.FinalRules[0].IP
	for _, target := range []string{"geoip:private", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7"} {
		if !slices.Contains(blocked, target) {
			t.Errorf("direct outbound does not block %s", target)
		}
	}
	if len(config.Routing.Rules) != 2 || config.Routing.Rules[0].OutboundTag != PanelDNSTag || config.Routing.Rules[1].OutboundTag != "direct" ||
		!slices.Equal(config.Routing.Rules[1].InboundTags, []string{"published-93.184.216.35:443"}) {
		t.Fatalf("SOCKS5 inbound is not routed to Freedom: %s", raw)
	}
	ports := map[string]int{"published-93.184.216.35:443": 1080}
	network, err := AppliedNetwork(raw, ports)
	if err != nil || network == nil || len(network.Outbounds) != 0 || len(network.Routes) != 0 {
		t.Fatalf("failed to reconstruct the applied SOCKS5 network: %v", err)
	}
}

func TestPanelTrojanSharesOneSealedIdentity(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	tls, err := NewPanelTLS(public, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	draft := Configuration{
		Inbounds: Plan{}, Network: &Network{Outbounds: []Outbound{}, Routes: []Route{}},
		Panel: &PanelConfiguration{Credentials: []string{}, TLS: tls},
	}
	for i := range maxPorts {
		n := strconv.Itoa(i)
		in := Inbound{Port: 1080 + i, Protocol: Trojan, TLSCertSHA256: tls.Trust.SHA256,
			PublicEndpoint: PublicEndpoint{Address: "93.184.216.36", Port: 443 + i}, Users: []string{"alice" + n}}
		box, err := SealPanelCredential(public, in, strings.Repeat("A", 43))
		if err != nil {
			t.Fatal(err)
		}
		tag := "target-" + n
		draft.Inbounds = append(draft.Inbounds, in)
		draft.Panel.Credentials = append(draft.Panel.Credentials, box)
		draft.Network.Outbounds = append(draft.Network.Outbounds, Outbound{Tag: tag, Destination: Destination{Address: "93.184.216.34", Port: 443 + i}})
		draft.Network.Routes = append(draft.Network.Routes, Route{InboundPort: in.Port, OutboundTag: tag})
	}
	encoded := draft.Encode()
	parsed, err := ParseConfiguration(encoded)
	if err != nil || strings.Contains(encoded, "PRIVATE KEY") {
		t.Fatalf("public drafts must fit the wire limit and keep the private key sealed: %d %v", len(encoded), err)
	}
	data, ref, err := parsed.RenderPanel(key)
	if err != nil || !ref.Matches(data) || bytes.Count(data, []byte(`"listen":"127.0.0.2"`)) != maxPorts {
		t.Fatalf("public Trojan config did not render: %d %v", len(data), err)
	}
	other, err := NewPanelTLS(public, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	parsed.Panel.TLS.Key = other.Key
	if _, _, err := parsed.RenderPanel(key); err == nil {
		t.Fatal("accepted a TLS key from a different certificate")
	}
}
