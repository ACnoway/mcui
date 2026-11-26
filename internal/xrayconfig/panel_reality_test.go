package xrayconfig

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestPanelRealitySealsNodeAndPort(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	reality, err := NewPanelReality(public, 443, "93.184.216.34:443", []string{"www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	private, err := hpke.NewDHKEMPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := reality.open(private, 443)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := RealityPublicKey(opened)
	if err != nil || derived != reality.PublicKey {
		t.Fatal("opened key does not match public key")
	}
	wrong, err := hpke.NewDHKEMPrivateKey(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reality.open(wrong, 443); err == nil {
		t.Fatal("opened REALITY key for another node")
	}
	if _, err := reality.open(private, 444); err == nil {
		t.Fatal("opened REALITY key for another port")
	}
	modified := *reality
	modified.PublicKey = base64.RawURLEncoding.EncodeToString(other.PublicKey().Bytes())
	if _, err := modified.open(private, 443); err == nil {
		t.Fatal("accepted modified public key")
	}
}

func TestPanelRealityRendersOnlyMatchingSealedIdentity(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	identity, err := NewPanelReality(public, 1080, "93.184.216.34:443", []string{"www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	in := Inbound{Port: 1080, Protocol: VLESS, Users: []string{"alice"},
		VLESSStream: &VLESSStream{Network: "tcp", Security: "reality", Reality: &identity.RealitySettings},
		VLESSFlows:  map[string]string{"alice": "xtls-rprx-vision"}}
	sealed, err := SealPanelCredential(public, in, "00000000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	draft := Configuration{Inbounds: Plan{in}, Network: &Network{Outbounds: []Outbound{}, Routes: []Route{}},
		Panel: &PanelConfiguration{Credentials: []string{sealed}, Reality: map[int]PanelReality{1080: *identity}}}
	parsed, err := ParseConfiguration(draft.Encode())
	if err != nil || parsed.Panel == nil || !parsed.Valid() {
		t.Fatalf("REALITY draft did not round-trip: %v", err)
	}
	data, ref, err := draft.RenderPanel(key)
	if err != nil || !ref.Matches(data) || !bytes.Contains(data, []byte(`"security":"reality"`)) ||
		!bytes.Contains(data, []byte(`"privateKey":`)) || bytes.Contains([]byte(draft.Encode()), []byte(`"privateKey"`)) {
		t.Fatalf("invalid REALITY rendering or draft: %v", err)
	}
	wrong := *identity
	wrong.Target = "93.184.216.35:443"
	draft.Panel.Reality[1080] = wrong
	if draft.Valid() {
		t.Fatal("accepted mismatched REALITY identity")
	}
}

func TestPanelRealityValidatesTargetAndNames(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	if !ValidRealityTargetInput("www.example.com:443") {
		t.Fatal("valid DNS target input rejected")
	}
	if _, err := NewPanelReality(public, 443, "www.example.com:443", []string{"www.example.com"}); err == nil {
		t.Fatal("accepted unpinned DNS target in signed identity")
	}
	for _, target := range []string{"127.0.0.1:443", "169.254.169.254:80", "example.com:0", "localhost:443", "example.com:0443", "bad name:443"} {
		if _, err := NewPanelReality(public, 443, target, []string{"www.example.com"}); err == nil {
			t.Errorf("accepted invalid target %q", target)
		}
	}
	for _, names := range [][]string{nil, {"localhost"}, {"www.example.com", "www.example.com"}, {"bad name.example"}} {
		if _, err := NewPanelReality(public, 443, "93.184.216.34:443", names); err == nil {
			t.Errorf("accepted invalid server names %q", names)
		}
	}
}
