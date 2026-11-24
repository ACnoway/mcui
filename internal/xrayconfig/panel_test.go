package xrayconfig

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
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
