package taskdispatch

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

func TestPublicVLESSRequiresAgentCapability(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inbound := xrayconfig.Inbound{Port: 1080, Protocol: xrayconfig.VLESS,
		PublicEndpoint: xrayconfig.PublicEndpoint{Address: "93.184.216.35", Port: 443}, Users: []string{"alice"}}
	box, err := xrayconfig.SealPanelCredential(base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), inbound,
		"00000000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	plan := xrayconfig.Configuration{Inbounds: xrayconfig.Plan{inbound},
		Network: &xrayconfig.Network{Outbounds: []xrayconfig.Outbound{}, Routes: []xrayconfig.Route{}},
		Panel:   &xrayconfig.PanelConfiguration{Credentials: []string{box}}}
	task := lifecycleauth.InstallTask{Operation: xrayconfig.Operation, Plan: plan.Encode()}
	caps := XrayDeliveryCapabilities{InstallMode: "xray-manifest-v1", Config: true, Plan: true,
		Protocols: true, Public: true, Routing: true, PanelInbounds: true}
	if caps.supportsTask(task) {
		t.Fatal("older Agent accepted public VLESS")
	}
	caps.PublicVLESS = true
	if !caps.supportsTask(task) {
		t.Fatal("capable Agent rejected public VLESS")
	}
}
