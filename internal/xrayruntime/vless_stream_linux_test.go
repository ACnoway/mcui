//go:build linux

package xrayruntime

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/xrayconfig"
)

func TestPanelVLESSAppliedTransportMatchesSignedDraft(t *testing.T) {
	r := newRuntime(t, &fakeService{})
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(key.Bytes())
	if err := r.writeControl(panelKeyFile, []byte(`"`+encoded+`"`)); err != nil {
		t.Fatal(err)
	}
	release := stageFixture(t, r, xrayconfig.Version)
	for _, stream := range []xrayconfig.VLESSStream{
		{Network: "ws", Path: "/socket", Host: "example.test"},
		{Network: "grpc", ServiceName: "proxy", Authority: "example.test", MultiMode: true},
		{Network: "httpupgrade", Path: "/upgrade"},
		{Network: "xhttp", Path: "/xhttp", Mode: "stream-one"},
		{Network: "tcp", Security: "tls"},
		{Network: "grpc", Security: "tls", ServiceName: "proxy"},
	} {
		t.Run(stream.Network, func(t *testing.T) {
			in := xrayconfig.Inbound{Port: 1080, Protocol: xrayconfig.VLESS, Users: []string{"alice"}, VLESSStream: &stream}
			var identity *xrayconfig.PanelTLS
			if stream.Security == "tls" {
				identity, err = xrayconfig.NewPanelTLS(base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), time.Now())
				if err != nil {
					t.Fatal(err)
				}
				in.TLSCertSHA256 = identity.Trust.SHA256
			}
			secret, err := xrayconfig.SealPanelCredential(base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), in, "00000000-0000-4000-8000-000000000001")
			if err != nil {
				t.Fatal(err)
			}
			draft := xrayconfig.Configuration{Inbounds: xrayconfig.Plan{in}, Network: &xrayconfig.Network{Outbounds: []xrayconfig.Outbound{}, Routes: []xrayconfig.Route{}}, Panel: &xrayconfig.PanelConfiguration{Credentials: []string{secret}, TLS: identity}}
			data, ref, err := draft.RenderPanel(key)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.writeControl(configName(ref), data); err != nil {
				t.Fatal(err)
			}
			state := Status{Current: selection{Release: release, Running: true, Revision: 1, Config: ref}}
			view := r.Inventory(state, "", true)
			draft.Panel = nil
			if view.Applied == nil || view.AppliedConfiguration().Encode() != draft.Encode() {
				t.Fatalf("applied transport differs from signed draft: got %+v, want %s", view.Applied, draft.Encode())
			}
			if identity != nil {
				draft.Inbounds[0].PublicEndpoint = xrayconfig.PublicEndpoint{Address: "93.184.216.34", Port: 443}
				draft.Panel = &xrayconfig.PanelConfiguration{Credentials: []string{secret}, TLS: identity}
				published, _, err := draft.RenderPanel(key)
				if err != nil {
					t.Fatal(err)
				}
				_, endpoints, _, err := configurationNetwork(published)
				if err != nil || len(endpoints) != 1 {
					t.Fatalf("TLS public listener rejected: %v", err)
				}
			}
		})
	}
}
