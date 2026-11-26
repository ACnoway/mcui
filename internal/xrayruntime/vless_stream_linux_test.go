//go:build linux

package xrayruntime

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
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
			if stream.Network == "tcp" {
				in.VLESSFlows = map[string]string{"alice": "xtls-rprx-vision"}
			}
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

func TestPanelRealityAppliedInventoryOmitsPrivateKey(t *testing.T) {
	r := newRuntime(t, &fakeService{})
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(key.Bytes())
	if err := r.writeControl(panelKeyFile, []byte(`"`+encoded+`"`)); err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	identity, err := xrayconfig.NewPanelReality(public, 1080, "93.184.216.34:443", []string{"www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	in := xrayconfig.Inbound{Port: 1080, Protocol: xrayconfig.VLESS, Users: []string{"alice"},
		VLESSStream: &xrayconfig.VLESSStream{Network: "tcp", Security: "reality", Reality: &identity.RealitySettings}}
	box, err := xrayconfig.SealPanelCredential(public, in, "00000000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	draft := xrayconfig.Configuration{Inbounds: xrayconfig.Plan{in}, Network: &xrayconfig.Network{Outbounds: []xrayconfig.Outbound{}, Routes: []xrayconfig.Route{}},
		Panel: &xrayconfig.PanelConfiguration{Credentials: []string{box}, Reality: map[int]xrayconfig.PanelReality{1080: *identity}}}
	data, ref, err := draft.RenderPanel(key)
	if err != nil {
		t.Fatal(err)
	}
	destinations, _, _, err := configurationNetwork(data)
	if err != nil || len(destinations) != 1 || destinations[0] != "93.184.216.34/32" {
		t.Fatalf("REALITY target not validated: %v", err)
	}
	if err := r.writeControl(configName(ref), data); err != nil {
		t.Fatal(err)
	}
	release := stageFixture(t, r, xrayconfig.Version)
	view := r.Inventory(Status{Current: selection{Release: release, Running: true, Revision: 1, Config: ref}}, "", true)
	draft.Panel = nil
	if view.Applied == nil || view.AppliedConfiguration().Encode() != draft.Encode() || bytes.Contains([]byte(view.Applied.Encode()), []byte(identity.Key)) ||
		bytes.Contains([]byte(view.Applied.Encode()), []byte("privateKey")) {
		t.Fatalf("REALITY inventory did not preserve the public signed configuration: %+v", view.Applied)
	}
}

func TestHostModeCannotUseIsolatedRuntime(t *testing.T) {
	tag := xrayconfig.HostInboundTag(1080, xrayconfig.PublicEndpoint{})
	data := []byte(fmt.Sprintf(`{"dns":{"tag":"mcui-host-dns","servers":["localhost"],"queryStrategy":"UseIPv4"},"inbounds":[{"listen":"0.0.0.0","port":443,"protocol":"vless","tag":%q}],"outbounds":[],"routing":{"rules":[]}}`, tag))
	if _, _, _, err := configurationNetwork(data); err != nil {
		t.Fatalf("valid host configuration rejected: %v", err)
	}
	r := newRuntime(t, &fakeService{})
	if err := r.checkConfigUnits(context.Background(), data, true); err == nil {
		t.Fatal("host mode accepted without a host-capable service")
	}
}

func TestHostUnitsInIsolatedVM(t *testing.T) {
	if os.Getenv("MCUI_TEST_HOST_UNITS") != "1" {
		t.Skip("requires an isolated systemd test VM")
	}
	ctx := context.Background()
	service := &systemdService{}
	if err := service.checkHostUnits(ctx); err != nil {
		t.Fatal(err)
	}
	if err := service.prepareHost(ctx, []string{"93.184.216.34/32"}, nil); err == nil {
		t.Fatal("accepted a route to an address of the node")
	}
	published := []publishedInbound{{host: true, port: 1080, listen: xrayconfig.HostListener{Address: "127.0.0.1", Port: 443}}}
	if err := service.prepareHost(ctx, nil, published); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exec.Command("systemctl", "stop", hostGuardUnit).Run() })
}
