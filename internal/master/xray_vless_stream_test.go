package master

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/xrayconfig"
)

func TestSubscriptionOnlyIncludesAuthorizedVLESSStreams(t *testing.T) {
	a := &xrayconfig.VLESSStream{Network: "ws", Path: "/alice"}
	b := &xrayconfig.VLESSStream{Network: "grpc", ServiceName: "bob"}
	grant := subscriptionGrant{revision: 7, plan: xrayconfig.Plan{
		{Port: 1080, Protocol: xrayconfig.VLESS, Users: []string{"alice"}, VLESSStream: a},
		{Port: 1081, Protocol: xrayconfig.VLESS, Users: []string{"bob"}, VLESSStream: b},
	}}
	payload := grant.payload("alice", grant.ports("alice"), 2000000000)
	streams, ok := payload["vless_streams"].(map[int]*xrayconfig.VLESSStream)
	if payload["schema_version"] != 5 || !ok || len(streams) != 1 || streams[1080] != a {
		t.Fatalf("unexpected VLESS subscription payload: %#v", payload)
	}
	if _, exists := streams[1081]; exists {
		t.Fatal("another user's VLESS transport was disclosed")
	}
}

func TestVLESSTLSRotationAndSubscriptionTrust(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	old, err := xrayconfig.NewPanelTLS(public, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	next, err := xrayconfig.NewPanelTLS(public, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	in := xrayconfig.Inbound{Port: 1080, Protocol: xrayconfig.VLESS, Users: []string{"alice"},
		TLSCertSHA256: old.Trust.SHA256, VLESSStream: &xrayconfig.VLESSStream{Network: "tcp", Security: "tls"}}
	box, err := xrayconfig.SealPanelCredential(public, in, "00000000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	draft := encodePanelInbounds([]panelInbound{{Inbound: in, Credentials: []string{box}}}, next,
		&xrayconfig.Network{Outbounds: []xrayconfig.Outbound{}, Routes: []xrayconfig.Route{}}, false)
	if !draft.Valid() || draft.Inbounds[0].TLSCertSHA256 != next.Trust.SHA256 || draft.Panel.TLS != next {
		t.Fatal("TLS rotation did not update the signed identity")
	}
	grant := subscriptionGrant{revision: 1, plan: draft.Inbounds, trojan: &next.Trust}
	payload := grant.payload("alice", grant.ports("alice"), 2000000000)
	if payload["trojan_trust"] != &next.Trust || payload["schema_version"] != 5 {
		t.Fatal("VLESS TLS subscription does not carry the applied trust")
	}
	if _, ok := grant.payload("bob", grant.ports("bob"), 2000000000)["trojan_trust"]; ok {
		t.Fatal("TLS trust disclosed to an unauthorized user")
	}
}
