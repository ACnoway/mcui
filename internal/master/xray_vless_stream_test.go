package master

import (
	"testing"

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
