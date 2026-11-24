package master

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/xraytraffic"
)

func TestXrayClientTrafficAcrossNodes(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "master.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(state *store.State) error {
		for _, id := range []string{"a", "b", "c"} {
			state.Nodes[id] = store.Node{ID: id, TokenHash: "token-" + id}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for id, value := range map[string]int64{"a": 5, "b": 7, "c": 100} {
		sample := xraytraffic.Sample{Revision: 1, Epoch: strings.Repeat(id, 64), At: now.UnixMilli(),
			Counters: map[string]xraytraffic.Bytes{"user:alice": {Up: value, Down: value * 2}}}
		if err := db.RecordXrayTraffic(t.Context(), id, "token-"+id, sample); err != nil {
			t.Fatal(err)
		}
	}
	binding := func(node string, port int, applied bool) clientBindingView {
		return clientBindingView{XrayBinding: store.XrayBinding{NodeID: node, Port: port, Credential: "alice"}, Applied: applied}
	}
	rows := []xrayClientView{{Username: "alice", Bindings: []clientBindingView{
		binding("a", 1081, false), binding("a", 1082, true), binding("a", 1083, true),
		binding("b", 1081, true), binding("c", 1081, true),
	}}}
	server := &Server{store: db}
	if err := server.attachXrayClientTraffic(t.Context(), rows, map[string]int64{"a": 1, "b": 1, "c": 2}, now); err != nil {
		t.Fatal(err)
	}
	want := xrayClientTraffic{Bytes: xraytraffic.Bytes{Up: 12, Down: 24}, Observed: 2, Scopes: 3}
	if rows[0].Traffic == nil || *rows[0].Traffic != want {
		t.Fatalf("wanted %v from two node samples without duplicate or stale revision bytes, got %+v", want, rows[0].Traffic)
	}
}
