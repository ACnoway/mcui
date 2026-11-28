package tunnel_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	agentcfg "github.com/ACnoway/mcui/internal/agent/config"
	"github.com/ACnoway/mcui/internal/agent/core"
	"github.com/ACnoway/mcui/internal/agent/core/xray"
	agenttunnel "github.com/ACnoway/mcui/internal/agent/tunnel"
	mastertunnel "github.com/ACnoway/mcui/internal/master/tunnel"
	"github.com/ACnoway/mcui/pkg/proto"
)

func TestReverseYamuxTunnelZeroPortRPC(t *testing.T) {
	mgr := mastertunnel.NewManager()
	var reports atomic.Int32
	connectedCh := make(chan uint, 1)

	mgr.SetHooks(
		func(nodeID uint, rep proto.AgentReport) {
			if nodeID == 7 && len(rep.Cores) == 1 && rep.Cores[0].CoreType == proto.CoreXray {
				reports.Add(1)
			}
		},
		func(nodeID uint) {
			select {
			case connectedCh <- nodeID:
			default:
			}
		},
		nil,
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/tunnel" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-node-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := mgr.AcceptWebSocket(w, r, 7); err != nil {
			t.Errorf("AcceptWebSocket failed: %v", err)
		}
	}))
	defer srv.Close()

	dataDir := filepath.Join(t.TempDir(), "agent-data")
	cfg := &agentcfg.Config{
		MasterURL: srv.URL,
		NodeID:    7,
		NodeToken: "test-node-token",
		DataDir:   dataDir,
	}
	cores := core.NewManager(xray.NewDriver(dataDir))
	client := agenttunnel.NewClient("", cfg, cores)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = client.RunLoop(ctx)
	}()

	select {
	case id := <-connectedCh:
		if id != 7 {
			t.Fatalf("connected node id = %d, want 7", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for agent reverse tunnel connection")
	}

	if !mgr.IsOnline(7) {
		t.Fatal("expected node 7 to be online")
	}

	deadline := time.Now().Add(5 * time.Second)
	for reports.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if reports.Load() == 0 {
		t.Fatal("expected at least one telemetry report from agent over reverse tunnel")
	}

	// Verify synchronous Master -> Agent RPC over the outbound-only tunnel:
	// an uninstalled Xray core should cleanly reject ApplyState with "not installed".
	_, err := mgr.ApplyState(ctx, 7, proto.DesiredCoreSpec{
		CoreType: proto.CoreXray,
		Inbounds: []proto.InboundSpec{{Tag: "ib-1", Protocol: proto.ProtocolVLESS, Port: 10443}},
	})
	if err == nil || err.Error() != "xray core is not installed on this node" {
		t.Fatalf("ApplyState error = %v, want 'xray core is not installed on this node'", err)
	}
}
