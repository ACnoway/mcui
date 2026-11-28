package service_test

import (
	"path/filepath"
	"testing"

	"github.com/ACnoway/mcui/internal/master/db"
	"github.com/ACnoway/mcui/internal/master/hub"
	"github.com/ACnoway/mcui/internal/master/service"
	"github.com/ACnoway/mcui/internal/master/tunnel"
	"github.com/ACnoway/mcui/pkg/proto"
)

func TestNodeService_EndToEnd(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "mcui.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	tunnels := tunnel.NewManager()
	wsHub := hub.New()
	ns := service.NewNodeService(gdb, tunnels, wsHub)

	enroll, err := ns.CreateNode(service.CreateNodeInput{
		Name:       "hk-bgp-01",
		PublicHost: "hk.example.com",
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if enroll.EnrollToken == "" {
		t.Fatal("expected non-empty enroll token")
	}

	enrollResp, err := ns.Enroll(proto.EnrollRequest{
		EnrollToken: enroll.EnrollToken,
		Hostname:    "hk-node-vm",
		OS:          "linux",
		Arch:        "amd64",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if enrollResp.NodeID != enroll.Node.ID {
		t.Fatalf("NodeID = %d, want %d", enrollResp.NodeID, enroll.Node.ID)
	}

	if _, err := ns.Enroll(proto.EnrollRequest{EnrollToken: enroll.EnrollToken}); err == nil {
		t.Fatal("expected consumed enroll token to be rejected on replay")
	}

	authed, err := ns.AuthenticateNodeToken("Bearer " + enrollResp.NodeToken)
	if err != nil {
		t.Fatalf("AuthenticateNodeToken: %v", err)
	}
	if authed.Name != "hk-bgp-01" {
		t.Fatalf("Name = %q, want hk-bgp-01", authed.Name)
	}

	_, err = ns.HandleAgentReport(authed.ID, proto.AgentReport{
		AgentVersion: "v0.1.0",
		System: proto.SystemMetrics{
			Hostname:   "hk-node-vm",
			OS:         "linux",
			Arch:       "amd64",
			PublicIPv4: "203.0.113.10",
			CPUPercent: 12.5,
		},
		Cores: []proto.CoreStatus{
			{CoreType: proto.CoreXray, Installed: false, State: proto.CoreUninstalled},
		},
	})
	if err != nil {
		t.Fatalf("HandleAgentReport: %v", err)
	}

	got, err := ns.GetNode(authed.ID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.PublicIPv4 != "203.0.113.10" {
		t.Fatalf("PublicIPv4 = %q, want 203.0.113.10", got.PublicIPv4)
	}
	if len(got.Cores) != 1 || got.Cores[0].State != proto.CoreUninstalled {
		t.Fatalf("Cores = %+v, want single uninstalled xray core", got.Cores)
	}
}
