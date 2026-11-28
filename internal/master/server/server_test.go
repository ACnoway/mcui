package server_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentcfg "github.com/ACnoway/mcui/internal/agent/config"
	"github.com/ACnoway/mcui/internal/agent/core"
	"github.com/ACnoway/mcui/internal/agent/core/xray"
	agenttunnel "github.com/ACnoway/mcui/internal/agent/tunnel"
	"github.com/ACnoway/mcui/internal/master/db"
	"github.com/ACnoway/mcui/internal/master/hub"
	"github.com/ACnoway/mcui/internal/master/model"
	"github.com/ACnoway/mcui/internal/master/server"
	"github.com/ACnoway/mcui/internal/master/service"
	"github.com/ACnoway/mcui/internal/master/tunnel"
	"github.com/ACnoway/mcui/pkg/proto"
)

func buildFakeXrayZip(t *testing.T) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("xray")
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	// Fake xray binary supporting `version`, `run -test`, `run -config`, and `api statsquery`.
	script := `#!/usr/bin/env sh
case "$1" in
  version)
    echo "Xray 26.10.31 (Xray, Penetrates Everything.)"
    exit 0
    ;;
  run)
    if [ "$2" = "-test" ]; then
      exit 0
    fi
    trap 'exit 0' TERM INT
    while :; do sleep 1; done
    ;;
  api)
    echo '{"stat":[{"name":"user>>>alice@example.com>>>traffic>>>uplink","value":1024},{"name":"user>>>alice@example.com>>>traffic>>>downlink","value":4096}]}'
    exit 0
    ;;
esac
exit 0
`
	if _, err := f.Write([]byte(script)); err != nil {
		t.Fatalf("write fake xray script: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	raw := buf.Bytes()
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:])
}

func doAdminJSON[T any](t *testing.T, method, url, token string, reqBody any) (int, proto.APIEnvelope[T]) {
	t.Helper()
	var reader io.Reader
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s failed: %v", method, url, err)
	}
	defer resp.Body.Close()
	var env proto.APIEnvelope[T]
	_ = json.NewDecoder(resp.Body).Decode(&env)
	return resp.StatusCode, env
}

func pickFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestFullWorkflow_BareAgent_RemoteInstallCore_MultiInboundClientSub(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "master.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	tunnels := tunnel.NewManager()
	wsHub := hub.New()
	srv, err := server.New(gdb, tunnels, wsHub, server.Config{BinDir: t.TempDir()})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Login with seeded admin
	code, loginEnv := doAdminJSON[map[string]any](t, http.MethodPost, ts.URL+"/api/auth/login", "", map[string]string{
		"username": "admin",
		"password": "admin",
	})
	if code != http.StatusOK || !loginEnv.Success {
		t.Fatalf("login failed: HTTP %d %+v", code, loginEnv)
	}
	adminToken, _ := loginEnv.Obj["token"].(string)
	if adminToken == "" {
		t.Fatal("missing admin session token")
	}

	// 2. Create Node on Master
	code, createNodeEnv := doAdminJSON[service.NodeWithEnroll](t, http.MethodPost, ts.URL+"/api/nodes", adminToken, service.CreateNodeInput{
		Name:       "tokyo-01",
		PublicHost: "tyo.example.com",
	})
	if code != http.StatusCreated || !createNodeEnv.Success {
		t.Fatalf("create node failed: HTTP %d %+v", code, createNodeEnv)
	}
	nodeID := createNodeEnv.Obj.Node.ID

	// 3. Boot bare Agent (0 cores installed)
	agentDir := filepath.Join(t.TempDir(), "agent")
	agentCfg := &agentcfg.Config{
		MasterURL:   ts.URL,
		EnrollToken: createNodeEnv.Obj.EnrollToken,
		DataDir:     agentDir,
	}
	cores := core.NewManager(xray.NewDriver(agentDir))
	agentClient := agenttunnel.NewClient(filepath.Join(agentDir, "agent.json"), agentCfg, cores)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = agentClient.RunLoop(ctx)
	}()

	// Wait for bare agent to come online
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		_, listEnv := doAdminJSON[[]model.Node](t, http.MethodGet, ts.URL+"/api/nodes", adminToken, nil)
		if len(listEnv.Obj) == 1 && listEnv.Obj[0].Online && len(listEnv.Obj[0].Cores) == 1 {
			break
		}
		time.Sleep(60 * time.Millisecond)
	}

	// 4. Verify Inbound creation is rejected BEFORE Xray Core is installed
	ibPort := pickFreePort(t)
	code, prematureIb := doAdminJSON[model.Inbound](t, http.MethodPost, ts.URL+"/api/inbounds", adminToken, service.InboundInput{
		NodeID:   nodeID,
		CoreType: proto.CoreXray,
		Protocol: proto.ProtocolVLESS,
		Port:     ibPort,
	})
	if code == http.StatusCreated || !strings.Contains(prematureIb.Msg, "not installed") {
		t.Fatalf("expected inbound creation before core install to be rejected, got HTTP %d msg=%q", code, prematureIb.Msg)
	}

	// 5. Serve fake Xray release archive + SHA256 and trigger Remote Core Install from Master
	zipBytes, zipSHA := buildFakeXrayZip(t)
	releaseSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases":
			_, _ = w.Write([]byte(`[{"tag_name":"v26.10.31","prerelease":false,"draft":false}]`))
		case "/Xray-linux-64.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipBytes)
		}
	}))
	defer releaseSrv.Close()
	srv.CoreService().SetReleasesURLForTest(releaseSrv.URL + "/releases")

	code, installEnv := doAdminJSON[proto.CoreStatus](t, http.MethodPost, ts.URL+"/api/nodes/1/cores/install", adminToken, service.InstallNodeCoreInput{
		CoreType:   proto.CoreXray,
		Version:    "v26.10.31",
		ArchiveURL: releaseSrv.URL + "/Xray-linux-64.zip",
		SHA256:     zipSHA,
	})
	if code != http.StatusAccepted || !installEnv.Success {
		t.Fatalf("install core failed: HTTP %d %+v", code, installEnv)
	}

	// Wait for Agent to finish installing Xray and report Installed=true, State=stopped
	var installed bool
	deadline = time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		_, nodeEnv := doAdminJSON[model.Node](t, http.MethodGet, ts.URL+"/api/nodes/1", adminToken, nil)
		if len(nodeEnv.Obj.Cores) == 1 && nodeEnv.Obj.Cores[0].Installed && nodeEnv.Obj.Cores[0].InstalledVersion == "v26.10.31" {
			installed = true
			break
		}
		time.Sleep(80 * time.Millisecond)
	}
	if !installed {
		t.Fatal("timed out waiting for remote Xray core installation to complete")
	}

	// 6. Generate Reality keys & create VLESS+Reality Inbound on the newly installed Xray core
	_, rkEnv := doAdminJSON[map[string]string](t, http.MethodPost, ts.URL+"/api/xray/reality-keys", adminToken, nil)
	streamJSON, _ := json.Marshal(map[string]any{
		"network":  "tcp",
		"security": "reality",
		"realitySettings": map[string]any{
			"dest":        "www.microsoft.com:443",
			"serverNames": []string{"www.microsoft.com"},
			"privateKey":  rkEnv.Obj["privateKey"],
			"publicKey":   rkEnv.Obj["publicKey"],
			"shortIds":    []string{rkEnv.Obj["shortId"]},
		},
	})
	code, ibEnv := doAdminJSON[model.Inbound](t, http.MethodPost, ts.URL+"/api/inbounds", adminToken, service.InboundInput{
		NodeID:         nodeID,
		CoreType:       proto.CoreXray,
		Remark:         "TYO-Reality",
		Port:           ibPort,
		Protocol:       proto.ProtocolVLESS,
		StreamSettings: streamJSON,
	})
	if code != http.StatusCreated || !ibEnv.Success {
		t.Fatalf("create inbound after core install failed: HTTP %d %+v", code, ibEnv)
	}

	// 7. Create centralized Client on Master bound to that Inbound
	code, clEnv := doAdminJSON[model.Client](t, http.MethodPost, ts.URL+"/api/clients", adminToken, service.ClientInput{
		Email:      "alice@example.com",
		SubID:      "alice-sub-01",
		Flow:       "xtls-rprx-vision",
		InboundIDs: []uint{ibEnv.Obj.ID},
	})
	if code != http.StatusCreated || !clEnv.Success {
		t.Fatalf("create client failed: HTTP %d %+v", code, clEnv)
	}

	// Verify Xray core transitioned to RUNNING and traffic accounting accumulates
	var coreRunning bool
	var trafficAccumulated bool
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		_, nodeEnv := doAdminJSON[model.Node](t, http.MethodGet, ts.URL+"/api/nodes/1", adminToken, nil)
		if len(nodeEnv.Obj.Cores) == 1 && nodeEnv.Obj.Cores[0].State == proto.CoreRunning {
			coreRunning = true
		}
		_, clientsEnv := doAdminJSON[[]model.Client](t, http.MethodGet, ts.URL+"/api/clients", adminToken, nil)
		if len(clientsEnv.Obj) == 1 && clientsEnv.Obj[0].Up >= 1024 && clientsEnv.Obj[0].Down >= 4096 {
			trafficAccumulated = true
		}
		if coreRunning && trafficAccumulated {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !coreRunning {
		t.Fatal("expected Xray core to transition to running after inbound & client were reconciled")
	}
	if !trafficAccumulated {
		t.Fatal("expected centralized client traffic to accumulate from Agent report")
	}

	// 8. Fetch public Subscription URL and verify VLESS Reality URI
	subResp, err := http.Get(ts.URL + "/sub/alice-sub-01?format=raw")
	if err != nil {
		t.Fatalf("GET /sub/alice-sub-01: %v", err)
	}
	defer subResp.Body.Close()
	subBody, _ := io.ReadAll(subResp.Body)
	subText := string(subBody)
	if !strings.HasPrefix(subText, "vless://"+clEnv.Obj.UUID+"@tyo.example.com:") || !strings.Contains(subText, "security=reality") {
		t.Fatalf("unexpected subscription output: %q", subText)
	}
}
