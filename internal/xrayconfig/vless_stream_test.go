package xrayconfig

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPanelVLESSTransports(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	for _, stream := range []VLESSStream{
		{Network: "ws", Path: "/socket", Host: "example.test"},
		{Network: "grpc", ServiceName: "proxy"},
		{Network: "grpc", ServiceName: "proxy", Authority: "example.test", MultiMode: true},
		{Network: "httpupgrade", Path: "/upgrade", Host: "example.test"},
		{Network: "xhttp", Path: "/xhttp", Host: "example.test", Mode: "auto"},
		{Network: "xhttp", Path: "/xhttp", Host: "example.test", Mode: "packet-up"},
		{Network: "xhttp", Path: "/xhttp", Host: "example.test", Mode: "stream-up"},
		{Network: "xhttp", Path: "/xhttp", Host: "example.test", Mode: "stream-one"},
	} {
		t.Run(stream.Network, func(t *testing.T) {
			in := Inbound{Port: 1080, Protocol: VLESS, Users: []string{"alice"}, VLESSStream: &stream}
			sealed, err := SealPanelCredential(public, in, "00000000-0000-4000-8000-000000000001")
			if err != nil {
				t.Fatal(err)
			}
			draft := Configuration{Inbounds: Plan{in}, Network: &Network{Outbounds: []Outbound{}, Routes: []Route{}},
				Panel: &PanelConfiguration{Credentials: []string{sealed}}}
			parsed, err := ParseConfiguration(draft.Encode())
			if err != nil {
				t.Fatal(err)
			}
			data, ref, err := parsed.RenderPanel(key)
			if err != nil || !ref.Matches(data) {
				t.Fatalf("render failed: %v", err)
			}
			var config struct {
				Inbounds []struct {
					Stream map[string]any `json:"streamSettings"`
				} `json:"inbounds"`
			}
			if err := json.Unmarshal(data, &config); err != nil || len(config.Inbounds) != 1 ||
				config.Inbounds[0].Stream["network"] != stream.Network || config.Inbounds[0].Stream[stream.Network+"Settings"] == nil {
				t.Fatalf("wrong rendered transport: %s (%v)", data, err)
			}
			if binary := os.Getenv("MCUI_TEST_XRAY"); binary != "" {
				configPath := filepath.Join(t.TempDir(), "server.json")
				if err := os.WriteFile(configPath, data, 0600); err != nil {
					t.Fatal(err)
				}
				if output, err := exec.Command(binary, "run", "-test", "-config", configPath).CombinedOutput(); err != nil {
					t.Fatalf("Xray rejected %s: %v\n%s", stream.Network, err, output)
				}
			}
		})
	}
}

// TestVLESSTransportConnections exercises both Xray endpoints over loopback.
// It does not alter the production routing policy.
func TestVLESSTransportConnections(t *testing.T) {
	binary := os.Getenv("MCUI_TEST_XRAY")
	if binary == "" {
		t.Skip("set MCUI_TEST_XRAY to a verified Xray executable")
	}
	for _, stream := range []VLESSStream{
		{Network: "ws", Path: "/socket", Host: "example.test"},
		{Network: "grpc", ServiceName: "proxy"},
		{Network: "grpc", ServiceName: "proxy", Authority: "example.test", MultiMode: true},
		{Network: "httpupgrade", Path: "/upgrade", Host: "example.test"},
		{Network: "xhttp", Path: "/xhttp", Host: "example.test", Mode: "auto"},
		{Network: "xhttp", Path: "/xhttp", Host: "example.test", Mode: "packet-up"},
		{Network: "xhttp", Path: "/xhttp", Host: "example.test", Mode: "stream-up"},
		{Network: "xhttp", Path: "/xhttp", Host: "example.test", Mode: "stream-one"},
	} {
		t.Run(stream.Network, func(t *testing.T) {
			target, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			go func() {
				conn, err := target.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				b := make([]byte, 4)
				if _, err := io.ReadFull(conn, b); err == nil && string(b) == "ping" {
					_, _ = conn.Write([]byte("pong"))
				}
			}()
			freePort := func() int {
				l, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				return l.Addr().(*net.TCPAddr).Port
			}
			serverPort, clientPort := freePort(), freePort()
			for clientPort == serverPort {
				clientPort = freePort()
			}
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			const id = "00000000-0000-4000-8000-000000000001"
			in := Inbound{Port: serverPort, Protocol: VLESS, Users: []string{"alice"}, VLESSStream: &stream}
			sealed, err := SealPanelCredential(base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), in, id)
			if err != nil {
				t.Fatal(err)
			}
			draft := Configuration{Inbounds: Plan{in}, Network: &Network{Outbounds: []Outbound{}, Routes: []Route{}}, Panel: &PanelConfiguration{Credentials: []string{sealed}}}
			data, _, err := draft.RenderPanel(key)
			if err != nil {
				t.Fatal(err)
			}
			var server map[string]any
			if err := json.Unmarshal(data, &server); err != nil {
				t.Fatal(err)
			}
			server["outbounds"] = []any{map[string]any{"protocol": "freedom", "settings": map[string]any{
				"finalRules": []any{map[string]any{"action": "allow", "network": "tcp", "ip": []string{"127.0.0.1/32"}, "port": target.Addr().(*net.TCPAddr).Port}},
			}}}
			server["log"] = map[string]string{"loglevel": "debug"}
			delete(server, "routing")
			client := map[string]any{
				"log":       map[string]string{"loglevel": "debug"},
				"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": clientPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}},
				"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"address": "127.0.0.1", "port": serverPort, "id": id, "encryption": "none"}, "streamSettings": stream.render()}},
			}
			start := func(config any) {
				raw, err := json.Marshal(config)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "config.json")
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(binary, "run", "-config", path)
				var output bytes.Buffer
				cmd.Stdout, cmd.Stderr = &output, &output
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
					if t.Failed() {
						t.Logf("Xray log: %s", output.String())
					}
				})
			}
			start(server)
			serverReady := false
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
				probe, probeErr := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", serverPort), 100*time.Millisecond)
				if probeErr == nil {
					_ = probe.Close()
					serverReady = true
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			if !serverReady {
				t.Fatal("Xray server did not start listening")
			}
			start(client)
			var conn net.Conn
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
				conn, err = net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", clientPort), 100*time.Millisecond)
				if err == nil {
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = conn.Write([]byte{5, 1, 0})
			response := make([]byte, 2)
			if _, err := io.ReadFull(conn, response); err != nil || response[1] != 0 {
				t.Fatalf("SOCKS negotiation: %x %v", response, err)
			}
			port := target.Addr().(*net.TCPAddr).Port
			_, _ = conn.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
			reply := make([]byte, 10)
			if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
				t.Fatalf("SOCKS connect: %x %v", reply, err)
			}
			_, _ = conn.Write([]byte("ping"))
			result := make([]byte, 4)
			if _, err := io.ReadFull(conn, result); err != nil || string(result) != "pong" {
				t.Fatalf("proxy exchange: %q %v", result, err)
			}
		})
	}
}

func TestVLESSStreamRejectsInvalidFields(t *testing.T) {
	for _, stream := range []VLESSStream{
		{Network: "ws", Path: "bad"}, {Network: "ws", Path: "/\r\nInjected"},
		{Network: "ws", Path: "/", Host: "evil\r\n"}, {Network: "grpc", Path: "/"},
		{Network: "xhttp", Path: "/", Mode: "wrong"}, {Network: "unknown"},
	} {
		if stream.Valid() {
			t.Errorf("accepted invalid transport: %+v", stream)
		}
	}
	if (Plan{{Port: 1080, Protocol: VMess, Users: []string{"alice"}, VLESSStream: &VLESSStream{Network: "ws", Path: "/"}}}).Valid() {
		t.Fatal("accepted VLESS transport on another protocol")
	}
}
