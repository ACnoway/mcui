package xrayconfig

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// This test requires a public test address bound to loopback inside an isolated VM.
func TestPanelRealityConnection(t *testing.T) {
	binary := os.Getenv("MCUI_TEST_XRAY")
	if binary == "" || os.Getenv("MCUI_TEST_REALITY") != "1" {
		t.Skip("requires isolated REALITY test environment")
	}
	for _, network := range []string{"tcp", "grpc", "xhttp"} {
		t.Run(network, func(t *testing.T) { testPanelRealityConnection(t, binary, network) })
	}
}

func testPanelRealityConnection(t *testing.T, binary, network string) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"www.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	target, err := net.Listen("tcp4", "93.184.216.34:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	tlsTarget := tls.NewListener(target, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
	targetErrors := make(chan error, 32)
	t.Cleanup(func() {
		if t.Failed() {
			for len(targetErrors) > 0 {
				t.Logf("target TLS handshake: %v", <-targetErrors)
			}
		}
	})
	go func() {
		for {
			conn, err := tlsTarget.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				if err := conn.(*tls.Conn).Handshake(); err != nil {
					targetErrors <- err
					return
				}
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	echo, err := net.Listen("tcp4", "93.184.216.34:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err == nil && string(buf) == "ping" {
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
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	identity, err := NewPanelReality(public, serverPort, target.Addr().String(), []string{"www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	const id = "00000000-0000-4000-8000-000000000001"
	stream := &VLESSStream{Network: network, Security: "reality", Reality: &identity.RealitySettings}
	clientStream := map[string]any{"network": network, "security": "reality", "realitySettings": map[string]any{
		"serverName": "www.example.com", "fingerprint": "chrome", "password": identity.PublicKey, "shortId": identity.ShortID}}
	flow := ""
	switch network {
	case "tcp":
		clientStream["network"], flow = "raw", "xtls-rprx-vision"
	case "grpc":
		stream.ServiceName = "test"
		clientStream["grpcSettings"] = map[string]any{"serviceName": "test"}
	case "xhttp":
		stream.Path, stream.Mode = "/test", "auto"
		clientStream["xhttpSettings"] = map[string]any{"path": "/test", "mode": "auto"}
	}
	in := Inbound{Port: serverPort, Protocol: VLESS, Users: []string{"alice"}, VLESSStream: stream}
	if flow != "" {
		in.VLESSFlows = map[string]string{"alice": flow}
	}
	box, err := SealPanelCredential(public, in, id)
	if err != nil {
		t.Fatal(err)
	}
	draft := Configuration{Inbounds: Plan{in}, Network: &Network{Outbounds: []Outbound{}, Routes: []Route{}},
		Panel: &PanelConfiguration{Credentials: []string{box}, DirectPorts: []int{serverPort}, Reality: map[int]PanelReality{serverPort: *identity}}}
	server, _, err := draft.RenderPanel(key)
	if err != nil {
		t.Fatal(err)
	}
	var serverConfig map[string]any
	if err := json.Unmarshal(server, &serverConfig); err != nil {
		t.Fatal(err)
	}
	serverConfig["log"] = map[string]string{"loglevel": "debug"}
	server, err = json.Marshal(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	client, err := json.Marshal(map[string]any{
		"log":      map[string]string{"loglevel": "debug"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": clientPort, "protocol": "socks"}},
		"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{
			"address": "127.0.0.1", "port": serverPort, "id": id, "encryption": "none", "flow": flow},
			"streamSettings": clientStream}},
	})
	if err != nil {
		t.Fatal(err)
	}
	start := func(data []byte) {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "run", "-config", path)
		var logs bytes.Buffer
		cmd.Stdout, cmd.Stderr = &logs, &logs
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			if t.Failed() {
				t.Logf("Xray: %s", logs.String())
			}
		})
	}
	wait := func(port int) net.Conn {
		for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); {
			conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
			if err == nil {
				return conn
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("Xray did not listen")
		return nil
	}
	start(server)
	_ = wait(serverPort).Close()
	start(client)
	conn := wait(clientPort)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = conn.Write([]byte{5, 1, 0})
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil || response[1] != 0 {
		t.Fatal("SOCKS negotiation failed", err)
	}
	port := echo.Addr().(*net.TCPAddr).Port
	_, _ = conn.Write([]byte{5, 1, 0, 1, 93, 184, 216, 34, byte(port >> 8), byte(port)})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
		t.Fatal("SOCKS connect failed", err)
	}
	_, _ = conn.Write([]byte("ping"))
	result := make([]byte, 4)
	if _, err := io.ReadFull(conn, result); err != nil || string(result) != "pong" {
		t.Fatalf("REALITY exchange: %q %v", result, err)
	}
}
