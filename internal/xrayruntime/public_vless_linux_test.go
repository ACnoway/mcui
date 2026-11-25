//go:build linux

package xrayruntime

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/xrayconfig"
)

func TestPublicVLESSWithXray(t *testing.T) {
	binaryPath := os.Getenv("MCUI_TEST_XRAY_BINARY")
	if binaryPath == "" {
		t.Skip("set MCUI_TEST_XRAY_BINARY to the verified Xray binary")
	}
	target, err := net.Listen("tcp4", "93.184.216.34:0")
	if err != nil {
		t.Fatal("run inside a network namespace with 93.184.216.34 bound to loopback: ", err)
	}
	defer target.Close()
	go func() {
		conn, err := target.Accept()
		if err == nil {
			defer conn.Close()
			request := make([]byte, 5)
			if _, err := io.ReadFull(conn, request); err == nil && string(request) == "hello" {
				_, _ = conn.Write([]byte("world"))
			}
		}
	}()
	freePort := func(address string) int {
		listener, err := net.Listen("tcp4", address+":0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port
	}
	serverPort := freePort("127.0.0.2")
	clientPort := freePort("127.0.0.1")
	const uuid = "00000000-0000-4000-8000-000000000001"
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inbound := xrayconfig.Inbound{Port: serverPort, Protocol: xrayconfig.VLESS,
		PublicEndpoint: xrayconfig.PublicEndpoint{Address: "93.184.216.35", Port: 443}, Users: []string{"alice"}}
	sealed, err := xrayconfig.SealPanelCredential(base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), inbound, uuid)
	if err != nil {
		t.Fatal(err)
	}
	destination := xrayconfig.Destination{Address: "93.184.216.34", Port: target.Addr().(*net.TCPAddr).Port}
	draft := xrayconfig.Configuration{Inbounds: xrayconfig.Plan{inbound},
		Network: &xrayconfig.Network{Outbounds: []xrayconfig.Outbound{{Tag: "target", Destination: destination}},
			Routes: []xrayconfig.Route{{InboundPort: serverPort, OutboundTag: "target"}}},
		Panel: &xrayconfig.PanelConfiguration{Credentials: []string{sealed}}}
	serverConfig, _, err := draft.RenderPanel(private)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := configurationNetwork(serverConfig); err != nil {
		t.Fatal(err)
	}
	clientConfig, err := json.Marshal(map[string]any{
		"log":      map[string]string{"loglevel": "none"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": clientPort, "protocol": "socks"}},
		"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{
			"address": "127.0.0.2", "port": serverPort, "id": uuid, "encryption": "none"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range [][]byte{serverConfig, clientConfig} {
		process := exec.CommandContext(t.Context(), binaryPath, "run", "-config", "stdin:")
		process.Stdin = bytes.NewReader(config)
		if err := process.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = process.Process.Kill(); _ = process.Wait() })
	}
	var conn net.Conn
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		conn, err = net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(clientPort)), 200*time.Millisecond)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	exchange := func(send, want []byte) {
		t.Helper()
		if _, err := conn.Write(send); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("received %v, want %v: %v", got, want, err)
		}
	}
	exchange([]byte{5, 1, 0}, []byte{5, 0})
	request := binary.BigEndian.AppendUint16([]byte{5, 1, 0, 1, 93, 184, 216, 34}, uint16(destination.Port))
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[0] != 5 || reply[1] != 0 || reply[3] != 1 {
		t.Fatalf("SOCKS connection failed: %v (%v)", reply, err)
	}
	exchange([]byte("hello"), []byte("world"))
}
