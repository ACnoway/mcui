//go:build linux

package xrayruntime

import (
	"bytes"
	"context"
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
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/xrayconfig"
)

func TestConfigurationNetworkValidatesSocksDirectPolicy(t *testing.T) {
	blockedIPs, err := json.Marshal(xrayconfig.PanelDirectBlockedIPs())
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":1080,"protocol":"socks","tag":"socks-1080"}],"outbounds":[{"protocol":"freedom","tag":"direct","settings":{"finalRules":[{"action":"block","ip":%s}]}}],"routing":{"rules":[{"inboundTag":["socks-1080"],"outboundTag":"direct"}]}}`, blockedIPs)
	_, _, direct, err := configurationNetwork([]byte(config))
	if err != nil || !direct {
		t.Fatalf("valid SOCKS direct configuration was rejected: %v", err)
	}
	for name, changed := range map[string]string{
		"non-SOCKS inbound":      strings.Replace(config, `"protocol":"socks"`, `"protocol":"trojan"`, 1),
		"incomplete final rules": strings.Replace(config, `,"169.254.0.0/16"`, "", 1),
		"non-SOCKS route tag":    strings.Replace(config, `"inboundTag":["socks-1080"]`, `"inboundTag":["vless-1080"]`, 1),
		"duplicate direct route": strings.Replace(config, `"rules":[`, `"rules":[{"inboundTag":["socks-1080"],"outboundTag":"direct"},`, 1),
		"missing final rules":    strings.Replace(config, `"finalRules":[{"action":"block","ip":`+string(blockedIPs)+`}]`, `"finalRules":[]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := configurationNetwork([]byte(changed)); err == nil {
				t.Fatal("accepted unsafe direct SOCKS configuration")
			}
		})
	}
}

func TestValidCurrentNetworkPolicy(t *testing.T) {
	base := map[string]string{"IPAddressDeny": "0.0.0.0/0 ::/0"}
	for name, allow := range map[string]string{
		"empty egress":             "",
		"initial service":          "127.0.0.1/32",
		"restricted public egress": "127.0.0.1/32 93.184.216.34/32 127.0.0.2/32",
	} {
		t.Run(name, func(t *testing.T) {
			values := map[string]string{"IPAddressDeny": base["IPAddressDeny"], "IPAddressAllow": allow}
			if !validCurrentNetworkPolicy(values) {
				t.Fatalf("rejected safe current network policy: %#v", values)
			}
		})
	}
	panel := map[string]string{
		"IPAddressDeny":  strings.Join(panelNetworkDeny, " "),
		"IPAddressAllow": strings.Join(panelNetworkAllow, " "),
	}
	if !validCurrentNetworkPolicy(panel) {
		t.Fatal("rejected the SOCKS direct-outbound policy")
	}
	for name, values := range map[string]map[string]string{
		"private allowance": {"IPAddressDeny": base["IPAddressDeny"], "IPAddressAllow": "10.0.0.1/32"},
		"broad allowance":   {"IPAddressDeny": base["IPAddressDeny"], "IPAddressAllow": "93.184.216.0/24"},
		"missing deny":      {"IPAddressAllow": "127.0.0.1/32"},
	} {
		t.Run(name, func(t *testing.T) {
			if validCurrentNetworkPolicy(values) {
				t.Fatalf("accepted unsafe current network policy: %#v", values)
			}
		})
	}
}

func TestPanelSocksWithXray(t *testing.T) {
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
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	const username, password = "alice", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inbound := xrayconfig.Inbound{Port: serverPort, Users: []string{username}}
	sealed, err := xrayconfig.SealPanelCredential(base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), inbound, password)
	if err != nil {
		t.Fatal(err)
	}
	draft := xrayconfig.Configuration{
		Inbounds: xrayconfig.Plan{inbound},
		Network:  &xrayconfig.Network{Outbounds: []xrayconfig.Outbound{}, Routes: []xrayconfig.Route{}},
		Panel:    &xrayconfig.PanelConfiguration{Credentials: []string{sealed}, DirectPorts: []int{serverPort}},
	}
	serverConfig, _, err := draft.RenderPanel(key)
	if err != nil {
		t.Fatal(err)
	}
	_, _, direct, err := configurationNetwork(serverConfig)
	if err != nil || !direct {
		t.Fatalf("runtime did not recognize the protected SOCKS direct route: %v", err)
	}
	process := exec.CommandContext(context.Background(), binaryPath, "run", "-config", "stdin:")
	process.Stdin = bytes.NewReader(serverConfig)
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Process.Kill(); _ = process.Wait() })
	var conn net.Conn
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		conn, err = net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	dialSocks := func() net.Conn {
		t.Helper()
		conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
			t.Fatal(err)
		}
		method := make([]byte, 2)
		if _, err := io.ReadFull(conn, method); err != nil || !bytes.Equal(method, []byte{5, 2}) {
			t.Fatalf("SOCKS5 did not require username and password: %v (%v)", method, err)
		}
		auth := append([]byte{1, byte(len(username))}, username...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, password...)
		if _, err := conn.Write(auth); err != nil {
			t.Fatal(err)
		}
		result := make([]byte, 2)
		if _, err := io.ReadFull(conn, result); err != nil || !bytes.Equal(result, []byte{1, 0}) {
			t.Fatalf("SOCKS5 rejected the valid credentials: %v (%v)", result, err)
		}
		return conn
	}
	conn = dialSocks()
	request := binary.BigEndian.AppendUint16([]byte{5, 1, 0, 1, 93, 184, 216, 34}, uint16(target.Addr().(*net.TCPAddr).Port))
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[0] != 5 || reply[1] != 0 || reply[3] != 1 {
		t.Fatalf("SOCKS5 could not reach the public IPv4 target: %v (%v)", reply, err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 5)
	if _, err := io.ReadFull(conn, response); err != nil || !bytes.Equal(response, []byte("world")) {
		t.Fatalf("SOCKS5 target exchange failed: %q (%v)", response, err)
	}
	_ = conn.Close()

	conn = dialSocks()
	defer conn.Close()
	blocked := binary.BigEndian.AppendUint16([]byte{5, 1, 0, 1, 169, 254, 169, 254}, 80)
	if _, err := conn.Write(blocked); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, reply); err != nil || reply[0] != 5 || reply[1] == 0 {
		t.Fatalf("SOCKS5 allowed a link-local metadata target: %v (%v)", reply, err)
	}
}
