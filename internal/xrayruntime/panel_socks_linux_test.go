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
	config := fmt.Sprintf(`{"dns":{"tag":"mcui-dns","servers":["10.0.2.3"],"queryStrategy":"UseIPv4"},"inbounds":[{"listen":"127.0.0.1","port":1080,"protocol":"socks","tag":"socks-1080"}],"outbounds":[{"protocol":"freedom","tag":"mcui-dns"},{"protocol":"freedom","tag":"direct","settings":{"domainStrategy":"UseIPv4","finalRules":[{"action":"block","ip":%s}]}}],"routing":{"rules":[{"inboundTag":["mcui-dns"],"network":"udp","ip":["10.0.2.3/32"],"port":53,"outboundTag":"mcui-dns"},{"inboundTag":["socks-1080"],"outboundTag":"direct"}]}}`, blockedIPs)
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
		"wrong DNS server":       strings.Replace(config, `10.0.2.3`, `127.0.0.1`, 1),
		"wrong domain strategy":  strings.Replace(config, `"domainStrategy":"UseIPv4"`, `"domainStrategy":"AsIs"`, 1),
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
	// systemd renders IPv4-mapped IPv6 prefixes in dotted notation.
	panel["IPAddressDeny"] = strings.Replace(panel["IPAddressDeny"], "::ffff:0.0.0.0/96", "::ffff:0:0/96", 1)
	if validCurrentNetworkPolicy(panel) {
		t.Fatal("expected the loaded systemd address notation")
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
	forbidden, err := net.Listen("tcp4", "169.254.169.254:80")
	if err != nil {
		t.Fatal("bind 169.254.169.254 to loopback in the test namespace: ", err)
	}
	defer forbidden.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			request := make([]byte, 5)
			if _, err := io.ReadFull(conn, request); err == nil && string(request) == "hello" {
				_, _ = conn.Write([]byte("world"))
			}
			_ = conn.Close()
		}
	}()
	// Supply deterministic DNS answers inside the test namespace. The second
	// answer checks the final destination policy after domain resolution.
	dns, err := net.ListenPacket("udp4", xrayconfig.PanelDNSAddress+":53")
	if err != nil {
		t.Fatal("bind 10.0.2.3 to loopback in the test namespace: ", err)
	}
	defer dns.Close()
	go func() {
		packet := make([]byte, 512)
		for {
			n, addr, err := dns.ReadFrom(packet)
			if err != nil {
				return
			}
			if n < 17 {
				continue
			}
			end := 12
			for end < n && packet[end] != 0 {
				end += int(packet[end]) + 1
			}
			if end+5 > n {
				continue
			}
			question := packet[12 : end+5]
			ip := []byte{93, 184, 216, 34}
			if bytes.Contains(question, []byte("blocked")) {
				ip = []byte{169, 254, 169, 254}
			}
			response := append([]byte{}, packet[:12]...)
			response[2], response[3], response[6], response[7] = 0x81, 0x80, 0, 1
			response[10], response[11] = 0, 0
			response = append(response, question...)
			response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4)
			response = append(response, ip...)
			_, _ = dns.WriteTo(response, addr)
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
	process.Stdout, process.Stderr = os.Stderr, os.Stderr
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
	wrong, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = wrong.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := wrong.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(wrong, method); err != nil || !bytes.Equal(method, []byte{5, 2}) {
		t.Fatalf("SOCKS5 did not require authentication: %v (%v)", method, err)
	}
	auth := append([]byte{1, byte(len(username))}, username...)
	auth = append(auth, 5)
	auth = append(auth, "wrong"...)
	if _, err := wrong.Write(auth); err != nil {
		t.Fatal(err)
	}
	result := make([]byte, 2)
	if _, err := io.ReadFull(wrong, result); err != nil || result[1] == 0 {
		t.Fatalf("SOCKS5 accepted an incorrect password: %v (%v)", result, err)
	}
	_ = wrong.Close()
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
	domain := "public.example"
	request = binary.BigEndian.AppendUint16(append([]byte{5, 1, 0, 3, byte(len(domain))}, domain...), uint16(target.Addr().(*net.TCPAddr).Port))
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
		t.Fatalf("SOCKS5 could not reach the resolved public target: %v (%v)", reply, err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, response); err != nil || string(response) != "world" {
		t.Fatalf("resolved target exchange failed: %q (%v)", response, err)
	}
	_ = conn.Close()

	conn = dialSocks()
	domain = "blocked.example"
	request = binary.BigEndian.AppendUint16(append([]byte{5, 1, 0, 3, byte(len(domain))}, domain...), 80)
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] == 0 {
		_, _ = conn.Write([]byte("hello"))
		if _, err := conn.Read(response); err == nil {
			t.Fatal("SOCKS5 exchanged data with a domain resolving to metadata")
		}
	}
	_ = conn.Close()

	conn = dialSocks()
	defer conn.Close()
	blocked := binary.BigEndian.AppendUint16([]byte{5, 1, 0, 1, 169, 254, 169, 254}, 80)
	if _, err := conn.Write(blocked); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, reply); err != nil || reply[0] != 5 {
		t.Fatalf("invalid SOCKS5 response: %v (%v)", reply, err)
	}
	if reply[1] == 0 {
		_, _ = conn.Write([]byte("hello"))
		if _, err := conn.Read(response); err == nil {
			t.Fatal("SOCKS5 exchanged data with a link-local metadata target")
		}
	}
	if err := forbidden.(*net.TCPListener).SetDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if accepted, err := forbidden.Accept(); err == nil {
		_ = accepted.Close()
		t.Fatal("SOCKS5 connected to the metadata target")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal(err)
	}
}
