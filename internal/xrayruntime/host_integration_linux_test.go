//go:build linux

package xrayruntime

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/xrayconfig"
)

// This test mutates systemd and the network in a disposable VM only.
func TestHostRuntimeInIsolatedVM(t *testing.T) {
	if os.Getenv("MCUI_TEST_HOST_RUNTIME") != "1" {
		t.Skip("requires a disposable systemd VM")
	}
	if _, err := os.Lstat(StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refusing to use an existing Xray state directory")
	}
	const unprivilegedPorts = "/proc/sys/net/ipv4/ip_unprivileged_port_start"
	previousPorts, err := os.ReadFile(unprivilegedPorts)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unprivilegedPorts, []byte("1024\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(unprivilegedPorts, previousPorts, 0644) })
	ctx := context.Background()
	command := func(name string, args ...string) {
		t.Helper()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v: %s", name, args, err, out)
		}
	}
	command("ip", "netns", "add", "mcui-e2e")
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", "mcui-e2e").Run() })
	command("ip", "link", "add", "mcui-e2eh", "type", "veth", "peer", "name", "mcui-e2eg")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "mcui-e2eh").Run() })
	command("ip", "link", "set", "mcui-e2eg", "netns", "mcui-e2e")
	command("ip", "addr", "add", "93.184.216.65/30", "dev", "mcui-e2eh")
	command("ip", "link", "set", "mcui-e2eh", "up")
	command("ip", "-n", "mcui-e2e", "addr", "add", "93.184.216.66/30", "dev", "mcui-e2eg")
	command("ip", "-n", "mcui-e2e", "link", "set", "mcui-e2eg", "up")
	server := exec.Command("ip", "netns", "exec", "mcui-e2e", "python3", "-u", "-c", `import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('93.184.216.66',18080)); s.listen()
while True:
 c,_=s.accept(); data=c.recv(4)
 if data: c.sendall(b'pong' if data==b'ping' else b'bad')
 c.close()`)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	for deadline := time.Now().Add(5 * time.Second); ; {
		conn, err := net.DialTimeout("tcp", "93.184.216.66:18080", 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("isolated target did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Give the VM an isolated resolver so the test can exercise both public
	// DNS resolution and a name resolving to an address owned by this node.
	dns, err := net.ListenPacket("udp4", "127.0.0.55:53")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dns.Close() })
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, peer, err := dns.ReadFrom(buffer)
			if err != nil {
				return
			}
			if n < 17 {
				continue
			}
			end, labels := 12, []string{}
			for end < n && buffer[end] != 0 {
				length := int(buffer[end])
				end++
				if length > 63 || end+length >= n {
					end = n
					break
				}
				labels = append(labels, string(buffer[end:end+length]))
				end += length
			}
			if end+5 > n {
				continue
			}
			typ := binary.BigEndian.Uint16(buffer[end+1 : end+3])
			name := strings.ToLower(strings.Join(labels, "."))
			var address []byte
			if typ == 1 && name == "public.example.test" {
				address = []byte{93, 184, 216, 66}
			} else if typ == 1 && name == "local.example.test" {
				address = []byte{93, 184, 216, 34}
			} else if typ == 1 && name == "dynamic.example.test" {
				address = []byte{93, 184, 216, 35}
			} else if typ == 1 && name == "metadata.example.test" {
				address = []byte{169, 254, 169, 254}
			}
			response := []byte{buffer[0], buffer[1], 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}
			response = append(response, buffer[12:end+5]...)
			if address != nil {
				response[7] = 1
				response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4)
				response = append(response, address...)
			}
			_, _ = dns.WriteTo(response, peer)
		}
	}()
	resolverLink, err := os.Readlink("/etc/resolv.conf")
	if err != nil {
		t.Fatal("test VM requires a symlinked resolver configuration", err)
	}
	if err := os.Remove("/etc/resolv.conf"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove("/etc/resolv.conf")
		_ = os.Symlink(resolverLink, "/etc/resolv.conf")
	})
	if err := os.WriteFile("/etc/resolv.conf", []byte("nameserver 127.0.0.55\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r, err := openRuntime(StateDir, &systemdService{}, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.service.stop(context.Background())
		_ = r.Close()
		_ = filepath.WalkDir(StateDir, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr == nil && entry.IsDir() {
				_ = os.Chmod(path, 0700)
			}
			return nil
		})
		_ = os.RemoveAll(StateDir)
	})
	binary, err := os.ReadFile("/root/xray")
	if err != nil {
		t.Fatal(err)
	}
	geoip, err := os.ReadFile("/root/geoip.dat")
	if err != nil {
		t.Fatal(err)
	}
	release, archive, size := makeArchive(t, xrayconfig.Version, []testEntry{{"xray", binary, 0755}, {"geoip.dat", geoip, 0644}, {"geosite.dat", []byte("unused"), 0644}})
	if err := r.stage(ctx, release, size, func() (string, error) { return archive, nil }); err != nil {
		t.Fatal(err)
	}
	if err := r.point("current", release); err != nil {
		t.Fatal(err)
	}
	state := Status{Schema: 1, Current: selection{Release: release, Running: true}}
	if err := r.save(state); err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey := base64.RawURLEncoding.EncodeToString(key.Bytes())
	if err := r.writeControl(panelKeyFile, []byte(`"`+encodedKey+`"`)); err != nil {
		t.Fatal(err)
	}
	const password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	listener, err := net.Listen("tcp4", "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	goodPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	makeConfig := func(port int) ([]byte, xrayconfig.Reference) {
		t.Helper()
		inbound := xrayconfig.Inbound{Port: 1080, Users: []string{"alice"}, HostListen: &xrayconfig.HostListener{Address: "127.0.0.1", Port: port},
			PublicEndpoint: xrayconfig.PublicEndpoint{Address: "93.184.216.37", Port: 8443}}
		box, err := xrayconfig.SealPanelCredential(base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), inbound, password)
		if err != nil {
			t.Fatal(err)
		}
		draft := xrayconfig.Configuration{Inbounds: xrayconfig.Plan{inbound}, Network: &xrayconfig.Network{Host: true, Outbounds: []xrayconfig.Outbound{}, Routes: []xrayconfig.Route{}},
			Panel: &xrayconfig.PanelConfiguration{Credentials: []string{box}, DirectPorts: []int{1080}}}
		data, ref, err := draft.RenderPanel(key)
		if err != nil {
			t.Fatal(err)
		}
		return data, ref
	}
	apply := func(data []byte, ref xrayconfig.Reference, revision int64) error {
		t.Helper()
		if err := r.checkConfigUnits(ctx, data, true); err != nil {
			return err
		}
		if err := r.preflightConfig(ctx, release, data); err != nil {
			return err
		}
		if err := r.writeControl(configName(ref), data); err != nil {
			return err
		}
		current, err := r.Status()
		if err != nil {
			return err
		}
		next := current.Current
		next.Config, next.Revision = ref, revision
		return r.change(ctx, current, intent{Action: Configure, Next: next, ConfigHash: strings.Repeat("a", 64)})
	}
	good, ref := makeConfig(goodPort)
	if err := apply(good, ref, 1); err != nil {
		t.Fatal(err)
	}
	active, err := r.Status()
	if err != nil {
		t.Fatal(err)
	}
	view := r.Inventory(active, "", true)
	if !view.PanelHost || view.AppliedNetwork == nil || !view.AppliedNetwork.Host || view.Applied == nil || len(*view.Applied) != 1 || (*view.Applied)[0].HostListen == nil ||
		(*view.Applied)[0].HostListen.Port != 443 || (*view.Applied)[0].PublicEndpoint != (xrayconfig.PublicEndpoint{Address: "93.184.216.37", Port: 8443}) {
		t.Fatalf("host listener or NAT advertisement not reported: %+v", view)
	}
	openSOCKS := func() net.Conn {
		t.Helper()
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", goodPort), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte{5, 1, 2})
		response := make([]byte, 2)
		if _, err := io.ReadFull(c, response); err != nil || response[1] != 2 {
			t.Fatal("SOCKS authentication method", err)
		}
		login := append([]byte{1, 5}, []byte("alice")...)
		login = append(login, byte(len(password)))
		login = append(login, []byte(password)...)
		_, _ = c.Write(login)
		if _, err := io.ReadFull(c, response); err != nil || response[1] != 0 {
			t.Fatal("SOCKS authentication", err)
		}
		return c
	}
	connect := func() {
		t.Helper()
		c := openSOCKS()
		defer c.Close()
		_, _ = c.Write([]byte{5, 1, 0, 1, 93, 184, 216, 66, 70, 160}) // port 18080
		reply := make([]byte, 10)
		if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0 {
			t.Fatal("SOCKS connection to external target", err, reply)
		}
		_, _ = c.Write([]byte("ping"))
		result := make([]byte, 4)
		if _, err := io.ReadFull(c, result); err != nil || string(result) != "pong" {
			t.Fatalf("host connection: %q %v", result, err)
		}
	}
	connect()
	connectDomain := func(name string, port int) (net.Conn, byte) {
		t.Helper()
		c := openSOCKS()
		request := append([]byte{5, 1, 0, 3, byte(len(name))}, []byte(name)...)
		request = append(request, byte(port>>8), byte(port))
		_, _ = c.Write(request)
		reply := make([]byte, 10)
		if _, err := io.ReadFull(c, reply); err != nil {
			_ = c.Close()
			t.Fatal("SOCKS domain connection", err)
		}
		return c, reply[1]
	}
	domainConn, code := connectDomain("public.example.test", 18080)
	if code != 0 {
		t.Fatalf("public DNS destination rejected: %d", code)
	}
	_, _ = domainConn.Write([]byte("ping"))
	domainResult := make([]byte, 4)
	if _, err := io.ReadFull(domainConn, domainResult); err != nil || string(domainResult) != "pong" {
		t.Fatalf("public DNS connection: %q %v", domainResult, err)
	}
	_ = domainConn.Close()
	localTarget, err := net.Listen("tcp4", "93.184.216.34:18081")
	if err != nil {
		t.Fatal(err)
	}
	defer localTarget.Close()
	localConn, _ := connectDomain("local.example.test", 18081)
	_, _ = localConn.Write([]byte("probe"))
	_ = localConn.Close()
	_ = localTarget.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
	if conn, err := localTarget.Accept(); err == nil {
		_ = conn.Close()
		t.Fatal("proxy connected to a local management endpoint")
	}
	command("ip", "addr", "add", "93.184.216.35/32", "dev", "lo")
	t.Cleanup(func() { _ = exec.Command("ip", "addr", "del", "93.184.216.35/32", "dev", "lo").Run() })
	dynamicTarget, err := net.Listen("tcp4", "93.184.216.35:18081")
	if err != nil {
		t.Fatal(err)
	}
	defer dynamicTarget.Close()
	dynamicConn, _ := connectDomain("dynamic.example.test", 18081)
	_, _ = dynamicConn.Write([]byte("probe"))
	_ = dynamicConn.Close()
	_ = dynamicTarget.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
	if conn, err := dynamicTarget.Accept(); err == nil {
		_ = conn.Close()
		t.Fatal("proxy connected to a newly added local endpoint")
	}
	command("ip", "addr", "add", "169.254.169.254/32", "dev", "lo")
	t.Cleanup(func() { _ = exec.Command("ip", "addr", "del", "169.254.169.254/32", "dev", "lo").Run() })
	metadataTarget, err := net.Listen("tcp4", "169.254.169.254:53")
	if err != nil {
		t.Fatal(err)
	}
	defer metadataTarget.Close()
	metadataConn, _ := connectDomain("metadata.example.test", 53)
	_, _ = metadataConn.Write([]byte("probe"))
	_ = metadataConn.Close()
	_ = metadataTarget.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
	if conn, err := metadataTarget.Accept(); err == nil {
		_ = conn.Close()
		t.Fatal("proxy connected to a metadata endpoint")
	}
	if err := r.service.stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openRuntime(StateDir, &systemdService{}, false)
	if err != nil {
		t.Fatal(err)
	}
	r = reopened
	if err := r.Recover(ctx); err != nil {
		t.Fatalf("host listener did not recover after restart: %v", err)
	}
	connect()
	conflict, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conflict.Close()
	bad, badRef := makeConfig(conflict.Addr().(*net.TCPAddr).Port)
	if err := apply(bad, badRef, 2); !errors.Is(err, errRollback) {
		t.Fatalf("port conflict was not rolled back: %v", err)
	}
	if current, err := r.Status(); err != nil || current.Current.Config != ref || current.LastResult != "rolled_back" {
		t.Fatalf("previous host revision was not restored: %+v %v", current, err)
	}
	connect()
	// Replace the authenticated SOCKS inbound with VLESS + REALITY + Vision.
	// The REALITY handshake target and echo server live in the separate namespace.
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"www.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, certificateKey.Public(), certificateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(certificateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(t.TempDir(), "cert.pem"), filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	tlsServer := exec.Command("ip", "netns", "exec", "mcui-e2e", "python3", "-u", "-c", `import socket,ssl,sys
x=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); x.minimum_version=ssl.TLSVersion.TLSv1_3; x.set_alpn_protocols(['h2','http/1.1']); x.load_cert_chain(sys.argv[1],sys.argv[2])
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('93.184.216.66',18443)); s.listen()
while True:
 c,_=s.accept()
 try:
  with x.wrap_socket(c,server_side=True) as tls: tls.recv(4096)
 except (ssl.SSLError,ConnectionError): c.close()`, certPath, keyPath)
	if err := tlsServer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tlsServer.Process.Kill(); _ = tlsServer.Wait() })
	for deadline := time.Now().Add(5 * time.Second); ; {
		conn, err := net.DialTimeout("tcp", "93.184.216.66:18443", 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("isolated REALITY target did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	identity, err := xrayconfig.NewPanelReality(publicKey, 1080, "93.184.216.66:18443", []string{"www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	const uuid = "00000000-0000-4000-8000-000000000001"
	vless := xrayconfig.Inbound{Port: 1080, Protocol: xrayconfig.VLESS, Users: []string{"alice"},
		HostListen:  &xrayconfig.HostListener{Address: "::1", Port: goodPort},
		VLESSStream: &xrayconfig.VLESSStream{Network: "tcp", Security: "reality", Reality: &identity.RealitySettings},
		VLESSFlows:  map[string]string{"alice": "xtls-rprx-vision"}}
	box, err := xrayconfig.SealPanelCredential(publicKey, vless, uuid)
	if err != nil {
		t.Fatal(err)
	}
	draft := xrayconfig.Configuration{Inbounds: xrayconfig.Plan{vless}, Network: &xrayconfig.Network{Host: true, Outbounds: []xrayconfig.Outbound{}, Routes: []xrayconfig.Route{}},
		Panel: &xrayconfig.PanelConfiguration{Credentials: []string{box}, DirectPorts: []int{1080}, Reality: map[int]xrayconfig.PanelReality{1080: *identity}}}
	vlessConfig, vlessRef, err := draft.RenderPanel(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(vlessConfig, vlessRef, 3); err != nil {
		t.Fatal(err)
	}
	clientSocket, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clientPort := clientSocket.Addr().(*net.TCPAddr).Port
	_ = clientSocket.Close()
	clientConfig, err := json.Marshal(map[string]any{
		"log":      map[string]string{"loglevel": "none"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": clientPort, "protocol": "socks"}},
		"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"address": "::1", "port": goodPort, "id": uuid, "encryption": "none", "flow": "xtls-rprx-vision"},
			"streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"serverName": "www.example.com", "fingerprint": "chrome", "password": identity.PublicKey, "shortId": identity.ShortID}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientPath := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(clientPath, clientConfig, 0600); err != nil {
		t.Fatal(err)
	}
	client := exec.Command("/root/xray", "run", "-config", clientPath)
	client.Env = append(os.Environ(), "XRAY_LOCATION_ASSET=/root")
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Process.Kill(); _ = client.Wait() })
	var conn net.Conn
	for deadline := time.Now().Add(5 * time.Second); ; {
		conn, err = net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", clientPort), 200*time.Millisecond)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("REALITY client did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = conn.Write([]byte{5, 1, 0})
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil || response[1] != 0 {
		t.Fatal("REALITY client SOCKS negotiation", err)
	}
	_, _ = conn.Write([]byte{5, 1, 0, 1, 93, 184, 216, 66, 70, 160})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
		t.Fatal("REALITY client connect", err, reply)
	}
	_, _ = conn.Write([]byte("ping"))
	result := make([]byte, 4)
	if _, err := io.ReadFull(conn, result); err != nil || string(result) != "pong" {
		t.Fatalf("REALITY host connection: %q %v", result, err)
	}
}
