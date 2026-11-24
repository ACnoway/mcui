//go:build linux

package xrayruntime

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/xraytraffic"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestQueryXrayStatsUsesNonResettingUnixRPC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	payload := make([]byte, 5)
	for _, name := range []string{"inbound>>>socks-1080>>>traffic>>>uplink", "user>>>alice>>>traffic>>>uplink", "outbound>>>prod>>>traffic>>>downlink", "outbound>>>deny>>>traffic>>>uplink"} {
		stat := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), name)
		stat = protowire.AppendVarint(protowire.AppendTag(stat, 2, protowire.VarintType), 10)
		payload = protowire.AppendBytes(protowire.AppendTag(payload, 1, protowire.BytesType), stat)
	}
	binary.BigEndian.PutUint32(payload[1:5], uint32(len(payload)-5))
	server := &http.Server{Protocols: protocols, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || r.URL.Path != "/xray.app.stats.command.StatsService/QueryStats" || r.Method != http.MethodPost ||
			r.Header.Get("Content-Type") != "application/grpc" || !bytes.Equal(body, make([]byte, 5)) {
			t.Error("expected a non-resetting QueryStats request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Trailer", "Grpc-Status")
		w.Header().Set("Content-Type", "application/grpc")
		_, _ = w.Write(payload)
		w.Header().Set("Grpc-Status", "0")
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := queryXrayStats(path, info.Sys().(*syscall.Stat_t))
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]string{"inbound>>>socks-1080": "inbound:1080", "user>>>alice": "user:alice", "outbound>>>prod": "outbound:prod"}
	result, err := parseXrayCounters(raw, known)
	if err != nil || len(result) != 3 || result["user:alice"] != (xraytraffic.Bytes{Up: 10}) ||
		result["inbound:1080"] != (xraytraffic.Bytes{Up: 10}) || result["outbound:prod"] != (xraytraffic.Bytes{Down: 10}) {
		t.Fatalf("unexpected Xray counters: %+v (%v)", result, err)
	}
	if _, err := parseXrayCounters(raw[:len(raw)-1], known); err == nil {
		t.Fatal("accepted truncated Xray response")
	}
}

func TestQueryXrayStatsWithCore(t *testing.T) {
	xray := os.Getenv("MCUI_TEST_XRAY_BINARY")
	if xray == "" {
		t.Skip("set MCUI_TEST_XRAY_BINARY to the verified Xray binary")
	}
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
		data := make([]byte, 5)
		if _, err := io.ReadFull(conn, data); err == nil && string(data) == "hello" {
			_, _ = conn.Write([]byte("goodbye"))
		}
	}()
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	port := probe.Addr().(*net.TCPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "stats.sock")
	config, err := json.Marshal(map[string]any{
		"api":   map[string]any{"tag": "@mcui-stats", "listen": socket + ",0660", "services": []string{"StatsService"}},
		"stats": map[string]any{},
		"policy": map[string]any{
			"levels": map[string]any{"0": map[string]bool{"statsUserUplink": true, "statsUserDownlink": true}},
			"system": map[string]bool{"statsInboundUplink": true, "statsInboundDownlink": true,
				"statsOutboundUplink": true, "statsOutboundDownlink": true},
		},
		"inbounds": []any{map[string]any{"tag": "socks", "protocol": "socks", "listen": "127.0.0.1", "port": port,
			"settings": map[string]any{"auth": "password", "users": []map[string]string{{"user": "alice", "pass": "secret"}}}}},
		"outbounds": []map[string]string{{"tag": "local", "protocol": "freedom"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	process := exec.CommandContext(t.Context(), xray, "run", "-config", "stdin:")
	process.Env = append(os.Environ(), "xray.buf.splice=disable")
	process.Stdin = bytes.NewReader(config)
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = process.Process.Kill()
		_ = process.Wait()
	})
	var identity *syscall.Stat_t
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if info, err := os.Lstat(socket); err == nil && info.Mode().Perm() == 0660 {
			identity = info.Sys().(*syscall.Stat_t)
			break
		}
	}
	if identity == nil {
		t.Fatal("Xray did not start its private statistics socket")
	}
	conn, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	exchange := func(send, want []byte) {
		t.Helper()
		if _, err := conn.Write(send); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("SOCKS response %v, want %v (%v)", got, want, err)
		}
	}
	exchange([]byte{5, 1, 2}, []byte{5, 2})
	login := append([]byte{1, 5}, "alice"...)
	login = append(append(login, 6), "secret"...)
	exchange(login, []byte{1, 0})
	connect := binary.BigEndian.AppendUint16([]byte{5, 1, 0, 1, 127, 0, 0, 1}, uint16(target.Addr().(*net.TCPAddr).Port))
	if _, err := conn.Write(connect); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[0] != 5 || reply[1] != 0 || reply[3] != 1 {
		t.Fatalf("SOCKS connection failed: %v (%v)", reply, err)
	}
	exchange([]byte("hello"), []byte("goodbye"))
	known := map[string]string{"inbound>>>socks": "inbound:1080", "user>>>alice": "user:alice", "outbound>>>local": "outbound:local"}
	want := xraytraffic.Bytes{Up: 5, Down: 7}
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		raw, err := queryXrayStats(socket, identity)
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseXrayCounters(raw, known)
		if err != nil {
			t.Fatal(err)
		}
		if got["user:alice"] == want && got["outbound:local"] == want && got["inbound:1080"].Up >= want.Up &&
			got["inbound:1080"].Down >= want.Down {
			return
		}
	}
	t.Fatal("Xray did not report the transferred bytes")
}
