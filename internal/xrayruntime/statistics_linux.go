//go:build linux

package xrayruntime

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ACnoway/mcui/internal/xrayconfig"
	"github.com/ACnoway/mcui/internal/xraytraffic"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protowire"
)

const statsReplyLimit = 16 * 1024

func statisticsGroup() (uint32, bool) {
	info, err := os.Lstat(filepath.Dir(xrayconfig.StatisticsSocket))
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0750 {
		return 0, false
	}
	group := info.Sys().(*syscall.Stat_t).Gid
	groups, err := os.Getgroups()
	return group, err == nil && group != 0 && slices.Contains(groups, int(group))
}

func statsSocket(group uint32) (*syscall.Stat_t, error) {
	info, err := os.Lstat(xrayconfig.StatisticsSocket)
	if err != nil {
		return nil, err
	}
	identity := info.Sys().(*syscall.Stat_t)
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 || identity.Uid == 0 || identity.Gid != group {
		return nil, errors.New("invalid Xray statistics socket")
	}
	return identity, nil
}

func queryXrayStats(socket string, identity *syscall.Stat_t) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{Protocols: protocols, DisableCompression: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			conn, err := dialer.DialContext(ctx, "unix", socket)
			if err != nil {
				return nil, err
			}
			raw, err := conn.(*net.UnixConn).SyscallConn()
			var credentials *unix.Ucred
			var peerErr error
			if err == nil {
				err = raw.Control(func(fd uintptr) {
					credentials, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
				})
			}
			if err != nil || peerErr != nil || credentials.Uid != identity.Uid || credentials.Gid != identity.Gid {
				_ = conn.Close()
				return nil, errors.New("invalid Xray statistics peer")
			}
			return conn, nil
		}}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://localhost/xray.app.stats.command.StatsService/QueryStats", bytes.NewReader(make([]byte, 5)))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("TE", "trailers")
	response, err := transport.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, statsReplyLimit+1))
	if err != nil || response.StatusCode != http.StatusOK || response.Trailer.Get("Grpc-Status") != "0" ||
		len(data) < 5 || len(data) > statsReplyLimit || data[0] != 0 || int(binary.BigEndian.Uint32(data[1:5])) != len(data)-5 {
		return nil, errors.New("invalid Xray statistics response")
	}
	return data[5:], nil
}

func collectXrayTraffic(group uint32, revision int64, ports map[string]int, plan xrayconfig.Plan, network *xrayconfig.Network) *xraytraffic.Sample {
	identity, err := statsSocket(group)
	if err != nil {
		return nil
	}
	raw, err := queryXrayStats(xrayconfig.StatisticsSocket, identity)
	if err != nil {
		return nil
	}
	current, err := statsSocket(group)
	if err != nil || identity.Dev != current.Dev || identity.Ino != current.Ino || identity.Ctim != current.Ctim {
		return nil
	}
	known := make(map[string]string)
	for tag, port := range ports {
		known["inbound>>>"+tag] = "inbound:" + strconv.Itoa(port)
	}
	for _, inbound := range plan {
		for _, user := range inbound.Users {
			known["user>>>"+user] = "user:" + user
		}
	}
	if network != nil {
		for _, outbound := range network.Outbounds {
			known["outbound>>>"+outbound.Tag] = "outbound:" + outbound.Tag
		}
	}
	counters, err := parseXrayCounters(raw, known)
	if err != nil {
		return nil
	}
	epoch := xrayconfig.PlanDigest(fmt.Sprintf("%d:%d:%d:%d", identity.Dev, identity.Ino, identity.Ctim.Sec, identity.Ctim.Nsec))
	sample := &xraytraffic.Sample{Revision: revision, Epoch: epoch, At: time.Now().UnixMilli(), Counters: counters}
	if !sample.Valid() {
		return nil
	}
	return sample
}

// QueryStatsResponse has repeated Stat messages in field 1. Each message
// carries the counter name in field 1 and an int64 counter in field 2.
func parseXrayCounters(raw []byte, known map[string]string) (map[string]xraytraffic.Bytes, error) {
	counters := make(map[string]xraytraffic.Bytes)
	seen := make(map[string]bool)
	invalid := errors.New("invalid Xray counter")
	for len(raw) != 0 {
		field, wireType, n := protowire.ConsumeTag(raw)
		if n < 0 || field != 1 || wireType != protowire.BytesType {
			return nil, invalid
		}
		stat, size := protowire.ConsumeBytes(raw[n:])
		if size < 0 {
			return nil, invalid
		}
		raw = raw[n+size:]
		name, value, ok := decodeXrayCounter(stat)
		if !ok || seen[name] {
			return nil, invalid
		}
		seen[name] = true
		prefix, direction, _ := strings.Cut(name, ">>>traffic>>>")
		key, exists := known[prefix]
		if !exists {
			continue
		}
		amount := counters[key]
		switch direction {
		case "uplink":
			amount.Up = value
		case "downlink":
			amount.Down = value
		default:
			return nil, invalid
		}
		counters[key] = amount
	}
	return counters, nil
}

func decodeXrayCounter(raw []byte) (string, int64, bool) {
	var name string
	var value uint64
	var hasValue bool
	for len(raw) != 0 {
		field, wireType, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return "", 0, false
		}
		raw = raw[n:]
		switch {
		case field == 1 && wireType == protowire.BytesType && name == "":
			name, n = protowire.ConsumeString(raw)
		case field == 2 && wireType == protowire.VarintType && !hasValue:
			value, n = protowire.ConsumeVarint(raw)
			hasValue = true
		default:
			return "", 0, false
		}
		if n < 0 {
			return "", 0, false
		}
		raw = raw[n:]
	}
	return name, int64(value), name != "" && value <= xraytraffic.MaxBytes
}
