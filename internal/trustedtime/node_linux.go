package trustedtime

import (
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const nodeClockSocket = "/run/mcui-clock/chrony.sock"

// NodeNow reads the systemd-owned, read-only clock socket when provisioned.
// Older nodes rely on their configured loopback chrony monitor.
func NodeNow() func() (time.Time, error) {
	if os.Getenv("MCUI_NODE_CLOCK_SOCKET") == "1" {
		return readNodeClock
	}
	return NewChrony(DefaultNTSSource).Now
}

func readNodeClock() (time.Time, error) {
	conn, err := net.DialTimeout("unix", nodeClockSocket, time.Second)
	if err != nil {
		return time.Time{}, ErrUntrusted
	}
	defer conn.Close()
	rawConn, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		return time.Time{}, ErrUntrusted
	}
	var trusted bool
	err = rawConn.Control(func(fd uintptr) {
		peer, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		trusted = err == nil && peer.Uid == 0
	})
	if err != nil || !trusted || conn.SetReadDeadline(time.Now().Add(4*time.Second)) != nil {
		return time.Time{}, ErrUntrusted
	}
	raw, err := io.ReadAll(io.LimitReader(conn, 65))
	if err != nil || len(raw) >= 65 {
		return time.Time{}, ErrUntrusted
	}
	now, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(raw)))
	if age := time.Since(now); err != nil || age < -time.Second || age > 5*time.Second {
		return time.Time{}, ErrUntrusted
	}
	return now.UTC(), nil
}
