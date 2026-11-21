//go:build linux

package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/runtimehealth"
	"golang.org/x/sys/unix"
)

const maxHelperFrame = 72 * 1024

type unixStatusExecutor struct{ socketPath string }

type helperSocketRequest struct {
	LeaseID          string          `json:"lease_id,omitempty"`
	Task             json.RawMessage `json:"task,omitempty"`
	ReconcileInstall bool            `json:"reconcile_install,omitempty"`
	Probe            bool            `json:"probe,omitempty"`
	XrayInventory    bool            `json:"xray_inventory,omitempty"`
}

func (e *unixStatusExecutor) ReadXrayInventory(ctx context.Context, node string) (*lifecycleauth.XrayInventory, error) {
	result, err := e.execute(ctx, helperSocketRequest{XrayInventory: true}, time.Second)
	if err != nil {
		return nil, err
	}
	var response struct {
		NodeID string                       `json:"node_id"`
		Xray   *lifecycleauth.XrayInventory `json:"xray"`
	}
	if json.Unmarshal(result, &response) != nil || response.NodeID != node || response.Xray == nil || !response.Xray.Valid() {
		return nil, errors.New("invalid Helper Xray inventory")
	}
	return response.Xray, nil
}

type helperSocketResponse struct {
	Result    json.RawMessage `json:"result,omitempty"`
	ErrorCode string          `json:"error_code,omitempty"`
}

func NewUnixStatusExecutor(socketPath string) (StatusExecutor, error) {
	if !strings.HasPrefix(socketPath, "/") || len(socketPath) > 100 || strings.ContainsRune(socketPath, '\x00') {
		return nil, errors.New("Helper socket path must be an absolute local path")
	}
	if info, err := os.Lstat(socketPath); err == nil && info.Mode()&os.ModeSocket == 0 {
		return nil, errors.New("Helper path is not a Unix socket")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return &unixStatusExecutor{socketPath: socketPath}, nil
}

func (e *unixStatusExecutor) ExecuteStatus(ctx context.Context, raw []byte, leaseID string) (json.RawMessage, error) {
	return e.execute(ctx, helperSocketRequest{LeaseID: leaseID, Task: raw}, 15*time.Second)
}

func (e *unixStatusExecutor) ExecuteInstall(ctx context.Context, raw []byte, leaseID string) (json.RawMessage, error) {
	return e.execute(ctx, helperSocketRequest{LeaseID: leaseID, Task: raw}, 8*time.Minute)
}

func (e *unixStatusExecutor) ReconcileInstall(ctx context.Context, raw []byte) (json.RawMessage, error) {
	return e.execute(ctx, helperSocketRequest{Task: raw, ReconcileInstall: true}, 95*time.Second)
}

func (e *unixStatusExecutor) ProbeRuntime(ctx context.Context, node string) error {
	result, err := e.execute(ctx, helperSocketRequest{Probe: true}, 5*time.Second)
	if err != nil {
		return err
	}
	var response struct {
		NodeID   string `json:"node_id"`
		Protocol int    `json:"protocol"`
	}
	if err := json.Unmarshal(result, &response); err != nil || response.NodeID != node || response.Protocol != runtimehealth.Protocol {
		return errors.New("Helper node or runtime protocol does not match")
	}
	return nil
}

func (e *unixStatusExecutor) execute(ctx context.Context, request helperSocketRequest, timeout time.Duration) (json.RawMessage, error) {
	query := request.Probe || request.XrayInventory
	if e == nil || ctx == nil || !query && (len(request.Task) == 0 || len(request.Task) > maxHelperFrame || request.ReconcileInstall == (request.LeaseID != "")) {
		return nil, errors.New("invalid Helper request")
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > maxHelperFrame {
		return nil, errors.New("Helper request too large")
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	dialer := net.Dialer{Timeout: min(5*time.Second, time.Until(deadline))}
	connection, err := dialer.DialContext(ctx, "unix", e.socketPath)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if query {
		if err := requireRootHelper(connection.(*net.UnixConn)); err != nil {
			return nil, err
		}
	}
	if err = connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(body)))
	if err = writeAll(connection, size[:]); err == nil {
		err = writeAll(connection, body)
	}
	if err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(connection, size[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(size[:])
	if length == 0 || length > maxHelperFrame {
		return nil, errors.New("invalid Helper response size")
	}
	responseBody := make([]byte, length)
	if _, err = io.ReadFull(connection, responseBody); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	var response helperSocketResponse
	if err = decoder.Decode(&response); err != nil {
		return nil, errors.New("invalid Helper response")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errors.New("invalid Helper response")
	}
	if response.ErrorCode != "" {
		switch response.ErrorCode {
		case "task_expired", "task_canceled", "helper_unavailable", "status_unavailable", "reconciliation_required":
			return nil, StatusExecutionError{Code: response.ErrorCode}
		default:
			return nil, errors.New("Helper returned an unknown failure code")
		}
	}
	if len(response.Result) == 0 || !json.Valid(response.Result) || len(response.Result) > 4096 {
		return nil, errors.New("invalid Helper status result")
	}
	return append(json.RawMessage(nil), response.Result...), nil
}

func requireRootHelper(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var peer *unix.Ucred
	var peerErr error
	err = raw.Control(func(fd uintptr) {
		peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil || peerErr != nil || peer == nil || peer.Uid != 0 {
		return errors.New("runtime handshake requires a root Helper")
	}
	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
