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
)

const maxHelperFrame = 72 * 1024

type unixStatusExecutor struct{ socketPath string }

type helperSocketRequest struct {
	LeaseID string          `json:"lease_id"`
	Task    json.RawMessage `json:"task"`
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
	if e == nil || ctx == nil || len(raw) == 0 || len(raw) > maxHelperFrame || leaseID == "" {
		return nil, errors.New("invalid Helper request")
	}
	body, err := json.Marshal(helperSocketRequest{LeaseID: leaseID, Task: append(json.RawMessage(nil), raw...)})
	if err != nil || len(body) > maxHelperFrame {
		return nil, errors.New("Helper request too large")
	}
	deadline := time.Now().Add(15 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	dialer := net.Dialer{Timeout: time.Until(deadline)}
	connection, err := dialer.DialContext(ctx, "unix", e.socketPath)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
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
