//go:build linux

package helper

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ACnoway/mcui/internal/runtimehealth"
	"golang.org/x/sys/unix"
)

const maxSocketFrame = 72 * 1024

type socketRequest struct {
	LeaseID          string          `json:"lease_id,omitempty"`
	Task             json.RawMessage `json:"task,omitempty"`
	ReconcileInstall bool            `json:"reconcile_install,omitempty"`
	Probe            bool            `json:"probe,omitempty"`
}

type socketResponse struct {
	Result    json.RawMessage `json:"result,omitempty"`
	ErrorCode string          `json:"error_code,omitempty"`
}

// RunSocket serves one framed request per connection. It never removes a
// pre-existing path; stale sockets require explicit operator inspection.
func (h *Helper) RunSocket(ctx context.Context, path string, groupID uint32) error {
	if h == nil || ctx == nil || os.Geteuid() != 0 || path == "" || groupID == 0 {
		return ErrDenied
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrDenied
	}
	var parentStat unix.Stat_t
	if err = unix.Stat(parent, &parentStat); err != nil || parentStat.Uid != 0 || parentStat.Mode&0022 != 0 {
		return ErrDenied
	}
	if _, err = os.Lstat(path); err == nil {
		return fmt.Errorf("helper socket path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	listener.SetUnlinkOnClose(false)
	if err = os.Chmod(path, 0660); err == nil {
		err = os.Chown(path, 0, int(groupID))
	}
	if err != nil {
		_ = listener.Close()
		return err
	}
	socketInfo, err := os.Lstat(path)
	if err != nil {
		_ = listener.Close()
		return err
	}
	defer func() {
		_ = listener.Close()
		if current, statErr := os.Lstat(path); statErr == nil && current.Mode()&os.ModeSocket != 0 && os.SameFile(socketInfo, current) {
			_ = os.Remove(path)
		}
	}()
	if h.cfg.RuntimeManaged {
		if err := runtimehealth.NotifyReady(); err != nil {
			return err
		}
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	var workers sync.WaitGroup
	semaphore := make(chan struct{}, 32)
	for {
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			if ctx.Err() != nil {
				workers.Wait()
				return nil
			}
			return acceptErr
		}
		select {
		case semaphore <- struct{}{}:
			workers.Add(1)
			go func(conn *net.UnixConn) {
				defer workers.Done()
				defer func() { <-semaphore }()
				_ = h.handleSocket(conn)
			}(conn)
		default:
			_ = conn.Close()
		}
	}
}

func (h *Helper) handleSocket(conn *net.UnixConn) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	var size [4]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(size[:])
	if length == 0 || length > maxSocketFrame {
		return ErrDenied
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var request socketRequest
	if err := decoder.Decode(&request); err != nil {
		return h.writeSocketResponse(conn, socketResponse{ErrorCode: "status_unavailable"})
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return h.writeSocketResponse(conn, socketResponse{ErrorCode: "status_unavailable"})
	}
	if request.Probe {
		if !h.cfg.RuntimeManaged || len(request.Task) != 0 || request.LeaseID != "" || request.ReconcileInstall || h.authorizePeer(conn) != nil {
			return h.writeSocketResponse(conn, socketResponse{ErrorCode: "status_unavailable"})
		}
		result, err := json.Marshal(map[string]any{"node_id": h.cfg.NodeID, "protocol": runtimehealth.Protocol})
		if err != nil {
			return err
		}
		return h.writeSocketResponse(conn, socketResponse{Result: result})
	}
	if len(request.Task) == 0 || request.ReconcileInstall == (request.LeaseID != "") {
		return h.writeSocketResponse(conn, socketResponse{ErrorCode: "status_unavailable"})
	}
	if h.cfg.RuntimeManaged {
		if trial, err := runtimehealth.Trial(); err != nil || trial {
			return h.writeSocketResponse(conn, socketResponse{ErrorCode: "helper_unavailable"})
		}
	}
	var result string
	var err error
	if request.ReconcileInstall {
		deadline := time.Now().Add(90 * time.Second)
		_ = conn.SetWriteDeadline(deadline)
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		result, err = h.reconcileInstall(ctx, conn, request.Task)
	} else {
		if h.cfg.XrayInstall != nil {
			if install, err := h.cfg.XrayInstall.Key.Verify(request.Task); err == nil {
				_ = conn.SetWriteDeadline(minTime(time.Now().Add(10*time.Minute), install.ExpiresAt.Add(70*time.Second)))
			}
		}
		result, err = h.Execute(conn, request.Task, request.LeaseID)
	}
	if err != nil {
		code := "helper_unavailable"
		if errors.Is(err, ErrDenied) {
			code = "status_unavailable"
		} else if errors.Is(err, ErrReconciliation) {
			code = "reconciliation_required"
		}
		return h.writeSocketResponse(conn, socketResponse{ErrorCode: code})
	}
	if !json.Valid([]byte(result)) || len(result) > taskStatusResultLimit {
		return h.writeSocketResponse(conn, socketResponse{ErrorCode: "status_unavailable"})
	}
	return h.writeSocketResponse(conn, socketResponse{Result: json.RawMessage(result)})
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

const taskStatusResultLimit = 4096

func (h *Helper) writeSocketResponse(conn *net.UnixConn, response socketResponse) error {
	body, err := json.Marshal(response)
	if err != nil || len(body) > maxSocketFrame {
		return ErrReconciliation
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(body)))
	if err = writeSocketBytes(conn, size[:]); err != nil {
		return err
	}
	return writeSocketBytes(conn, body)
}

func writeSocketBytes(writer io.Writer, raw []byte) error {
	for len(raw) > 0 {
		n, err := writer.Write(raw)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}
