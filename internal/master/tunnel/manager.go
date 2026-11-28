package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ACnoway/mcui/pkg/proto"
	"github.com/ACnoway/mcui/pkg/wsconn"
	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

var ErrNodeOffline = errors.New("agent node is offline")

type ReportHandler func(nodeID uint, report proto.AgentReport)

type ConnectHandler func(nodeID uint)

type nodeSession struct {
	nodeID  uint
	session *yamux.Session
	client  *http.Client
}

type Manager struct {
	mu          sync.RWMutex
	sessions    map[uint]*nodeSession
	onReport    ReportHandler
	onConnected ConnectHandler
	onClosed    ConnectHandler
}

func NewManager() *Manager {
	return &Manager{
		sessions: make(map[uint]*nodeSession),
	}
}

func (m *Manager) SetHooks(onReport ReportHandler, onConnected, onClosed ConnectHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onReport = onReport
	m.onConnected = onConnected
	m.onClosed = onClosed
}

func (m *Manager) IsOnline(nodeID uint) bool {
	m.mu.RLock()
	ns, ok := m.sessions[nodeID]
	m.mu.RUnlock()
	return ok && !ns.session.IsClosed()
}

func (m *Manager) Disconnect(nodeID uint) {
	m.mu.Lock()
	ns, ok := m.sessions[nodeID]
	if ok {
		delete(m.sessions, nodeID)
	}
	m.mu.Unlock()
	if ok {
		_ = ns.session.Close()
	}
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(*http.Request) bool { return true },
}

func (m *Manager) AcceptWebSocket(w http.ResponseWriter, r *http.Request, nodeID uint) error {
	ws, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return err
	}

	ymCfg := yamux.DefaultConfig()
	ymCfg.EnableKeepAlive = true
	ymCfg.KeepAliveInterval = 15 * time.Second
	ymCfg.LogOutput = io.Discard

	session, err := yamux.Client(wsconn.New(ws), ymCfg)
	if err != nil {
		_ = ws.Close()
		return err
	}

	httpClient := &http.Client{
		Timeout: 25 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return session.Open()
			},
		},
	}

	ns := &nodeSession{
		nodeID:  nodeID,
		session: session,
		client:  httpClient,
	}

	m.mu.Lock()
	prev := m.sessions[nodeID]
	m.sessions[nodeID] = ns
	onConnected := m.onConnected
	onClosed := m.onClosed
	m.mu.Unlock()

	if prev != nil {
		_ = prev.session.Close()
	}
	if onConnected != nil {
		go onConnected(nodeID)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/report", func(rw http.ResponseWriter, req *http.Request) {
		var rep proto.AgentReport
		if err := json.NewDecoder(io.LimitReader(req.Body, 4<<20)).Decode(&rep); err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		m.mu.RLock()
		fn := m.onReport
		m.mu.RUnlock()
		if fn != nil {
			fn(nodeID, rep)
		}
		rw.WriteHeader(http.StatusNoContent)
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		_ = srv.Serve(session)
		m.mu.Lock()
		if cur, ok := m.sessions[nodeID]; ok && cur == ns {
			delete(m.sessions, nodeID)
		}
		m.mu.Unlock()
		_ = session.Close()
		if onClosed != nil {
			onClosed(nodeID)
		}
	}()

	return nil
}

func (m *Manager) doJSON(ctx context.Context, nodeID uint, method, path string, reqBody any, respObj any) error {
	m.mu.RLock()
	ns, ok := m.sessions[nodeID]
	m.mu.RUnlock()
	if !ok || ns.session.IsClosed() {
		return ErrNodeOffline
	}

	var bodyReader io.Reader
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, "http://agent"+path, bodyReader)
	if err != nil {
		return err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := ns.client.Do(req)
	if err != nil {
		return fmt.Errorf("agent rpc %s: %w", path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}

	var env struct {
		Success bool            `json:"success"`
		Msg     string          `json:"msg"`
		Obj     json.RawMessage `json:"obj"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("agent invalid response (HTTP %d): %w", resp.StatusCode, err)
	}
	if !env.Success {
		if env.Msg != "" {
			return errors.New(env.Msg)
		}
		return fmt.Errorf("agent HTTP %d", resp.StatusCode)
	}
	if respObj != nil && len(env.Obj) > 0 {
		return json.Unmarshal(env.Obj, respObj)
	}
	return nil
}

func (m *Manager) InstallCore(ctx context.Context, nodeID uint, req proto.InstallCoreRequest) (proto.CoreStatus, error) {
	var out proto.CoreStatus
	err := m.doJSON(ctx, nodeID, http.MethodPost, "/v1/cores/install", req, &out)
	return out, err
}

func (m *Manager) UninstallCore(ctx context.Context, nodeID uint, coreType proto.CoreType) (proto.CoreStatus, error) {
	var out proto.CoreStatus
	err := m.doJSON(ctx, nodeID, http.MethodPost, "/v1/cores/uninstall", proto.UninstallCoreRequest{CoreType: coreType}, &out)
	return out, err
}

func (m *Manager) CoreAction(ctx context.Context, nodeID uint, coreType proto.CoreType, action string) (proto.CoreStatus, error) {
	var out proto.CoreStatus
	err := m.doJSON(ctx, nodeID, http.MethodPost, "/v1/cores/action", proto.CoreActionRequest{CoreType: coreType, Action: action}, &out)
	return out, err
}

func (m *Manager) ApplyState(ctx context.Context, nodeID uint, spec proto.DesiredCoreSpec) (proto.ApplyStateResponse, error) {
	var out proto.ApplyStateResponse
	err := m.doJSON(ctx, nodeID, http.MethodPost, "/v1/state/apply", spec, &out)
	return out, err
}

func (m *Manager) CoreLogs(ctx context.Context, nodeID uint, coreType proto.CoreType, lines int) ([]string, error) {
	var out []string
	q := fmt.Sprintf("/v1/cores/logs?coreType=%s&lines=%d", url.QueryEscape(string(coreType)), lines)
	err := m.doJSON(ctx, nodeID, http.MethodGet, q, nil, &out)
	return out, err
}
