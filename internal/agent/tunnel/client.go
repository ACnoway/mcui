package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/agent/api"
	"github.com/ACnoway/mcui/internal/agent/config"
	"github.com/ACnoway/mcui/internal/agent/core"
	"github.com/ACnoway/mcui/internal/agent/sysinfo"
	"github.com/ACnoway/mcui/pkg/proto"
	"github.com/ACnoway/mcui/pkg/wsconn"
	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

const AgentVersion = "v0.1.0"

type Client struct {
	cfgPath   string
	cfg       *config.Config
	cores     *core.Manager
	collector *sysinfo.Collector
	triggerCh chan struct{}
}

func NewClient(cfgPath string, cfg *config.Config, cores *core.Manager) *Client {
	return &Client{
		cfgPath:   cfgPath,
		cfg:       cfg,
		cores:     cores,
		collector: sysinfo.NewCollector(),
		triggerCh: make(chan struct{}, 1),
	}
}

func (c *Client) TriggerImmediateReport() {
	select {
	case c.triggerCh <- struct{}{}:
	default:
	}
}

func (c *Client) EnrollIfNeeded(ctx context.Context) error {
	if c.cfg.NodeToken != "" {
		return nil
	}
	if c.cfg.EnrollToken == "" {
		return errors.New("neither nodeToken nor enrollToken is configured")
	}

	hostname, _ := os.Hostname()
	payload := proto.EnrollRequest{
		EnrollToken: c.cfg.EnrollToken,
		Hostname:    hostname,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
	}
	body, _ := json.Marshal(payload)

	endpoint := strings.TrimRight(c.cfg.MasterURL, "/") + "/api/agent/enroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: c.cfg.InsecureTLS},
		},
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("enroll request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var env proto.APIEnvelope[proto.EnrollResponse]
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("enroll decode failed (HTTP %d): %w", resp.StatusCode, err)
	}
	if !env.Success {
		return fmt.Errorf("enroll rejected: %s", env.Msg)
	}

	c.cfg.NodeID = env.Obj.NodeID
	c.cfg.NodeName = env.Obj.NodeName
	c.cfg.NodeToken = env.Obj.NodeToken
	c.cfg.EnrollToken = ""
	if c.cfgPath != "" {
		if err := config.Save(c.cfgPath, c.cfg); err != nil {
			return fmt.Errorf("save enrolled config: %w", err)
		}
	}
	slog.Info("enrolled with master", "nodeId", c.cfg.NodeID, "nodeName", c.cfg.NodeName)
	return nil
}

func (c *Client) RunLoop(ctx context.Context) error {
	backoff := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if err := c.EnrollIfNeeded(ctx); err != nil {
			slog.Warn("enrollment pending", "err", err)
		} else {
			start := time.Now()
			err := c.connectOnce(ctx)
			if time.Since(start) > 15*time.Second {
				backoff = time.Second
			}
			if err != nil && !errors.Is(err, context.Canceled) {
				slog.Warn("tunnel disconnected", "err", err, "retryIn", backoff)
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
			if backoff < 30*time.Second {
				backoff *= 2
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
			}
		}
	}
}

func (c *Client) connectOnce(ctx context.Context) error {
	wsURL, err := toWebSocketURL(c.cfg.MasterURL, "/api/agent/tunnel")
	if err != nil {
		return err
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 12 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: c.cfg.InsecureTLS},
	}
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+c.cfg.NodeToken)

	ws, resp, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("dial %s: HTTP %d: %w", wsURL, resp.StatusCode, err)
		}
		return fmt.Errorf("dial %s: %w", wsURL, err)
	}
	defer ws.Close()

	ymCfg := yamux.DefaultConfig()
	ymCfg.EnableKeepAlive = true
	ymCfg.KeepAliveInterval = 15 * time.Second
	ymCfg.LogOutput = io.Discard

	// Agent acts as Yamux Server so Master can open RPC streams to it, AND Agent can
	// also call session.Open() to push periodic telemetry streams back to Master!
	session, err := yamux.Server(wsconn.New(ws), ymCfg)
	if err != nil {
		return err
	}
	defer session.Close()

	slog.Info("reverse tunnel established (zero local listening ports)", "master", c.cfg.MasterURL)

	apiSrv := api.NewServer(c.cores, c.TriggerImmediateReport)
	httpSrv := &http.Server{
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- httpSrv.Serve(session)
	}()

	masterClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return session.Open()
			},
		},
	}

	reportCtx, cancelReport := context.WithCancel(ctx)
	defer cancelReport()
	go c.reportLoop(reportCtx, masterClient)

	select {
	case <-ctx.Done():
		_ = session.Close()
		return ctx.Err()
	case err := <-serveErrCh:
		return err
	}
}

func (c *Client) reportLoop(ctx context.Context, masterClient *http.Client) {
	c.sendReport(ctx, masterClient)
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.triggerCh:
			c.sendReport(ctx, masterClient)
		case <-ticker.C:
			c.sendReport(ctx, masterClient)
		}
	}
}

func (c *Client) sendReport(ctx context.Context, masterClient *http.Client) {
	users, inbounds := c.cores.CollectAllTraffic(ctx)
	report := proto.AgentReport{
		AgentVersion:   AgentVersion,
		System:         c.collector.Collect(ctx),
		Cores:          c.cores.AllStatuses(),
		UserTraffic:    users,
		InboundTraffic: inbounds,
		Timestamp:      time.Now().UnixMilli(),
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://master/internal/v1/report", bytes.NewReader(raw))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := masterClient.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func toWebSocketURL(baseURL, path string) (string, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("unsupported master URL scheme %q", u.Scheme)
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String(), nil
}
