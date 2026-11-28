package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ACnoway/mcui/internal/agent/config"
	"github.com/ACnoway/mcui/internal/agent/core"
	"github.com/ACnoway/mcui/internal/agent/core/xray"
	"github.com/ACnoway/mcui/internal/agent/tunnel"
)

func main() {
	var (
		cfgPath     = flag.String("config", "/etc/mcui-agent/agent.json", "Path to agent JSON configuration")
		masterURL   = flag.String("master", "", "Master base URL (overrides config)")
		enrollToken = flag.String("enroll-token", "", "One-time enrollment token")
		nodeToken   = flag.String("token", "", "Persistent node token")
		dataDir     = flag.String("data-dir", "", "Agent data directory")
		insecureTLS = flag.Bool("insecure", false, "Skip TLS verification when connecting to Master")
	)
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Error("failed to read config", "path", *cfgPath, "err", err)
			os.Exit(1)
		}
		cfg = &config.Config{DataDir: "/var/lib/mcui-agent"}
	}

	if *masterURL != "" {
		cfg.MasterURL = *masterURL
	}
	if *enrollToken != "" {
		cfg.EnrollToken = *enrollToken
	}
	if *nodeToken != "" {
		cfg.NodeToken = *nodeToken
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if *insecureTLS {
		cfg.InsecureTLS = true
	}

	if cfg.MasterURL == "" {
		slog.Error("master URL is required (--master or config.masterUrl)")
		os.Exit(1)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		slog.Error("failed to create data directory", "dir", cfg.DataDir, "err", err)
		os.Exit(1)
	}

	xrayDrv := xray.NewDriver(cfg.DataDir)
	cores := core.NewManager(xrayDrv)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Restore any previously applied LKG core configurations immediately on boot
	// so existing proxy traffic works even before Master comes online.
	cores.RestoreAll(ctx)
	defer cores.StopAll(context.Background())

	client := tunnel.NewClient(*cfgPath, cfg, cores)
	if err := client.RunLoop(ctx); err != nil {
		slog.Error("agent exited with error", "err", err)
		os.Exit(1)
	}
}
