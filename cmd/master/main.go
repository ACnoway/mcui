package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ACnoway/mcui/internal/master/db"
	"github.com/ACnoway/mcui/internal/master/hub"
	"github.com/ACnoway/mcui/internal/master/server"
	"github.com/ACnoway/mcui/internal/master/tunnel"
)

func main() {
	var (
		dbPath  = flag.String("db", "./data/mcui.db", "Path to SQLite database")
		addr    = flag.String("addr", ":2053", "HTTP(S) listen address")
		binDir  = flag.String("bin-dir", "./bin", "Directory holding prebuilt mcui-agent binaries")
		tlsCert = flag.String("tls-cert", "", "Optional TLS certificate PEM path")
		tlsKey  = flag.String("tls-key", "", "Optional TLS private key PEM path")
	)
	flag.Parse()

	gdb, err := db.Open(*dbPath)
	if err != nil {
		slog.Error("failed to open database", "err", err)
		os.Exit(1)
	}

	tunnels := tunnel.NewManager()
	wsHub := hub.New()
	srv, err := server.New(gdb, tunnels, wsHub, server.Config{BinDir: *binDir})
	if err != nil {
		slog.Error("failed to initialize master server", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv.StartBackgroundLoop(ctx)

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(sctx)
	}()

	slog.Info("mcui-master listening", "addr", *addr, "tls", *tlsCert != "")
	if *tlsCert != "" && *tlsKey != "" {
		err = httpSrv.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		err = httpSrv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		slog.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}
