package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ACnoway/mcui/internal/master"
	"github.com/ACnoway/mcui/internal/store"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8080", "development HTTP listen address")
	dbPath := flag.String("db", "./data/mcui.db", "SQLite database path")
	webDir := flag.String("web", "./web/dist", "built web assets directory")
	flag.Parse()
	_ = os.MkdirAll(filepath.Dir(*dbPath), 0700)
	s, err := store.Open(*dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()
	srv := master.New(s, os.Getenv("MCUI_BOOTSTRAP_TOKEN"), *webDir)
	httpServer := &http.Server{Addr: *addr, Handler: srv.Handler(), ReadHeaderTimeout: 5 * 1000000000}
	log.Printf("mcui development master listening on http://%s", *addr)
	log.Fatal(httpServer.ListenAndServe())
}
