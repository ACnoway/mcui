package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/ACnoway/mcui/internal/master/db"
)

func main() {
	dbPath := flag.String("db", "./data/mcui.db", "Path to SQLite database")
	flag.Parse()

	gdb, err := db.Open(*dbPath)
	if err != nil {
		slog.Error("failed to open master database", "err", err)
		os.Exit(1)
	}
	sqlDB, _ := gdb.DB()
	if sqlDB != nil {
		_ = sqlDB.Close()
	}
	slog.Info("mcui-master database initialized", "db", *dbPath)
}
