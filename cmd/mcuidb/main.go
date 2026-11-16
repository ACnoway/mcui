package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ACnoway/mcui/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "backup":
		fs := flag.NewFlagSet("backup", flag.ExitOnError)
		db := fs.String("db", "", "source SQLite database")
		out := fs.String("out", "", "new backup file path")
		_ = fs.Parse(os.Args[2:])
		if *db == "" || *out == "" {
			fs.Usage()
			os.Exit(2)
		}
		err = store.Backup(*db, *out)
		if err == nil {
			fmt.Println("backup created and verified")
		}
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		db := fs.String("db", "", "SQLite database or backup file")
		_ = fs.Parse(os.Args[2:])
		if *db == "" {
			fs.Usage()
			os.Exit(2)
		}
		var version int
		version, err = store.VerifyDatabase(*db)
		if err == nil {
			fmt.Printf("integrity_check: ok; schema_version: %d\n", version)
		}
	case "restore":
		fs := flag.NewFlagSet("restore", flag.ExitOnError)
		backup := fs.String("backup", "", "verified backup file")
		out := fs.String("out", "", "new restore candidate path")
		_ = fs.Parse(os.Args[2:])
		if *backup == "" || *out == "" {
			fs.Usage()
			os.Exit(2)
		}
		err = store.Restore(*backup, *out)
		if err == nil {
			fmt.Println("restore candidate created and verified; live database was not replaced")
		}
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: mcuidb {backup|verify|restore} [options]")
}
