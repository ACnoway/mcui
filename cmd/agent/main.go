package main

import (
	"flag"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/agent"
)

func main() {
	masterURL := flag.String("master", "", "HTTPS master URL")
	name := flag.String("name", "", "node display name")
	group := flag.String("group", "default", "node group")
	inviteFile := flag.String("invite-file", "", "path to a one-time invitation file readable only by the Agent account")
	serverCA := flag.String("server-ca", "", "pre-trusted Master CA certificate PEM")
	flag.Parse()
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		log.Fatal("Agent must run as a non-root account")
	}
	if *masterURL == "" || *name == "" || *serverCA == "" {
		log.Fatal("-master, -name, and -server-ca are required")
	}
	invite := ""
	if *inviteFile != "" {
		info, err := os.Lstat(*inviteFile)
		if err != nil {
			log.Fatalf("read invitation file metadata: %v", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			log.Fatal("invitation file must be a regular file")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
			log.Fatal("invitation file permissions must exclude group and other access")
		}
		data, err := os.ReadFile(*inviteFile)
		if err != nil {
			log.Fatalf("read invitation file: %v", err)
		}
		invite = strings.TrimSpace(string(data))
	}
	client, err := agent.New(*masterURL, *name, *group, invite, *serverCA)
	if err != nil {
		log.Fatal(err)
	}
	for {
		if err := client.RunOnce(); err != nil {
			log.Printf("agent heartbeat failed: %v", err)
		}
		time.Sleep(client.NextDelay())
	}
}
