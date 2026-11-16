package main

import (
	"flag"
	"log"
	"time"

	"github.com/ACnoway/mcui/internal/agent"
)

func main() {
	masterURL := flag.String("master", "", "HTTPS master URL")
	name := flag.String("name", "", "node display name")
	group := flag.String("group", "default", "node group")
	invite := flag.String("invite", "", "one-time registration invitation")
	flag.Parse()
	if *masterURL == "" || *name == "" || *invite == "" {
		log.Fatal("-master, -name, and -invite are required")
	}
	client, err := agent.New(*masterURL, *name, *group, *invite)
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
