package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/agent"
	"github.com/ACnoway/mcui/internal/agenttasks"
	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/taskauth"
	"github.com/ACnoway/mcui/internal/taskledger"
)

func main() {
	masterURL := flag.String("master", "", "HTTPS master URL")
	name := flag.String("name", "", "node display name")
	group := flag.String("group", "default", "node group")
	inviteFile := flag.String("invite-file", "", "path to a one-time invitation file readable only by the Agent account")
	serverCA := flag.String("server-ca", "", "pre-trusted Master CA certificate PEM")
	taskKeyID := flag.String("task-key-id", "", "trusted status-task signing key identifier")
	taskPublicKeyPath := flag.String("task-public-key", "", "trusted status-task Ed25519 public key (PKIX PEM or Base64 raw key)")
	taskLedgerPath := flag.String("task-ledger", "/var/lib/mcui-agent/tasks.db", "private durable status-task ledger")
	helperSocket := flag.String("helper-socket", "/run/mcui/helper.sock", "local privileged Helper Unix socket")
	initializeTaskLedger := flag.Bool("initialize-task-ledger", false, "explicitly initialize a missing ledger for a previously registered node and exit")
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
	if *initializeTaskLedger {
		nodeID, err := client.NodeID()
		if err != nil || nodeID == "" {
			log.Fatal("task ledger initialization requires an already registered node identity")
		}
		if err = os.MkdirAll(filepath.Dir(*taskLedgerPath), 0700); err != nil {
			log.Fatalf("create Agent task ledger directory: %v", err)
		}
		ledger, initErr := taskledger.Initialize(*taskLedgerPath)
		if initErr != nil {
			log.Fatalf("initialize Agent task ledger: %v", initErr)
		}
		if err = ledger.Close(); err != nil {
			log.Fatalf("close Agent task ledger: %v", err)
		}
		return
	}
	if *taskKeyID != "" || *taskPublicKeyPath != "" {
		if *taskKeyID == "" || *taskPublicKeyPath == "" {
			log.Fatal("status-task runtime requires both -task-key-id and -task-public-key")
		}
		publicKeyData, err := os.ReadFile(*taskPublicKeyPath)
		if err != nil {
			log.Fatalf("read task public key: %v", err)
		}
		publicKey, err := security.ParseEd25519PublicKey(publicKeyData)
		if err != nil {
			log.Fatalf("parse task public key: %v", err)
		}
		nodeID, err := client.NodeID()
		if err != nil {
			log.Fatalf("read Agent identity: %v", err)
		}
		ledger, err := openTaskLedger(*taskLedgerPath, nodeID == "")
		if err != nil {
			log.Fatalf("open Agent task ledger: %v", err)
		}
		defer ledger.Close()
		executor, err := agent.NewUnixStatusExecutor(*helperSocket)
		if err != nil {
			log.Fatalf("configure Helper client: %v", err)
		}
		if err = client.SetTaskHandlerFactory(func(node string) (agent.TaskHandler, error) {
			processor, e := agenttasks.New(agenttasks.Config{
				NodeID: node,
				Keys:   map[string]taskauth.Key{*taskKeyID: {PublicKey: append(ed25519.PublicKey(nil), publicKey...), Active: true, Purpose: taskauth.PurposeTask}},
				Now:    time.Now,
				Ledger: ledger,
			})
			if e != nil {
				return nil, e
			}
			runner, e := agenttasks.NewRunner(processor, ledger, executor, time.Now)
			if e != nil {
				return nil, e
			}
			return agentTaskHandler{runner: runner}, nil
		}); err != nil {
			log.Fatalf("configure status-task runtime: %v", err)
		}
	}
	for {
		if err := client.RunOnce(); err != nil {
			log.Printf("agent heartbeat failed: %v", err)
		}
		time.Sleep(client.NextDelay())
	}
}

type agentTaskHandler struct{ runner *agenttasks.Runner }

func (h agentTaskHandler) ProcessStatusTask(ctx context.Context, raw []byte, leaseID string, lastStatusVersion int64) ([]agent.TaskAck, error) {
	acks, err := h.runner.ProcessStatusTask(ctx, raw, leaseID, lastStatusVersion)
	if err != nil {
		return nil, err
	}
	out := make([]agent.TaskAck, 0, len(acks))
	for _, ack := range acks {
		out = append(out, agent.TaskAck{StatusVersion: ack.StatusVersion, Status: ack.Status, Result: append(json.RawMessage(nil), ack.Result...)})
	}
	return out, nil
}

func openTaskLedger(path string, newIdentity bool) (*taskledger.Ledger, error) {
	if _, err := os.Stat(path); err == nil {
		return taskledger.Open(path)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if !newIdentity {
		return nil, errors.New("registered Agent task ledger is missing; reconciliation is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	return taskledger.Initialize(path)
}
