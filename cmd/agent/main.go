package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/agent"
	"github.com/ACnoway/mcui/internal/agenttasks"
	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/runtimehealth"
	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/taskauth"
	"github.com/ACnoway/mcui/internal/taskledger"
	"github.com/ACnoway/mcui/internal/trustedtime"
)

func main() {
	masterURL := flag.String("master", "", "HTTPS master URL")
	expectedNode := flag.String("node-id", "", "expected node ID for enrollment and service identity checks")
	serverCA := flag.String("server-ca", "", "optional locally trusted Master CA certificate PEM")
	enroll := flag.Bool("enroll", false, "read a one-time installation code from stdin, redeem it and exit")
	prepareEnrollment := flag.Bool("prepare-enrollment", false, "verify the local identity and task ledger before enrollment")
	allowNewLedger := flag.Bool("allow-new-ledger", false, "initialize a missing ledger for a newly created node during enrollment preparation")
	taskKeyID := flag.String("task-key-id", "", "trusted status-task signing key identifier")
	taskPublicKeyPath := flag.String("task-public-key", "", "trusted status-task Ed25519 public key (PKIX PEM or Base64 raw key)")
	installKeyID := flag.String("xray-install-key-id", os.Getenv("MCUI_XRAY_INSTALL_KEY_ID"), "trusted Xray install signing key ID")
	installKeyPath := flag.String("xray-install-public-key", os.Getenv("MCUI_XRAY_INSTALL_PUBLIC_KEY"), "trusted Xray install signing public key")
	tufRoot := flag.String("xray-tuf-root", os.Getenv("MCUI_XRAY_TUF_ROOT"), "locally provisioned Xray TUF root")
	tufOrigin := flag.String("xray-tuf-origin", os.Getenv("MCUI_XRAY_TUF_ORIGIN"), "approved Xray TUF HTTPS metadata origin")
	releaseKeyPath := flag.String("xray-release-public-key", os.Getenv("MCUI_XRAY_RELEASE_PUBLIC_KEY"), "locally provisioned artifact release public key")
	taskLedgerPath := flag.String("task-ledger", "/var/lib/mcui-agent/tasks.db", "private durable status-task ledger")
	helperSocket := flag.String("helper-socket", "/run/mcui/helper.sock", "local privileged Helper Unix socket")
	initializeTaskLedger := flag.Bool("initialize-task-ledger", false, "explicitly initialize a missing ledger for a previously registered node and exit")
	flag.Parse()
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		log.Fatal("Agent must run as a non-root account")
	}
	client, err := agent.New(*masterURL, *serverCA)
	if err != nil {
		log.Fatal(err)
	}
	if *expectedNode != "" || *prepareEnrollment || *enroll {
		if err = client.CheckEnrollment(*expectedNode); err != nil {
			log.Fatal(err)
		}
	}
	if *prepareEnrollment {
		nodeID, err := client.NodeID()
		if err != nil {
			log.Fatal(err)
		}
		ledger, err := openTaskLedger(*taskLedgerPath, *allowNewLedger && nodeID == "")
		if err != nil {
			log.Fatalf("verify Agent task ledger: %v", err)
		}
		if err = ledger.Close(); err != nil {
			log.Fatalf("close Agent task ledger: %v", err)
		}
		return
	}
	if *enroll {
		code, err := io.ReadAll(io.LimitReader(os.Stdin, 64))
		if err != nil {
			log.Fatal("read installation code")
		}
		if err = client.Enroll(*expectedNode, strings.TrimSpace(string(code))); err != nil {
			log.Fatal(err)
		}
		return
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
	nodeID, err := client.NodeID()
	if err != nil {
		log.Fatalf("read Agent identity: %v", err)
	}
	if nodeID == "" {
		log.Fatal("no node identity; run the installation command first")
	}
	managed := runtimehealth.Managed()
	trial, err := runtimehealth.Trial()
	if err != nil {
		log.Fatal(err)
	}
	if managed && (*taskKeyID == "" || *taskPublicKeyPath == "") {
		log.Fatal("managed runtime requires the task ledger and Helper configuration")
	}
	installEnabled := *installKeyID != "" || *installKeyPath != "" || *releaseKeyPath != "" || *tufRoot != "" || *tufOrigin != ""
	signedManifest := *releaseKeyPath != ""
	if installEnabled && (*installKeyID == "" || *installKeyPath == "" || *taskKeyID == "" ||
		(signedManifest && (*tufRoot != "" || *tufOrigin != "")) || (!signedManifest && (*tufRoot == "" || *tufOrigin == ""))) {
		log.Fatal("Xray installs require task trust and exactly one artifact trust configuration")
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
		openLedger := taskledger.Open
		if trial {
			openLedger = taskledger.OpenIdle
		}
		ledger, err := openLedger(*taskLedgerPath)
		if err != nil {
			log.Fatalf("open Agent task ledger: %v", err)
		}
		defer ledger.Close()
		if err = client.SetTaskSequenceProvider(func() (int64, error) { return ledger.Next() }); err != nil {
			log.Fatalf("configure Agent sequence provider: %v", err)
		}
		executor, err := agent.NewUnixStatusExecutor(*helperSocket)
		if err != nil {
			log.Fatalf("configure Helper client: %v", err)
		}
		trustedClock := trustedtime.NewChrony(trustedtime.DefaultNTSSource)
		var installKey lifecycleauth.InstallKey
		var artifacts *artifacttrust.Client
		var installer agenttasks.InstallExecutor
		if installEnabled {
			var ok bool
			installer, ok = executor.(agenttasks.InstallExecutor)
			if !ok {
				log.Fatal("Xray installer requires the Linux Helper socket")
			}
			raw, err := os.ReadFile(*installKeyPath)
			if err != nil {
				log.Fatalf("read Xray install public key: %v", err)
			}
			key, err := security.ParseEd25519PublicKey(raw)
			if err != nil {
				log.Fatalf("parse Xray install public key: %v", err)
			}
			installKey = lifecycleauth.InstallKey{ID: *installKeyID, PublicKey: key}
			if signedManifest {
				artifacts, err = artifacttrust.OpenSignedCore(*releaseKeyPath, filepath.Join(filepath.Dir(*taskLedgerPath), "xray-manifest"), trustedClock.Now, publicKey, key)
				if err == nil {
					err = artifacts.ConfigureMasterBackup(*masterURL, *serverCA)
				}
			} else {
				artifacts, err = artifacttrust.OpenProvisionedCore(*tufRoot, *tufOrigin, filepath.Join(filepath.Dir(*taskLedgerPath), "xray-tuf"), func() error {
					_, err := trustedClock.Now()
					return err
				})
			}
			if err != nil {
				log.Fatalf("open Agent Xray artifact trust: %v", err)
			}
			client.EnableXrayInstalls(signedManifest)
			if reader, ok := executor.(interface {
				ReadXrayInventory(context.Context, string) (*lifecycleauth.XrayInventory, error)
			}); signedManifest && ok {
				client.SetXrayInventory(reader.ReadXrayInventory)
			}
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
			if e = runner.SetTrustedClock(trustedClock.Now); e != nil {
				return nil, e
			}
			if installEnabled {
				if e = runner.ConfigureXrayInstall(installKey, artifacts, installer); e != nil {
					return nil, e
				}
			}
			return agentTaskHandler{runner: runner}, nil
		}); err != nil {
			log.Fatalf("configure status-task runtime: %v", err)
		}
		if managed {
			if err := client.CheckRuntimeIdentity(); err != nil {
				log.Fatal(err)
			}
			probe, ok := executor.(interface {
				ProbeRuntime(context.Context, string) error
			})
			if !ok {
				log.Fatal("managed runtime requires the Linux Helper socket")
			}
			if err := probe.ProbeRuntime(context.Background(), nodeID); err != nil {
				log.Fatal(err)
			}
			if err := runtimehealth.NotifyReady(); err != nil {
				log.Fatal(err)
			}
			if err := runtimehealth.WaitForCommit(); err != nil {
				log.Fatal(err)
			}
		}
	}
	for {
		if err := client.RunOnce(); err != nil {
			log.Printf("agent cycle failed: %v", err)
		}
		time.Sleep(client.NextDelay())
	}
}

type agentTaskHandler struct{ runner *agenttasks.Runner }

func (h agentTaskHandler) ProcessXrayInstall(ctx context.Context, raw []byte, leaseID string, skip []byte, lastStatusVersion int64, serverNow time.Time) ([]agent.TaskAck, error) {
	return convertTaskAcks(h.runner.ProcessXrayInstall(ctx, raw, leaseID, skip, lastStatusVersion, serverNow))
}

func (h agentTaskHandler) ReconcileXrayInstall(ctx context.Context, raw []byte, lastStatusVersion int64) ([]agent.TaskAck, error) {
	return convertTaskAcks(h.runner.ReconcileXrayInstall(ctx, raw, lastStatusVersion))
}

func (h agentTaskHandler) ProcessStatusTask(ctx context.Context, raw []byte, leaseID string, lastStatusVersion int64, serverNow time.Time) ([]agent.TaskAck, error) {
	acks, err := h.runner.ProcessStatusTaskAt(ctx, raw, leaseID, lastStatusVersion, serverNow)
	return convertTaskAcks(acks, err)
}

func (h agentTaskHandler) ProcessControlTask(ctx context.Context, taskRaw []byte, controlKind string, controlRaw []byte, leaseID string, lastStatusVersion int64, serverNow time.Time) ([]agent.TaskAck, error) {
	acks, err := h.runner.ProcessControlTask(ctx, taskRaw, controlKind, controlRaw, leaseID, lastStatusVersion, serverNow)
	return convertTaskAcks(acks, err)
}

func (h agentTaskHandler) ProcessSequenceSkip(ctx context.Context, controlRaw []byte, sequence int64, lastStatusVersion int64, serverNow time.Time) ([]agent.TaskAck, error) {
	acks, err := h.runner.ProcessSequenceSkip(ctx, controlRaw, sequence, lastStatusVersion, serverNow)
	return convertTaskAcks(acks, err)
}

func convertTaskAcks(acks []agenttasks.Ack, err error) ([]agent.TaskAck, error) {
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
