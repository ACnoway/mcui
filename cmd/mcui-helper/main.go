//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/helper"
	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/runtimehealth"
	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/trustedtime"
	"github.com/ACnoway/mcui/internal/xrayruntime"
)

const maxSystemctlOutput = 2048

var statusToken = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

func main() {
	nodeID := flag.String("node-id", "", "provisioned MCUI node ID")
	masterURL := flag.String("master", "", "HTTPS Master origin")
	masterCAPath := flag.String("master-ca", "", "optional locally trusted Master CA certificate PEM")
	taskKeyID := flag.String("task-key-id", "", "trusted status-task signing key identifier")
	taskPublicKeyPath := flag.String("task-public-key", "", "trusted status-task Ed25519 public key")
	installKeyID := flag.String("xray-install-key-id", os.Getenv("MCUI_XRAY_INSTALL_KEY_ID"), "trusted Xray install signing key ID")
	installKeyPath := flag.String("xray-install-public-key", os.Getenv("MCUI_XRAY_INSTALL_PUBLIC_KEY"), "trusted Xray install signing public key")
	tufRoot := flag.String("xray-tuf-root", os.Getenv("MCUI_XRAY_TUF_ROOT"), "locally provisioned Xray TUF root")
	tufOrigin := flag.String("xray-tuf-origin", os.Getenv("MCUI_XRAY_TUF_ORIGIN"), "approved Xray TUF HTTPS metadata origin")
	releaseKeyPath := flag.String("xray-release-public-key", os.Getenv("MCUI_XRAY_RELEASE_PUBLIC_KEY"), "locally provisioned artifact release public key")
	stateDir := flag.String("state-dir", "/var/lib/mcui-helper", "root-owned private helper state directory")
	socketPath := flag.String("socket", "/run/mcui/helper.sock", "Agent-facing Unix socket")
	agentUser := flag.String("agent-user", "mcui-agent", "unprivileged Agent account")
	socketGroup := flag.String("socket-group", "mcui-agent", "group permitted to connect to the socket")
	initialize := flag.Bool("initialize-ledger", false, "explicitly initialize a new helper ledger and exit")
	check := flag.Bool("check-ledger", false, "verify an existing Helper ledger and exit")
	enrollmentKey := flag.String("expected-enrollment-key", "", "verify the existing or staged task public key against this key file and exit")
	enrollmentCA := flag.String("expected-enrollment-ca", "", "also verify the existing or staged Master CA against this CA bundle")
	flag.Parse()
	if os.Geteuid() != 0 {
		log.Fatal("mcui-helper must run as root")
	}
	if *enrollmentKey != "" || *enrollmentCA != "" {
		if err := checkEnrollmentTrust(*taskPublicKeyPath, *enrollmentKey, *masterCAPath, *enrollmentCA); err != nil {
			log.Fatalf("check enrollment trust: %v", err)
		}
		return
	}
	if *nodeID == "" || *masterURL == "" || *taskKeyID == "" || *taskPublicKeyPath == "" {
		log.Fatal("-node-id, -master, -task-key-id, and -task-public-key are required")
	}
	account, err := user.Lookup(*agentUser)
	if err != nil {
		log.Fatalf("find Agent account: %v", err)
	}
	allowedUID, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || allowedUID == 0 {
		log.Fatal("Agent account must have a non-root numeric UID")
	}
	group, err := user.LookupGroup(*socketGroup)
	if err != nil {
		log.Fatalf("find socket group: %v", err)
	}
	groupID, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || groupID == 0 {
		log.Fatal("socket group must have a non-root numeric GID")
	}
	keyData, err := os.ReadFile(*taskPublicKeyPath)
	if err != nil {
		log.Fatalf("read task signing public key: %v", err)
	}
	publicKey, err := security.ParseEd25519PublicKey(keyData)
	if err != nil {
		log.Fatalf("parse task signing public key: %v", err)
	}
	var caPEM []byte
	if *masterCAPath != "" {
		caPEM, err = os.ReadFile(*masterCAPath)
		if err != nil {
			log.Fatalf("read Master CA: %v", err)
		}
	}
	checkpoint, err := helper.NewHTTPCheckpoint(*masterURL, caPEM)
	if err != nil {
		log.Fatalf("configure Master checkpoint: %v", err)
	}
	trustedClock := trustedtime.NewChrony(trustedtime.DefaultNTSSource)
	installEnabled := *installKeyID != "" || *installKeyPath != "" || *releaseKeyPath != "" || *tufRoot != "" || *tufOrigin != ""
	signedManifest := *releaseKeyPath != ""
	config := helper.Config{
		RuntimeManaged:     runtimehealth.Managed(),
		NodeID:             *nodeID,
		AllowedUID:         uint32(allowedUID),
		Keys:               map[string]helper.TrustedKey{*taskKeyID: {PublicKey: publicKey, Purpose: "task"}},
		Now:                time.Now,
		TrustedTimeHealthy: trustedClock.Healthy,
		Checkpoint:         checkpoint,
		ReadStatusAt: func(unit string, observedAt time.Time) (string, error) {
			if installEnabled && unit == "xray.service" {
				unit = "mcui-xray.service"
			}
			return readFixedStatus(unit, observedAt)
		},
	}
	if installEnabled {
		if *installKeyID == "" || *installKeyPath == "" ||
			(signedManifest && (*tufRoot != "" || *tufOrigin != "")) || (!signedManifest && (*tufRoot == "" || *tufOrigin == "")) {
			log.Fatal("Xray installs require task trust and exactly one artifact trust configuration")
		}
		raw, err := os.ReadFile(*installKeyPath)
		if err != nil {
			log.Fatalf("read Xray install public key: %v", err)
		}
		key, err := security.ParseEd25519PublicKey(raw)
		if err != nil {
			log.Fatalf("parse Xray install public key: %v", err)
		}
		clock := trustedtime.NewChronyUnix(trustedtime.DefaultNTSSource)
		config.TrustedTimeHealthy = clock.Healthy
		var artifacts *artifacttrust.Client
		if signedManifest {
			artifacts, err = artifacttrust.OpenSignedCore(*releaseKeyPath, filepath.Join(xrayruntime.StateDir, "control", "xray-manifest"), clock.Now, publicKey, key)
			if err == nil {
				err = artifacts.ConfigureMasterBackup(*masterURL, *masterCAPath)
			}
		} else {
			artifacts, err = artifacttrust.OpenProvisionedCore(*tufRoot, *tufOrigin, filepath.Join(*stateDir, "xray-tuf"), func() error {
				_, err := clock.Now()
				return err
			})
		}
		if err != nil {
			log.Fatalf("open Helper Xray artifact trust: %v", err)
		}
		config.XrayInstall = &helper.XrayInstallConfig{
			Key: lifecycleauth.InstallKey{ID: *installKeyID, PublicKey: key},
			Apply: func(ctx context.Context, task lifecycleauth.InstallTask, hash string, authorize func(context.Context) error) (string, error) {
				control := lifecycleauth.IsControlOperation(task.Operation)
				if !control && task.SignedManifest != signedManifest {
					return "FAILED", nil
				}
				runtime, err := xrayruntime.Open(false)
				if err != nil {
					return "", err
				}
				defer runtime.Close()
				release := xrayruntime.Release{Version: task.Version, SHA256: task.SHA256}
				action := xrayruntime.Action(strings.TrimPrefix(task.Operation, "core."))
				if control {
					return runtime.ControlAuthorized(ctx, action, release, hash, authorize)
				}
				expected := xrayruntime.Release{Version: task.CurrentVersion, SHA256: task.CurrentSHA256}
				return runtime.ApplyAuthorized(ctx, action, expected, release, artifacts, task.ManifestVersion, hash, authorize)
			},
			Reconcile: func(ctx context.Context, task lifecycleauth.InstallTask, hash string) (string, error) {
				runtime, err := xrayruntime.Open(false)
				if err != nil {
					return "", err
				}
				defer runtime.Close()
				release := xrayruntime.Release{Version: task.Version, SHA256: task.SHA256}
				return runtime.ReconcileTask(ctx, xrayruntime.Action(strings.TrimPrefix(task.Operation, "core.")), release, hash)
			},
		}
	}
	if *initialize {
		if err = ensureStateDirectory(*stateDir); err != nil {
			log.Fatalf("prepare helper state directory: %v", err)
		}
		instance, initErr := helper.Initialize(*stateDir, config)
		if initErr != nil {
			log.Fatalf("initialize helper ledger: %v", initErr)
		}
		if err = instance.Close(); err != nil {
			log.Fatalf("close helper ledger: %v", err)
		}
		return
	}
	instance, err := helper.Open(*stateDir, config)
	if err != nil {
		log.Fatalf("open helper ledger: %v", err)
	}
	defer instance.Close()
	if *check {
		return
	}
	if trial, err := runtimehealth.Trial(); err != nil {
		log.Fatal(err)
	} else if trial {
		if err := instance.CheckRuntimeIdle(); err != nil {
			log.Fatalf("open trial Helper ledger: %v", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("mcui Helper listening on %s for node %s", *socketPath, *nodeID)
	if err = instance.RunSocket(ctx, *socketPath, uint32(groupID)); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func ensureStateDirectory(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("state directory must be an absolute path")
	}
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return errors.New("state directory must be a real 0700 directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("state directory must be owned by root")
	}
	return nil
}

func readFixedStatus(unit string, observedAt time.Time) (string, error) {
	allowed := map[string]string{
		"xray.service":      "xray",
		"mcui-xray.service": "xray",
		"sing-box.service":  "sing-box",
		"mita.service":      "mita",
	}
	core, ok := allowed[unit]
	if !ok || observedAt.IsZero() {
		return "", errors.New("invalid fixed status target")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "--no-pager", "--property=LoadState", "--property=ActiveState", "--property=SubState", unit)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0"}
	var output boundedBuffer
	command.Stdout = &output
	var stderr boundedBuffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("read fixed systemd status: %w", err)
	}
	values := make(map[string]string, 3)
	for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
		name, value, found := strings.Cut(line, "=")
		if !found || (name != "LoadState" && name != "ActiveState" && name != "SubState") || !statusToken.MatchString(value) {
			return "", errors.New("invalid systemd status output")
		}
		if _, duplicate := values[name]; duplicate {
			return "", errors.New("duplicate systemd status field")
		}
		values[name] = value
	}
	if len(values) != 3 {
		return "", errors.New("incomplete systemd status output")
	}
	result, err := json.Marshal(struct {
		Core        string `json:"core"`
		LoadState   string `json:"load_state"`
		ActiveState string `json:"active_state"`
		SubState    string `json:"sub_state"`
		ObservedAt  string `json:"observed_at"`
	}{core, values["LoadState"], values["ActiveState"], values["SubState"], observedAt.UTC().Format(time.RFC3339)})
	return string(result), err
}

type boundedBuffer struct{ bytes []byte }

func (b *boundedBuffer) Write(data []byte) (int, error) {
	if len(b.bytes)+len(data) > maxSystemctlOutput {
		return 0, errors.New("systemctl output exceeds limit")
	}
	b.bytes = append(b.bytes, data...)
	return len(data), nil
}

func (b *boundedBuffer) String() string { return string(b.bytes) }
