package main

import (
	"bytes"
	"context"
	"crypto/tls"
	json "encoding/json/v2"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ACnoway/mcui/internal/checkpoint"
	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/master"
	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/taskdispatch"
	"github.com/ACnoway/mcui/internal/tasksigner"
	"github.com/ACnoway/mcui/internal/trustedtime"
)

func main() {
	addr := flag.String("listen", envOr("MCUI_LISTEN", "127.0.0.1:8080"), "listen address; without TLS, loopback by default")
	dbPath := flag.String("db", "./data/mcui.db", "SQLite database path")
	webDir := flag.String("web", "./web/dist", "built web assets directory")
	tlsCertPath := flag.String("tls-cert", os.Getenv("MCUI_TLS_CERT"), "Master HTTPS certificate PEM")
	tlsKeyPath := flag.String("tls-key", os.Getenv("MCUI_TLS_KEY"), "Master HTTPS private key PEM")
	publicURL := flag.String("public-url", os.Getenv("MCUI_PUBLIC_URL"), "public HTTPS Master origin for the proxy and Agent install commands")
	proxyPeer := flag.String("https-proxy-peer", os.Getenv("MCUI_HTTPS_PROXY_PEER"), "exact IP of the trusted HTTPS reverse proxy")
	containerHTTP := flag.Bool("container-http", false, "allow HTTP on the isolated Compose network")
	managed := flag.Bool("managed", false, "initialize signing and use the packaged GitHub release for this single-admin deployment")
	releaseDir := flag.String("release-dir", envOr("MCUI_RELEASE_DIR", "/opt/mcui/release"), "directory containing packaged GitHub release metadata")
	singleAdmin := flag.Bool("single-admin", false, "enable single-admin deployment and initialize a fresh database")
	initAdminOnly := flag.Bool("init-admin-only", false, "prepare a single administrator locally and exit")
	recoverAdmin := flag.Bool("recover-initial-admin", false, "rotate the initial password of a pending administrator locally and exit")
	installerURL := flag.String("agent-installer-url", os.Getenv("MCUI_AGENT_INSTALLER_URL"), "approved Agent installer HTTPS URL")
	installerDigest := flag.String("agent-installer-sha256", os.Getenv("MCUI_AGENT_INSTALLER_SHA256"), "approved Agent installer SHA-256 digest")
	installerKeyID := flag.String("agent-installer-task-key-id", os.Getenv("MCUI_AGENT_INSTALLER_TASK_KEY_ID"), "status-task signing key ID to provision with the approved Agent installer")
	installerKeyPath := flag.String("agent-installer-task-public-key", os.Getenv("MCUI_AGENT_INSTALLER_TASK_PUBLIC_KEY"), "status-task public key to provision with the approved Agent installer")
	installerCAPath := flag.String("agent-installer-master-ca", os.Getenv("MCUI_AGENT_INSTALLER_MASTER_CA"), "optional private Master CA bundle to provision with the approved Agent installer")
	coreBackupDir := flag.String("core-backup-dir", "./data/core-backups", "directory for one latest stable Core backup per official project")
	taskDBPath := flag.String("task-db", "", "durable status-task database; task APIs stay disabled when omitted")
	taskKeyID := flag.String("task-key-id", "", "trusted status-task signing key identifier")
	taskPublicKeyPath := flag.String("task-public-key", "", "trusted status-task Ed25519 public key (PKIX PEM or Base64 raw key)")
	taskSignerURL := flag.String("task-signer-url", "", "loopback URL of the isolated task signer")
	taskSignerTokenPath := flag.String("task-signer-token-file", "", "shared token file for the isolated task signer")
	xrayInstallPolicyPath := flag.String("xray-install-policy", os.Getenv("MCUI_XRAY_INSTALL_POLICY"), "independently provisioned Xray install authorization policy JSON")
	xrayPanelURL := flag.String("xray-panel-signer-url", os.Getenv("MCUI_XRAY_PANEL_SIGNER_URL"), "loopback URL of the dedicated Xray panel signer")
	xrayPanelToken := flag.String("xray-panel-signer-token-file", os.Getenv("MCUI_XRAY_PANEL_SIGNER_TOKEN_FILE"), "shared bearer token file for the dedicated Xray panel signer")
	runtimeUpdatePolicyPath := flag.String("runtime-update-policy", os.Getenv("MCUI_RUNTIME_UPDATE_POLICY"), "independently provisioned Agent/Helper remote update policy JSON")
	checkpointConfig := registerTaskCheckpointFlags()
	flag.Parse()
	usingTLS := *tlsCertPath != "" || *tlsKeyPath != ""
	usingProxy := *proxyPeer != ""
	if *initAdminOnly && *recoverAdmin {
		log.Fatal("choose either -init-admin-only or -recover-initial-admin")
	}
	if (*initAdminOnly || *recoverAdmin) && checkpointConfig.enabled() {
		log.Fatal("offline administrator setup cannot open a checkpoint-coordinated database")
	}
	if usingTLS && (*tlsCertPath == "" || *tlsKeyPath == "") {
		log.Fatal("TLS mode requires -tls-cert and -tls-key")
	}
	if usingTLS && usingProxy {
		log.Fatal("choose either direct TLS or the trusted HTTPS proxy")
	}
	if !usingTLS && !usingProxy && !*containerHTTP && !loopbackListen(*addr) {
		log.Fatal("plain HTTP must listen on loopback outside the isolated Compose network")
	}
	secureTransport := usingTLS || usingProxy
	if *managed && (!*singleAdmin || *taskDBPath != "" || *taskKeyID != "" || *taskPublicKeyPath != "" ||
		*taskSignerURL != "" || *taskSignerTokenPath != "" || checkpointConfig.enabled() ||
		*installerURL != "" || *installerDigest != "" || *installerKeyID != "" || *installerKeyPath != "" ||
		*xrayInstallPolicyPath != "" || *xrayPanelURL != "" || *xrayPanelToken != "" || *runtimeUpdatePolicyPath != "") {
		log.Fatal("managed deployment requires single-admin mode and its own signing and installer configuration")
	}
	if (*xrayInstallPolicyPath != "" || *runtimeUpdatePolicyPath != "") && (!secureTransport || *taskDBPath == "") {
		log.Fatal("remote Xray and runtime updates require Master HTTPS and -task-db")
	}
	var tlsConfig *tls.Config
	if usingTLS {
		serverCertPEM, err := os.ReadFile(*tlsCertPath)
		if err != nil {
			log.Fatalf("read Master TLS certificate: %v", err)
		}
		serverKeyPEM, err := readPrivateKey(*tlsKeyPath)
		if err != nil {
			log.Fatalf("read Master TLS private key: %v", err)
		}
		serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
		if err != nil {
			log.Fatalf("load Master TLS certificate: %v", err)
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}}
	}
	var machine *checkpoint.Machine
	var s *store.Store
	var err error
	if checkpointConfig.enabled() {
		if *taskDBPath == "" || !secureTransport {
			log.Fatal("task checkpoint requires -task-db and Master HTTPS")
		}
		if err = checkpointConfig.validate(); err != nil {
			log.Fatal(err)
		}
		var closeCheckpoint func()
		machine, closeCheckpoint, err = checkpointConfig.open()
		if err != nil {
			log.Fatalf("open task checkpoint: %v", err)
		}
		defer closeCheckpoint()
		s, err = store.OpenExisting(*dbPath)
	} else if *recoverAdmin {
		s, err = store.OpenExisting(*dbPath)
	} else {
		if err = os.MkdirAll(filepath.Dir(*dbPath), 0700); err != nil {
			log.Fatalf("create panel database directory: %v", err)
		}
		s, err = store.Open(*dbPath)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()
	if *initAdminOnly || *recoverAdmin {
		prepareAdmin(s, *recoverAdmin)
		return
	}
	var xrayInstallPolicy *lifecycleauth.Policy
	if *xrayInstallPolicyPath != "" {
		xrayInstallPolicy, err = readXrayInstallPolicy(*xrayInstallPolicyPath)
		if err != nil {
			log.Fatalf("read Xray install authorization policy: %v", err)
		}
	}
	srv := master.New(s, os.Getenv("MCUI_BOOTSTRAP_TOKEN"), *webDir)
	if *singleAdmin {
		srv.EnableSingleAdmin()
	}
	if usingProxy {
		if err := srv.ConfigureHTTPSProxy(*publicURL, *proxyPeer); err != nil {
			log.Fatalf("configure HTTPS proxy: %v", err)
		}
	}
	if *installerURL != "" || *installerDigest != "" {
		if !secureTransport {
			log.Fatal("Agent install commands require Master HTTPS")
		}
		if err := srv.ConfigureAgentInstaller(*publicURL, *installerURL, *installerDigest); err != nil {
			log.Fatalf("configure Agent installer: %v", err)
		}
	}
	if !*managed && (*installerKeyID != "" || *installerKeyPath != "" || *installerCAPath != "") {
		if err := configureAgentInstallerTrust(srv, *installerKeyID, *installerKeyPath, *installerCAPath); err != nil {
			log.Fatalf("configure Agent installer trust: %v", err)
		}
	}
	if *managed {
		closeRuntime, err := configureManagedRuntime(srv, filepath.Dir(*dbPath), *releaseDir, *publicURL, *installerCAPath, secureTransport)
		if err != nil {
			log.Fatalf("configure managed deployment: %v", err)
		}
		defer closeRuntime()
	}
	catalog := corecatalog.NewClient()
	srv.ConfigureCoreCatalog(catalog)
	backupStore, backupErr := corecatalog.NewBackupStore(*coreBackupDir, catalog)
	if backupErr != nil {
		log.Printf("Core release catalog enabled; backup cache unavailable: %v", backupErr)
	} else {
		srv.ConfigureCoreBackups(backupStore)
		go syncCoreBackups(backupStore)
	}
	if *taskDBPath != "" || *taskKeyID != "" || *taskPublicKeyPath != "" || *taskSignerURL != "" || *taskSignerTokenPath != "" {
		if *taskDBPath == "" || *taskKeyID == "" || *taskPublicKeyPath == "" || *taskSignerURL == "" || *taskSignerTokenPath == "" {
			log.Fatal("task runtime requires -task-db, -task-key-id, -task-public-key, -task-signer-url, and -task-signer-token-file")
		}
		publicKeyData, err := os.ReadFile(*taskPublicKeyPath)
		if err != nil {
			log.Fatalf("read task public key: %v", err)
		}
		publicKey, err := security.ParseEd25519PublicKey(publicKeyData)
		if err != nil {
			log.Fatalf("parse task public key: %v", err)
		}
		token, err := readSharedToken(*taskSignerTokenPath)
		if err != nil {
			log.Fatalf("read task signer token: %v", err)
		}
		signer, err := tasksigner.NewHTTPClient(*taskSignerURL, token)
		if err != nil {
			log.Fatalf("configure task signer: %v", err)
		}
		if err = os.MkdirAll(filepath.Dir(*taskDBPath), 0700); err != nil {
			log.Fatalf("create task database directory: %v", err)
		}
		tasks, err := openTaskStore(*taskDBPath, machine == nil)
		if err != nil {
			log.Fatalf("open task database: %v", err)
		}
		defer tasks.Close()
		trustedClock := trustedtime.NewChrony(trustedtime.DefaultNTSSource)
		if err = srv.ConfigureTaskRuntime(master.TaskRuntime{Store: tasks, Signer: signer, KeyID: *taskKeyID, PublicKey: publicKey, TrustedNow: trustedClock.Now, Checkpoint: machine, XrayInstallPolicy: xrayInstallPolicy}); err != nil {
			log.Fatalf("configure task runtime: %v", err)
		}
		if err = srv.ReconcileTaskRuntime(); err != nil {
			log.Fatalf("reconcile task/audit history: %v", err)
		}
		log.Printf("read-only status-task runtime enabled with signing key %s", *taskKeyID)
	}
	if *xrayPanelURL != "" || *xrayPanelToken != "" {
		token, err := readSharedToken(*xrayPanelToken)
		if err != nil {
			log.Fatalf("read Xray signer token: %v", err)
		}
		signer, err := lifecycleauth.NewPanelSignerClient(*xrayPanelURL, bytes.TrimSpace(token))
		if err == nil {
			err = srv.ConfigurePanelXray(signer)
		}
		if err != nil {
			log.Fatalf("configure panel Xray signer: %v", err)
		}
	}
	if *runtimeUpdatePolicyPath != "" {
		policy, err := readRuntimeUpdatePolicy(*runtimeUpdatePolicyPath)
		if err == nil {
			err = srv.ConfigureRuntimeUpdates(policy)
		}
		if err != nil {
			log.Fatalf("configure remote runtime update: %v", err)
		}
	}
	httpServer := &http.Server{Addr: *addr, Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, TLSConfig: tlsConfig}
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	if *singleAdmin {
		prepareAdmin(s, false)
	}
	if err := notifyReady(); err != nil {
		log.Fatalf("notify systemd readiness: %v", err)
	}
	if usingTLS {
		log.Printf("mcui Master listening with TLS 1.3 on %s", *addr)
		log.Fatal(httpServer.ServeTLS(listener, "", ""))
	}
	if usingProxy {
		log.Printf("mcui Master listening for the configured HTTPS proxy on %s", *addr)
	} else {
		log.Printf("mcui Master listening on local HTTP %s; Agent enrollment is unavailable", *addr)
	}
	log.Fatal(httpServer.Serve(listener))
}

func configureAgentInstallerTrust(srv *master.Server, keyID, publicKeyPath, caPath string) error {
	if keyID == "" || publicKeyPath == "" {
		return fmt.Errorf("Agent installer trust requires both -agent-installer-task-key-id and -agent-installer-task-public-key")
	}
	raw, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("read installer task public key: %w", err)
	}
	key, err := security.ParseEd25519PublicKey(raw)
	if err != nil {
		return fmt.Errorf("parse installer task public key: %w", err)
	}
	var ca []byte
	if caPath != "" {
		ca, err = security.ReadEnrollmentCA(caPath)
		if err != nil {
			return fmt.Errorf("read installer Master CA: %w", err)
		}
	}
	return srv.ConfigureAgentInstallerTrust(keyID, key, ca)
}

func notifyReady() error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte("READY=1"))
	return err
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func prepareAdmin(s *store.Store, recoverPending bool) {
	username, password, err := master.PrepareSingleAdmin(s, recoverPending)
	if err != nil {
		log.Fatalf("prepare administrator: %v", err)
	}
	if username != "" {
		fmt.Printf("MCUI initial administrator\nUsername: %s\nPassword: %s\n", username, password)
	}
}

func readRuntimeUpdatePolicy(path string) (master.RuntimeUpdatePolicy, error) {
	var policy master.RuntimeUpdatePolicy
	const limit = 1 << 20
	info, err := os.Lstat(path)
	if err != nil {
		return policy, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit || runtime.GOOS != "windows" && info.Mode().Perm()&0022 != 0 {
		return policy, fmt.Errorf("runtime update policy must be a bounded regular file without group or other write access")
	}
	f, err := os.Open(path)
	if err != nil {
		return policy, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return policy, fmt.Errorf("runtime update policy changed during open")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(raw) > limit {
		return policy, fmt.Errorf("read runtime update policy")
	}
	err = json.Unmarshal(raw, &policy, json.RejectUnknownMembers(true))
	return policy, err
}

func readXrayInstallPolicy(path string) (*lifecycleauth.Policy, error) {
	const maxPolicyBytes = 256 << 10
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0022 != 0) {
		return nil, fmt.Errorf("authorization policy must be a regular file without group or other write access")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, fmt.Errorf("authorization policy changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxPolicyBytes+1))
	if err != nil {
		return nil, err
	}
	return lifecycleauth.ParsePolicy(raw)
}

func syncCoreBackups(backups *corecatalog.BackupStore) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	manifest, err := backups.Sync(ctx)
	for _, core := range manifest.Cores {
		log.Printf("Core backup available: %s %s (%d architectures)", core.ID, core.Version, len(core.Assets))
	}
	if err != nil {
		log.Printf("Core backup refresh incomplete; previous verified per-Core versions were preserved: %v", err)
	}
}

func openTaskStore(path string, initializeMissing bool) (*taskdispatch.Store, error) {
	if !initializeMissing {
		return taskdispatch.Open(path)
	}
	if _, err := os.Stat(path); err == nil {
		return taskdispatch.Open(path)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return taskdispatch.Init(path)
}

func loopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func readPrivateKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("private key path must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("private key file permissions must exclude group and other access")
	}
	return os.ReadFile(path)
}

func readSharedToken(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	mode := info.Mode().Perm()
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || (mode != 0600 && mode != 0640) {
		return nil, fmt.Errorf("task signer token must be a regular 0600 or 0640 file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 32 {
		return nil, fmt.Errorf("task signer token must contain at least 32 bytes")
	}
	return data, nil
}
