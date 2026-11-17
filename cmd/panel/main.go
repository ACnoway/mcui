package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/ACnoway/mcui/internal/master"
	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/taskdispatch"
	"github.com/ACnoway/mcui/internal/tasksigner"
	"github.com/ACnoway/mcui/internal/trustedtime"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8080", "listen address; without TLS, loopback only")
	dbPath := flag.String("db", "./data/mcui.db", "SQLite database path")
	webDir := flag.String("web", "./web/dist", "built web assets directory")
	tlsCertPath := flag.String("tls-cert", "", "Master HTTPS certificate PEM")
	tlsKeyPath := flag.String("tls-key", "", "Master HTTPS private key PEM")
	nodeCACertPath := flag.String("node-ca-cert", "", "node client certificate CA PEM")
	nodeCAKeyPath := flag.String("node-ca-key", "", "node client certificate CA private key PEM")
	coreBackupDir := flag.String("core-backup-dir", "./data/core-backups", "directory for one latest stable Core backup per official project")
	taskDBPath := flag.String("task-db", "", "durable status-task database; task APIs stay disabled when omitted")
	taskKeyID := flag.String("task-key-id", "", "trusted status-task signing key identifier")
	taskPublicKeyPath := flag.String("task-public-key", "", "trusted status-task Ed25519 public key (PKIX PEM or Base64 raw key)")
	taskSignerURL := flag.String("task-signer-url", "", "loopback URL of the isolated task signer")
	taskSignerTokenPath := flag.String("task-signer-token-file", "", "shared token file for the isolated task signer")
	flag.Parse()
	usingTLS := *tlsCertPath != "" || *tlsKeyPath != ""
	if usingTLS && (*tlsCertPath == "" || *tlsKeyPath == "" || *nodeCACertPath == "" || *nodeCAKeyPath == "") {
		log.Fatal("TLS mode requires -tls-cert, -tls-key, -node-ca-cert, and -node-ca-key")
	}
	if !usingTLS && (*nodeCACertPath != "" || *nodeCAKeyPath != "") {
		log.Fatal("node CA options require TLS mode")
	}
	if !usingTLS && !loopbackListen(*addr) {
		log.Fatal("HTTP mode is development-only and must listen on loopback")
	}
	var nodeCA *security.CertificateAuthority
	var tlsConfig *tls.Config
	if usingTLS {
		certPEM, err := os.ReadFile(*nodeCACertPath)
		if err != nil {
			log.Fatalf("read node CA certificate: %v", err)
		}
		keyPEM, err := readPrivateKey(*nodeCAKeyPath)
		if err != nil {
			log.Fatalf("read node CA private key: %v", err)
		}
		nodeCA, err = security.LoadCertificateAuthority(certPEM, keyPEM)
		if err != nil {
			log.Fatalf("load node CA: %v", err)
		}
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
		clientCAs := x509.NewCertPool()
		if !clientCAs.AppendCertsFromPEM(certPEM) {
			log.Fatal("node CA certificate contains no certificates")
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: clientCAs}
	}
	_ = os.MkdirAll(filepath.Dir(*dbPath), 0700)
	s, err := store.Open(*dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()
	srv := master.NewWithNodeCA(s, os.Getenv("MCUI_BOOTSTRAP_TOKEN"), *webDir, nodeCA)
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
		tasks, err := openTaskStore(*taskDBPath)
		if err != nil {
			log.Fatalf("open task database: %v", err)
		}
		defer tasks.Close()
		trustedClock := trustedtime.NewChrony(trustedtime.DefaultNTSSource)
		if err = srv.ConfigureTaskRuntime(master.TaskRuntime{Store: tasks, Signer: signer, KeyID: *taskKeyID, PublicKey: publicKey, TrustedNow: trustedClock.Now}); err != nil {
			log.Fatalf("configure task runtime: %v", err)
		}
		if err = srv.ReconcileTaskRuntime(); err != nil {
			log.Fatalf("reconcile task/audit history: %v", err)
		}
		log.Printf("read-only status-task runtime enabled with signing key %s", *taskKeyID)
	}
	httpServer := &http.Server{Addr: *addr, Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, TLSConfig: tlsConfig}
	if usingTLS {
		log.Printf("mcui Master listening with TLS 1.3 on %s", *addr)
		log.Fatal(httpServer.ListenAndServeTLS("", ""))
	}
	log.Printf("mcui development Master listening on loopback HTTP %s; Agent enrollment is unavailable", *addr)
	log.Fatal(httpServer.ListenAndServe())
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

func openTaskStore(path string) (*taskdispatch.Store, error) {
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
