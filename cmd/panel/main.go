package main

import (
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

	"github.com/ACnoway/mcui/internal/master"
	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/store"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8080", "listen address; without TLS, loopback only")
	dbPath := flag.String("db", "./data/mcui.db", "SQLite database path")
	webDir := flag.String("web", "./web/dist", "built web assets directory")
	tlsCertPath := flag.String("tls-cert", "", "Master HTTPS certificate PEM")
	tlsKeyPath := flag.String("tls-key", "", "Master HTTPS private key PEM")
	nodeCACertPath := flag.String("node-ca-cert", "", "node client certificate CA PEM")
	nodeCAKeyPath := flag.String("node-ca-key", "", "node client certificate CA private key PEM")
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
	httpServer := &http.Server{Addr: *addr, Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, TLSConfig: tlsConfig}
	if usingTLS {
		log.Printf("mcui Master listening with TLS 1.3 on %s", *addr)
		log.Fatal(httpServer.ListenAndServeTLS("", ""))
	}
	log.Printf("mcui development Master listening on loopback HTTP %s; Agent enrollment is unavailable", *addr)
	log.Fatal(httpServer.ListenAndServe())
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
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("private key file permissions must exclude group and other access")
	}
	return os.ReadFile(path)
}
