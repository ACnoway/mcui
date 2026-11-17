package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/ACnoway/mcui/internal/tasksigner"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9231", "loopback address for the local signing API")
	keyID := flag.String("key-id", "", "task-signing key identifier")
	keyPath := flag.String("key-file", "", "Ed25519 PKCS#8 private key PEM file")
	tokenPath := flag.String("token-file", "", "shared bearer token file (at least 32 bytes)")
	flag.Parse()

	if *keyID == "" || *keyPath == "" || *tokenPath == "" || !loopback(*listen) {
		log.Fatal("-key-id, -key-file, and -token-file are required; -listen must be loopback")
	}
	keyPEM, err := readPrivateFile(*keyPath)
	if err != nil {
		log.Fatalf("read task-signing key: %v", err)
	}
	block, rest := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		log.Fatal("task-signing key must be PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("parse task-signing key: %v", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		log.Fatal("task-signing key must be Ed25519")
	}
	signer, err := tasksigner.New(*keyID, key)
	if err != nil {
		log.Fatalf("initialize task signer: %v", err)
	}
	token, err := readTokenFile(*tokenPath)
	if err != nil {
		log.Fatalf("read signer token: %v", err)
	}
	if len(token) < 32 {
		log.Fatal("signer token must contain at least 32 bytes")
	}
	handler, err := tasksigner.NewHTTPHandler(signer, token)
	if err != nil {
		log.Fatalf("initialize signer API: %v", err)
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen for signer requests: %v", err)
	}
	defer listener.Close()
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("mcui task signer listening on %s with key %s", listener.Addr(), *keyID)
	log.Fatal(server.Serve(listener))
}

func loopback(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func readPrivateFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%s permissions must exclude group and other access", path)
	}
	return os.ReadFile(path)
}

func readTokenFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	mode := info.Mode().Perm()
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || (mode != 0600 && mode != 0640) {
		return nil, fmt.Errorf("%s must be a regular 0600 or 0640 token file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 32 {
		return nil, fmt.Errorf("%s must contain at least 32 token bytes", path)
	}
	return data, nil
}
