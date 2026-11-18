package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ACnoway/mcui/internal/checkpoint"
	"github.com/ACnoway/mcui/internal/checkpointhttp"
	"github.com/ACnoway/mcui/internal/checkpointstore"
	"github.com/ACnoway/mcui/internal/security"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: mcui-checkpointd <init|serve> [flags]")
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = initialize(os.Args[2:])
	case "serve":
		err = serve(os.Args[2:])
	default:
		err = errors.New("expected init or serve")
	}
	if err != nil {
		log.Fatal(err)
	}
}

func initialize(args []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	db := flags.String("db", "", "new checkpoint database path")
	node := flags.String("node", "", "checkpoint identity")
	epoch := flags.Uint64("epoch", 0, "checkpoint epoch")
	digest := flags.String("sha256", "", "verified initial state digest in hex")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *db == "" || !security.ValidNodeID(*node) || *epoch == 0 {
		return errors.New("init requires -db, -node, -epoch and -sha256")
	}
	sum, err := fingerprint(*digest)
	if err != nil {
		return err
	}
	store, err := checkpointstore.Create(*db, checkpoint.Record{Node: *node, Epoch: *epoch, Digest: sum})
	if err != nil {
		return err
	}
	return store.Close()
}

func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	db := flags.String("db", "", "existing checkpoint database path")
	listen := flags.String("listen", "127.0.0.1:9232", "TLS listen address")
	cert := flags.String("tls-cert", "", "server certificate chain PEM")
	key := flags.String("tls-key", "", "server private key PEM")
	clientCA := flags.String("client-ca", "", "client certificate issuer PEM")
	clientKey := flags.String("client-key-sha256", "", "enrolled client SPKI fingerprint in hex")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *db == "" || *cert == "" || *key == "" || *clientCA == "" {
		return errors.New("serve requires -db, -tls-cert, -tls-key, -client-ca and -client-key-sha256")
	}
	pin, err := fingerprint(*clientKey)
	if err != nil {
		return err
	}
	pem, err := os.ReadFile(*clientCA)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("client CA contains no certificates")
	}
	store, err := checkpointstore.Open(*db)
	if err != nil {
		return err
	}
	defer store.Close()
	handler, err := checkpointhttp.NewHandler(store, pin)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      13 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		TLSConfig: &tls.Config{
			MinVersion:             tls.VersionTLS13,
			ClientAuth:             tls.RequireAndVerifyClientCert,
			ClientCAs:              roots,
			SessionTicketsDisabled: true,
		},
	}
	return server.ListenAndServeTLS(*cert, *key)
}

func fingerprint(value string) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != len(sum) {
		return sum, errors.New("expected a 64-digit hex SHA-256 digest")
	}
	copy(sum[:], raw)
	if sum == ([sha256.Size]byte{}) {
		return sum, errors.New("expected a nonzero SHA-256 digest")
	}
	return sum, nil
}
