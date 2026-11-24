package main

import (
	"bytes"
	"errors"
	"flag"
	"net"
	"net/http"
	"time"

	"github.com/ACnoway/mcui/internal/lifecycleauth"
)

func servePanelSigner(flags *flag.FlagSet, args []string, now func() (time.Time, error)) error {
	listen := flags.String("listen", "127.0.0.1:9232", "loopback address for the Xray signing API")
	policyPath := flags.String("policy", "", "trusted lifecycle authorization policy JSON")
	keyPath := flags.String("key", "", "dedicated Ed25519 lifecycle signing key in PKCS#8 PEM")
	ledgerPath := flags.String("ledger", "", "existing private lifecycle issuance ledger")
	tokenPath := flags.String("token-file", "", "shared API bearer token file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(*listen)
	if flags.NArg() != 0 || err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("Xray signer must listen on a loopback IP")
	}
	rawPolicy, err := readRegular(*policyPath, 256<<10, 0022)
	if err != nil {
		return err
	}
	policy, err := lifecycleauth.ParsePolicy(rawPolicy)
	if err != nil {
		return err
	}
	privateKey, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	token, err := readRegular(*tokenPath, 4096, 0037)
	if err != nil {
		return err
	}
	ledger, err := lifecycleauth.OpenLedger(*ledgerPath)
	if err != nil {
		return err
	}
	defer ledger.Close()
	handler, err := lifecycleauth.NewPanelSignerHandler(policy, ledger, privateKey, bytes.TrimSpace(token), now)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	return server.ListenAndServe()
}
