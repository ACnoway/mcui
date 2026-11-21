package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"flag"
	"net"
	"net/http"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/lifecycleauth"
)

func servePanelSigner(flags *flag.FlagSet, args []string, now func() (time.Time, error)) error {
	listen := flags.String("listen", "127.0.0.1:9232", "loopback address for the Xray signing API")
	policyPath := flags.String("policy", "", "trusted lifecycle authorization policy JSON")
	keyPath := flags.String("key", "", "dedicated Ed25519 lifecycle signing key in PKCS#8 PEM")
	ledgerPath := flags.String("ledger", "", "existing private lifecycle issuance ledger")
	tokenPath := flags.String("token-file", "", "shared API bearer token file")
	releaseKey := flags.String("release-key", "", "protected release public key file")
	state := flags.String("manifest-state", "", "initialized private manifest rollback state")
	manifest := flags.String("manifest", "", "signed release manifest file")
	signature := flags.String("manifest-signature", "", "detached release manifest signature file")
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
	source, err := artifacttrust.OpenLocalManifest(*state, *releaseKey, *manifest, *signature, now, func(key ed25519.PublicKey) bool {
		return !policy.UsesPublicKey(key)
	})
	if err != nil {
		return err
	}
	handler, err := lifecycleauth.NewPanelSignerHandler(policy, ledger, privateKey, bytes.TrimSpace(token), now, source)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	return server.ListenAndServe()
}
