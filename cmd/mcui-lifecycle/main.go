package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/trustedtime"
)

func main() {
	args := os.Args[1:]
	localNow := trustedtime.NewChronyUnix(trustedtime.DefaultNTSSource).Now
	now := localNow
	if len(args) > 0 && args[0] == "serve" {
		monitor := trustedtime.NewChrony(trustedtime.DefaultNTSSource)
		now = func() (time.Time, error) {
			if observed, err := monitor.Now(); err == nil {
				return observed, nil
			}
			return localNow()
		}
	}
	err := run(args, os.Stdout, now)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer, trustedNow func() (time.Time, error)) error {
	if len(args) == 0 {
		return errors.New("usage: mcui-lifecycle <request|init-ledger|issue|serve> [flags]")
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	switch command {
	case "init-ledger":
		path := flags.String("ledger", "", "new signing ledger path")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || *path == "" {
			return errors.New("init-ledger requires -ledger")
		}
		return lifecycleauth.InitLedger(*path)
	case "request", "issue":
		return signCommand(command, flags, args[1:], output, trustedNow)
	case "serve":
		return servePanelSigner(flags, args[1:], trustedNow)
	default:
		return errors.New("expected request, init-ledger, issue or serve")
	}
}

func signCommand(command string, flags *flag.FlagSet, args []string, output io.Writer, trustedNow func() (time.Time, error)) error {
	policyPath := flags.String("policy", "", "trusted Xray authorization policy JSON")
	keyPath := flags.String("key", "", "local Ed25519 PKCS#8 private key PEM")
	inputPath := flags.String("input", "", "proposal or signed request JSON")
	var ledgerPath *string
	if command == "issue" {
		ledgerPath = flags.String("ledger", "", "existing signing ledger path")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *policyPath == "" || *keyPath == "" || *inputPath == "" || (ledgerPath != nil && *ledgerPath == "") {
		return errors.New("signing requires -policy, -key, -input, and -ledger for issue")
	}

	policyRaw, err := readRegular(*policyPath, 256<<10, 0022)
	if err != nil {
		return err
	}
	policy, err := lifecycleauth.ParsePolicy(policyRaw)
	if err != nil {
		return err
	}
	input, err := readRegular(*inputPath, 16<<10, 0)
	if err != nil {
		return err
	}
	key, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	switch command {
	case "request":
		proposal, err := lifecycleauth.ParseProposal(input)
		if err != nil {
			return err
		}
		request, err := policy.SignRequest(proposal, key, time.Now())
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(request)
	default:
		return issue(policy, input, key, *ledgerPath, output, trustedNow)
	}
}

func issue(policy *lifecycleauth.Policy, input []byte, key ed25519.PrivateKey, path string, output io.Writer, trustedNow func() (time.Time, error)) error {
	request, err := lifecycleauth.ParseRequest(input)
	if err != nil {
		return err
	}
	ledger, err := lifecycleauth.OpenLedger(path)
	if err != nil {
		return err
	}
	defer ledger.Close()
	now, err := trustedNow()
	if err != nil {
		return fmt.Errorf("trusted time required to issue Xray install task: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	task, err := policy.Issue(ctx, ledger, request, key, now)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, string(task))
	return err
}

func readKey(path string) (ed25519.PrivateKey, error) {
	data, err := readRegular(path, 4096, 0077)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("private key must be Ed25519 PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key must be Ed25519")
	}
	return private, nil
}

func readRegular(path string, limit int64, forbiddenPerm os.FileMode) ([]byte, error) {
	entry, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !entry.Mode().IsRegular() || entry.Size() <= 0 || entry.Size() > limit ||
		(runtime.GOOS != "windows" && entry.Mode().Perm()&forbiddenPerm != 0) {
		return nil, errors.New("invalid input file type, size or permissions")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(entry, opened) || (runtime.GOOS != "windows" && opened.Mode().Perm()&forbiddenPerm != 0) {
		return nil, errors.New("input file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != entry.Size() {
		return nil, errors.New("input file changed while reading")
	}
	return data, nil
}
