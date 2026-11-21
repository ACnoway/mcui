//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ACnoway/mcui/internal/runtimeupdate"
	"github.com/ACnoway/mcui/internal/trustedtime"
)

const usage = "usage: mcui-runtime init|status|sign|apply|poll|boot-recover|repair|repair-pending|revert [options]"

func main() {
	log.SetFlags(0)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	command := args[0]
	flags := flag.NewFlagSet("mcui-runtime "+command, flag.ContinueOnError)
	var node, version, releaseKey, updateKey, authorization, signature string
	var master, ca, token string
	switch command {
	case "init":
		flags.StringVar(&node, "node-id", "", "expected enrolled node ID")
		flags.StringVar(&version, "version", "", "version of the audited installed pair")
		flags.StringVar(&releaseKey, "release-key", "/etc/mcui-runtime/release.pub", "independent runtime release public key")
		flags.StringVar(&updateKey, "update-key", "/etc/mcui-runtime/update.pub", "independent node update authorization public key")
	case "sign":
		flags.StringVar(&updateKey, "private-key", "", "offline Ed25519 PKCS#8 update authorization key")
		flags.StringVar(&authorization, "input", "authorization.json", "exact authorization JSON to sign")
		flags.StringVar(&signature, "signature", "authorization.json.sig", "new detached signature file")
	case "poll":
		flags.StringVar(&master, "master", "", "locally configured Master HTTPS origin")
		flags.StringVar(&ca, "server-ca", "", "locally trusted private Master CA")
		flags.StringVar(&token, "token-file", "/etc/mcui-runtime/supervisor.token", "private root supervisor token file")
	case "status", "apply", "boot-recover", "repair", "repair-pending", "revert":
	default:
		return errors.New(usage)
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New(usage)
	}
	if command == "sign" {
		return sign(authorization, signature, updateKey)
	}
	if command == "init" && (node == "" || version == "") {
		return errors.New("init requires -node-id and -version")
	}
	manager, err := runtimeupdate.Open(command == "init")
	if err != nil {
		return err
	}
	defer manager.Close()
	switch command {
	case "init":
		release, err := runtimeupdate.ReadPublicKey(releaseKey)
		if err != nil {
			return err
		}
		update, err := runtimeupdate.ReadPublicKey(updateKey)
		if err != nil {
			return err
		}
		return manager.Bootstrap(ctx, node, version, release, update)
	case "status":
		state, err := manager.Status()
		if err != nil {
			return err
		}
		fmt.Printf("node_id=%s version=%s current_pair_sha256=%s sequence=%d manifest_version=%d last_result=%s\n",
			state.NodeID, state.Current.Version, state.Current.Digest(), state.Sequence, state.ManifestVersion, state.LastResult)
		if state.Previous != nil {
			fmt.Printf("previous_version=%s previous_pair_sha256=%s\n", state.Previous.Version, state.Previous.Digest())
		}
		if state.Pending != nil {
			fmt.Printf("pending_version=%s pending_pair_sha256=%s\n", state.Pending.Version, state.Pending.Digest())
		}
		if state.RemoteReceipt != nil {
			fmt.Printf("remote_update_id=%s remote_status=%s remote_pair_sha256=%s\n",
				state.RemoteReceipt.ID, state.RemoteReceipt.Status, state.RemoteReceipt.CurrentPair)
		}
		return nil
	case "apply":
		return manager.Apply(ctx, trustedtime.NewChronyUnix(trustedtime.DefaultNTSSource).Now)
	case "poll":
		return manager.Poll(ctx, master, ca, token, trustedtime.NewChronyUnix(trustedtime.DefaultNTSSource).Now)
	case "boot-recover":
		return manager.BootRecover()
	case "repair":
		return manager.Repair(ctx)
	case "repair-pending":
		return manager.RepairPending(ctx)
	case "revert":
		return manager.Revert(ctx)
	}
	return errors.New(usage)
}

func sign(input, signature, privateKey string) error {
	raw, err := readOffline(input, runtimeupdate.MaxAuthorizationBytes, 0)
	if err != nil {
		return err
	}
	keyData, err := readOffline(privateKey, 4096, 0077)
	if err != nil {
		return err
	}
	block, rest := pem.Decode(keyData)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("update signing key must be Ed25519 PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return errors.New("update signing key is not Ed25519")
	}
	sig, err := runtimeupdate.SignAuthorization(raw, key)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(signature, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	_, err = out.Write(sig)
	err = errors.Join(err, out.Sync(), out.Close())
	if err != nil {
		_ = os.Remove(signature)
	}
	return err
}

func readOffline(path string, limit int64, forbidden os.FileMode) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&forbidden != 0 || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("invalid offline input file type, size, or permissions")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("offline input file changed")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) != info.Size() {
		return nil, errors.New("invalid offline input size")
	}
	return data, nil
}
