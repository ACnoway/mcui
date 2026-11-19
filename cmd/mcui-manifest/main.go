package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/security"
)

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: mcui-manifest sign|verify|init-state|suspend [options]")
	}
	command := args[0]
	flags := flag.NewFlagSet("mcui-manifest "+command, flag.ContinueOnError)
	if command == "suspend" {
		state := flags.String("state", "", "absolute path to the caller's private manifest state")
		if err := flags.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if *state == "" || flags.NArg() != 0 {
			return errors.New("suspend requires -state")
		}
		return artifacttrust.SuspendManifestState(*state)
	}
	manifest := flags.String("manifest", "manifest.json", "release manifest")
	signature := flags.String("signature", "manifest.json.sig", "raw detached Ed25519 signature")
	var keyPath, stateDir string
	switch command {
	case "sign":
		flags.StringVar(&keyPath, "private-key", "", "offline Ed25519 PKCS#8 PEM private key")
	case "verify", "init-state":
		flags.StringVar(&keyPath, "public-key", "", "trusted Ed25519 public key")
		if command == "init-state" {
			flags.StringVar(&stateDir, "state", "", "absolute path to the caller's private manifest state")
		}
	default:
		return errors.New("usage: mcui-manifest sign|verify|init-state|suspend [options]")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || keyPath == "" || (command == "init-state" && stateDir == "") {
		return errors.New("invalid release manifest options")
	}
	raw, err := readRegular(*manifest, artifacttrust.MaxManifestBytes, 0)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if command == "sign" {
		m, err := artifacttrust.ParseManifest(raw)
		if err != nil {
			return err
		}
		if !now.Before(m.ExpiresAt) {
			return errors.New("refusing to sign an expired manifest")
		}
		key, err := readPrivateKey(keyPath)
		if err != nil {
			return err
		}
		return writeSignature(*signature, ed25519.Sign(key, raw))
	}
	keyData, err := readRegular(keyPath, 4096, 0)
	if err != nil {
		return err
	}
	key, err := security.ParseEd25519PublicKey(keyData)
	if err != nil {
		return err
	}
	sig, err := readRegular(*signature, ed25519.SignatureSize, 0)
	if err != nil {
		return err
	}
	m, err := artifacttrust.VerifyManifest(raw, sig, key, now)
	if err != nil {
		return err
	}
	if command == "init-state" {
		if err := artifacttrust.InitializeManifestState(stateDir, raw, sig, key, now); err != nil {
			return err
		}
	}
	fmt.Printf("manifest_version=%d sha256=%x public_key_sha256=%x\n", m.ManifestVersion, sha256.Sum256(raw), sha256.Sum256(key))
	return nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
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
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key must be Ed25519")
	}
	return key, nil
}

func readRegular(path string, limit int64, forbiddenPerm os.FileMode) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit ||
		(runtime.GOOS != "windows" && info.Mode().Perm()&forbiddenPerm != 0) {
		return nil, fmt.Errorf("invalid input file type, size or permissions: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("input file changed")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) != opened.Size() || int64(len(data)) > limit {
		return nil, errors.New("invalid input size")
	}
	return data, nil
}

func writeSignature(path string, sig []byte) error {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	if _, err = out.Write(sig); err == nil {
		err = out.Sync()
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}
