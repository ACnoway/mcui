package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/tufrepo"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const maxMetadata = 5 << 20

var targetRoles = []string{metadata.TARGETS, tufrepo.CoreRole, tufrepo.RuntimeRole}

type document interface {
	ToBytes(bool) ([]byte, error)
	Sign(signature.Signer) (*metadata.Signature, error)
}

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: mcui-tuf prepare|sign|assemble")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	var role, input, output, key, expiry, root, previous string
	var version int64
	switch args[0] {
	case "prepare":
		flags.StringVar(&role, "role", "", "TUF role name")
		flags.StringVar(&input, "input", "", "public key manifest, review inventory, or directory of signed dependencies")
		flags.Int64Var(&version, "version", 0, "positive metadata version")
		flags.StringVar(&expiry, "expires", "", "expiration in RFC3339 UTC")
	case "sign":
		flags.StringVar(&role, "role", "", "TUF role name")
		flags.StringVar(&input, "input", "", "unsigned or partially signed metadata")
		flags.StringVar(&key, "key", "", "private Ed25519 PKCS#8 PEM for this signing operation")
	case "assemble":
		flags.StringVar(&root, "root", "", "offline bootstrap root")
		flags.StringVar(&input, "input", "", "directory of complete signed metadata")
		flags.StringVar(&previous, "previous", "", "previous published generation, required for updates")
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	flags.StringVar(&output, "output", "", "new output file or generation directory")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || output == "" {
		return errors.New("an output path and no positional arguments are required")
	}
	if args[0] == "assemble" {
		return assemble(root, input, previous, output)
	}
	var doc document
	var err error
	if args[0] == "prepare" {
		expires, parseErr := time.Parse(time.RFC3339, expiry)
		if parseErr != nil || !expires.After(time.Now()) || version < 1 {
			return errors.New("a future RFC3339 expiration and positive version are required")
		}
		doc, err = prepare(role, input, version, expires.UTC())
	} else {
		doc, err = sign(role, input, key)
	}
	if err != nil {
		return err
	}
	data, err := doc.ToBytes(true)
	if err != nil {
		return err
	}
	return writeNew(output, append(data, '\n'))
}

func prepare(role, input string, version int64, expires time.Time) (document, error) {
	switch role {
	case metadata.ROOT:
		doc := metadata.Root(expires)
		doc.Signed.Version, doc.Signed.ConsistentSnapshot = version, true
		counts := map[string]int{metadata.ROOT: 3, metadata.TARGETS: 3, metadata.SNAPSHOT: 1, metadata.TIMESTAMP: 1}
		err := eachPublicKey(input, counts, func(role string, key *metadata.Key) error {
			doc.Signed.Roles[role].Threshold = 1
			if counts[role] == 3 {
				doc.Signed.Roles[role].Threshold = 2
			}
			return doc.Signed.AddKey(key, role)
		})
		if err != nil {
			return nil, err
		}
		return doc, tufrepo.ValidateRootLayout(doc.Signed)
	case metadata.TARGETS:
		doc := metadata.Targets(expires)
		doc.Signed.Version = version
		delegationCounts := map[string]int{tufrepo.CoreRole: 3, tufrepo.RuntimeRole: 3}
		delegations := &metadata.Delegations{Keys: map[string]*metadata.Key{}, Roles: []metadata.DelegatedRole{
			{Name: tufrepo.CoreRole, Threshold: 2, Terminating: true, Paths: []string{tufrepo.CorePath}},
			{Name: tufrepo.RuntimeRole, Threshold: 2, Terminating: true, Paths: []string{tufrepo.RuntimePath}},
		}}
		err := eachPublicKey(input, delegationCounts, func(role string, key *metadata.Key) error {
			id, err := key.ID()
			if err != nil {
				return err
			}
			if _, duplicate := delegations.Keys[id]; duplicate {
				return errors.New("delegation release keys must be distinct")
			}
			delegations.Keys[id] = key
			for i := range delegations.Roles {
				if delegations.Roles[i].Name == role {
					delegations.Roles[i].KeyIDs = append(delegations.Roles[i].KeyIDs, id)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		doc.Signed.Delegations = delegations
		return doc, nil
	case tufrepo.CoreRole:
		doc := metadata.Targets(expires)
		doc.Signed.Version = version
		var reviews []artifacttrust.CoreReview
		if err := readJSON(input, &reviews); err != nil {
			return nil, err
		}
		if reviews == nil {
			return nil, errors.New("Core release inventory must be a JSON array")
		}
		for _, review := range reviews {
			target, err := artifacttrust.ReviewedCoreTarget(review)
			if err != nil {
				return nil, err
			}
			if _, exists := doc.Signed.Targets[target.Path]; exists {
				return nil, fmt.Errorf("duplicate reviewed target %s", target.Path)
			}
			doc.Signed.Targets[target.Path] = target
		}
		return doc, nil
	case tufrepo.RuntimeRole:
		doc := metadata.Targets(expires)
		doc.Signed.Version = version
		if input == "" {
			return doc, nil
		}
		var reviews []tufrepo.RuntimeReview
		if err := readJSON(input, &reviews); err != nil {
			return nil, err
		}
		if reviews == nil {
			return nil, errors.New("runtime release inventory must be a JSON array")
		}
		for _, review := range reviews {
			target, err := tufrepo.ReviewedRuntimeTarget(review)
			if err != nil {
				return nil, err
			}
			if _, exists := doc.Signed.Targets[target.Path]; exists {
				return nil, fmt.Errorf("duplicate reviewed target %s", target.Path)
			}
			doc.Signed.Targets[target.Path] = target
		}
		return doc, nil
	case metadata.SNAPSHOT:
		doc := metadata.Snapshot(expires)
		doc.Signed.Version = version
		for _, name := range targetRoles {
			file := name + ".json"
			data, err := readRegular(filepath.Join(input, file), maxMetadata, false)
			if err != nil {
				return nil, err
			}
			child, err := metadata.Targets().FromBytes(data)
			if err != nil {
				return nil, err
			}
			doc.Signed.Meta[file] = binding(child.Signed.Version, data)
		}
		return doc, nil
	case metadata.TIMESTAMP:
		doc := metadata.Timestamp(expires)
		doc.Signed.Version = version
		data, err := readRegular(filepath.Join(input, "snapshot.json"), maxMetadata, false)
		if err != nil {
			return nil, err
		}
		child, err := metadata.Snapshot().FromBytes(data)
		if err != nil {
			return nil, err
		}
		doc.Signed.Meta["snapshot.json"] = binding(child.Signed.Version, data)
		return doc, nil
	default:
		return nil, fmt.Errorf("unsupported TUF role %q", role)
	}
}

func binding(version int64, data []byte) *metadata.MetaFiles {
	digest := sha256.Sum256(data)
	return &metadata.MetaFiles{Version: version, Length: int64(len(data)), Hashes: metadata.Hashes{"sha256": digest[:]}}
}

func eachPublicKey(input string, expected map[string]int, add func(string, *metadata.Key) error) error {
	var public map[string][]string
	if err := readJSON(input, &public); err != nil {
		return err
	}
	if len(public) != len(expected) {
		return errors.New("public key manifest does not match TUF roles")
	}
	for role, count := range expected {
		if len(public[role]) != count {
			return fmt.Errorf("TUF role %s needs %d public keys", role, count)
		}
		for _, file := range public[role] {
			if !filepath.IsAbs(file) {
				file = filepath.Join(filepath.Dir(input), file)
			}
			data, err := readRegular(file, 4096, false)
			if err != nil {
				return err
			}
			key, err := security.ParseEd25519PublicKey(data)
			if err != nil {
				return err
			}
			tufKey, err := metadata.KeyFromPublicKey(key)
			if err != nil {
				return err
			}
			if err := add(role, tufKey); err != nil {
				return err
			}
		}
	}
	return nil
}

func sign(role, path, keyPath string) (document, error) {
	input, err := readRegular(path, maxMetadata, false)
	if err != nil {
		return nil, err
	}
	var doc document
	switch role {
	case metadata.ROOT:
		doc, err = metadata.Root().FromBytes(input)
	case metadata.TARGETS, tufrepo.CoreRole, tufrepo.RuntimeRole:
		doc, err = metadata.Targets().FromBytes(input)
	case metadata.SNAPSHOT:
		doc, err = metadata.Snapshot().FromBytes(input)
	case metadata.TIMESTAMP:
		doc, err = metadata.Timestamp().FromBytes(input)
	default:
		return nil, fmt.Errorf("unsupported TUF role %q", role)
	}
	if err != nil {
		return nil, err
	}
	data, err := readRegular(keyPath, 4096, true)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("release key must be Ed25519 PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("release key must be Ed25519")
	}
	signer, err := signature.LoadED25519Signer(private)
	if err != nil {
		return nil, err
	}
	if _, err := doc.Sign(signer); err != nil {
		return nil, err
	}
	return doc, nil
}

func readJSON(path string, out any) error {
	data, err := readRegular(path, maxMetadata, false)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing JSON data")
	}
	return nil
}

func readRegular(path string, limit int64, private bool) ([]byte, error) {
	if path == "" {
		return nil, errors.New("missing input path")
	}
	entry, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !entry.Mode().IsRegular() || entry.Size() <= 0 || entry.Size() > limit ||
		(private && runtime.GOOS != "windows" && entry.Mode().Perm()&0077 != 0) {
		return nil, errors.New("invalid input file type, size or permissions")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(entry, opened) {
		return nil, errors.New("input file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) != entry.Size() {
		return nil, errors.New("input file changed while reading")
	}
	return data, nil
}

func writeNew(path string, data []byte) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, f.Close())
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}
