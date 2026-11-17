// Package tasksigner provides only a narrow V2 status-task signing primitive.
// It is not an independent approval mechanism or an authorized standalone
// signer. Callers must provide authorization, trusted key selection and secure
// custody, time and node checks, sequencing, persistence, and replay controls.
// This package exposes no runtime, network, socket, or API endpoint.
package tasksigner

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/ACnoway/mcui/internal/protocol"
)

// PlaceholderSignature is the canonical Base64 encoding of 64 zero bytes.
// A complete, unsigned input task must explicitly use this exact value.
const PlaceholderSignature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

// Keep in sync with the protocol's identifier grammar.
var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// Signer binds a configured key identifier to an Ed25519 private key.
type Signer struct {
	keyID string
	key   ed25519.PrivateKey
}

// New creates a signer with a private copy of the key. The caller must bind the
// identifier to the correct trusted key in its own configuration.
func New(keyID string, key ed25519.PrivateKey) (*Signer, error) {
	if !keyIDPattern.MatchString(keyID) {
		return nil, errors.New("invalid signing key ID")
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key size")
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if !bytes.Equal(key, derived) {
		return nil, errors.New("inconsistent Ed25519 private key")
	}
	return &Signer{keyID: keyID, key: derived}, nil
}

// SignStatus validates a complete V2 status task with PlaceholderSignature,
// signs the protocol's domain-separated canonical bytes, and returns the exact
// signed JSON to persist or transmit. It does not mutate the input. A correct
// signature does not establish approval, authorization, freshness or trust.
func (s *Signer) SignStatus(raw []byte) ([]byte, error) {
	if s == nil || len(s.key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid signer")
	}
	canonical, err := protocol.CanonicalV2TaskBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid task: %w", err)
	}
	var fields struct {
		KeyID     string `json:"signing_key_id"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("decode task: %w", err)
	}
	if fields.KeyID != s.keyID {
		return nil, errors.New("signing key ID mismatch")
	}
	if fields.Signature != PlaceholderSignature {
		return nil, errors.New("signature placeholder required")
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, canonical))
	const domain = "MCUI-TASK-V2\n"
	if !bytes.HasPrefix(canonical, []byte(domain)) || len(canonical) <= len(domain) || canonical[len(canonical)-1] != '}' {
		return nil, errors.New("unexpected canonical task format")
	}
	body := canonical[len(domain):]
	signed := append([]byte(nil), body[:len(body)-1]...)
	signed = append(signed, []byte(`,"signature":"`)...)
	signed = append(signed, sig...)
	signed = append(signed, '"', '}')
	recanonical, err := protocol.CanonicalV2TaskBytes(signed)
	if err != nil || !bytes.Equal(canonical, recanonical) {
		return nil, errors.New("signed task canonicalization mismatch")
	}
	if err := protocol.VerifyV2Task(signed, s.key.Public().(ed25519.PublicKey)); err != nil {
		return nil, fmt.Errorf("signed task verification: %w", err)
	}
	return signed, nil
}
