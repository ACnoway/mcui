package security

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
)

func ParseEd25519PublicKey(data []byte) (ed25519.PublicKey, error) {
	if block, rest := pem.Decode(data); block != nil {
		if block.Type != "PUBLIC KEY" || strings.TrimSpace(string(rest)) != "" {
			return nil, errors.New("invalid public key PEM")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("public key is not Ed25519")
		}
		return append(ed25519.PublicKey(nil), key...), nil
	}
	encoded := strings.TrimSpace(string(data))
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("public key must be PKIX PEM or Base64 raw Ed25519")
	}
	return ed25519.PublicKey(key), nil
}
