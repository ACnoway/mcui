package xrayconfig

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
)

const trojanServerName = "localhost"

var errTrojanTLS = errors.New("invalid node-local Trojan TLS identity")

// TrojanTLS holds the node-local PEM certificate and private key. Only the
// public certificate and its digest may be placed in the inventory.
type TrojanTLS struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

type TrojanTrust struct {
	Certificate string `json:"certificate"`
	SHA256      string `json:"sha256"`
}

func parseTrojanCertificate(text string) (*x509.Certificate, error) {
	if len(text) > 1024 {
		return nil, errTrojanTLS
	}
	text = strings.TrimSpace(strings.ReplaceAll(text, "\r\n", "\n"))
	if !strings.HasPrefix(text, "-----BEGIN CERTIFICATE-----\n") {
		return nil, errTrojanTLS
	}
	block, rest := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, errTrojanTLS
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.IsCA || cert.SignatureAlgorithm != x509.PureEd25519 ||
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) != nil ||
		cert.VerifyHostname(trojanServerName) != nil {
		return nil, errTrojanTLS
	}
	return cert, nil
}

func TrojanCertificateDigest(text string) (string, error) {
	cert, err := parseTrojanCertificate(text)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

func (trust TrojanTrust) Valid() bool {
	sum, err := TrojanCertificateDigest(trust.Certificate)
	return err == nil && sum == trust.SHA256
}

func (config *TrojanTLS) trust() (*TrojanTrust, error) {
	if config == nil || len(config.PrivateKey) > 256 {
		return nil, errTrojanTLS
	}
	key := strings.TrimSpace(strings.ReplaceAll(config.PrivateKey, "\r\n", "\n"))
	if !strings.HasPrefix(key, "-----BEGIN PRIVATE KEY-----\n") {
		return nil, errTrojanTLS
	}
	block, rest := pem.Decode([]byte(key))
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, errTrojanTLS
	}
	cert, err := parseTrojanCertificate(config.Certificate)
	if err != nil {
		return nil, err
	}
	if _, err := tls.X509KeyPair([]byte(config.Certificate), []byte(config.PrivateKey)); err != nil {
		return nil, errTrojanTLS
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: trojanServerName}); err != nil {
		return nil, errTrojanTLS
	}
	sum := sha256.Sum256(cert.Raw)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return &TrojanTrust{Certificate: string(certificate), SHA256: hex.EncodeToString(sum[:])}, nil
}

func (config TrojanTLS) streamSettings() map[string]any {
	return map[string]any{
		"network": "raw", "security": "tls",
		"tlsSettings": map[string]any{
			"minVersion": "1.3", "rejectUnknownSni": true,
			"certificates": []map[string]any{{
				"certificate":    []string{strings.TrimSpace(config.Certificate)},
				"key":            []string{strings.TrimSpace(config.PrivateKey)},
				"oneTimeLoading": true,
			}},
		},
	}
}
