package xrayconfig

import (
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// PanelTLS shares one server identity across the panel's Trojan inbounds on
// a node. The signed draft carries the public trust and a sealed private seed.
type PanelTLS struct {
	Trust TrojanTrust `json:"trust"`
	Key   string      `json:"key"`
}

func (p PanelTLS) valid() bool {
	return p.Trust.Valid() && validPanelBox(p.Key, ed25519.SeedSize)
}

func (p PanelTLS) context() []byte {
	return []byte("MCUI-XRAY-PANEL-TLS-V1\n" + p.Trust.SHA256)
}

func NewPanelTLS(nodeKey string, now time.Time) (*PanelTLS, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	serial.SetBit(serial, 128, 1)
	cert := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: trojanServerName}, DNSNames: []string{trojanServerName},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(90 * 24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	data, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		return nil, err
	}
	text := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data}))
	digest, err := TrojanCertificateDigest(text)
	if err != nil {
		return nil, err
	}
	p := &PanelTLS{Trust: TrojanTrust{Certificate: text, SHA256: digest}}
	p.Key, err = sealPanelSecret(nodeKey, p.context(), private.Seed())
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p PanelTLS) open(private hpke.PrivateKey) (*TrojanTLS, error) {
	seed, err := openPanelSecret(private, p.context(), p.Key)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errTrojanTLS
	}
	key, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		return nil, errTrojanTLS
	}
	tls := &TrojanTLS{
		Certificate: p.Trust.Certificate,
		PrivateKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})),
	}
	if _, err := tls.trust(); err != nil {
		return nil, err
	}
	return tls, nil
}
