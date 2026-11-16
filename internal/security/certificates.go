package security

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var nodeIDPattern = regexp.MustCompile(`^node-[a-f0-9]{32}$`)

type CertificateAuthority struct {
	Certificate *x509.Certificate
	Signer      crypto.Signer
}

func LoadCertificateAuthority(certPEM, keyPEM []byte) (*CertificateAuthority, error) {
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytesTrimSpace(rest)) != 0 {
		return nil, errors.New("invalid node CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse node CA certificate: %w", err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("node CA certificate is not authorized to sign certificates")
	}
	keyBlock, keyRest := pem.Decode(keyPEM)
	if keyBlock == nil || len(bytesTrimSpace(keyRest)) != 0 {
		return nil, errors.New("invalid node CA private key PEM")
	}
	var signer crypto.Signer
	if key, e := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); e == nil {
		signer, _ = key.(crypto.Signer)
	} else if key, e := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); e == nil {
		signer = key
	} else if key, e := x509.ParseECPrivateKey(keyBlock.Bytes); e == nil {
		signer = key
	}
	if signer == nil || !publicKeysEqual(cert.PublicKey, signer.Public()) {
		return nil, errors.New("node CA private key does not match certificate")
	}
	return &CertificateAuthority{Certificate: cert, Signer: signer}, nil
}

func bytesTrimSpace(b []byte) []byte { return []byte(strings.TrimSpace(string(b))) }

func NewNodeID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "node-" + hex.EncodeToString(b), nil
}

func NewCSR(privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid agent private key")
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkixName("MCUI Agent")}, privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

func pkixName(commonName string) pkix.Name { return pkix.Name{CommonName: commonName} }

func ParseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytesTrimSpace(rest)) != 0 {
		return nil, errors.New("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid CSR")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("CSR proof of possession failed")
	}
	if csr.PublicKeyAlgorithm != x509.Ed25519 || len(csr.DNSNames) != 0 || len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 {
		return nil, errors.New("CSR must contain an Ed25519 key and no SANs")
	}
	return csr, nil
}

func (ca *CertificateAuthority) IssueNodeCertificate(csr *x509.CertificateRequest, nodeID string, now time.Time) ([]byte, string, int64, error) {
	if ca == nil || ca.Certificate == nil || ca.Signer == nil {
		return nil, "", 0, errors.New("node CA is unavailable")
	}
	if !nodeIDPattern.MatchString(nodeID) {
		return nil, "", 0, errors.New("invalid node ID")
	}
	if csr == nil || csr.CheckSignature() != nil || csr.PublicKeyAlgorithm != x509.Ed25519 {
		return nil, "", 0, errors.New("invalid CSR")
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 159)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, "", 0, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	notBefore := now.UTC().Add(-30 * time.Second)
	if notBefore.Before(ca.Certificate.NotBefore) {
		notBefore = ca.Certificate.NotBefore
	}
	notAfter := now.UTC().AddDate(1, 0, 0)
	if notAfter.After(ca.Certificate.NotAfter) {
		notAfter = ca.Certificate.NotAfter
	}
	if !notAfter.After(now) || now.Before(ca.Certificate.NotBefore) {
		return nil, "", 0, errors.New("node CA is outside its validity period")
	}
	uri, _ := url.Parse("urn:mcui:node:" + nodeID)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkixName("MCUI Agent " + nodeID),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:         false,
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, csr.PublicKey, ca.Signer)
	if err != nil {
		return nil, "", 0, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", 0, err
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate.Raw})...)
	return chain, cert.SerialNumber.String(), cert.NotAfter.Unix(), nil
}

func NodeIDFromCertificate(cert *x509.Certificate) (string, error) {
	if cert == nil || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !hasClientAuth(cert.ExtKeyUsage) || len(cert.URIs) != 1 {
		return "", errors.New("invalid node client certificate")
	}
	u := cert.URIs[0]
	if u.Scheme != "urn" || !strings.HasPrefix(u.Opaque, "mcui:node:") {
		return "", errors.New("invalid node certificate identity")
	}
	nodeID := strings.TrimPrefix(u.Opaque, "mcui:node:")
	if !nodeIDPattern.MatchString(nodeID) {
		return "", errors.New("invalid node certificate identity")
	}
	return nodeID, nil
}

func hasClientAuth(usages []x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func publicKeysEqual(a, b any) bool {
	left, errA := x509.MarshalPKIXPublicKey(a)
	right, errB := x509.MarshalPKIXPublicKey(b)
	return errA == nil && errB == nil && string(left) == string(right)
}
