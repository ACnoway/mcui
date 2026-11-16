package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func makeTestCA(t *testing.T, notBefore time.Time) ([]byte, []byte, *x509.Certificate) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "MCUI test node CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), certificate
}

func TestLoadCertificateAuthorityAndIssueNodeCertificate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	caPEM, keyPEM, caCertificate := makeTestCA(t, now.Add(-10*time.Second))
	ca, err := LoadCertificateAuthority(caPEM, keyPEM)
	if err != nil {
		t.Fatalf("load CA: %v", err)
	}
	_, agentKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := NewCSR(agentKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	const nodeID = "node-0123456789abcdef0123456789abcdef"
	chainPEM, serial, expiry, err := ca.IssueNodeCertificate(csr, nodeID, now)
	if err != nil {
		t.Fatalf("issue node certificate: %v", err)
	}
	block, rest := pem.Decode(chainPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("certificate chain does not begin with the node certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(bytesTrimSpace(rest)) == 0 {
		t.Fatal("certificate chain omits the issuing CA")
	}
	if leaf.NotBefore.Before(caCertificate.NotBefore) || leaf.NotAfter.After(caCertificate.NotAfter) || expiry != leaf.NotAfter.Unix() {
		t.Fatalf("leaf validity is not bounded by CA validity: leaf=%s..%s CA=%s..%s", leaf.NotBefore, leaf.NotAfter, caCertificate.NotBefore, caCertificate.NotAfter)
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !hasClientAuth(leaf.ExtKeyUsage) || len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 {
		t.Fatal("node certificate has unexpected key usages or names")
	}
	gotNodeID, err := NodeIDFromCertificate(leaf)
	if err != nil || gotNodeID != nodeID {
		t.Fatalf("node certificate identity = %q, %v", gotNodeID, err)
	}
	if serial != leaf.SerialNumber.String() || publicKeysEqual(leaf.PublicKey, agentKey.Public()) == false {
		t.Fatal("issued certificate serial or public key does not match CSR")
	}
	if _, err := url.Parse("urn:mcui:node:" + nodeID); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCertificateAuthorityRejectsMismatchedKey(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute)
	caPEM, _, _ := makeTestCA(t, now)
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKeyDER, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	otherKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherKeyDER})
	if _, err := LoadCertificateAuthority(caPEM, otherKeyPEM); err == nil {
		t.Fatal("mismatched CA private key was accepted")
	}
}

func TestParseCSRRejectsUnexpectedSubjectAlternativeNames(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "MCUI Agent"}, DNSNames: []string{"attacker.example"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if _, err := ParseCSR(csrPEM); err == nil {
		t.Fatal("CSR with caller-selected SAN was accepted")
	}
}

func TestNodeIDFromCertificateRejectsUnexpectedURI(t *testing.T) {
	cert := &x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	cert.URIs = []*url.URL{{Scheme: "urn", Opaque: "mcui:node:node-INVALID"}}
	if _, err := NodeIDFromCertificate(cert); err == nil {
		t.Fatal("invalid node ID URI was accepted")
	}
}
