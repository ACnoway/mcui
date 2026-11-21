package security

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestEnrollmentCABundleCanonicalizesOnlyCACertificates(t *testing.T) {
	first := enrollmentCertificate(t, 1, true)
	second := enrollmentCertificate(t, 2, true)
	leaf := enrollmentCertificate(t, 3, false)
	expected, err := CanonicalEnrollmentCA(append(bytes.Clone(first), second...))
	if err != nil {
		t.Fatal(err)
	}
	reordered := bytes.Join([][]byte{second, first, first}, []byte("\n"))
	actual, err := CanonicalEnrollmentCA(reordered)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatalf("equivalent CA bundles must match: %v", err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("test only")})
	for name, input := range map[string][]byte{
		"empty":            nil,
		"non-CA":           leaf,
		"mixed PEM":        append(bytes.Clone(first), private...),
		"malformed block":  append([]byte("-----BEGIN CERTIFICATE-----\nnot certificate data\n"), first...),
		"trailing text":    append(bytes.Clone(first), []byte("non-PEM text")...),
		"oversized bundle": bytes.Repeat(first, MaxEnrollmentCABytes/len(first)+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CanonicalEnrollmentCA(input); err == nil {
				t.Fatal("invalid CA bundle was accepted")
			}
		})
	}
}

func enrollmentCertificate(t *testing.T, serial int64, isCA bool) []byte {
	t.Helper()
	key, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), BasicConstraintsValid: true, IsCA: isCA,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key, private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
