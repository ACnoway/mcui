package xrayconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func makeTrojanTLS(t *testing.T, name string, start time.Time) *TrojanTLS {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{name}, NotBefore: start, NotAfter: start.Add(2 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, spec, spec, public, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &TrojanTLS{
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
		PrivateKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
	}
}

func TestTrojanTLSBindsCertificateAndKeepsKeyLocal(t *testing.T) {
	now := time.Now()
	identity := makeTrojanTLS(t, "localhost", now.Add(-time.Hour))
	rotated := makeTrojanTLS(t, "localhost", now.Add(-time.Hour))
	release, password := strings.Repeat("a", 64), strings.Repeat("E", 43)
	catalog := LocalCatalog{
		ReleaseSHA256: release, Ports: []int{1080}, DestinationIP: "93.184.216.34", DestinationPort: 8080,
		PortProtocols: map[int]string{1080: Trojan}, ProtocolCredentials: map[string]map[string]string{Trojan: {"alice": password}},
		TrojanTLS: identity,
	}
	view, err := catalog.Public(release)
	if err != nil || view.TrojanTrust == nil || !view.TrojanTrust.Valid() {
		t.Fatalf("valid TLS identity rejected: %v", err)
	}
	wire, err := json.Marshal(view)
	if err != nil || strings.Contains(string(wire), "PRIVATE KEY") || strings.Contains(string(wire), password) {
		t.Fatal("public inventory contains Trojan secrets")
	}
	plan := Plan{{Port: 1080, Protocol: Trojan, TLSCertSHA256: view.TrojanTrust.SHA256, Users: []string{"alice"}}}
	if parsed, err := ParsePlan(plan.Encode()); err != nil || !view.Allows(parsed) {
		t.Fatalf("Trojan certificate digest was not accepted in the plan: %v", err)
	}
	raw, ref, err := catalog.Render(release, plan)
	if err != nil || !ref.Matches(raw) || !strings.Contains(string(raw), `"minVersion":"1.3"`) ||
		!strings.Contains(string(raw), `"security":"tls"`) || strings.Contains(string(raw), "certificateFile") {
		t.Fatalf("incorrect Trojan TLS config: %v", err)
	}
	catalog.TrojanTLS = rotated
	if _, _, err := catalog.Render(release, plan); err == nil {
		t.Fatal("old plan accepted after certificate rotation")
	}
	for _, invalid := range []*TrojanTLS{
		nil, {Certificate: identity.Certificate, PrivateKey: rotated.PrivateKey},
		makeTrojanTLS(t, "other.test", now.Add(-time.Hour)), makeTrojanTLS(t, "localhost", now.Add(-3*time.Hour)),
	} {
		catalog.TrojanTLS = invalid
		if _, err := catalog.Public(release); err == nil {
			t.Fatal("accepted an invalid, missing or expired Trojan certificate")
		}
	}
}
