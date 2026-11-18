package checkpointhttp_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/checkpoint"
	"github.com/ACnoway/mcui/internal/checkpointhttp"
	"github.com/ACnoway/mcui/internal/checkpointjournal"
	"github.com/ACnoway/mcui/internal/checkpointstore"
)

func TestAuthorityOverMutualTLS(t *testing.T) {
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caPair := issueCertificate(t, ca, nil, nil)
	serverCert := issueCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    ca.NotBefore,
		NotAfter:     ca.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}, ca, caPair.PrivateKey.(ed25519.PrivateKey))
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		NotBefore:    ca.NotBefore,
		NotAfter:     ca.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCert := issueCertificate(t, clientTemplate, ca, caPair.PrivateKey.(ed25519.PrivateKey))
	clientTemplate.SerialNumber = big.NewInt(4)
	unenrolledCert := issueCertificate(t, clientTemplate, ca, caPair.PrivateKey.(ed25519.PrivateKey))
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caPair.Certificate[0]})
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(caPair.Leaf)

	initial := checkpoint.Record{Node: "master-test", Epoch: 1, Digest: [32]byte{1}}
	next := initial
	next.Revision++
	next.Digest[0] = 2
	root := t.TempDir()
	authority, err := checkpointstore.Create(filepath.Join(root, "authority.db"), initial)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	journal, err := checkpointjournal.Create(filepath.Join(root, "journal.db"), initial)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	restored, err := checkpointjournal.Create(filepath.Join(root, "restored.db"), initial)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()

	handler, err := checkpointhttp.NewHandler(authority, sha256.Sum256(clientCert.Leaf.RawSubjectPublicKeyInfo))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
	}
	server.StartTLS()
	defer server.Close()

	ctx := t.Context()
	challenge := checkpoint.Challenge{1}
	otherClient, err := checkpointhttp.NewClient(server.URL, caPEM, unenrolledCert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherClient.CompareAndSwap(ctx, initial, next, challenge); err == nil {
		t.Fatal("client signed by the same CA but using an unenrolled key advanced the checkpoint")
	}

	client, err := checkpointhttp.NewClient(server.URL, caPEM, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	machine := checkpoint.Machine{Journal: journal, Authority: client}
	if err := machine.Transition(ctx, next); err != nil {
		t.Fatal(err)
	}
	observed, err := client.CompareAndSwap(ctx, initial, next, challenge)
	if err != nil || observed != (checkpoint.Observation{Record: next, Challenge: challenge}) {
		t.Fatalf("retry observation = %+v, err = %v", observed, err)
	}
	if err := (checkpoint.Machine{Journal: restored, Authority: client}).Recover(ctx); !errors.Is(err, checkpoint.ErrDenied) {
		t.Fatalf("older restored journal should be denied, got %v", err)
	}

	noCertificate := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: clientRoots}},
		Timeout:   time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/checkpoint/read", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := noCertificate.Do(req); err == nil {
		response.Body.Close()
		t.Fatal("TLS accepted a client without a certificate")
	}
}

func issueCertificate(t *testing.T, template, issuer *x509.Certificate, signing ed25519.PrivateKey) tls.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if issuer == nil {
		issuer, signing = template, private
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, issuer, public, signing)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: private, Leaf: leaf}
}

func TestClientRejectsWrongChallenge(t *testing.T) {
	record := checkpoint.Record{Node: "master-test", Epoch: 1, Digest: [32]byte{1}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(checkpoint.Observation{Record: record, Challenge: checkpoint.Challenge{1}})
	})
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	cert := server.TLS.Certificates[0]
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	client, err := checkpointhttp.NewClient(server.URL, caPEM, cert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(context.Background(), record.Node, record.Epoch, checkpoint.Challenge{2}); !errors.Is(err, checkpoint.ErrDenied) {
		t.Fatalf("mismatched challenge should be denied, got %v", err)
	}
}
