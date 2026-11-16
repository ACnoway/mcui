package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/master"
	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/store"
)

func testNodeAuthority(t *testing.T) *security.CertificateAuthority {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Agent Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := security.LoadCertificateAuthority(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestRunOnceEnrollsWithMTLSHeartbeatAndRotates(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "identity.json")
	t.Setenv("MCUI_AGENT_STATE", statePath)
	storePath := filepath.Join(dir, "master.db")
	st, err := store.Open(storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	invite := "test-once-invitation"
	inviteDigest := sha256.Sum256([]byte(invite))
	inviteHash := hex.EncodeToString(inviteDigest[:])
	if err := st.Update(func(state *store.State) error {
		state.Invites[inviteHash] = store.Invite{Hash: inviteHash, NodeGroup: "test-group", ExpiresAt: time.Now().Add(time.Hour).Unix()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	nodeCA := testNodeAuthority(t)
	caPool := x509.NewCertPool()
	caPool.AddCert(nodeCA.Certificate)
	server := master.NewWithNodeCA(st, "", "", nodeCA)
	ts := httptest.NewUnstartedServer(server.Handler())
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: caPool}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	masterCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	masterCAPath := filepath.Join(dir, "master-ca.pem")
	if err := os.WriteFile(masterCAPath, masterCAPEM, 0600); err != nil {
		t.Fatal(err)
	}
	client, err := New(ts.URL, "node-test", "test-group", invite, masterCAPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.RunOnce(); err != nil {
		t.Fatalf("initial mTLS run: %v", err)
	}
	state, err := client.loadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if state.NodeID == "" || state.CertificatePEM == "" || state.CertificateSerial == "" {
		t.Fatal("enrollment did not persist the client identity")
	}
	var beforeLastSeen int64
	if err := st.View(func(current store.State) error {
		node := current.Nodes[state.NodeID]
		if node.ID == "" || node.Disabled || node.CurrentSerial != state.CertificateSerial {
			t.Fatalf("Master stored an invalid node identity: %+v", node)
		}
		beforeLastSeen = node.LastSeen
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	oldSerial := state.CertificateSerial
	state, err = client.rotate(state)
	if err != nil {
		t.Fatalf("certificate rotation: %v", err)
	}
	if state.CertificateSerial == oldSerial || state.PendingKey != "" {
		t.Fatal("rotation did not atomically replace the local certificate identity")
	}
	if err := client.RunOnce(); err != nil {
		t.Fatalf("heartbeat with rotated certificate: %v", err)
	}
	if err := st.View(func(current store.State) error {
		node := current.Nodes[state.NodeID]
		if node.CurrentSerial != state.CertificateSerial || node.LastSeen < beforeLastSeen {
			t.Fatalf("Master did not accept rotated certificate: %+v", node)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
