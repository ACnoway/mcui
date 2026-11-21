package runtimeupdate

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
)

func TestSupervisorPollTLSAndRecoverReceipt(t *testing.T) {
	for _, result := range []string{Committed, RolledBack, Rejected} {
		t.Run(result, func(t *testing.T) {
			f := newUpdateFixture(t)
			f.provision(t, "v2.0.0", 1, 7)
			incoming := filepath.Join(f.manager.dir, "incoming")
			read := func(name string) []byte {
				t.Helper()
				data, err := os.ReadFile(filepath.Join(incoming, name))
				if err != nil {
					t.Fatal(err)
				}
				return data
			}
			archive := read("mcui-runtime-linux-" + runtime.GOARCH + ".zip")
			proof := Package{Authorization: read("authorization.json"), AuthorizationSignature: read("authorization.json.sig"),
				Manifest: read("manifest.json"), ManifestSignature: read("manifest.json.sig")}
			if result == RolledBack {
				before, err := f.manager.Status()
				if err != nil {
					t.Fatal(err)
				}
				f.services.ifStarted = func(pair string) error {
					if pair != before.Current.Digest() {
						return errors.New("candidate failed readiness")
					}
					return nil
				}
			}
			if result == Rejected {
				f.now = f.now.AddDate(0, 0, 1)
			}
			const token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			var receiptMu sync.Mutex
			var receipts []Receipt
			base := RemoteEndpoint + "node-test"
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer "+token {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				switch r.Method + " " + r.URL.Path {
				case "POST " + base + "/poll":
					_ = json.NewEncoder(w).Encode(Delivery{ID: proof.ID(), Package: proof})
				case "GET " + base + "/archive/" + proof.ID():
					if result == Rejected {
						t.Error("expired delivery attempted an archive download")
					}
					w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
					_, _ = w.Write(archive)
				case "POST " + base + "/receipt":
					var receipt Receipt
					if err := json.NewDecoder(r.Body).Decode(&receipt); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					receiptMu.Lock()
					receipts = append(receipts, receipt)
					first := len(receipts) == 1
					receiptMu.Unlock()
					if first {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					w.WriteHeader(http.StatusNoContent)
				default:
					http.NotFound(w, r)
				}
			}))
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
			server.StartTLS()
			defer server.Close()
			path := t.TempDir()
			ca, secret := filepath.Join(path, "master.pem"), filepath.Join(path, "token")
			writeTestFile(t, ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
			writeTestFile(t, secret, []byte(token))
			poll := func(m *Manager) error {
				return m.Poll(t.Context(), server.URL, ca, secret, f.clock)
			}
			if err := poll(f.manager); (err != nil) != (result == RolledBack) {
				t.Fatalf("first poll: %v", err)
			}
			state, err := f.manager.Status()
			if err != nil || state.Pending != nil || state.RemoteReceipt == nil || state.RemoteReceipt.Status != result {
				t.Fatalf("durable outcome: %+v, %v", state, err)
			}
			if result == Committed && state.Current.Version != "v2.0.0" || result != Committed && state.Current.Version != "v1.0.0" {
				t.Fatalf("wrong selected pair: %+v", state.Current)
			}
			before := f.services.calls
			if err := poll(f.manager); err == nil {
				t.Fatal("failed receipt response accepted")
			}
			if err := f.manager.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := openManager(f.services.dir, false, f.services)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if err := poll(reopened); err != nil {
				t.Fatal(err)
			}
			receiptMu.Lock()
			defer receiptMu.Unlock()
			if len(receipts) != 2 || receipts[0] != receipts[1] || receipts[1] != *state.RemoteReceipt || f.services.calls != before {
				t.Fatalf("receipt retries changed the outcome or restarted services: %+v", receipts)
			}
			state, err = reopened.Status()
			if err != nil || state.RemoteReceipt != nil {
				t.Fatalf("receipt should be cleared after acknowledgement: %+v, %v", state, err)
			}
		})
	}
}
