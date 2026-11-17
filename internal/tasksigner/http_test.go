package tasksigner

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ACnoway/mcui/internal/protocol"
)

const httpTaskInput = `{"schema_version":2,"task_id":"task-001","node_id":"node-001","sequence":1,"operation":"core.status","issued_at":"2026-11-16T00:00:00Z","not_before":"2026-11-16T00:00:00Z","expires_at":"2026-11-16T00:10:00Z","payload":{"core":"xray"},"step":{"step_id":"core.status","parameters":{"core":"xray"},"artifact_sha256":"not-applicable","architecture":"not-applicable","expected_state":"observe"},"signing_key_id":"test-key","signature_algorithm":"Ed25519","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}`

func TestHTTPClientUsesNarrowAuthenticatedSigningAPI(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer, err := New("test-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	token := []byte("0123456789abcdef0123456789abcdef")
	handler, err := NewHTTPHandler(signer, token)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client, err := NewHTTPClient(server.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := client.SignStatus([]byte(httpTaskInput))
	if err != nil {
		t.Fatal(err)
	}
	if err = protocol.VerifyV2Task(signed, privateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("signed response failed verification: %v", err)
	}
}

func TestSignerHandlerRejectsWrongTokenAndExtraOperation(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer, err := New("test-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	token := []byte("0123456789abcdef0123456789abcdef")
	handler, err := NewHTTPHandler(signer, token)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/sign/status", strings.NewReader(`{"task":"e30="}`))
	request.Header.Set("Authorization", "Bearer wrong-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token returned HTTP %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/sign/status", strings.NewReader(`{"task":"e30="}`))
	request.Header.Set("Authorization", string(token))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("bare token returned HTTP %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/sign/arbitrary", strings.NewReader(`{"task":"e30="}`))
	request.Header.Set("Authorization", "Bearer "+string(token))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unexpected route returned HTTP %d", response.Code)
	}
}

func TestHTTPClientRejectsNonLoopbackEndpoint(t *testing.T) {
	if _, err := NewHTTPClient("http://example.com:9231", []byte("0123456789abcdef0123456789abcdef")); err == nil {
		t.Fatal("accepted a non-loopback signer endpoint")
	}
}
