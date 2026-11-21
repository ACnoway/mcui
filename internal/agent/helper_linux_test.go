//go:build linux

package agent

import (
	"encoding/json"
	"testing"
)

func TestRuntimeProbeOmitsTaskFields(t *testing.T) {
	body, err := json.Marshal(helperSocketRequest{Probe: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"probe":true}` {
		t.Fatalf("unexpected runtime handshake fields: %s", body)
	}
}
