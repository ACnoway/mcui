package protocol

import (
	"strings"
	"testing"
)

func TestV2CanonicalStatusTask(t *testing.T) {
	raw := `{"schema_version":2,"task_id":"task-001","node_id":"node-001","sequence":1,"operation":"core.status","issued_at":"2026-11-16T00:00:00Z","not_before":"2026-11-16T00:00:00Z","expires_at":"2026-11-16T00:10:00Z","payload":{"core":"xray"},"step":{"step_id":"core.status","parameters":{"core":"xray"},"artifact_sha256":"not-applicable","architecture":"not-applicable","expected_state":"observe"},"signing_key_id":"test-key","signature_algorithm":"Ed25519","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}`
	got, err := CanonicalV2TaskBytes([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), "MCUI-TASK-V2\n") {
		t.Fatalf("wrong domain: %q", got)
	}
	if !strings.Contains(string(got), `"step":{"architecture":"not-applicable","artifact_sha256":"not-applicable","expected_state":"observe","parameters":{"core":"xray"},"step_id":"core.status"}`) {
		t.Fatalf("step not signed canonically: %s", got)
	}
}
