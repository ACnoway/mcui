package protocol

import (
	"strings"
	"testing"
)

func TestV2RejectsObjectAndArrayInScalarFields(t *testing.T) {
	input := `{"schema_version":2,"task_id":"task-001","node_id":"node-001","sequence":1,"operation":"core.status","issued_at":"2026-11-16T00:00:00Z","not_before":"2026-11-16T00:00:00Z","expires_at":"2026-11-16T00:10:00Z","payload":{"core":"xray"},"step":{"step_id":"core.status","parameters":{"core":"xray"},"artifact_sha256":"not-applicable","architecture":"not-applicable","expected_state":"observe"},"signing_key_id":"test-key","signature_algorithm":"Ed25519","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}`
	for _, old := range []string{`"operation":"core.status"`, `"signature_algorithm":"Ed25519"`, `"step_id":"core.status"`, `"artifact_sha256":"not-applicable"`, `"architecture":"not-applicable"`, `"expected_state":"observe"`, `"parameters":{"core":"xray"}`} {
		for _, replacement := range []string{"{}", "[]"} {
			t.Run(old+replacement, func(t *testing.T) {
				colon := strings.Index(old, ":")
				next := old[:colon+1] + replacement
				if strings.HasPrefix(old, `"parameters"`) {
					next = `"parameters":{"core":` + replacement + `}`
				}
				raw := strings.Replace(input, old, next, 1)
				if _, err := CanonicalV2TaskBytes([]byte(raw)); err == nil {
					t.Fatal("accepted invalid scalar")
				}
			})
		}
	}
}
