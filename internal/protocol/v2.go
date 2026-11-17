package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// V2 is a draft, status-only schema. "not-applicable" explicitly means no
// artifact or architecture is authorized; "observe" asserts no target state.
// This parser does not authorize execution, select trusted keys, validate the
// receiving node, or check the current time. It is not wired to any runtime.
func CanonicalV2TaskBytes(raw []byte) (_ []byte, resultErr error) {
	defer func() {
		if resultErr != nil && !strings.HasPrefix(resultErr.Error(), "size: ") && !strings.HasPrefix(resultErr.Error(), "utf8: ") && !strings.HasPrefix(resultErr.Error(), "duplicate-key: ") {
			resultErr = fmt.Errorf("schema: %w", resultErr)
		}
	}()
	if len(raw) == 0 || len(raw) > maxMessageBytes {
		return nil, errors.New("size: invalid message size")
	}
	if !utf8.Valid(raw) {
		return nil, errors.New("utf8: invalid UTF-8")
	}
	v, err := decodeStrict(raw)
	if err != nil {
		if strings.HasPrefix(err.Error(), "duplicate object key ") {
			return nil, fmt.Errorf("duplicate-key: %w", err)
		}
		return nil, err
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("task must be an object")
	}
	if err = exactFields(o, []string{"schema_version", "task_id", "node_id", "sequence", "operation", "issued_at", "not_before", "expires_at", "payload", "step", "signing_key_id", "signature_algorithm", "signature"}); err != nil {
		return nil, err
	}
	if err = validInteger(o, "schema_version", 2, 2); err != nil {
		return nil, err
	}
	if err = validInteger(o, "sequence", 1, maxSafeInteger); err != nil {
		return nil, err
	}
	for _, name := range []string{"task_id", "node_id", "signing_key_id"} {
		if err = validIdentifier(o, name); err != nil {
			return nil, err
		}
	}
	if o["operation"] != "core.status" || o["signature_algorithm"] != "Ed25519" {
		return nil, errors.New("unsupported operation or algorithm")
	}
	p, ok := o["payload"].(map[string]any)
	if !ok {
		return nil, errors.New("invalid payload")
	}
	if err = exactFields(p, []string{"core"}); err != nil {
		return nil, err
	}
	if err = validCore(p, "core"); err != nil {
		return nil, err
	}
	s, ok := o["step"].(map[string]any)
	if !ok {
		return nil, errors.New("invalid step")
	}
	if err = exactFields(s, []string{"step_id", "parameters", "artifact_sha256", "architecture", "expected_state"}); err != nil {
		return nil, err
	}
	if s["step_id"] != "core.status" || s["artifact_sha256"] != "not-applicable" || s["architecture"] != "not-applicable" || s["expected_state"] != "observe" {
		return nil, errors.New("invalid status step")
	}
	params, ok := s["parameters"].(map[string]any)
	if !ok {
		return nil, errors.New("invalid parameters")
	}
	if err = exactFields(params, []string{"core"}); err != nil {
		return nil, err
	}
	if params["core"] != p["core"] {
		return nil, errors.New("step core mismatch")
	}
	issued, err := validTime(o, "issued_at")
	if err != nil {
		return nil, err
	}
	before, err := validTime(o, "not_before")
	if err != nil {
		return nil, err
	}
	expires, err := validTime(o, "expires_at")
	if err != nil {
		return nil, err
	}
	if issued.After(before) || !before.Before(expires) || expires.Sub(issued) > maxTaskLifetime {
		return nil, errors.New("invalid task time interval")
	}
	signature, ok := o["signature"].(string)
	if !ok {
		return nil, errors.New("invalid signature")
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != signature {
		return nil, errors.New("invalid signature encoding")
	}
	delete(o, "signature")
	body, err := canonicalJSON(o)
	if err != nil {
		return nil, err
	}
	return append([]byte("MCUI-TASK-V2\n"), body...), nil
}

// VerifyV2Task checks the draft schema and signature using a caller-supplied key.
func VerifyV2Task(raw []byte, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}
	message, err := CanonicalV2TaskBytes(raw)
	if err != nil {
		return err
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return err
	}
	sig, _ := base64.StdEncoding.DecodeString(value.(map[string]any)["signature"].(string))
	if !ed25519.Verify(key, message, sig) {
		return errors.New("signature: verification failed")
	}
	return nil
}
