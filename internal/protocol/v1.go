package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/ACnoway/mcui/internal/xrayconfig"
)

type Kind string

const (
	Task            Kind = "task"
	Config          Kind = "config"
	Cancel          Kind = "cancel"
	Skip            Kind = "skip"
	maxMessageBytes      = 64 * 1024
	maxSafeInteger       = uint64(9007199254740991)
	maxTaskLifetime      = 10 * time.Minute
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func Domain(kind Kind) ([]byte, error) {
	switch kind {
	case Task:
		return []byte("MCUI-TASK-V1\n"), nil
	case Config:
		return []byte("MCUI-CONFIG-V1\n"), nil
	case Cancel:
		return []byte("MCUI-CANCEL-V1\n"), nil
	case Skip:
		return []byte("MCUI-SKIP-V1\n"), nil
	default:
		return nil, errors.New("unknown signed object kind")
	}
}

// CanonicalSignedBytes validates the frozen V1 schema and returns its domain-separated JCS input.
// Protocol string fields are restricted to ASCII so Go and ECMAScript implementations sort and
// serialize the same field names without depending on locale or Unicode normalization.
func CanonicalSignedBytes(kind Kind, raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxMessageBytes || !utf8.Valid(raw) {
		return nil, errors.New("invalid or oversized signed message")
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("signed message must be an object")
	}
	if err := validateObject(kind, object); err != nil {
		return nil, err
	}
	signature, ok := object["signature"].(string)
	if !ok {
		return nil, errors.New("signature must be a string")
	}
	decoded, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(decoded) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(decoded) != signature {
		return nil, errors.New("signature must be canonical padded Base64")
	}
	delete(object, "signature")
	canonical, err := canonicalJSON(object)
	if err != nil {
		return nil, err
	}
	domain, _ := Domain(kind)
	return append(domain, canonical...), nil
}

func Verify(kind Kind, raw []byte, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	message, err := CanonicalSignedBytes(kind, raw)
	if err != nil {
		return err
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return err
	}
	signature := value.(map[string]any)["signature"].(string)
	sig, _ := base64.StdEncoding.DecodeString(signature)
	if !ed25519.Verify(publicKey, message, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

func decodeStrict(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := parseValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON value")
	}
	return value, nil
}

func parseValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("duplicate object key %q", key)
				}
				child, err := parseValue(decoder)
				if err != nil {
					return nil, err
				}
				object[key] = child
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("unterminated JSON object")
			}
			return object, nil
		case '[':
			var array []any
			for decoder.More() {
				child, err := parseValue(decoder)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("unterminated JSON array")
			}
			return array, nil
		default:
			return nil, errors.New("unexpected JSON delimiter")
		}
	case string, json.Number, bool, nil:
		return value, nil
	default:
		return nil, errors.New("unsupported JSON value")
	}
}

func validateObject(kind Kind, object map[string]any) error {
	var fields []string
	switch kind {
	case Task:
		operation, ok := object["operation"].(string)
		if !ok {
			return errors.New("task operation is missing")
		}
		fields = []string{"schema_version", "task_id", "node_id", "sequence", "operation", "issued_at", "not_before", "expires_at", "payload", "signing_key_id", "signature_algorithm", "signature"}
		if operation != "core.status" {
			fields = append(fields, "approval_id")
		}
		if err := exactFields(object, fields); err != nil {
			return err
		}
		if operation != "core.status" {
			if err := validIdentifier(object, "approval_id"); err != nil {
				return err
			}
		}
		if err := validIdentifier(object, "task_id"); err != nil {
			return err
		}
		if err := validInteger(object, "sequence", 1, maxSafeInteger); err != nil {
			return err
		}
		if err := validateTaskPayload(operation, object["payload"]); err != nil {
			return err
		}
	case Config:
		fields = []string{"schema_version", "node_id", "core", "core_version", "revision", "content_sha256", "content_size", "issued_at", "not_before", "expires_at", "signing_key_id", "signature_algorithm", "signature"}
		if err := exactFields(object, fields); err != nil {
			return err
		}
		if err := validCore(object, "core"); err != nil {
			return err
		}
		if err := validIdentifier(object, "core_version"); err != nil {
			return err
		}
		if err := validInteger(object, "revision", 1, maxSafeInteger); err != nil {
			return err
		}
		if err := validInteger(object, "content_size", 0, 4*1024*1024); err != nil {
			return err
		}
		digest, ok := object["content_sha256"].(string)
		if !ok || !digestPattern.MatchString(digest) {
			return errors.New("invalid content_sha256")
		}
	case Cancel:
		fields = []string{"schema_version", "node_id", "task_id", "sequence", "issued_at", "not_before", "expires_at", "signing_key_id", "signature_algorithm", "signature"}
		if err := exactFields(object, fields); err != nil {
			return err
		}
		if err := validIdentifier(object, "task_id"); err != nil {
			return err
		}
		if err := validInteger(object, "sequence", 1, maxSafeInteger); err != nil {
			return err
		}
	case Skip:
		fields = []string{"schema_version", "node_id", "sequence", "reason", "issued_at", "not_before", "expires_at", "signing_key_id", "signature_algorithm", "signature"}
		if err := exactFields(object, fields); err != nil {
			return err
		}
		if err := validInteger(object, "sequence", 1, maxSafeInteger); err != nil {
			return err
		}
		reason, ok := object["reason"].(string)
		if !ok || (reason != "VOID_UNISSUED" && reason != "EXPIRED" && reason != "CANCELED") {
			return errors.New("invalid skip reason")
		}
	default:
		return errors.New("unknown signed object kind")
	}
	if err := validInteger(object, "schema_version", 1, 1); err != nil {
		return err
	}
	if err := validIdentifier(object, "node_id"); err != nil {
		return err
	}
	if err := validIdentifier(object, "signing_key_id"); err != nil {
		return err
	}
	algorithm, ok := object["signature_algorithm"].(string)
	if !ok || algorithm != "Ed25519" {
		return errors.New("unsupported signature algorithm")
	}
	issued, err := validTime(object, "issued_at")
	if err != nil {
		return err
	}
	notBefore, err := validTime(object, "not_before")
	if err != nil {
		return err
	}
	expires, err := validTime(object, "expires_at")
	if err != nil {
		return err
	}
	if issued.After(notBefore) || !notBefore.Before(expires) {
		return errors.New("invalid signed message time interval")
	}
	if kind == Task && expires.Sub(issued) > maxTaskLifetime {
		return errors.New("task validity exceeds the maximum lifetime")
	}
	return nil
}

func exactFields(object map[string]any, fields []string) error {
	if len(object) != len(fields) {
		return errors.New("missing or unknown signed message field")
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return fmt.Errorf("missing signed message field %q", field)
		}
	}
	return nil
}

func validIdentifier(object map[string]any, name string) error {
	value, ok := object[name].(string)
	if !ok || !identifierPattern.MatchString(value) {
		return fmt.Errorf("invalid identifier field %q", name)
	}
	return nil
}

func validCore(object map[string]any, name string) error {
	value, ok := object[name].(string)
	if !ok || (value != "xray" && value != "sing-box" && value != "mita") {
		return fmt.Errorf("invalid Core field %q", name)
	}
	return nil
}

func validInteger(object map[string]any, name string, min, max uint64) error {
	value, ok := object[name].(json.Number)
	if !ok {
		return fmt.Errorf("invalid integer field %q", name)
	}
	text := value.String()
	if text == "" || text[0] == '-' || bytes.ContainsAny([]byte(text), ".eE+") {
		return fmt.Errorf("invalid integer field %q", name)
	}
	parsed, err := strconv.ParseUint(text, 10, 64)
	if err != nil || parsed < min || parsed > max || parsed > maxSafeInteger {
		return fmt.Errorf("integer field %q is out of range", name)
	}
	return nil
}

func validTime(object map[string]any, name string) (time.Time, error) {
	value, ok := object[name].(string)
	if !ok {
		return time.Time{}, fmt.Errorf("invalid time field %q", name)
	}
	parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
	if err != nil || parsed.UTC().Format("2006-01-02T15:04:05Z") != value {
		return time.Time{}, fmt.Errorf("invalid UTC time field %q", name)
	}
	return parsed, nil
}

func validateTaskPayload(operation string, value any) error {
	payload, ok := value.(map[string]any)
	if !ok {
		return errors.New("task payload must be an object")
	}
	expected := []string{"core"}
	releaseControl := (operation == "core.start" || operation == "core.stop" || operation == "core.uninstall") && len(payload) != 1
	releaseChange := (operation == "core.upgrade" || operation == "core.downgrade") && len(payload) != 4
	localConfig := operation == "config.apply" && len(payload) != 4
	if releaseControl {
		expected = append(expected, "version", "architecture", "sha256")
	}
	switch operation {
	case "core.status", "core.start", "core.stop", "core.restart", "core.uninstall":
	case "core.install", "core.upgrade", "core.downgrade":
		expected = append(expected, "version", "artifact_id", "manifest_version")
		if releaseChange {
			expected = append(expected, "current_version", "current_sha256")
		}
	case "config.apply":
		if localConfig {
			expected = append(expected, "version", "architecture", "sha256", "manifest_version", "port", "config")
			if _, present := payload["plan"]; present {
				expected = append(expected, "plan")
			}
		} else {
			expected = append(expected, "revision", "content_sha256", "core_version")
		}
	default:
		return errors.New("unsupported task operation")
	}
	if err := exactFields(payload, expected); err != nil {
		return err
	}
	if err := validCore(payload, "core"); err != nil {
		return err
	}
	if releaseControl {
		digest, ok := payload["sha256"].(string)
		if payload["core"] != "xray" || (payload["architecture"] != "amd64" && payload["architecture"] != "arm64") ||
			!ok || !digestPattern.MatchString(digest) {
			return errors.New("invalid Xray control release identity")
		}
		return validIdentifier(payload, "version")
	}
	switch operation {
	case "core.install", "core.upgrade", "core.downgrade":
		if releaseChange {
			digest, ok := payload["current_sha256"].(string)
			if payload["core"] != "xray" || !ok || !digestPattern.MatchString(digest) {
				return errors.New("invalid installed Xray release digest")
			}
			if err := validIdentifier(payload, "current_version"); err != nil {
				return err
			}
		}
		if err := validIdentifier(payload, "version"); err != nil {
			return err
		}
		if err := validIdentifier(payload, "artifact_id"); err != nil {
			return err
		}
		return validInteger(payload, "manifest_version", 1, maxSafeInteger)
	case "config.apply":
		if localConfig {
			if value, present := payload["plan"]; present {
				text, ok := value.(string)
				if _, err := xrayconfig.ParseConfiguration(text); !ok || err != nil {
					return errors.New("invalid Xray configuration draft")
				}
			}
			if payload["core"] != "xray" || (payload["architecture"] != "amd64" && payload["architecture"] != "arm64") {
				return errors.New("invalid Xray configuration release identity")
			}
			digest, ok := payload["sha256"].(string)
			if !ok || !digestPattern.MatchString(digest) {
				return errors.New("invalid Xray configuration release digest")
			}
			if err := validIdentifier(payload, "version"); err != nil {
				return err
			}
			if err := validInteger(payload, "manifest_version", 1, maxSafeInteger); err != nil {
				return err
			}
			if err := validInteger(payload, "port", 1024, 65535); err != nil {
				return err
			}
			config, ok := payload["config"].(map[string]any)
			if !ok || config["core"] != payload["core"] || config["core_version"] != payload["version"] {
				return errors.New("invalid signed Xray configuration metadata")
			}
			return validateObject(Config, config)
		}
		if err := validInteger(payload, "revision", 1, maxSafeInteger); err != nil {
			return err
		}
		if err := validIdentifier(payload, "core_version"); err != nil {
			return err
		}
		digest, ok := payload["content_sha256"].(string)
		if !ok || !digestPattern.MatchString(digest) {
			return errors.New("invalid task content digest")
		}
	}
	return nil
}

func canonicalJSON(value any) ([]byte, error) {
	var output bytes.Buffer
	if err := writeCanonical(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeCanonical(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		output.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				output.WriteByte(',')
			}
			if err := writeJSONString(output, key); err != nil {
				return err
			}
			output.WriteByte(':')
			if err := writeCanonical(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	case []any:
		output.WriteByte('[')
		for i, item := range typed {
			if i > 0 {
				output.WriteByte(',')
			}
			if err := writeCanonical(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case string:
		return writeJSONString(output, typed)
	case json.Number:
		if err := validNumber(typed); err != nil {
			return err
		}
		output.WriteString(typed.String())
	case nil, bool:
		return errors.New("null and boolean values are not permitted in V1 signed objects")
	default:
		return errors.New("unsupported canonical JSON value")
	}
	return nil
}

func utf16Less(left, right string) bool {
	a, b := utf16.Encode([]rune(left)), utf16.Encode([]rune(right))
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func writeJSONString(output *bytes.Buffer, value string) error {
	output.WriteByte('"')
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 0x7f {
			return errors.New("non-ASCII strings are not permitted in V1 signed objects")
		}
		switch c {
		case '"', '\\':
			output.WriteByte('\\')
			output.WriteByte(c)
		case '\b':
			output.WriteString(`\b`)
		case '\t':
			output.WriteString(`\t`)
		case '\n':
			output.WriteString(`\n`)
		case '\f':
			output.WriteString(`\f`)
		case '\r':
			output.WriteString(`\r`)
		default:
			if c < 0x20 {
				fmt.Fprintf(output, `\u%04x`, c)
			} else {
				output.WriteByte(c)
			}
		}
	}
	output.WriteByte('"')
	return nil
}

func validNumber(number json.Number) error {
	text := number.String()
	if text == "" || text[0] == '-' || bytes.ContainsAny([]byte(text), ".eE+") {
		return errors.New("only non-negative integer values are permitted")
	}
	parsed, err := strconv.ParseUint(text, 10, 64)
	if err != nil || parsed > maxSafeInteger {
		return errors.New("integer exceeds the interoperable range")
	}
	return nil
}
