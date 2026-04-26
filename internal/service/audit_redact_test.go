package service

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// Bundle-6 / Audit H-008 + M-022 / CWE-532 regression suite.

func TestRedactDetailsForAudit_NilAndEmpty(t *testing.T) {
	if got := RedactDetailsForAudit(nil); got != nil {
		t.Errorf("nil input → expected nil out, got %v", got)
	}
	if got := RedactDetailsForAudit(map[string]interface{}{}); got != nil {
		t.Errorf("empty input → expected nil out, got %v", got)
	}
}

func TestRedactDetailsForAudit_CredentialKeys(t *testing.T) {
	cases := []string{
		"api_key", "ApiKey", "API_KEY", "password", "Passphrase",
		"secret", "client_secret", "token", "access_token",
		"refresh_token", "bootstrap_token", "private_key", "PrivateKey",
		"private_key_pem", "key_pem", "cert_pem", "chain_pem", "full_pem",
		"eab_secret", "eab_kid", "acme_account_key", "hmac",
		"signature", "auth", "authorization", "bearer",
	}
	for _, key := range cases {
		t.Run(key, func(t *testing.T) {
			in := map[string]interface{}{
				key:                 "sensitive-value-do-not-leak",
				"non_sensitive_id":  "ok-public-id",
			}
			out := RedactDetailsForAudit(in)
			if out[key] != "[REDACTED:CREDENTIAL]" {
				t.Errorf("expected credential redaction, got %v", out[key])
			}
			if out["non_sensitive_id"] != "ok-public-id" {
				t.Errorf("non-sensitive field mutated: %v", out["non_sensitive_id"])
			}
			redactedKeys, ok := out["redacted_keys"].([]string)
			if !ok || len(redactedKeys) != 1 || redactedKeys[0] != key {
				t.Errorf("redacted_keys = %v, expected [%q]", out["redacted_keys"], key)
			}
		})
	}
}

func TestRedactDetailsForAudit_PIIKeys(t *testing.T) {
	cases := []string{
		"email", "Email_Address", "phone", "telephone", "ssn",
		"social_security", "dob", "date_of_birth", "name", "full_name",
		"first_name", "last_name", "surname", "address", "street",
		"street_address", "city", "postal_code", "zip", "ip_address",
	}
	for _, key := range cases {
		t.Run(key, func(t *testing.T) {
			in := map[string]interface{}{key: "personal-data"}
			out := RedactDetailsForAudit(in)
			if out[key] != "[REDACTED:PII]" {
				t.Errorf("expected PII redaction, got %v", out[key])
			}
		})
	}
}

func TestRedactDetailsForAudit_NestedMap(t *testing.T) {
	in := map[string]interface{}{
		"resource_id": "iss-prod",
		"config": map[string]interface{}{
			"endpoint": "https://acme.example.com",
			"eab_secret": "do-not-leak-this-secret",
			"contact": map[string]interface{}{
				"email": "ops@example.com",
				"role":  "admin",
			},
		},
	}
	out := RedactDetailsForAudit(in)

	cfg, ok := out["config"].(map[string]interface{})
	if !ok {
		t.Fatalf("config field shape changed: %T", out["config"])
	}
	if cfg["eab_secret"] != "[REDACTED:CREDENTIAL]" {
		t.Errorf("nested credential not redacted: %v", cfg["eab_secret"])
	}
	if cfg["endpoint"] != "https://acme.example.com" {
		t.Errorf("non-sensitive nested field mutated: %v", cfg["endpoint"])
	}
	contact, ok := cfg["contact"].(map[string]interface{})
	if !ok {
		t.Fatalf("contact field shape changed: %T", cfg["contact"])
	}
	if contact["email"] != "[REDACTED:PII]" {
		t.Errorf("nested PII not redacted: %v", contact["email"])
	}
	if contact["role"] != "admin" {
		t.Errorf("non-sensitive nested field mutated: %v", contact["role"])
	}

	// redacted_keys array surfaces the dotted paths
	redactedKeys, ok := out["redacted_keys"].([]string)
	if !ok {
		t.Fatalf("redacted_keys missing or wrong type: %T", out["redacted_keys"])
	}
	sort.Strings(redactedKeys)
	wantKeys := []string{"config.contact.email", "config.eab_secret"}
	if len(redactedKeys) != len(wantKeys) {
		t.Errorf("redacted_keys len mismatch: got %v want %v", redactedKeys, wantKeys)
	}
	for i, want := range wantKeys {
		if i >= len(redactedKeys) || redactedKeys[i] != want {
			t.Errorf("redacted_keys[%d] = %q want %q", i, redactedKeys[i], want)
		}
	}
}

func TestRedactDetailsForAudit_NestedArray(t *testing.T) {
	// Arrays of maps (e.g. SANs with metadata) — credentials inside array
	// elements must also be redacted.
	in := map[string]interface{}{
		"contacts": []interface{}{
			map[string]interface{}{
				"name":  "Alice",
				"email": "alice@example.com",
			},
			map[string]interface{}{
				"name":  "Bob",
				"email": "bob@example.com",
			},
		},
	}
	out := RedactDetailsForAudit(in)
	contacts, ok := out["contacts"].([]interface{})
	if !ok {
		t.Fatalf("contacts shape changed: %T", out["contacts"])
	}
	if len(contacts) != 2 {
		t.Fatalf("expected 2 contacts, got %d", len(contacts))
	}
	for i, c := range contacts {
		m, ok := c.(map[string]interface{})
		if !ok {
			t.Fatalf("contact %d shape changed: %T", i, c)
		}
		if m["email"] != "[REDACTED:PII]" {
			t.Errorf("contact[%d].email not redacted: %v", i, m["email"])
		}
		if m["name"] != "[REDACTED:PII]" {
			t.Errorf("contact[%d].name not redacted: %v", i, m["name"])
		}
	}
}

func TestRedactDetailsForAudit_NoRedactionPath(t *testing.T) {
	// Maps with no sensitive keys should NOT have a redacted_keys array
	// — clutter-free for the common case.
	in := map[string]interface{}{
		"action":   "create_certificate",
		"cert_id":  "mc-prod-001",
		"latency_ms": float64(42),
	}
	out := RedactDetailsForAudit(in)
	if _, present := out["redacted_keys"]; present {
		t.Errorf("expected no redacted_keys when no redaction occurred, got %v", out["redacted_keys"])
	}
}

func TestRedactDetailsForAudit_DoesNotMutateInput(t *testing.T) {
	in := map[string]interface{}{
		"api_key": "secret-do-not-leak",
		"resource": "iss-prod",
	}
	_ = RedactDetailsForAudit(in)
	if in["api_key"] != "secret-do-not-leak" {
		t.Errorf("input map was mutated: api_key = %v", in["api_key"])
	}
}

func TestRedactDetailsForAudit_CaseInsensitive(t *testing.T) {
	cases := []string{"API_KEY", "Api_Key", "api_KEY", "EMAIL", "Email"}
	for _, key := range cases {
		t.Run(key, func(t *testing.T) {
			out := RedactDetailsForAudit(map[string]interface{}{key: "leak-me"})
			val, _ := out[key].(string)
			if !strings.HasPrefix(val, "[REDACTED:") {
				t.Errorf("case-insensitive match failed for %q: %v", key, out[key])
			}
		})
	}
}

func TestRedactDetailsForAudit_JSONRoundTrip(t *testing.T) {
	// The redacted map MUST round-trip through json.Marshal (the
	// AuditService persistence path). Catches type-assertion regressions.
	in := map[string]interface{}{
		"reason":    "compromised-key",
		"api_key":   "leak-me",
		"contacts": []interface{}{
			map[string]interface{}{"email": "ops@example.com"},
		},
	}
	out := RedactDetailsForAudit(in)
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("redacted map failed json.Marshal: %v", err)
	}
	body := string(b)
	if strings.Contains(body, "leak-me") {
		t.Errorf("credential value leaked through marshal: %s", body)
	}
	if strings.Contains(body, "ops@example.com") {
		t.Errorf("PII value leaked through marshal: %s", body)
	}
	if !strings.Contains(body, "[REDACTED:CREDENTIAL]") {
		t.Errorf("redaction sentinel missing from marshaled output: %s", body)
	}
	if !strings.Contains(body, "[REDACTED:PII]") {
		t.Errorf("PII redaction sentinel missing from marshaled output: %s", body)
	}
	if !strings.Contains(body, "redacted_keys") {
		t.Errorf("redacted_keys array missing from marshaled output: %s", body)
	}
}

// TestRedactDetailsForAudit_ScalarTypes confirms the recursive arm doesn't
// mishandle non-map non-slice values.
func TestRedactDetailsForAudit_ScalarTypes(t *testing.T) {
	in := map[string]interface{}{
		"string_field": "hello",
		"int_field":    42,
		"float_field":  3.14,
		"bool_field":   true,
		"nil_field":    nil,
	}
	out := RedactDetailsForAudit(in)
	if out["string_field"] != "hello" || out["int_field"] != 42 ||
		out["float_field"] != 3.14 || out["bool_field"] != true ||
		out["nil_field"] != nil {
		t.Errorf("scalar pass-through failed: %v", out)
	}
}
