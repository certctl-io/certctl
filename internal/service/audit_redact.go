package service

import (
	"strings"
)

// Bundle-6 / Audit H-008 + M-022 / CWE-532 (Insertion of Sensitive Information into Log File):
//
// Audit events flow into the audit_events.details JSONB column. Pre-Bundle-6,
// the middleware stored only `body_hash` (sha256 truncated) — no raw body —
// but service-layer call sites pass arbitrary map[string]interface{} details
// at every RecordEvent invocation. A future call site that accidentally
// includes a credential key (api_key, password, ACME EAB secret, etc.) or
// a PII key (email, phone, SSN, etc.) would persist plaintext into the
// append-only audit table.
//
// This file is the chokepoint that scrubs every details map BEFORE
// AuditService.RecordEvent marshals it. Two deny-lists:
//
//   credentialKeys — value replaced with "[REDACTED:CREDENTIAL]"
//   piiKeys        — value replaced with "[REDACTED:PII]"
//
// The redacted entry surfaces in `details.redacted_keys` so operators can
// audit the redactor itself during a compliance review (GDPR Art. 30
// records-of-processing requires this transparency).
//
// Match semantics:
//   - case-insensitive
//   - structural: walks nested maps and arrays
//   - exact key match (substring would over-redact — e.g. "tokenized_data")
//
// Compliance mapping:
//   - GDPR Art. 32 (data minimization)        — M-022
//   - HIPAA §164.312(b) (audit controls)      — paired with WORM trigger
//   - PCI-DSS 4.0 Req 3 (protect stored PII)  — paired with M-018 (deferred)

// credentialKeys are field names whose values must never appear in the
// audit log. Match is case-insensitive. Add new entries when a new
// credential-bearing field is introduced anywhere in the codebase.
var credentialKeys = map[string]bool{
	"api_key":          true,
	"apikey":           true,
	"password":         true,
	"passphrase":       true,
	"secret":           true,
	"client_secret":    true,
	"token":            true,
	"access_token":     true,
	"refresh_token":    true,
	"bootstrap_token":  true,
	"credential":       true,
	"credentials":      true,
	"private_key":      true,
	"privatekey":       true,
	"private_key_pem":  true,
	"key_pem":          true,
	"cert_pem":         true,
	"chain_pem":        true,
	"full_pem":         true,
	"eab_secret":       true,
	"eab_kid":          true,
	"acme_account_key": true,
	"hmac":             true,
	"hmac_key":         true,
	"signature":        true,
	"auth":             true,
	"authorization":    true,
	"bearer":           true,
}

// piiKeys are field names that may carry personal data. Redacted by
// default; per-route opt-in retention is a future enhancement (post-Bundle-6).
// Note `ip_address` is debatable — useful for forensics but flagged by
// GDPR Art. 32 — defaulting to redact, operators can audit + adjust.
var piiKeys = map[string]bool{
	"email":           true,
	"email_address":   true,
	"phone":           true,
	"phone_number":    true,
	"telephone":       true,
	"ssn":             true,
	"social_security": true,
	"dob":             true,
	"date_of_birth":   true,
	"name":            true,
	"full_name":       true,
	"first_name":      true,
	"last_name":       true,
	"surname":         true,
	"address":         true,
	"street":          true,
	"street_address":  true,
	"city":            true,
	"postal_code":     true,
	"zip":             true,
	"zipcode":         true,
	"ip":              true,
	"ip_address":      true,
}

// RedactDetailsForAudit walks a details map and returns a NEW map with
// credential + PII values scrubbed. The original map is NOT mutated (so
// service-layer code that reuses the map for other purposes is safe).
//
// The returned map is the original shape PLUS a `redacted_keys` array
// listing every key path that was scrubbed. The array surfaces redaction
// footprint to operators without exposing values.
//
// nil-in / empty-in returns nil so callers can pass through to
// json.Marshal which renders "null" — matches pre-Bundle-6 behaviour
// for nil-details RecordEvent calls.
func RedactDetailsForAudit(details map[string]interface{}) map[string]interface{} {
	if len(details) == 0 {
		return nil
	}

	out := make(map[string]interface{}, len(details)+1)
	var redactedKeys []string

	for k, v := range details {
		lower := strings.ToLower(k)
		switch {
		case credentialKeys[lower]:
			out[k] = "[REDACTED:CREDENTIAL]"
			redactedKeys = append(redactedKeys, k)
		case piiKeys[lower]:
			out[k] = "[REDACTED:PII]"
			redactedKeys = append(redactedKeys, k)
		default:
			// Recurse into nested maps + arrays so deeply-nested credentials
			// don't bypass the redactor. Primitives pass through unchanged.
			out[k] = redactValue(v, &redactedKeys, k)
		}
	}

	if len(redactedKeys) > 0 {
		// Surface the redaction footprint. If the caller accidentally
		// passed `redacted_keys` themselves, prefer ours — the redactor's
		// view of what was scrubbed is the load-bearing audit signal.
		out["redacted_keys"] = redactedKeys
	}
	return out
}

// redactValue is the recursive arm of RedactDetailsForAudit. It walks
// arbitrary JSON-shaped values (map / slice / scalar) and returns a value
// with credential + PII keys scrubbed. Mutation-free.
func redactValue(v interface{}, redactedKeys *[]string, parentKey string) interface{} {
	switch typed := v.(type) {
	case map[string]interface{}:
		nested := make(map[string]interface{}, len(typed))
		for k, vv := range typed {
			lower := strings.ToLower(k)
			switch {
			case credentialKeys[lower]:
				nested[k] = "[REDACTED:CREDENTIAL]"
				*redactedKeys = append(*redactedKeys, parentKey+"."+k)
			case piiKeys[lower]:
				nested[k] = "[REDACTED:PII]"
				*redactedKeys = append(*redactedKeys, parentKey+"."+k)
			default:
				nested[k] = redactValue(vv, redactedKeys, parentKey+"."+k)
			}
		}
		return nested
	case []interface{}:
		nested := make([]interface{}, len(typed))
		for i, item := range typed {
			nested[i] = redactValue(item, redactedKeys, parentKey)
		}
		return nested
	default:
		// scalar (string, number, bool, nil) — pass through unchanged.
		return typed
	}
}
