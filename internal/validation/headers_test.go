package validation

import (
	"strings"
	"testing"
)

func TestValidateHeaderValue_AcceptsSafeInput(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
	}{
		{"plain ASCII", "Subject", "Renewal reminder"},
		{"empty string", "Reply-To", ""},
		{"utf-8 multibyte", "Subject", "résumé — 日本語"},
		{"tabs and spaces permitted", "Subject", "a\tb c"},
		{"typical email address", "From", "alerts@example.com"},
		{"long Subject within limits", "Subject", strings.Repeat("x", 998)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateHeaderValue(tc.field, tc.value); err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestValidateHeaderValue_RejectsControlCharacters(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
	}{
		{"injected CRLF + header", "Subject", "hello\r\nBcc: attacker@example.com"},
		{"lone LF", "From", "alice@example.com\nBcc: x@y"},
		{"lone CR", "Subject", "hello\rworld"},
		{"NUL byte", "To", "bob@example.com\x00extra"},
		{"CRLFCRLF body injection", "Subject", "ping\r\n\r\nMalicious body"},
		{"CR at end", "Subject", "trailing\r"},
		{"LF at start", "Subject", "\nleading"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHeaderValue(tc.field, tc.value)
			if err == nil {
				t.Fatalf("expected error rejecting control characters, got nil")
			}
			// Error must mention the field so operators can pinpoint the offender.
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("expected error to mention field %q, got %q", tc.field, err.Error())
			}
			// Error must NOT leak the raw value back into logs.
			if strings.Contains(err.Error(), tc.value) {
				t.Errorf("error leaks raw value; expected redaction: %q", err.Error())
			}
		})
	}
}

func TestValidateHeaderValue_DefaultFieldName(t *testing.T) {
	err := ValidateHeaderValue("", "bad\r\nvalue")
	if err == nil {
		t.Fatal("expected error for CRLF input, got nil")
	}
	if !strings.Contains(err.Error(), "header") {
		t.Errorf("expected default field name 'header' in error, got %q", err.Error())
	}
}

// TestSanitizeEmailBodyValue_PreservesSafeInput pins the contract that
// ordinary body content (including non-Latin scripts and tabs) flows
// through unchanged. The sanitizer must be a no-op for legitimate input
// — over-stripping degrades operator notifications.
func TestSanitizeEmailBodyValue_PreservesSafeInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"plain ASCII", "Renewal reminder for prod.example.com"},
		{"empty", ""},
		{"utf-8 multibyte", "résumé — 日本語 — مرحبا"},
		{"tabs allowed", "key:\tvalue"},
		{"spaces", "  multiple  spaces  "},
		{"common cert DN", "CN=api.example.com,O=Acme Corp,C=US"},
		{"URL with safe chars", "https://docs.example.com/cert/mc-prod-api"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeEmailBodyValue(tc.input)
			if got != tc.input {
				t.Errorf("expected unchanged %q, got %q", tc.input, got)
			}
		})
	}
}

// TestSanitizeEmailBodyValue_StripsControlChars pins the CodeQL
// go/email-injection (CWE-640) defense — every attacker-plant-able
// control character is stripped or replaced.
func TestSanitizeEmailBodyValue_StripsControlChars(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      string
		wantSafer bool // want output != input
	}{
		{"NUL byte stripped", "before\x00after", "beforeafter", true},
		{"bare LF replaced with space", "line1\nline2", "line1 line2", true},
		{"bare CR replaced with space", "line1\rline2", "line1 line2", true},
		{"CRLF replaced (both stripped)", "line1\r\nline2", "line1  line2", true},
		{"BEL stripped", "alert\x07now", "alertnow", true},
		{"backspace stripped", "x\x08y", "xy", true},
		{"DEL stripped", "x\x7fy", "xy", true},
		// C1 control chars must be specified via Unicode escape (\u) so
		// the source remains valid UTF-8; bare \x80 / \x9f bytes would
		// be invalid UTF-8 and Go's range emits U+FFFD instead, which
		// would test the malformed-UTF-8 strip path, not the C1 path.
		{"C1 control char stripped (U+0080)", "x\u0080y", "xy", true},
		{"C1 control char stripped (U+009F)", "x\u009Fy", "xy", true},
		// U+FFFD is the replacement char Go emits for malformed UTF-8.
		// We strip it as defense-in-depth so attacker-planted invalid
		// UTF-8 doesn't survive into operator notifications as an
		// arbitrary glyph.
		{"replacement char stripped", "x\uFFFDy", "xy", true},
		{"TAB preserved (legitimate body content)", "k:\tv", "k:\tv", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeEmailBodyValue(tc.input)
			if got != tc.want {
				t.Errorf("input %q: want %q, got %q", tc.input, tc.want, got)
			}
			if tc.wantSafer && got == tc.input {
				t.Errorf("expected sanitization to change %q, but output unchanged", tc.input)
			}
		})
	}
}

// TestSanitizeEmailBodyValue_StripsBidiOverride pins the
// visually-spoofable Unicode defense (homograph / RTL-override /
// zero-width attacks). An attacker who controls a CN or metadata value
// could otherwise plant a malicious URL that renders benignly in mail
// clients that honor bidi-override codepoints.
func TestSanitizeEmailBodyValue_StripsBidiOverride(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		// U+202E = Right-to-left override
		{"RTL override", "Click ‮www.evil.com‬ to verify"},
		// U+202D = Left-to-right override
		{"LRO override", "Click ‭www.evil.com‬ to verify"},
		// U+2066 = Left-to-right isolate
		{"LRI isolate", "Click ⁦www.evil.com⁩ to verify"},
		// U+200B = Zero-width space
		{"zero-width space", "evil​.example.com"},
		// U+200C = ZWNJ
		{"zero-width non-joiner", "ad‌min@example.com"},
		// U+FEFF = byte-order mark / zero-width no-break space
		{"BOM", "x\uFEFFy"},
		// U+180E = Mongolian Vowel Separator
		{"MVS", "a᠎b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeEmailBodyValue(tc.input)
			if got == tc.input {
				t.Errorf("expected bidi/zero-width stripping for %q, got unchanged %q", tc.input, got)
			}
		})
	}
}

// TestSanitizeEmailBodyValue_ContentSpoofingScenario pins the specific
// CodeQL go/email-injection (CWE-640) example: an attacker who controls
// a body field plants header-like content. The sanitizer neutralizes
// the attempt by stripping bare LF/CR within the field.
func TestSanitizeEmailBodyValue_ContentSpoofingScenario(t *testing.T) {
	// Attacker plants a body value that tries to fake a "Reply-To"
	// header inside the body. Even if mail clients don't honor it, a
	// recipient skimming the body could be fooled.
	attacker := "alert from compromised cert\r\nReply-To: attacker@evil.com\r\nClick https://evil.example.com/reset"
	got := SanitizeEmailBodyValue(attacker)
	if got == attacker {
		t.Fatalf("attacker input passed through unchanged: %q", got)
	}
	// Specifically: no CR or LF should remain in the field.
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("CR/LF still present after sanitization: %q", got)
	}
}
