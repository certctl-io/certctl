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
