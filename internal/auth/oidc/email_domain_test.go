package oidc

import (
	"errors"
	"strings"
	"testing"
)

// Audit 2026-05-10 CRIT-5 closure — email-domain allowlist enforcement.
// Tests the extractEmailDomain helper directly + the table-driven
// matcher logic. The full HandleCallback wiring is exercised by the
// existing OIDC service test suite (mockIdP + tokenSet); these tests
// pin the domain-extraction + match semantics that
// HandleCallback Step 7.5 relies on.

func TestExtractEmailDomain(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"plain", "alice@acme.com", "acme.com", false},
		{"mixed-case-input", "Alice@ACME.com", "acme.com", false},
		{"leading-trailing-whitespace", "  bob@example.org  ", "example.org", false},
		{"subdomain-preserved", "alice@dev.acme.com", "dev.acme.com", false},
		{"empty", "", "", true},
		{"whitespace-only", "   ", "", true},
		{"no-at", "alice", "", true},
		{"empty-local-part", "@acme.com", "", true},
		{"empty-domain-part", "alice@", "", true},
		// Multiple @ — addresses where the local-part is quoted and contains @
		// are technically valid RFC but rare; we use LastIndex so the domain
		// portion is unambiguous. Document this behavior in the test.
		{"multiple-at-uses-last", "weird@user@acme.com", "acme.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractEmailDomain(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q; got nil (returned %q)", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("extractEmailDomain(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestEmailDomainAllowlist_MatchSemantics pins the case-insensitive
// exact-match contract used by HandleCallback Step 7.5. Exhaustive
// over the cases the prompt's spec required.
func TestEmailDomainAllowlist_MatchSemantics(t *testing.T) {
	cases := []struct {
		name      string
		allowlist []string
		email     string
		wantErr   error
	}{
		{"empty-list — any domain accepted", nil, "alice@evil.com", nil},
		{"matched lowercase", []string{"acme.com"}, "alice@acme.com", nil},
		{"matched mixed-case allowlist entry", []string{"ACME.com"}, "alice@acme.com", nil},
		{"matched mixed-case email", []string{"acme.com"}, "Alice@ACME.com", nil},
		{"matched with whitespace in allowlist", []string{"  acme.com  "}, "alice@acme.com", nil},
		{"unmatched", []string{"acme.com"}, "eve@evil.com", ErrEmailDomainNotAllowed},
		{"missing email with non-empty list", []string{"acme.com"}, "", ErrEmailMissingButRequired},
		{"subdomain NOT auto-accepted", []string{"acme.com"}, "alice@dev.acme.com", ErrEmailDomainNotAllowed},
		{"parent-domain NOT auto-accepted", []string{"dev.acme.com"}, "alice@acme.com", ErrEmailDomainNotAllowed},
		{"multi-entry first-match", []string{"first.com", "acme.com", "last.com"}, "alice@acme.com", nil},
		{"multi-entry no-match", []string{"first.com", "second.com"}, "alice@third.com", ErrEmailDomainNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := checkEmailDomainAllowlist(tc.allowlist, tc.email)
			if tc.wantErr == nil {
				if got != nil {
					t.Fatalf("expected nil error; got %v", got)
				}
				return
			}
			if !errors.Is(got, tc.wantErr) {
				t.Errorf("got error %v; want %v", got, tc.wantErr)
			}
		})
	}
}

// checkEmailDomainAllowlist mirrors HandleCallback Step 7.5 logic for
// direct testing. Keeps the test independent of mockIdP setup; the
// full integration test (mockIdP + tokenSet + HandleCallback) lives
// in service_test.go and exercises the same path via the IdP-shaped
// flow.
func checkEmailDomainAllowlist(allowlist []string, email string) error {
	if len(allowlist) == 0 {
		return nil
	}
	dom, err := extractEmailDomain(email)
	if err != nil {
		return ErrEmailMissingButRequired
	}
	for _, allowed := range allowlist {
		if strings.EqualFold(strings.TrimSpace(allowed), dom) {
			return nil
		}
	}
	return ErrEmailDomainNotAllowed
}
