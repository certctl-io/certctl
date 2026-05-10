package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func validUser() *User {
	now := time.Now().UTC()
	return &User{
		ID:             "u-alice",
		TenantID:       "t-default",
		Email:          "alice@example.com",
		DisplayName:    "Alice Smith",
		OIDCSubject:    "okta-user-12345",
		OIDCProviderID: "op-okta-prod",
		LastLoginAt:    now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func TestUser_Validate_HappyPath(t *testing.T) {
	u := validUser()
	if err := u.Validate(); err != nil {
		t.Fatalf("validate happy path: %v", err)
	}
	// WebAuthnCredentials defaulted to []
	if string(u.WebAuthnCredentials) != "[]" {
		t.Errorf("default webauthn_credentials = %q; want []", string(u.WebAuthnCredentials))
	}
}

func TestUser_Validate_RejectsInvalidID(t *testing.T) {
	for _, bad := range []string{"", "alice", "user-alice", "U-alice"} {
		u := validUser()
		u.ID = bad
		if err := u.Validate(); !errors.Is(err, ErrUserInvalidID) {
			t.Errorf("ID=%q: err = %v; want ErrUserInvalidID", bad, err)
		}
	}
}

func TestUser_Validate_RejectsEmptyEmail(t *testing.T) {
	for _, bad := range []string{"", "   ", "\t"} {
		u := validUser()
		u.Email = bad
		if err := u.Validate(); !errors.Is(err, ErrUserEmptyEmail) {
			t.Errorf("email=%q: err = %v; want ErrUserEmptyEmail", bad, err)
		}
	}
}

func TestUser_Validate_RejectsMalformedEmail(t *testing.T) {
	for _, bad := range []string{
		"alice",              // no @
		"alice@@example.com", // double @
		"@example.com",       // empty local
		"alice@",             // empty domain
		"alice@example",      // no dot in domain
		" alice@example.com", // leading whitespace
		"alice@example.com ", // trailing whitespace
	} {
		u := validUser()
		u.Email = bad
		if err := u.Validate(); !errors.Is(err, ErrUserInvalidEmail) {
			t.Errorf("email=%q: err = %v; want ErrUserInvalidEmail", bad, err)
		}
	}
}

func TestUser_Validate_RejectsEmptyOIDCSubject(t *testing.T) {
	u := validUser()
	u.OIDCSubject = ""
	if err := u.Validate(); !errors.Is(err, ErrUserEmptyOIDCSubject) {
		t.Errorf("err = %v; want ErrUserEmptyOIDCSubject", err)
	}
}

func TestUser_Validate_RejectsInvalidOIDCProviderID(t *testing.T) {
	for _, bad := range []string{"", "okta-prod", "OP-okta-prod", "provider-okta"} {
		u := validUser()
		u.OIDCProviderID = bad
		if err := u.Validate(); !errors.Is(err, ErrUserInvalidProviderID) {
			t.Errorf("provider=%q: err = %v; want ErrUserInvalidProviderID", bad, err)
		}
	}
}

func TestUser_Validate_DefaultsTenantID(t *testing.T) {
	u := validUser()
	u.TenantID = ""
	if err := u.Validate(); err != nil {
		t.Fatalf("err: %v", err)
	}
	if u.TenantID != "t-default" {
		t.Errorf("default tenant = %q; want t-default", u.TenantID)
	}
}

func TestUser_Validate_PreservesExistingWebAuthnCredentials(t *testing.T) {
	u := validUser()
	u.WebAuthnCredentials = []byte(`[{"id":"cred1"}]`)
	if err := u.Validate(); err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(string(u.WebAuthnCredentials), "cred1") {
		t.Errorf("Validate clobbered existing webauthn_credentials: %q", string(u.WebAuthnCredentials))
	}
}
