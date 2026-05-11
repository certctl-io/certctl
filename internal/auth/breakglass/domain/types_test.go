package domain

import (
	"errors"
	"testing"
	"time"
)

func validBreakglass() *BreakglassCredential {
	now := time.Now().UTC()
	return &BreakglassCredential{
		ID:                   "bg-alice",
		TenantID:             "t-default",
		ActorID:              "u-alice",
		PasswordHash:         "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
		CreatedAt:            now,
		LastPasswordChangeAt: now,
		FailureCount:         0,
	}
}

func TestBreakglass_Validate_HappyPath(t *testing.T) {
	b := validBreakglass()
	if err := b.Validate(); err != nil {
		t.Fatalf("validate happy path: %v", err)
	}
}

func TestBreakglass_Validate_RejectsInvalidID(t *testing.T) {
	for _, bad := range []string{"", "alice", "credential-1", "BG-1"} {
		b := validBreakglass()
		b.ID = bad
		if err := b.Validate(); !errors.Is(err, ErrBreakglassInvalidID) {
			t.Errorf("ID=%q: err = %v; want ErrBreakglassInvalidID", bad, err)
		}
	}
}

func TestBreakglass_Validate_RejectsEmptyActorID(t *testing.T) {
	for _, bad := range []string{"", "   "} {
		b := validBreakglass()
		b.ActorID = bad
		if err := b.Validate(); !errors.Is(err, ErrBreakglassEmptyActorID) {
			t.Errorf("actor=%q: err = %v; want ErrBreakglassEmptyActorID", bad, err)
		}
	}
}

func TestBreakglass_Validate_RejectsEmptyPasswordHash(t *testing.T) {
	b := validBreakglass()
	b.PasswordHash = ""
	if err := b.Validate(); !errors.Is(err, ErrBreakglassEmptyPasswordHash) {
		t.Errorf("err = %v; want ErrBreakglassEmptyPasswordHash", err)
	}
}

func TestBreakglass_Validate_RejectsNonArgon2idHash(t *testing.T) {
	for _, bad := range []string{
		"$argon2i$v=19$...",  // argon2i not argon2id
		"$argon2d$v=19$...",  // argon2d not argon2id
		"$2y$10$...",         // bcrypt
		"$pbkdf2-sha256$...", // pbkdf2
		"plaintext-password", // raw plaintext
		"argon2id$v=19$...",  // missing leading $
	} {
		b := validBreakglass()
		b.PasswordHash = bad
		if err := b.Validate(); !errors.Is(err, ErrBreakglassInvalidHashFormat) {
			t.Errorf("hash=%q: err = %v; want ErrBreakglassInvalidHashFormat", bad, err)
		}
	}
}

func TestBreakglass_Validate_RejectsNegativeFailureCount(t *testing.T) {
	b := validBreakglass()
	b.FailureCount = -1
	if err := b.Validate(); !errors.Is(err, ErrBreakglassNegativeFailures) {
		t.Errorf("err = %v; want ErrBreakglassNegativeFailures", err)
	}
}

func TestBreakglass_Validate_DefaultsTenantID(t *testing.T) {
	b := validBreakglass()
	b.TenantID = ""
	if err := b.Validate(); err != nil {
		t.Fatalf("err: %v", err)
	}
	if b.TenantID != "t-default" {
		t.Errorf("default tenant = %q; want t-default", b.TenantID)
	}
}

func TestBreakglass_IsLocked(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(15 * time.Minute)
	past := now.Add(-15 * time.Minute)

	b := validBreakglass()

	// No LockedUntil set: not locked.
	if b.IsLocked(now) {
		t.Errorf("IsLocked with nil LockedUntil = true; want false")
	}

	// LockedUntil in the future: locked.
	b.LockedUntil = &future
	if !b.IsLocked(now) {
		t.Errorf("IsLocked with future LockedUntil = false; want true")
	}

	// LockedUntil in the past: not locked (window expired).
	b.LockedUntil = &past
	if b.IsLocked(now) {
		t.Errorf("IsLocked with past LockedUntil = true; want false (window expired)")
	}
}

// TestBreakglass_Validate_RejectsTenantIDOnlyWhitespace pins the
// strings.TrimSpace path so a tenant_id of " " gets re-defaulted
// rather than passed through silently.
func TestBreakglass_Validate_NormalizesWhitespaceTenantID(t *testing.T) {
	b := validBreakglass()
	b.TenantID = "   "
	if err := b.Validate(); err != nil {
		t.Fatalf("err: %v", err)
	}
	if b.TenantID != "t-default" {
		t.Errorf("tenant after whitespace trim = %q; want t-default", b.TenantID)
	}
}

// TestBreakglass_PasswordLengthConstantsArePinned exists so a future
// PR doesn't silently change the operator-facing minimum / maximum
// password length. The service layer + handler tests all reference
// these constants; flipping them here changes the operator surface.
func TestBreakglass_PasswordLengthConstantsArePinned(t *testing.T) {
	if MinPasswordLengthBytes != 12 {
		t.Errorf("MinPasswordLengthBytes = %d; want 12 (OWASP 2024 floor)", MinPasswordLengthBytes)
	}
	if MaxPasswordLengthBytes != 256 {
		t.Errorf("MaxPasswordLengthBytes = %d; want 256 (DoS upper bound)", MaxPasswordLengthBytes)
	}
}
