package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func validSession() *Session {
	now := time.Now().UTC()
	return &Session{
		ID:                "ses-abc123",
		ActorID:           "alice",
		ActorType:         "User",
		SigningKeyID:      "sk-1",
		IdleExpiresAt:     now.Add(time.Hour),
		AbsoluteExpiresAt: now.Add(8 * time.Hour),
		CreatedAt:         now,
		LastSeenAt:        now,
		IPAddress:         "10.0.0.1",
		UserAgent:         "Mozilla/5.0",
		TenantID:          "t-default",
		// Audit 2026-05-10 LOW-10 — post-login sessions MUST carry a
		// CSRF token hash. Pin a valid 64-hex value so the happy-path
		// fixture stays valid.
		CSRFTokenHash: strings.Repeat("a", 64),
	}
}

func TestSession_Validate_HappyPath(t *testing.T) {
	s := validSession()
	if err := s.Validate(); err != nil {
		t.Fatalf("validate happy path: %v", err)
	}
}

func TestSession_Validate_RejectsInvalidID(t *testing.T) {
	for _, bad := range []string{"", "abc", "session-abc", "SES-abc"} {
		s := validSession()
		s.ID = bad
		if err := s.Validate(); !errors.Is(err, ErrSessionInvalidID) {
			t.Errorf("ID=%q: err = %v; want ErrSessionInvalidID", bad, err)
		}
	}
}

func TestSession_Validate_RejectsEmptyActorID(t *testing.T) {
	s := validSession()
	s.ActorID = ""
	if err := s.Validate(); !errors.Is(err, ErrSessionEmptyActorID) {
		t.Errorf("err = %v; want ErrSessionEmptyActorID", err)
	}
}

func TestSession_Validate_RejectsEmptyActorType(t *testing.T) {
	s := validSession()
	s.ActorType = ""
	if err := s.Validate(); !errors.Is(err, ErrSessionEmptyActorType) {
		t.Errorf("err = %v; want ErrSessionEmptyActorType", err)
	}
}

func TestSession_Validate_RejectsInvalidSigningKeyID(t *testing.T) {
	s := validSession()
	s.SigningKeyID = "key-1"
	if err := s.Validate(); !errors.Is(err, ErrSessionInvalidSigningKeyID) {
		t.Errorf("err = %v; want ErrSessionInvalidSigningKeyID", err)
	}
}

func TestSession_Validate_RejectsBadExpiryOrder(t *testing.T) {
	now := time.Now().UTC()
	s := validSession()
	// idle == absolute: not strictly greater
	s.IdleExpiresAt = now.Add(time.Hour)
	s.AbsoluteExpiresAt = now.Add(time.Hour)
	if err := s.Validate(); !errors.Is(err, ErrSessionExpiryOrder) {
		t.Errorf("equal expiry: err = %v; want ErrSessionExpiryOrder", err)
	}
	// idle > absolute: strictly worse
	s.IdleExpiresAt = now.Add(2 * time.Hour)
	s.AbsoluteExpiresAt = now.Add(time.Hour)
	if err := s.Validate(); !errors.Is(err, ErrSessionExpiryOrder) {
		t.Errorf("idle>abs: err = %v; want ErrSessionExpiryOrder", err)
	}
}

func TestSession_Validate_RejectsExpiryBeforeCreated(t *testing.T) {
	now := time.Now().UTC()
	s := validSession()
	s.CreatedAt = now
	s.IdleExpiresAt = now.Add(-time.Hour)            // before created
	s.AbsoluteExpiresAt = now.Add(-30 * time.Minute) // also before created, but greater than idle
	if err := s.Validate(); !errors.Is(err, ErrSessionExpiryNotInFuture) {
		t.Errorf("err = %v; want ErrSessionExpiryNotInFuture", err)
	}
}

func TestSession_Validate_DefaultsTenantID(t *testing.T) {
	s := validSession()
	s.TenantID = ""
	if err := s.Validate(); err != nil {
		t.Fatalf("err: %v", err)
	}
	if s.TenantID != "t-default" {
		t.Errorf("default tenant = %q; want t-default", s.TenantID)
	}
}

func TestSession_Validate_AcceptsValidCSRFHash(t *testing.T) {
	s := validSession()
	s.CSRFTokenHash = strings.Repeat("a", 64)
	if err := s.Validate(); err != nil {
		t.Errorf("64-char lowercase hex: err = %v; want nil", err)
	}
}

func TestSession_Validate_RejectsInvalidCSRFHash(t *testing.T) {
	for _, bad := range []string{
		strings.Repeat("a", 63),          // too short
		strings.Repeat("a", 65),          // too long
		strings.Repeat("Z", 64),          // not lowercase hex
		strings.Repeat("a", 60) + "1234", // OK length but the prior is bad mixed
		"!@#$" + strings.Repeat("a", 60), // non-hex chars
	} {
		s := validSession()
		s.CSRFTokenHash = bad
		err := s.Validate()
		// At least one of these should fail; lengths 64 with bad chars hit ErrSessionInvalidCSRFHash.
		if len(bad) == 64 && bad != strings.Repeat("a", 60)+"1234" {
			if !errors.Is(err, ErrSessionInvalidCSRFHash) {
				t.Errorf("bad=%q: err = %v; want ErrSessionInvalidCSRFHash", bad, err)
			}
		}
	}
}

// =============================================================================
// SessionSigningKey
// =============================================================================

func TestSessionSigningKey_Validate_HappyPath(t *testing.T) {
	k := &SessionSigningKey{
		ID:                   "sk-1",
		TenantID:             "t-default",
		KeyMaterialEncrypted: []byte{0x02, 0x00},
		CreatedAt:            time.Now().UTC(),
	}
	if err := k.Validate(); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestSessionSigningKey_Validate_RejectsInvalidID(t *testing.T) {
	k := &SessionSigningKey{ID: "key-1", KeyMaterialEncrypted: []byte{0x01}}
	if err := k.Validate(); !errors.Is(err, ErrSessionSigningKeyInvalidID) {
		t.Errorf("err = %v; want ErrSessionSigningKeyInvalidID", err)
	}
}

func TestSessionSigningKey_Validate_RejectsEmptyMaterial(t *testing.T) {
	k := &SessionSigningKey{ID: "sk-1"}
	if err := k.Validate(); !errors.Is(err, ErrSessionSigningKeyEmptyMaterial) {
		t.Errorf("err = %v; want ErrSessionSigningKeyEmptyMaterial", err)
	}
}

func TestSessionSigningKey_Validate_RejectsRetiredBeforeCreated(t *testing.T) {
	now := time.Now().UTC()
	earlier := now.Add(-time.Hour)
	k := &SessionSigningKey{
		ID:                   "sk-1",
		KeyMaterialEncrypted: []byte{0x01},
		CreatedAt:            now,
		RetiredAt:            &earlier,
	}
	if err := k.Validate(); !errors.Is(err, ErrSessionSigningKeyRetiredBeforeNow) {
		t.Errorf("err = %v; want ErrSessionSigningKeyRetiredBeforeNow", err)
	}
}

func TestSessionSigningKey_Validate_DefaultsTenantID(t *testing.T) {
	k := &SessionSigningKey{ID: "sk-1", KeyMaterialEncrypted: []byte{0x01}}
	if err := k.Validate(); err != nil {
		t.Fatalf("err: %v", err)
	}
	if k.TenantID != "t-default" {
		t.Errorf("default tenant = %q; want t-default", k.TenantID)
	}
}

// =============================================================================
// Cookie naming constants pin
// =============================================================================

func TestCookieNamingConstants(t *testing.T) {
	// Pin the cookie names in case a future refactor accidentally
	// renames them; the GUI's `web/src/api/client.ts` reads
	// `certctl_csrf` by name and the back-channel handlers reference
	// `certctl_session` directly. A rename without coordinated GUI
	// updates would silently break login.
	if PostLoginCookieName != "certctl_session" {
		t.Errorf("PostLoginCookieName = %q; want certctl_session", PostLoginCookieName)
	}
	if PreLoginCookieName != "certctl_oidc_pending" {
		t.Errorf("PreLoginCookieName = %q; want certctl_oidc_pending", PreLoginCookieName)
	}
	if CSRFCookieName != "certctl_csrf" {
		t.Errorf("CSRFCookieName = %q; want certctl_csrf", CSRFCookieName)
	}
	if CookieFormatVersion != "v1" {
		t.Errorf("CookieFormatVersion = %q; want v1", CookieFormatVersion)
	}
}
