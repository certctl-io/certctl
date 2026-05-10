// Package domain holds the session-management persisted-shape types.
//
// Auth Bundle 2 Phase 1: types only. Phase 2 ships the SQL migration;
// Phase 4 ships the service layer (cookie minting, validation,
// revocation, idle / absolute expiry, signing-key rotation, GC).
//
// Two cookie shapes share this Session table. Post-login sessions are
// minted by SessionService.Create after a successful OIDC callback (or
// break-glass authenticate); they carry the cookie HMAC-signed via the
// active SessionSigningKey, idle timeout 1h default, absolute timeout
// 8h default. Pre-login sessions are minted at /auth/oidc/login to
// hold the state, nonce, and PKCE verifier across the IdP redirect;
// same row shape, `is_pre_login = true`, 10-minute absolute TTL, GC'd
// by the same scheduler sweep as expired post-login sessions.
//
// CSRFTokenHash holds the SHA-256 of the operator-facing CSRF token
// (the plaintext lives in a separate `certctl_csrf` cookie that is
// JS-readable by design so the GUI can echo it into the X-CSRF-Token
// header). The hash on the session row defends against DB-read leaks:
// a compromised read-only DB user cannot replay live tokens.
package domain

import (
	"errors"
	"strings"
	"time"

	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
)

// Session is one cookie's worth of authenticated state. Created on
// login (post-login row) or on /auth/oidc/login (pre-login row);
// destroyed by Revoke / GarbageCollect.
type Session struct {
	ID                string     `json:"id"` // prefix `ses-`
	ActorID           string     `json:"actor_id"`
	ActorType         string     `json:"actor_type"` // matches domain.ActorType strings
	SigningKeyID      string     `json:"signing_key_id"`
	IsPreLogin        bool       `json:"is_pre_login"`
	CSRFTokenHash     string     `json:"-"` // hex-encoded SHA-256; never wire-exposed
	IdleExpiresAt     time.Time  `json:"idle_expires_at"`
	AbsoluteExpiresAt time.Time  `json:"absolute_expires_at"`
	CreatedAt         time.Time  `json:"created_at"`
	LastSeenAt        time.Time  `json:"last_seen_at"`
	IPAddress         string     `json:"ip_address"`
	UserAgent         string     `json:"user_agent"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	TenantID          string     `json:"tenant_id"`
}

// SessionSigningKey holds the HMAC key material used to sign session
// cookies. Phase 4's `Service.RotateSigningKey` mints new keys and
// retires old ones; retired keys stay valid for verification during
// the configurable retention window so existing cookies don't
// immediately fail. KeyMaterialEncrypted is the v2 blob produced by
// `internal/crypto/encryption.go`; the plaintext is the 32-byte HMAC
// key the session cookie is signed with.
type SessionSigningKey struct {
	ID                   string     `json:"id"` // prefix `sk-`
	TenantID             string     `json:"tenant_id"`
	KeyMaterialEncrypted []byte     `json:"-"` // v2 blob; never JSON-encoded
	CreatedAt            time.Time  `json:"created_at"`
	RetiredAt            *time.Time `json:"retired_at,omitempty"`
}

// Cookie naming constants (referenced by Phase 4's service + Phase 5's
// handler).
const (
	// PostLoginCookieName is the post-authentication session cookie.
	// Set HttpOnly + Secure + SameSite=Lax (or Strict via env var).
	PostLoginCookieName = "certctl_session"

	// PreLoginCookieName is the pre-authentication session cookie that
	// holds the OIDC state + nonce + PKCE verifier across the IdP
	// redirect. 10-minute lifetime, separate from the post-login
	// cookie, Path=/auth/oidc/.
	PreLoginCookieName = "certctl_oidc_pending"

	// CSRFCookieName is the JS-readable cookie holding the CSRF token
	// plaintext. Mirrors the SHA-256 hash on the session row. The GUI
	// reads this and echoes the value into the X-CSRF-Token header on
	// every state-changing request.
	CSRFCookieName = "certctl_csrf"

	// CookieFormatVersion is the prefix on every session cookie value.
	// Format: `v1.<session_id>.<signing_key_id>.<base64url-no-pad
	// HMAC>`. Reserved so a future incompatible format upgrade ships
	// as `v2.` without overlapping the validator.
	CookieFormatVersion = "v1"

	// PreLoginAbsoluteTTL is the maximum lifetime of a pre-login
	// session row. The IdP redirect handshake should complete inside
	// 10 minutes; rows older than this are GC'd.
	PreLoginAbsoluteTTL = 10 * time.Minute
)

// Validation errors. Service layer maps these to HTTP 400 / 500.
var (
	ErrSessionInvalidID                  = errors.New("session: id must start with 'ses-'")
	ErrSessionEmptyActorID               = errors.New("session: actor_id is required")
	ErrSessionEmptyActorType             = errors.New("session: actor_type is required")
	ErrSessionInvalidSigningKeyID        = errors.New("session: signing_key_id must start with 'sk-'")
	ErrSessionExpiryOrder                = errors.New("session: absolute_expires_at must be > idle_expires_at")
	ErrSessionExpiryNotInFuture          = errors.New("session: idle_expires_at must be after created_at")
	ErrSessionEmptyTenantID              = errors.New("session: tenant_id is required")
	ErrSessionInvalidCSRFHash            = errors.New("session: csrf_token_hash must be 64 hex characters (sha256) when set")
	ErrSessionSigningKeyInvalidID        = errors.New("session: signing key id must start with 'sk-'")
	ErrSessionSigningKeyEmptyMaterial    = errors.New("session: signing key material is required")
	ErrSessionSigningKeyRetiredBeforeNow = errors.New("session: retired_at cannot be before created_at")
	ErrSessionSigningKeyEmptyTenantID    = errors.New("session: signing key tenant_id is required")
)

// Validate checks the persisted-shape invariants on a Session.
// Defaults applied in-place: TenantID upgrades to authdomain.DefaultTenantID
// when empty.
func (s *Session) Validate() error {
	if !strings.HasPrefix(s.ID, "ses-") {
		return ErrSessionInvalidID
	}
	if strings.TrimSpace(s.ActorID) == "" {
		return ErrSessionEmptyActorID
	}
	if strings.TrimSpace(s.ActorType) == "" {
		return ErrSessionEmptyActorType
	}
	if !strings.HasPrefix(s.SigningKeyID, "sk-") {
		return ErrSessionInvalidSigningKeyID
	}
	if !s.AbsoluteExpiresAt.After(s.IdleExpiresAt) {
		return ErrSessionExpiryOrder
	}
	if !s.CreatedAt.IsZero() && !s.IdleExpiresAt.After(s.CreatedAt) {
		return ErrSessionExpiryNotInFuture
	}
	if s.CSRFTokenHash != "" {
		// SHA-256 is 32 bytes => 64 lowercase hex chars.
		if len(s.CSRFTokenHash) != 64 || !isHex(s.CSRFTokenHash) {
			return ErrSessionInvalidCSRFHash
		}
	}
	if strings.TrimSpace(s.TenantID) == "" {
		s.TenantID = authdomain.DefaultTenantID
	}
	return nil
}

// Validate checks the persisted-shape invariants on a SessionSigningKey.
func (k *SessionSigningKey) Validate() error {
	if !strings.HasPrefix(k.ID, "sk-") {
		return ErrSessionSigningKeyInvalidID
	}
	if len(k.KeyMaterialEncrypted) == 0 {
		return ErrSessionSigningKeyEmptyMaterial
	}
	if k.RetiredAt != nil && !k.CreatedAt.IsZero() && k.RetiredAt.Before(k.CreatedAt) {
		return ErrSessionSigningKeyRetiredBeforeNow
	}
	if strings.TrimSpace(k.TenantID) == "" {
		k.TenantID = authdomain.DefaultTenantID
	}
	return nil
}

// isHex reports whether s contains only lowercase hex characters.
// Used by Session.Validate to pin CSRFTokenHash format.
func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
