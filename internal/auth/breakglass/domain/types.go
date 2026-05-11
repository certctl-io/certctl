// Package domain holds the break-glass-admin persisted-shape type.
//
// Auth Bundle 2 Phase 1 / Phase 7.5: types only. Phase 2 ships the
// SQL migration; Phase 7.5 ships the service layer (set / authenticate
// / unlock / remove / lockout-window).
//
// Break-glass is the SSO-broken-case recovery path. Decision 4 frames
// it explicitly: enabled per-deployment via CERTCTL_BREAKGLASS_ENABLED,
// default-OFF, paired with WebAuthn 2FA in v3 (Decision 12). The
// threat-model is clear: enabling break-glass is a deliberate bypass
// of the SSO security boundary; an attacker who phishes the password
// bypasses every other defense. Operators turn it on during SSO
// incidents and turn it off after recovery.
//
// `password_hash` is the Argon2id PHC-format string
// (`$argon2id$v=19$m=65536,t=3,p=4$<salt-base64>$<hash-base64>`).
// Validation here checks the field has the Argon2id magic prefix;
// actual hashing / verifying happens in the service layer via
// `golang.org/x/crypto/argon2`.
package domain

import (
	"errors"
	"strings"
	"time"

	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
)

// BreakglassCredential is one actor's password-based recovery
// credential. At most one row per actor (Phase 2 migration enforces
// `UNIQUE(actor_id)`). FailureCount + LockedUntil track the lockout
// state machine that defeats brute-force attacks against the password.
type BreakglassCredential struct {
	ID                   string     `json:"id"` // prefix `bg-`
	TenantID             string     `json:"tenant_id"`
	ActorID              string     `json:"actor_id"`
	PasswordHash         string     `json:"-"` // Argon2id PHC string; never JSON-encoded
	CreatedAt            time.Time  `json:"created_at"`
	LastPasswordChangeAt time.Time  `json:"last_password_change_at"`
	FailureCount         int        `json:"failure_count"`
	LockedUntil          *time.Time `json:"locked_until,omitempty"`
	LastFailureAt        *time.Time `json:"last_failure_at,omitempty"`
}

// Argon2id parameter constants. The defaults match OWASP 2024
// recommendations + sit on the same compute-budget tier as
// internal/crypto/encryption.go's PBKDF2-SHA256 600k rounds. Phase
// 7.5's service can override via env vars; the defaults are what
// Validate() requires of a hash issued without override.
const (
	// Argon2idPHCPrefix is the Argon2id PHC-format magic prefix.
	// Validate() checks every PasswordHash starts with this.
	Argon2idPHCPrefix = "$argon2id$"

	// MinPasswordLengthBytes is the floor on raw password input
	// length (the service layer enforces this before hashing). 12
	// bytes is the OWASP 2024 lower bound for memorized secrets;
	// shorter passwords are rejected at SetPassword time. The domain
	// layer doesn't see plaintext, but the constant lives here so
	// the service + handler + GUI all reference the same number.
	MinPasswordLengthBytes = 12

	// MaxPasswordLengthBytes is the upper bound on raw password
	// input. Argon2id handles arbitrary input but capping at 256
	// bytes prevents trivial DoS where an attacker submits a 1-MB
	// password to consume CPU on the verify path. Pre-hashing length
	// check in the service layer.
	MaxPasswordLengthBytes = 256
)

// Validation errors. Service layer maps these to HTTP 400.
var (
	ErrBreakglassInvalidID         = errors.New("breakglass: id must start with 'bg-'")
	ErrBreakglassEmptyActorID      = errors.New("breakglass: actor_id is required")
	ErrBreakglassEmptyPasswordHash = errors.New("breakglass: password_hash is required")
	ErrBreakglassInvalidHashFormat = errors.New("breakglass: password_hash must be Argon2id PHC format ($argon2id$...)")
	ErrBreakglassNegativeFailures  = errors.New("breakglass: failure_count cannot be negative")
	ErrBreakglassEmptyTenantID     = errors.New("breakglass: tenant_id is required")
)

// Validate checks the persisted-shape invariants on a
// BreakglassCredential. Defaults applied in-place: TenantID upgrades
// to authdomain.DefaultTenantID when empty.
//
// IMPORTANT: this validator does NOT receive plaintext passwords. The
// service-layer SetPassword method validates plaintext length /
// strength before hashing; only the resulting Argon2id hash flows into
// this struct.
func (b *BreakglassCredential) Validate() error {
	if !strings.HasPrefix(b.ID, "bg-") {
		return ErrBreakglassInvalidID
	}
	if strings.TrimSpace(b.ActorID) == "" {
		return ErrBreakglassEmptyActorID
	}
	if strings.TrimSpace(b.PasswordHash) == "" {
		return ErrBreakglassEmptyPasswordHash
	}
	if !strings.HasPrefix(b.PasswordHash, Argon2idPHCPrefix) {
		return ErrBreakglassInvalidHashFormat
	}
	if b.FailureCount < 0 {
		return ErrBreakglassNegativeFailures
	}
	if strings.TrimSpace(b.TenantID) == "" {
		b.TenantID = authdomain.DefaultTenantID
	}
	return nil
}

// IsLocked reports whether the credential is currently locked out
// (LockedUntil is set and in the future). Phase 7.5 service uses this
// at Authenticate time; Validate() does not call it.
func (b *BreakglassCredential) IsLocked(now time.Time) bool {
	return b.LockedUntil != nil && b.LockedUntil.After(now)
}
