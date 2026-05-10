// Package domain holds the federated-human user persisted-shape type.
//
// Auth Bundle 2 Phase 1: types only. Phase 2 ships the SQL migration;
// Phase 3's OIDCService.HandleCallback creates / updates rows here on
// successful login.
//
// Distinction from `internal/domain/auth.Tenant / Role / Permission`:
// Bundle 1's RBAC indexes by `actor_id` strings (free-form names). For
// federated humans, the user's actor_id IS the user's `User.ID` so
// Bundle 1's `actor_roles.actor_id = User.ID` for SSO logins. API-key
// actors continue to use the env-var-name as their actor_id; they are
// not represented here.
//
// `webauthn_credentials` is reserved for v3 (Decision 12). Bundle 2
// always stores `[]`; v3's WebAuthn enrollment populates it.
package domain

import (
	"errors"
	"strings"
	"time"

	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
)

// User is a federated-human identity. One row per (oidc_subject,
// oidc_provider_id) tuple per the Phase 2 unique index. A person who
// authenticates against multiple providers gets multiple rows by
// design: identity is per-provider, not global.
type User struct {
	ID                  string    `json:"id"` // prefix `u-`
	TenantID            string    `json:"tenant_id"`
	Email               string    `json:"email"`
	DisplayName         string    `json:"display_name"`
	OIDCSubject         string    `json:"oidc_subject"`
	OIDCProviderID      string    `json:"oidc_provider_id"`
	LastLoginAt         time.Time `json:"last_login_at"`
	WebAuthnCredentials []byte    `json:"webauthn_credentials,omitempty"` // JSONB; reserved for v3, always `[]` in Bundle 2
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// Validation errors. Service layer maps these to HTTP 400.
var (
	ErrUserInvalidID         = errors.New("user: id must start with 'u-'")
	ErrUserEmptyEmail        = errors.New("user: email is required")
	ErrUserInvalidEmail      = errors.New("user: email format is invalid")
	ErrUserEmptyOIDCSubject  = errors.New("user: oidc_subject is required")
	ErrUserInvalidProviderID = errors.New("user: oidc_provider_id must start with 'op-'")
	ErrUserEmptyTenantID     = errors.New("user: tenant_id is required")
)

// Validate checks the persisted-shape invariants on a User.
//
// Email format is checked with a basic invariant (contains exactly one
// `@`, has a non-empty local part, has a non-empty domain part). RFC
// 5321 / RFC 5322 grammars are intentionally NOT enforced fully:
// production deployments accept whatever the IdP issued + don't reject
// based on email pickiness. The check below catches gross corruption
// (empty / multiple `@` / leading-or-trailing whitespace).
func (u *User) Validate() error {
	if !strings.HasPrefix(u.ID, "u-") {
		return ErrUserInvalidID
	}
	if strings.TrimSpace(u.Email) == "" {
		return ErrUserEmptyEmail
	}
	if !isPlausibleEmail(u.Email) {
		return ErrUserInvalidEmail
	}
	if strings.TrimSpace(u.OIDCSubject) == "" {
		return ErrUserEmptyOIDCSubject
	}
	if !strings.HasPrefix(u.OIDCProviderID, "op-") {
		return ErrUserInvalidProviderID
	}
	// WebAuthnCredentials default to empty array (`[]`) at the SQL layer
	// via DEFAULT '[]'. Bundle 2 doesn't populate; v3 does.
	if u.WebAuthnCredentials == nil {
		u.WebAuthnCredentials = []byte("[]")
	}
	if strings.TrimSpace(u.TenantID) == "" {
		u.TenantID = authdomain.DefaultTenantID
	}
	return nil
}

// isPlausibleEmail catches gross corruption without enforcing
// RFC 5321 / 5322 grammars. The IdP issued the email; we trust it
// shape-wise but reject obvious garbage.
func isPlausibleEmail(s string) bool {
	if s != strings.TrimSpace(s) {
		return false
	}
	at := strings.Count(s, "@")
	if at != 1 {
		return false
	}
	parts := strings.SplitN(s, "@", 2)
	if len(parts) != 2 {
		return false
	}
	if strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return false
	}
	if !strings.Contains(parts[1], ".") {
		return false
	}
	return true
}
