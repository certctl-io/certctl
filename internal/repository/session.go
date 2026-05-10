package repository

import (
	"context"
	"errors"

	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
)

// Sentinel errors for the session repositories.
var (
	// ErrSessionNotFound: Get returned no row. Phase 4 maps to 401
	// (the cookie either expired or was forged with a known-good key
	// id but stale session id).
	ErrSessionNotFound = errors.New("session: not found")

	// ErrSessionRevoked: Get found a row but RevokedAt is set. Phase 4
	// maps to 401.
	ErrSessionRevoked = errors.New("session: revoked")

	// ErrSessionExpired: Get found a row but the absolute expiry has
	// passed (Phase 4 also enforces idle expiry but that's a service-
	// level check against last_seen_at, not a repository sentinel).
	ErrSessionExpired = errors.New("session: expired")

	// ErrSessionSigningKeyNotFound: GetActive returned no row. Phase 4
	// EnsureInitialSigningKey treats this as "boot-time provisioning
	// needed" and mints the first key.
	ErrSessionSigningKeyNotFound = errors.New("session: signing key not found")

	// ErrSessionSigningKeyInUse: Delete (full purge, not Retire) failed
	// because at least one sessions row still references the key. Phase
	// 4's GarbageCollect waits for sessions to expire before purging.
	ErrSessionSigningKeyInUse = errors.New("session: signing key still referenced by active sessions")
)

// SessionRepository wraps the sessions table. Two cookie shapes share
// the rows: post-login sessions (1h-idle/8h-absolute) and pre-login
// sessions (10-minute TTL, IsPreLogin=true; carry OIDC state + nonce
// + PKCE verifier across the IdP redirect).
type SessionRepository interface {
	// Create persists a session row. Caller MUST have called
	// s.Validate(). Returns ErrAuthDuplicateName-shape on the
	// extremely-unlikely id collision (the id is a 32-byte random;
	// callers SHOULD generate fresh ids on the second attempt).
	Create(ctx context.Context, s *sessiondomain.Session) error

	// Get returns a session by id. ErrSessionNotFound on miss.
	// Returns the row even if revoked / expired so the service layer
	// can produce the right 401 reason code (revoked vs expired vs
	// not-found are all 401 to the wire but distinguishable in audit).
	Get(ctx context.Context, id string) (*sessiondomain.Session, error)

	// ListByActor returns every active (non-revoked, non-expired,
	// non-pre-login) session for an actor. Used by the GUI's
	// /v1/auth/sessions surface so users can revoke their old laptops.
	ListByActor(ctx context.Context, actorID, actorType, tenantID string) ([]*sessiondomain.Session, error)

	// UpdateLastSeen sets last_seen_at = NOW() for the named session.
	// Phase 4's middleware calls this on every request to keep the
	// idle-expiry sliding window fresh.
	UpdateLastSeen(ctx context.Context, id string) error

	// UpdateCSRFTokenHash replaces the csrf_token_hash on the session
	// row. Phase 4's RotateCSRFToken consumes this on login completion,
	// logout, and any actor-role mutation against this actor. The hash
	// is the SHA-256 hex of the operator-facing CSRF token plaintext.
	UpdateCSRFTokenHash(ctx context.Context, id, csrfTokenHash string) error

	// Revoke sets revoked_at = NOW() for the named session. Subsequent
	// Get returns the row with RevokedAt set; Phase 4's Validate maps
	// to 401.
	Revoke(ctx context.Context, id string) error

	// RevokeAllForActor sets revoked_at = NOW() on every active session
	// for an actor. Used on role change, fired-employee scenarios, and
	// the back-channel logout endpoint (Phase 5).
	RevokeAllForActor(ctx context.Context, actorID, actorType, tenantID string) error

	// GarbageCollectExpired deletes sessions whose absolute expiry
	// has passed AND whose revoked_at is older than the configurable
	// retention window (default 24h). Pre-login rows older than the
	// 10-minute TTL are also deleted. Returns the number of rows
	// deleted.
	GarbageCollectExpired(ctx context.Context) (int, error)

	// Delete unconditionally removes a session row. Used for the
	// admin-only "purge a specific session" surface (rarely needed;
	// Revoke is the normal path).
	Delete(ctx context.Context, id string) error
}

// SessionSigningKeyRepository wraps the session_signing_keys table.
// Phase 4's Service.RotateSigningKey + EnsureInitialSigningKey + the
// scheduler-driven retention sweep consume this.
type SessionSigningKeyRepository interface {
	// List returns every signing key in the tenant (including
	// retired). Order: created_at DESC.
	List(ctx context.Context, tenantID string) ([]*sessiondomain.SessionSigningKey, error)

	// GetActive returns the most-recently-created non-retired key.
	// ErrSessionSigningKeyNotFound when no non-retired key exists
	// (Phase 4's EnsureInitialSigningKey treats this as "mint first
	// key").
	GetActive(ctx context.Context, tenantID string) (*sessiondomain.SessionSigningKey, error)

	// Get returns one key by id (including retired keys; Phase 4's
	// Validate consults this for cookies signed under retired-but-
	// in-retention keys).
	Get(ctx context.Context, id string) (*sessiondomain.SessionSigningKey, error)

	// Add persists a new signing key. Caller MUST have called
	// k.Validate() and encrypted the key_material via
	// internal/crypto/encryption.go. CreatedAt defaults to NOW() if
	// zero.
	Add(ctx context.Context, k *sessiondomain.SessionSigningKey) error

	// Retire marks an active key as retired (sets retired_at = NOW()).
	// The key stays in the table for verification of cookies signed
	// under it; the scheduler's retention sweep purges it after the
	// configurable retention window (default 24h beyond retired_at).
	Retire(ctx context.Context, id string) error

	// Delete unconditionally removes a signing key row. Returns
	// ErrSessionSigningKeyInUse if any sessions row still references
	// the key (FK ON DELETE RESTRICT). Phase 4's GarbageCollect calls
	// this only after RetentionWindow has passed AND no sessions
	// reference the key.
	Delete(ctx context.Context, id string) error
}
