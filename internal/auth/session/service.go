// Package session implements the post-login session lifecycle for
// Auth Bundle 2 Phase 4: cookie minting + signature validation +
// idle/absolute expiry + revocation + signing-key rotation + GC.
//
// =============================================================================
// Cookie wire format (`v1.<session_id>.<signing_key_id>.<HMAC>`):
//
//	v1.ses-XXXXXXXX.sk-YYYYYYYY.<base64url-no-pad(HMAC-SHA256)>
//
// HMAC INPUT IS LENGTH-PREFIXED to defeat concatenation collisions:
//
//	len(session_id) || ":" || session_id || ":" || len(signing_key_id) || ":" || signing_key_id
//
// where len(...) is the ASCII decimal byte-length. Without the length
// prefix, the bare-concatenation form `session_id || signing_key_id`
// would let a forger swap one byte across the boundary — `<a, bc>` and
// `<ab, c>` produce identical HMAC inputs. The length prefix moves the
// boundary into the input itself so the two cases never collide.
//
// HMAC KEY is the 32-byte plaintext of the SessionSigningKey row's
// KeyMaterialEncrypted blob (decrypted via internal/crypto/encryption.go's
// EncryptIfKeySet/DecryptIfKeySet path — same blob format issuer/target
// credentials use). The plaintext is held in memory only during signature
// computation; never logged, never persisted in plaintext form.
//
// VERSION PREFIX is reserved. v1 is the only accepted prefix today.
// A future incompatible upgrade ships as `v2.` and the validator
// rejects unknown prefixes (no fallback attempt — fail closed).
//
// =============================================================================
// CSRF token model:
//
//   - Plaintext lives in a JS-readable certctl_csrf cookie (HttpOnly=false
//     intentional; the GUI must read it to echo into X-CSRF-Token header).
//   - SHA-256 hash of the plaintext lives on the session row (csrf_token_hash).
//   - Validation: SHA-256(X-CSRF-Token header) constant-time-compared
//     against the session row's stored hash.
//   - Rotated by Service.RotateCSRFToken on: login completion, logout,
//     any actor-role mutation against this actor, explicit operator
//     "rotate CSRF" admin endpoint.
//
// =============================================================================
// Failure semantics:
//
// Validate returns ErrSessionInvalidCookie for any tamper / format /
// missing-key fault. The handler maps to HTTP 401 uniformly (no leak
// of which check failed; specific reason in the audit row). Idle +
// absolute expiry surface as ErrSessionExpiredIdle / ErrSessionExpiredAbsolute
// so the audit row distinguishes; both wire to 401. Revocation is
// ErrSessionRevoked. Signing-key not found / fully purged is
// ErrSigningKeyNotFound. Length-prefix-defeating concatenation collision
// attempts also surface as ErrSessionInvalidCookie because the HMAC
// recomputation fails.
//
// =============================================================================
// Token-leak hygiene:
//
// Cookie values, CSRF token plaintexts, signing-key plaintexts, and the
// HMAC bytes themselves MUST NEVER be logged at any level. The service
// contains zero log statements that include those values; the
// session_id and signing_key_id (both opaque IDs) are the only identifiers
// that ever land in audit rows.
package session

import (
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	sessiondomain "github.com/certctl-io/certctl/internal/auth/session/domain"
	cryptopkg "github.com/certctl-io/certctl/internal/crypto"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// =============================================================================
// Encrypt/decrypt helpers for SessionSigningKey.KeyMaterialEncrypted
// blobs. Production wires the real CERTCTL_CONFIG_ENCRYPTION_KEY value;
// tests pass empty (encrypted == plaintext passthrough so the test
// surface doesn't require an encryption-key env var).
// =============================================================================

func encryptKeyMaterial(plaintext []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		// Test path: no encryption configured. Round-trip is identity.
		// Production main.go REQUIRES CERTCTL_CONFIG_ENCRYPTION_KEY for
		// any deployment that runs the session service; the empty case
		// is intentionally only useful in unit tests.
		return plaintext, nil
	}
	blob, _, err := cryptopkg.EncryptIfKeySet(plaintext, passphrase)
	return blob, err
}

func decryptKeyMaterial(blob []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return blob, nil
	}
	return cryptopkg.DecryptIfKeySet(blob, passphrase)
}

// =============================================================================
// Service-layer sentinel errors.
// =============================================================================

var (
	// ErrSessionInvalidCookie is returned by Validate when the cookie
	// fails any of: format check, version-prefix check, base64 decode,
	// HMAC recomputation. The handler maps to HTTP 401 uniformly.
	ErrSessionInvalidCookie = errors.New("session: invalid cookie")

	// ErrSessionExpiredIdle: the session's last_seen_at is older than
	// the configured idle timeout. HTTP 401.
	ErrSessionExpiredIdle = errors.New("session: idle timeout exceeded")

	// ErrSessionExpiredAbsolute: the session's absolute_expires_at is
	// in the past. HTTP 401.
	ErrSessionExpiredAbsolute = errors.New("session: absolute timeout exceeded")

	// ErrSessionRevoked: the session row's revoked_at is set. HTTP 401.
	ErrSessionRevoked = errors.New("session: revoked")

	// ErrSigningKeyNotFound: the cookie's signing_key_id doesn't match
	// any row in session_signing_keys (forged cookie OR fully-purged
	// retired key). HTTP 401.
	ErrSigningKeyNotFound = errors.New("session: signing key not found")

	// ErrSigningKeyRetired: the cookie's signing_key_id is retired and
	// past the retention window. HTTP 401.
	ErrSigningKeyRetired = errors.New("session: signing key retired beyond retention window")

	// ErrCSRFMissing: the X-CSRF-Token header is empty on a state-
	// changing request. HTTP 403.
	ErrCSRFMissing = errors.New("session: CSRF token missing")

	// ErrCSRFMismatch: the X-CSRF-Token header doesn't match the
	// session row's hash. HTTP 403.
	ErrCSRFMismatch = errors.New("session: CSRF token mismatch")

	// ErrSessionIPMismatch: the configured CERTCTL_SESSION_BIND_IP gate
	// rejected the request because the client IP doesn't match the
	// session row's recorded IP. HTTP 401, audit row, session NOT
	// auto-revoked (user may have legitimate IP change).
	ErrSessionIPMismatch = errors.New("session: client IP does not match session-bound IP")

	// ErrSessionUAMismatch: same shape as ErrSessionIPMismatch for the
	// optional CERTCTL_SESSION_BIND_USER_AGENT gate.
	ErrSessionUAMismatch = errors.New("session: User-Agent does not match session-bound User-Agent")

	// ErrInitialSigningKeyMintFailed: EnsureInitialSigningKey could not
	// mint a key (crypto/rand failure, encryption failure, repository
	// failure). The server boot path treats this as fatal.
	ErrInitialSigningKeyMintFailed = errors.New("session: initial signing key mint failed")
)

// =============================================================================
// Service collaborator interfaces — narrow projections of the Phase 2
// repositories so unit tests can stub without the full DB.
// =============================================================================

// SessionRepo is the slice of repository.SessionRepository the service
// consumes. Defining the projection here keeps the service decoupled
// from the wider repo surface.
type SessionRepo interface {
	Create(ctx context.Context, s *sessiondomain.Session) error
	Get(ctx context.Context, id string) (*sessiondomain.Session, error)
	// ListByActor returns every session row for the (actor_id, actor_type)
	// pair in the tenant. Used by RotateCSRFTokenForActor (Audit
	// 2026-05-10 HIGH-2). Order is implementation-defined; the caller
	// filters revoked/expired rows post-fetch.
	ListByActor(ctx context.Context, actorID, actorType, tenantID string) ([]*sessiondomain.Session, error)
	UpdateLastSeen(ctx context.Context, id string) error
	UpdateCSRFTokenHash(ctx context.Context, id, csrfTokenHash string) error
	Revoke(ctx context.Context, id string) error
	RevokeAllForActor(ctx context.Context, actorID, actorType, tenantID string) error
	// RevokeAllExceptForActor revokes every active session for the
	// actor except the named exceptSessionID; returns the count revoked.
	// Audit 2026-05-10 MED-3 closure — the bench-test stub forwards to
	// this method on the inner *Service.
	RevokeAllExceptForActor(ctx context.Context, actorID, actorType, tenantID, exceptSessionID string) (int, error)
	GarbageCollectExpired(ctx context.Context) (int, error)
}

// SigningKeyRepo is the slice of repository.SessionSigningKeyRepository
// the service consumes.
type SigningKeyRepo interface {
	GetActive(ctx context.Context, tenantID string) (*sessiondomain.SessionSigningKey, error)
	Get(ctx context.Context, id string) (*sessiondomain.SessionSigningKey, error)
	Add(ctx context.Context, k *sessiondomain.SessionSigningKey) error
	Retire(ctx context.Context, id string) error
	List(ctx context.Context, tenantID string) ([]*sessiondomain.SessionSigningKey, error)
	Delete(ctx context.Context, id string) error
}

// AuditRecorder is the slice of service.AuditService the session
// service uses. Every audit row this service emits carries
// event_category=auth (Phase 8 contract).
type AuditRecorder interface {
	RecordEventWithCategory(ctx context.Context, actor string, actorType domain.ActorType, action, eventCategory, resourceType, resourceID string, details map[string]interface{}) error
}

// =============================================================================
// Service.
// =============================================================================

// Service implements the session lifecycle. Construct via NewService.
type Service struct {
	sessions   SessionRepo
	keys       SigningKeyRepo
	audit      AuditRecorder
	tenantID   string
	cfg        Config
	encryption string

	// clockNow is injectable for tests; defaults to time.Now.
	clockNow func() time.Time

	// readRand is injectable for tests; defaults to crypto/rand.Read.
	// Wraps crypto/rand so EnsureInitialSigningKey + Create + RotateCSRFToken
	// can be exercised against a deterministic-failure RNG.
	readRand func([]byte) (int, error)
}

// Config bundles the operator-tunable knobs Phase 4 exposes via
// CERTCTL_SESSION_* env vars. internal/config/config.go owns the
// env-binding + defaulting; this package owns the consumption.
type Config struct {
	// IdleTimeout: maximum time between requests on a single session
	// before re-auth is required. Default 1h. Wire: CERTCTL_SESSION_IDLE_TIMEOUT.
	IdleTimeout time.Duration

	// AbsoluteTimeout: maximum lifetime of a session regardless of
	// activity. Default 8h. Wire: CERTCTL_SESSION_ABSOLUTE_TIMEOUT.
	AbsoluteTimeout time.Duration

	// SigningKeyRetention: time a retired signing key stays valid for
	// verification before being purged. Default 24h. Wire:
	// CERTCTL_SESSION_SIGNING_KEY_RETENTION.
	SigningKeyRetention time.Duration

	// BindIP: when true, Validate compares the request's client IP to
	// the session row's recorded IP. Default false. Mobile + corporate-
	// NAT environments leave this off. Wire: CERTCTL_SESSION_BIND_IP.
	BindIP bool

	// BindUserAgent: when true, Validate compares the request's User-
	// Agent to the session row's recorded UA. Default false. Wire:
	// CERTCTL_SESSION_BIND_USER_AGENT.
	BindUserAgent bool
}

// DefaultConfig returns the Phase 4 defaults. cmd/server/main.go
// merges CERTCTL_SESSION_* env vars over these.
func DefaultConfig() Config {
	return Config{
		IdleTimeout:         1 * time.Hour,
		AbsoluteTimeout:     8 * time.Hour,
		SigningKeyRetention: 24 * time.Hour,
		BindIP:              false,
		BindUserAgent:       false,
	}
}

// NewService constructs a session Service.
//
// encryptionKey is the CERTCTL_CONFIG_ENCRYPTION_KEY value used to
// decrypt SessionSigningKey.KeyMaterialEncrypted blobs. Required in
// production; tests may pass empty (the v3 blob path falls back via
// internal/crypto/encryption.go's plaintext-passthrough behavior when
// the blob is short-circuited via the test-only NewService variant —
// see service_test.go's helpers).
//
// audit may be nil in test setups that don't care about audit rows;
// production wires *service.AuditService from cmd/server/main.go.
func NewService(
	sessions SessionRepo,
	keys SigningKeyRepo,
	audit AuditRecorder,
	tenantID string,
	cfg Config,
	encryptionKey string,
) *Service {
	return &Service{
		sessions:   sessions,
		keys:       keys,
		audit:      audit,
		tenantID:   tenantID,
		cfg:        cfg,
		encryption: encryptionKey,
		clockNow:   time.Now,
		readRand:   cryptorand.Read,
	}
}

// SetClockForTest replaces the clock used for expiry calculations.
// ONLY for tests; production reads time.Now via the default seam.
func (s *Service) SetClockForTest(now func() time.Time) {
	s.clockNow = now
}

// SetRandReaderForTest replaces the entropy source. ONLY for tests;
// production reads crypto/rand via the default seam.
func (s *Service) SetRandReaderForTest(r func([]byte) (int, error)) {
	s.readRand = r
}

// =============================================================================
// Create + cookie minting.
// =============================================================================

// CreateResult is the post-login session payload. The handler sets
// the cookies + redirects.
type CreateResult struct {
	Session     *sessiondomain.Session
	CookieValue string // certctl_session cookie body (`v1.ses-XX.sk-YY.HMAC`)
	CSRFToken   string // certctl_csrf cookie body (32 random bytes b64url)
}

// Create mints a new post-login session row, signs the cookie value,
// and returns both the session-cookie payload and the CSRF token
// plaintext. The handler:
//   - Sets `certctl_session` HttpOnly Secure SameSite=Lax(or Strict) Path=/
//     to CookieValue with Expires=session.AbsoluteExpiresAt.
//   - Sets `certctl_csrf`  Secure SameSite=Lax(or Strict) Path=/ HttpOnly=false
//     to CSRFToken with Expires=session.AbsoluteExpiresAt.
func (s *Service) Create(ctx context.Context, actorID, actorType, ip, userAgent string) (*CreateResult, error) {
	if strings.TrimSpace(actorID) == "" {
		return nil, fmt.Errorf("session: actor_id is required")
	}
	if strings.TrimSpace(actorType) == "" {
		return nil, fmt.Errorf("session: actor_type is required")
	}

	active, err := s.keys.GetActive(ctx, s.tenantID)
	if err != nil {
		return nil, fmt.Errorf("session: get active signing key: %w", err)
	}
	hmacKey, err := decryptKeyMaterial(active.KeyMaterialEncrypted, s.encryption)
	if err != nil {
		return nil, fmt.Errorf("session: decrypt active key material: %w", err)
	}

	sessionID, err := s.newOpaqueID("ses-")
	if err != nil {
		return nil, fmt.Errorf("session: generate session id: %w", err)
	}

	csrfToken, err := s.newCSRFToken()
	if err != nil {
		return nil, fmt.Errorf("session: generate csrf token: %w", err)
	}

	now := s.clockNow().UTC()
	row := &sessiondomain.Session{
		ID:                sessionID,
		ActorID:           actorID,
		ActorType:         actorType,
		SigningKeyID:      active.ID,
		IsPreLogin:        false,
		CSRFTokenHash:     hashCSRFToken(csrfToken),
		IdleExpiresAt:     now.Add(s.cfg.IdleTimeout),
		AbsoluteExpiresAt: now.Add(s.cfg.AbsoluteTimeout),
		CreatedAt:         now,
		LastSeenAt:        now,
		IPAddress:         ip,
		UserAgent:         userAgent,
		TenantID:          s.tenantID,
	}
	if verr := row.Validate(); verr != nil {
		return nil, fmt.Errorf("session: validate row: %w", verr)
	}
	if cerr := s.sessions.Create(ctx, row); cerr != nil {
		return nil, fmt.Errorf("session: create row: %w", cerr)
	}

	cookieValue := signCookie(row.ID, row.SigningKeyID, hmacKey)

	return &CreateResult{
		Session:     row,
		CookieValue: cookieValue,
		CSRFToken:   csrfToken,
	}, nil
}

// =============================================================================
// Validate.
// =============================================================================

// ValidateInput bundles the data Validate needs from the HTTP request.
// The handler builds it from the session cookie, request IP, and
// User-Agent header.
type ValidateInput struct {
	CookieValue string
	ClientIP    string
	UserAgent   string
}

// Validate verifies the cookie's signature, looks up the session row,
// and enforces idle + absolute expiry, revocation, optional IP/UA
// binding. Returns the session on success; one of the package-scoped
// sentinels on failure.
//
// Note: Validate does NOT call UpdateLastSeen — the middleware does
// that explicitly so the test surface stays unambiguous about side
// effects under the read path.
func (s *Service) Validate(ctx context.Context, in ValidateInput) (*sessiondomain.Session, error) {
	sessionID, signingKeyID, providedHMAC, err := parseCookie(in.CookieValue)
	if err != nil {
		return nil, ErrSessionInvalidCookie
	}
	// Defense-in-depth: post-login cookies must carry the `ses-` prefix.
	// Pre-login cookies (`pl-`) are verified by the OIDC pre-login
	// machinery via internal/auth/oidc/prelogin.go and never reach
	// SessionService.Validate.
	if !strings.HasPrefix(sessionID, "ses-") {
		return nil, ErrSessionInvalidCookie
	}

	signingKey, err := s.keys.Get(ctx, signingKeyID)
	if err != nil {
		return nil, ErrSigningKeyNotFound
	}

	now := s.clockNow().UTC()

	// Retired key still in retention window is OK; past retention is not.
	if signingKey.RetiredAt != nil {
		retentionExpiresAt := signingKey.RetiredAt.Add(s.cfg.SigningKeyRetention)
		if now.After(retentionExpiresAt) {
			return nil, ErrSigningKeyRetired
		}
	}

	hmacKey, err := decryptKeyMaterial(signingKey.KeyMaterialEncrypted, s.encryption)
	if err != nil {
		return nil, ErrSessionInvalidCookie
	}

	expectedHMAC := computeHMAC(sessionID, signingKeyID, hmacKey)
	if subtle.ConstantTimeCompare(expectedHMAC, providedHMAC) != 1 {
		return nil, ErrSessionInvalidCookie
	}

	row, err := s.sessions.Get(ctx, sessionID)
	if err != nil {
		return nil, ErrSessionInvalidCookie
	}

	if row.RevokedAt != nil {
		return nil, ErrSessionRevoked
	}

	// Absolute expiry: hard cap regardless of activity.
	if !now.Before(row.AbsoluteExpiresAt) {
		return nil, ErrSessionExpiredAbsolute
	}

	// Idle expiry: re-evaluated against last_seen_at + idle window.
	idleDeadline := row.LastSeenAt.Add(s.cfg.IdleTimeout)
	if !now.Before(idleDeadline) {
		return nil, ErrSessionExpiredIdle
	}

	// Optional defense-in-depth IP / UA binding.
	if s.cfg.BindIP && in.ClientIP != "" && row.IPAddress != "" && in.ClientIP != row.IPAddress {
		s.recordAudit(ctx, "auth.session_ip_mismatch", row.ActorID, domain.ActorType(row.ActorType), row.ID,
			map[string]interface{}{"session_id": row.ID, "expected_ip": row.IPAddress, "request_ip": in.ClientIP})
		return nil, ErrSessionIPMismatch
	}
	if s.cfg.BindUserAgent && in.UserAgent != "" && row.UserAgent != "" && in.UserAgent != row.UserAgent {
		s.recordAudit(ctx, "auth.session_ua_mismatch", row.ActorID, domain.ActorType(row.ActorType), row.ID,
			map[string]interface{}{"session_id": row.ID})
		return nil, ErrSessionUAMismatch
	}

	return row, nil
}

// ValidateCSRF compares the SHA-256 of the X-CSRF-Token header against
// the session row's stored hash. Constant-time-compares to defeat
// timing attacks. Empty header → ErrCSRFMissing.
func (s *Service) ValidateCSRF(headerValue string, sess *sessiondomain.Session) error {
	if strings.TrimSpace(headerValue) == "" {
		return ErrCSRFMissing
	}
	if sess == nil || sess.CSRFTokenHash == "" {
		return ErrCSRFMismatch
	}
	provided := hashCSRFToken(headerValue)
	if subtle.ConstantTimeCompare([]byte(provided), []byte(sess.CSRFTokenHash)) != 1 {
		return ErrCSRFMismatch
	}
	return nil
}

// UpdateLastSeen advances the session's last_seen_at to now. Called by
// the middleware on every authenticated request to keep the idle-expiry
// sliding window fresh.
func (s *Service) UpdateLastSeen(ctx context.Context, sessionID string) error {
	if err := s.sessions.UpdateLastSeen(ctx, sessionID); err != nil {
		return fmt.Errorf("session: update_last_seen: %w", err)
	}
	return nil
}

// =============================================================================
// Revoke + RevokeAllForActor + RotateCSRFToken.
// =============================================================================

// Revoke sets revoked_at on the session row. Idempotent at the repo
// layer (re-revoking is a no-op). Subsequent Validate returns
// ErrSessionRevoked.
func (s *Service) Revoke(ctx context.Context, sessionID string) error {
	if err := s.sessions.Revoke(ctx, sessionID); err != nil {
		return fmt.Errorf("session: revoke: %w", err)
	}
	s.recordAudit(ctx, "auth.session_revoked", "system", domain.ActorTypeSystem, sessionID,
		map[string]interface{}{"session_id": sessionID})
	return nil
}

// RevokeAllForActor sets revoked_at on every active session for the
// (actorID, actorType, tenantID) tuple. Used on role change, fired-
// employee scenarios, and the back-channel logout endpoint (Phase 5).
func (s *Service) RevokeAllForActor(ctx context.Context, actorID, actorType string) error {
	if err := s.sessions.RevokeAllForActor(ctx, actorID, actorType, s.tenantID); err != nil {
		return fmt.Errorf("session: revoke_all_for_actor: %w", err)
	}
	s.recordAudit(ctx, "auth.sessions_revoked_for_actor", actorID, domain.ActorType(actorType), actorID,
		map[string]interface{}{"actor_id": actorID, "actor_type": actorType})
	return nil
}

// RotateCSRFToken mints a fresh CSRF token, persists its SHA-256 hash
// on the session row, and returns the plaintext for the handler to
// re-emit in the certctl_csrf cookie. Called on:
//
//   - Login completion (Service.Create already mints a token; explicit
//     rotation here is for follow-up calls).
//   - Logout (defense-in-depth even though the session is revoked).
//   - Any actor-role mutation against this actor.
//   - Explicit operator-triggered "rotate CSRF" admin endpoint.
func (s *Service) RotateCSRFToken(ctx context.Context, sessionID string) (string, error) {
	csrfToken, err := s.newCSRFToken()
	if err != nil {
		return "", fmt.Errorf("session: generate csrf token: %w", err)
	}
	hash := hashCSRFToken(csrfToken)
	if uerr := s.sessions.UpdateCSRFTokenHash(ctx, sessionID, hash); uerr != nil {
		return "", fmt.Errorf("session: update csrf hash: %w", uerr)
	}
	s.recordAudit(ctx, "auth.session_csrf_rotated", "system", domain.ActorTypeSystem, sessionID,
		map[string]interface{}{"session_id": sessionID})
	return csrfToken, nil
}

// RotateCSRFTokenForActor rotates the CSRF token across every active
// (non-revoked) session of the given actor. Returns the count of
// successfully rotated rows. Per-row failures are logged + skipped —
// the function NEVER returns an error to the caller, because rotation
// is defense-in-depth and must not block the role-mutation that
// triggered it.
//
// Audit 2026-05-10 HIGH-2 closure — wires the documented "any actor-
// role mutation rotates this actor's CSRF tokens" contract (see
// RotateCSRFToken doc block). Pre-fix the rotate primitive existed
// but the only call site was Service.Create (login mint).
func (s *Service) RotateCSRFTokenForActor(ctx context.Context, actorID, actorType string) int {
	rows, err := s.sessions.ListByActor(ctx, actorID, actorType, s.tenantID)
	if err != nil {
		slog.WarnContext(ctx, "session: list-by-actor for csrf rotate failed",
			"actor_id", actorID, "actor_type", actorType, "err", err)
		return 0
	}
	rotated := 0
	now := s.clockNow().UTC()
	for _, sess := range rows {
		// Skip revoked / expired rows — they're not consultable anyway.
		if sess.RevokedAt != nil {
			continue
		}
		if sess.AbsoluteExpiresAt.Before(now) || sess.IdleExpiresAt.Before(now) {
			continue
		}
		if _, rerr := s.RotateCSRFToken(ctx, sess.ID); rerr != nil {
			slog.WarnContext(ctx, "session: csrf rotate per-row failed",
				"actor_id", actorID, "session_id", sess.ID, "err", rerr)
			continue
		}
		rotated++
	}
	return rotated
}

// =============================================================================
// Signing-key lifecycle.
// =============================================================================

// RotateSigningKey mints a fresh 32-byte HMAC key, persists it as the
// new active key, and retires the previously-active key. The retired
// key stays valid for verification during cfg.SigningKeyRetention so
// existing cookies don't immediately fail; the GarbageCollect sweep
// purges it after the retention window passes (and after no sessions
// reference it).
func (s *Service) RotateSigningKey(ctx context.Context) error {
	currentActive, err := s.keys.GetActive(ctx, s.tenantID)
	if err != nil {
		// No active key at all: this is a bootstrap-not-yet-run state;
		// EnsureInitialSigningKey is the right entrypoint.
		return fmt.Errorf("session: get active for rotate: %w", err)
	}

	newID, err := s.newOpaqueID("sk-")
	if err != nil {
		return fmt.Errorf("session: generate signing key id: %w", err)
	}
	newPlaintext, err := s.newKeyMaterial()
	if err != nil {
		return fmt.Errorf("session: generate signing key material: %w", err)
	}
	newCiphertext, err := encryptKeyMaterial(newPlaintext, s.encryption)
	if err != nil {
		return fmt.Errorf("session: encrypt signing key material: %w", err)
	}

	newKey := &sessiondomain.SessionSigningKey{
		ID:                   newID,
		TenantID:             s.tenantID,
		KeyMaterialEncrypted: newCiphertext,
	}
	if verr := newKey.Validate(); verr != nil {
		return fmt.Errorf("session: validate new key: %w", verr)
	}
	if aerr := s.keys.Add(ctx, newKey); aerr != nil {
		return fmt.Errorf("session: add new signing key: %w", aerr)
	}

	if rerr := s.keys.Retire(ctx, currentActive.ID); rerr != nil {
		return fmt.Errorf("session: retire previous active key: %w", rerr)
	}

	s.recordAudit(ctx, "auth.session_signing_key_rotated", "system", domain.ActorTypeSystem, newID,
		map[string]interface{}{"new_key_id": newID, "retired_key_id": currentActive.ID})
	return nil
}

// EnsureInitialSigningKey is idempotent: if a non-retired signing key
// exists for the tenant, it returns nil. Otherwise it mints a fresh
// 32-byte key, persists it, and emits an
// auth.session_signing_key_bootstrap audit row with event_category=auth.
//
// Production wires this into cmd/server/main.go startup AFTER
// migrations + RBAC backfill, BEFORE the HTTP listener binds. Failure
// is fatal — the server refuses to boot rather than serve session-less.
func (s *Service) EnsureInitialSigningKey(ctx context.Context) error {
	_, err := s.keys.GetActive(ctx, s.tenantID)
	if err == nil {
		return nil // a key already exists; idempotent no-op.
	}

	// Any error other than "not found" should bubble; the boot loader
	// fails fatal regardless, but distinguishing repo-error from
	// no-row-yet is useful in logs.
	if !errors.Is(err, repository.ErrSessionSigningKeyNotFound) {
		return fmt.Errorf("session: probe active signing key: %w", err)
	}

	newID, err := s.newOpaqueID("sk-")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInitialSigningKeyMintFailed, err)
	}
	plaintext, err := s.newKeyMaterial()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInitialSigningKeyMintFailed, err)
	}
	ciphertext, err := encryptKeyMaterial(plaintext, s.encryption)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInitialSigningKeyMintFailed, err)
	}

	k := &sessiondomain.SessionSigningKey{
		ID:                   newID,
		TenantID:             s.tenantID,
		KeyMaterialEncrypted: ciphertext,
	}
	if verr := k.Validate(); verr != nil {
		return fmt.Errorf("%w: validate: %v", ErrInitialSigningKeyMintFailed, verr)
	}
	if aerr := s.keys.Add(ctx, k); aerr != nil {
		return fmt.Errorf("%w: persist: %v", ErrInitialSigningKeyMintFailed, aerr)
	}

	s.recordAudit(ctx, "auth.session_signing_key_bootstrap", "system", domain.ActorTypeSystem, newID,
		map[string]interface{}{"key_id": newID})
	return nil
}

// =============================================================================
// GarbageCollect.
// =============================================================================

// GarbageCollect runs one sweep:
//   - Deletes sessions whose absolute_expires_at is in the past
//     (post-login expired) AND pre-login rows older than 10 minutes
//     (delegated to the repo's GarbageCollectExpired).
//   - Deletes signing keys whose retired_at + retention window has
//     passed AND that are not still referenced by sessions (the FK
//     ON DELETE RESTRICT in the schema is the safety net; we attempt
//     and ignore ErrSessionSigningKeyInUse).
//
// Wired into the scheduler's sessionGCLoop on a CERTCTL_SESSION_GC_INTERVAL
// tick (default 1h). Returns the count of session rows deleted.
func (s *Service) GarbageCollect(ctx context.Context) (int, error) {
	deleted, err := s.sessions.GarbageCollectExpired(ctx)
	if err != nil {
		return 0, fmt.Errorf("session: gc expired sessions: %w", err)
	}

	// Sweep retired-and-expired signing keys. Best-effort; in-use keys
	// (FK reference) are skipped by the repo's ErrSessionSigningKeyInUse
	// return.
	keys, listErr := s.keys.List(ctx, s.tenantID)
	if listErr != nil {
		// Listing failed but we already deleted sessions; return the
		// session count + the list error so the operator sees both.
		return deleted, fmt.Errorf("session: gc list keys: %w", listErr)
	}
	now := s.clockNow().UTC()
	for _, k := range keys {
		if k.RetiredAt == nil {
			continue
		}
		if !now.After(k.RetiredAt.Add(s.cfg.SigningKeyRetention)) {
			continue
		}
		if derr := s.keys.Delete(ctx, k.ID); derr != nil {
			// In-use keys (sessions still reference) are kept; any other
			// error short-circuits to surface it.
			if errors.Is(derr, repository.ErrSessionSigningKeyInUse) {
				continue
			}
			return deleted, fmt.Errorf("session: gc delete signing key %s: %w", k.ID, derr)
		}
	}
	return deleted, nil
}

// =============================================================================
// Helpers.
// =============================================================================

// SignCookieValue is the public wrapper around the cookie-signing helper.
// Phase 5's pre-login cookie machinery (internal/auth/oidc/prelogin.go)
// reuses this so the cookie wire format stays identical across both
// post-login and pre-login surfaces. id1 is the resource identifier
// (`ses-...` or `pl-...`); id2 is the signing-key id; hmacKey is the
// 32-byte plaintext HMAC key.
func SignCookieValue(id1, id2 string, hmacKey []byte) string {
	return signCookie(id1, id2, hmacKey)
}

// ParseCookieValue is the public wrapper around the cookie-parser. It
// validates the v1. version prefix, splits the four segments,
// base64url-decodes the HMAC, and returns the two embedded ids + the
// HMAC bytes. Caller is responsible for the HMAC re-compute /
// constant-time compare. expectedID1Prefix is the prefix the caller
// expects on segment 1 ("ses-" for post-login, "pl-" for pre-login);
// passing empty skips the prefix check.
func ParseCookieValue(cookieValue, expectedID1Prefix string) (id1, id2 string, hmacBytes []byte, err error) {
	id1, id2, hmacBytes, err = parseCookie(cookieValue)
	if err != nil {
		return "", "", nil, err
	}
	if expectedID1Prefix != "" && !strings.HasPrefix(id1, expectedID1Prefix) {
		return "", "", nil, errInvalidIDPrefix
	}
	return id1, id2, hmacBytes, nil
}

// ComputeCookieHMAC is the public wrapper around the length-prefixed
// HMAC compute helper. Pre-login cookie verification uses this to
// recompute the HMAC against the same canonical input the post-login
// signing path uses.
func ComputeCookieHMAC(id1, id2 string, hmacKey []byte) []byte {
	return computeHMAC(id1, id2, hmacKey)
}

// DecryptKeyMaterial is the public wrapper around decryptKeyMaterial.
// Pre-login cookie verification uses this to derive the HMAC key from
// the SessionSigningKey row's key_material_encrypted blob.
func DecryptKeyMaterial(blob []byte, passphrase string) ([]byte, error) {
	return decryptKeyMaterial(blob, passphrase)
}

var errInvalidIDPrefix = errors.New("session: cookie id has unexpected prefix")

// signCookie returns the wire-format session cookie value:
// `v1.<session_id>.<signing_key_id>.<base64url-no-pad(HMAC-SHA256)>`.
func signCookie(sessionID, signingKeyID string, hmacKey []byte) string {
	mac := computeHMAC(sessionID, signingKeyID, hmacKey)
	return fmt.Sprintf("%s.%s.%s.%s",
		sessiondomain.CookieFormatVersion,
		sessionID,
		signingKeyID,
		base64.RawURLEncoding.EncodeToString(mac),
	)
}

// computeHMAC returns the HMAC-SHA256 over the LENGTH-PREFIXED
// canonical input
//
//	len(sessionID) || ":" || sessionID || ":" || len(signingKeyID) || ":" || signingKeyID
//
// where len(...) is the ASCII decimal byte-length. The length prefix
// is load-bearing: without it, `<a, bc>` and `<ab, c>` produce
// identical input and a forger could swap one byte across the boundary.
func computeHMAC(sessionID, signingKeyID string, hmacKey []byte) []byte {
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(strconv.Itoa(len(sessionID))))
	mac.Write([]byte(":"))
	mac.Write([]byte(sessionID))
	mac.Write([]byte(":"))
	mac.Write([]byte(strconv.Itoa(len(signingKeyID))))
	mac.Write([]byte(":"))
	mac.Write([]byte(signingKeyID))
	return mac.Sum(nil)
}

// parseCookie splits the wire format and returns the three identifying
// parts plus the decoded HMAC. Any format/version/decode failure
// returns an error; the caller maps to ErrSessionInvalidCookie without
// surfacing which check failed (no information leak).
func parseCookie(cookieValue string) (sessionID, signingKeyID string, hmacBytes []byte, err error) {
	if cookieValue == "" {
		return "", "", nil, errors.New("empty cookie")
	}
	parts := strings.Split(cookieValue, ".")
	if len(parts) != 4 {
		return "", "", nil, errors.New("expected 4 segments")
	}
	if parts[0] != sessiondomain.CookieFormatVersion {
		return "", "", nil, errors.New("unsupported version prefix")
	}
	// Phase 5: parseCookie itself does NOT enforce a fixed prefix on
	// segment 1. The post-login Validate path checks `ses-` via the
	// prefix on the row id; the pre-login verifier (in
	// internal/auth/oidc/prelogin.go) checks `pl-` via the public
	// ParseCookieValue wrapper. Keeping the check out of parseCookie
	// lets both surfaces share the same HMAC parser.
	if parts[1] == "" {
		return "", "", nil, errors.New("session id segment empty")
	}
	if !strings.HasPrefix(parts[2], "sk-") {
		return "", "", nil, errors.New("signing key id missing prefix")
	}
	mac, derr := base64.RawURLEncoding.DecodeString(parts[3])
	if derr != nil {
		return "", "", nil, fmt.Errorf("hmac base64: %w", derr)
	}
	if len(mac) != sha256.Size {
		return "", "", nil, errors.New("hmac length")
	}
	return parts[1], parts[2], mac, nil
}

// hashCSRFToken returns the lowercase-hex SHA-256 of the plaintext
// CSRF token. The session row stores this hash; the cookie holds the
// plaintext.
func hashCSRFToken(plaintext string) string {
	h := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(h[:])
}

// newOpaqueID returns prefix + base64url-no-pad of 16 random bytes.
// 128 bits of entropy is sufficient against guessing for both session
// ids and signing-key ids in any realistic deployment.
func (s *Service) newOpaqueID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := s.readRand(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// newCSRFToken returns base64url-no-pad of 32 random bytes (~256 bits
// of entropy). Plaintext goes in the certctl_csrf cookie; SHA-256
// hash goes on the session row.
func (s *Service) newCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := s.readRand(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// newKeyMaterial returns 32 raw random bytes for use as an HMAC-SHA256
// key. crypto/rand is the source.
func (s *Service) newKeyMaterial() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := s.readRand(b); err != nil {
		return nil, err
	}
	return b, nil
}

// recordAudit is a thin wrapper around s.audit.RecordEventWithCategory
// that swallows audit-layer errors (the audit row is best-effort; a
// failed audit must not block a successful session operation). The
// Phase 8 contract is event_category=auth for everything in this
// service.
func (s *Service) recordAudit(ctx context.Context, action, actor string, actorType domain.ActorType, resourceID string, details map[string]interface{}) {
	if s.audit == nil {
		return
	}
	// Audit 2026-05-10 HIGH-6 partial closure — emit WARN on audit-write
	// failure so the silent row-miss is observable. The transactional-
	// leg WithinTx refactor (action + audit row atomic) is a v3 follow-on.
	if err := s.audit.RecordEventWithCategory(ctx, actor, actorType, action,
		"auth", "session", resourceID, details); err != nil {
		slog.WarnContext(ctx, "session audit write failed (action committed; audit row may be missing)",
			"action", action,
			"actor_id", actor,
			"resource_id", resourceID,
			"err", err)
	}
}
