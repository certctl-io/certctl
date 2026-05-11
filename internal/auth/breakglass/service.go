// Package breakglass — Auth Bundle 2 Phase 7.5 / break-glass admin service.
//
// Decision 4: operator-toggleable local-password admin for the SSO-broken
// case. No second factor in this bundle (WebAuthn pairs in v3 per
// Decision 12). The path exists so an admin can recover when OIDC is
// down; it is NOT for general human auth.
//
// Threat model (load-bearing):
//
//   - Break-glass is a deliberate bypass of the SSO security boundary.
//     An attacker who phishes the password OR finds it in a compromised
//     password manager bypasses MFA, OIDC, and every group-claim gate.
//   - Operators MUST keep CERTCTL_BREAKGLASS_ENABLED=false in steady-
//     state. Enable only during SSO-broken incidents. Disable after
//     recovery.
//   - WebAuthn pairing (v3 per Decision 12) is the load-bearing second
//     factor. Without it, break-glass is best treated as an
//     emergency-only path.
//   - Audit trail surfaces every break-glass action under
//     event_category=auth; the auditor role can monitor for unexpected
//     break-glass logins.
//
// Defense-in-depth (load-bearing):
//
//   - Argon2id with OWASP-2024 parameters (m=64MiB, t=3, p=4, salt=16
//     bytes, output=32 bytes). Per-password random salt; PHC-format
//     hash for forward-compat parameter rotation.
//   - subtle.ConstantTimeCompare on every password verify. Identical
//     timing + identical error shape across the wrong-password,
//     locked-account, and non-existent-actor paths so an attacker
//     cannot probe whether a given actor has break-glass configured.
//   - Lockout state machine: failure_count increments on every wrong
//     attempt; threshold (default 5) trips locked_until = NOW() +
//     duration (default 15m). Successful Authenticate resets the
//     counter. Admin-initiated Unlock also resets.
//   - Surface invisibility: when Service.Enabled() == false, every
//     handler returns 404 (NOT 403) so the surface is invisible to
//     scanners.
//   - Token-leak hygiene: passwords NEVER appear in any log line at
//     any level. Pinned by logging_test.go's slog buffer + grep-assert.
//   - PasswordHash is `json:"-"` on the domain type so a misconfigured
//     handler cannot wire-leak the hash via JSON marshaling.
package breakglass

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	bgdomain "github.com/certctl-io/certctl/internal/auth/breakglass/domain"
	"github.com/certctl-io/certctl/internal/domain"
	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/repository"
)

// =============================================================================
// Service-layer sentinel errors.
// =============================================================================

var (
	// ErrDisabled: Service.Enabled() returned false. The handler MUST
	// translate to HTTP 404 (NOT 403) so the surface is invisible.
	ErrDisabled = errors.New("breakglass: service disabled")

	// ErrInvalidCredentials: wrong password OR account locked OR
	// no credential exists for the actor. The wire response is
	// uniform 401 + identical timing across all three cases.
	ErrInvalidCredentials = errors.New("breakglass: invalid credentials")

	// ErrWeakPassword: SetPassword rejected the input for being
	// shorter than MinPasswordLengthBytes (12) or longer than
	// MaxPasswordLengthBytes (256).
	ErrWeakPassword = errors.New("breakglass: password fails strength requirements (min 12, max 256 bytes)")

	// ErrUnauthenticated: Service.SetPassword / Unlock / RemoveCredential
	// called without a non-empty caller actor id.
	ErrUnauthenticated = errors.New("breakglass: caller is unauthenticated")
)

// =============================================================================
// Config.
// =============================================================================

// Config bundles the operator-tunable knobs Phase 7.5 exposes via
// CERTCTL_BREAKGLASS_* env vars.
type Config struct {
	// Enabled gates the entire service surface. Default false; operator
	// flips to true via CERTCTL_BREAKGLASS_ENABLED. When false, every
	// public method returns ErrDisabled and every handler 404s.
	Enabled bool

	// LockoutThreshold: failure count that trips locked_until. Default 5.
	// Wire: CERTCTL_BREAKGLASS_LOCKOUT_THRESHOLD.
	LockoutThreshold int

	// LockoutDuration: how long the account stays locked after the
	// threshold trips. Default 15m. Wire: CERTCTL_BREAKGLASS_LOCKOUT_DURATION.
	LockoutDuration time.Duration

	// LockoutResetInterval: idle time after last_failure_at before
	// the failure_count resets to 0 on next attempt. Default 1h.
	// Wire: CERTCTL_BREAKGLASS_LOCKOUT_RESET_INTERVAL.
	LockoutResetInterval time.Duration
}

// DefaultConfig returns the Phase 7.5 defaults. cmd/server/main.go
// merges CERTCTL_BREAKGLASS_* env vars over these.
func DefaultConfig() Config {
	return Config{
		Enabled:              false,
		LockoutThreshold:     5,
		LockoutDuration:      15 * time.Minute,
		LockoutResetInterval: 1 * time.Hour,
	}
}

// Argon2id parameters — OWASP 2024 recommendations, fixed.
const (
	argon2Memory      = 64 * 1024 // KiB → 64 MiB
	argon2Iterations  = 3
	argon2Parallelism = 4
	argon2SaltSize    = 16
	argon2OutputSize  = 32
)

// =============================================================================
// Collaborator interfaces (narrow projections for stub-friendly tests).
// =============================================================================

// AuditRecorder is the slice of *service.AuditService used by the
// break-glass service. Every audit row carries event_category=auth.
type AuditRecorder interface {
	RecordEventWithCategory(ctx context.Context, actor string, actorType domain.ActorType, action, eventCategory, resourceType, resourceID string, details map[string]interface{}) error
}

// SessionMinter is the slice of *session.Service the Authenticate path
// uses to mint a post-login session after a successful break-glass
// password verify. Audit 2026-05-10 HIGH-1 closure: SetPassword and
// RemoveCredential now also call RevokeAllForActor on the same
// session.Service so a phished-then-rotated password no longer leaves
// stale sessions alive (CWE-613). The interface gains RevokeAllForActor.
type SessionMinter interface {
	Create(ctx context.Context, actorID, actorType, ip, userAgent string) (cookieValue, csrfToken string, err error)
	RevokeAllForActor(ctx context.Context, actorID, actorType string) error
}

// =============================================================================
// Service.
// =============================================================================

// Service implements the break-glass admin lifecycle.
type Service struct {
	repo     repository.BreakglassCredentialRepository
	audit    AuditRecorder
	sessions SessionMinter
	cfg      Config
	tenantID string

	// Test seams.
	clockNow func() time.Time
	readRand func([]byte) (int, error)
}

// NewService constructs the break-glass service.
func NewService(
	repo repository.BreakglassCredentialRepository,
	audit AuditRecorder,
	sessions SessionMinter,
	cfg Config,
	tenantID string,
) *Service {
	return &Service{
		repo:     repo,
		audit:    audit,
		sessions: sessions,
		cfg:      cfg,
		tenantID: tenantID,
		clockNow: time.Now,
		readRand: rand.Read,
	}
}

// SetClockForTest replaces the clock used for lockout-window
// calculations. ONLY for tests.
func (s *Service) SetClockForTest(now func() time.Time) { s.clockNow = now }

// SetRandReaderForTest replaces the entropy source used for salts.
// ONLY for tests.
func (s *Service) SetRandReaderForTest(r func([]byte) (int, error)) { s.readRand = r }

// Enabled reflects CERTCTL_BREAKGLASS_ENABLED.
func (s *Service) Enabled() bool { return s.cfg.Enabled }

// =============================================================================
// SetPassword — admin-only; sets / rotates the break-glass password.
// =============================================================================

// SetPasswordResult is the return shape for SetPassword.
type SetPasswordResult struct {
	ActorID   string
	CreatedAt time.Time
}

// SetPassword hashes + persists a fresh break-glass password for the
// target actor. Caller must hold auth.breakglass.admin (gated at the
// router level via rbacGate). Audit row: auth.breakglass_password_set.
//
// callerActorID is the operator performing the rotation (audit
// attribution). targetActorID is the actor whose break-glass cred is
// being set.
func (s *Service) SetPassword(ctx context.Context, callerActorID, targetActorID, plaintext string) (*SetPasswordResult, error) {
	if !s.Enabled() {
		return nil, ErrDisabled
	}
	if strings.TrimSpace(callerActorID) == "" {
		return nil, ErrUnauthenticated
	}
	if strings.TrimSpace(targetActorID) == "" {
		return nil, fmt.Errorf("breakglass: target actor id is required")
	}
	if l := len(plaintext); l < bgdomain.MinPasswordLengthBytes || l > bgdomain.MaxPasswordLengthBytes {
		return nil, ErrWeakPassword
	}

	hash, err := s.hashPassword(plaintext)
	if err != nil {
		return nil, fmt.Errorf("breakglass: hash password: %w", err)
	}

	// Try Update first; fall back to Create when the row doesn't exist.
	if uerr := s.repo.UpdatePasswordHash(ctx, targetActorID, s.tenantID, hash); uerr != nil {
		if !errors.Is(uerr, repository.ErrBreakglassNotFound) {
			return nil, fmt.Errorf("breakglass: update: %w", uerr)
		}
		// First-time set — Create the row.
		newID, idErr := s.newID()
		if idErr != nil {
			return nil, fmt.Errorf("breakglass: id generate: %w", idErr)
		}
		cred := &bgdomain.BreakglassCredential{
			ID:           newID,
			TenantID:     s.tenantID,
			ActorID:      targetActorID,
			PasswordHash: hash,
		}
		if cerr := s.repo.Create(ctx, cred); cerr != nil {
			return nil, fmt.Errorf("breakglass: create: %w", cerr)
		}
	}

	s.recordAudit(ctx, "auth.breakglass_password_set", callerActorID, domain.ActorTypeUser, targetActorID,
		map[string]interface{}{"caller_actor_id": callerActorID, "target_actor_id": targetActorID})

	// Audit 2026-05-10 HIGH-1 closure — revoke every active session for
	// the target actor. A phished-then-rotated password must NOT leave
	// the attacker's session alive. Best-effort: failure here is logged
	// + audited but DOES NOT roll back the password rotation (the
	// operator rotated for a reason, and forcing rollback opens a worse
	// window). The audit row distinguishes outcome=session_revoke_failed.
	if s.sessions != nil {
		if rerr := s.sessions.RevokeAllForActor(ctx, targetActorID, string(domain.ActorTypeUser)); rerr != nil {
			slog.WarnContext(ctx, "breakglass: session revoke after password rotation failed",
				"target_actor_id", targetActorID, "err", rerr)
			s.recordAudit(ctx, "auth.breakglass_password_set", callerActorID, domain.ActorTypeUser, targetActorID,
				map[string]interface{}{
					"caller_actor_id": callerActorID,
					"target_actor_id": targetActorID,
					"outcome":         "session_revoke_failed",
				})
		}
	}

	return &SetPasswordResult{
		ActorID:   targetActorID,
		CreatedAt: s.clockNow().UTC(),
	}, nil
}

// =============================================================================
// Authenticate — auth-bypass; the whole point is to log in WITHOUT
// existing creds. Rate-limited at the handler layer. Identical timing
// + identical 401 across the wrong-password, locked-account, and
// non-existent-actor paths.
// =============================================================================

// AuthenticateResult is the return shape for Authenticate.
type AuthenticateResult struct {
	CookieValue string
	CSRFToken   string
}

// Authenticate verifies the supplied plaintext against the stored
// Argon2id hash. Returns (cookie, csrf, nil) on success; ErrInvalidCredentials
// uniformly otherwise.
//
// Failure modes (all return ErrInvalidCredentials at the wire):
//   - Service disabled → ErrDisabled (handler maps to 404).
//   - Actor has no credential row → ErrInvalidCredentials.
//   - Account locked → ErrInvalidCredentials.
//   - Wrong password → ErrInvalidCredentials, failure_count++, may
//     trigger lockout.
//
// On success: failure_count reset, audit row, session minted via
// SessionService.Create.
func (s *Service) Authenticate(ctx context.Context, actorID, plaintext, ip, userAgent string) (*AuthenticateResult, error) {
	if !s.Enabled() {
		return nil, ErrDisabled
	}

	cred, err := s.repo.GetByActor(ctx, actorID, s.tenantID)
	if err != nil {
		// Both not-found AND DB error map to identical-shape error
		// + identical timing path. Audit the attempt.
		s.recordAudit(ctx, "auth.breakglass_login_failed", actorID, domain.ActorTypeUser, actorID,
			map[string]interface{}{
				"actor_id":         actorID,
				"failure_category": "no_credential_or_lookup_error",
				"ip_address":       ip,
			})
		// Run a dummy Argon2id verify to keep timing parity with
		// the wrong-password path (so an attacker can't
		// time-side-channel "actor has no breakglass row").
		_ = s.verifyDummy(plaintext)
		return nil, ErrInvalidCredentials
	}

	now := s.clockNow().UTC()

	// Lockout check.
	if cred.LockedUntil != nil && now.Before(*cred.LockedUntil) {
		s.recordAudit(ctx, "auth.breakglass_login_failed", actorID, domain.ActorTypeUser, actorID,
			map[string]interface{}{
				"actor_id":         actorID,
				"failure_category": "locked",
				"ip_address":       ip,
			})
		// Run dummy verify for timing parity.
		_ = s.verifyDummy(plaintext)
		return nil, ErrInvalidCredentials
	}

	// Reset-window check: if last_failure_at is older than
	// LockoutResetInterval, the failure_count has aged out — reset
	// it before this attempt counts.
	if cred.LastFailureAt != nil && now.Sub(*cred.LastFailureAt) > s.cfg.LockoutResetInterval && cred.FailureCount > 0 {
		_ = s.repo.ResetFailureCount(ctx, actorID, s.tenantID)
	}

	// Constant-time verify against the stored Argon2id PHC hash.
	ok, verr := verifyPassword(plaintext, cred.PasswordHash)
	if verr != nil || !ok {
		// Wrong password (or hash format corruption). Increment +
		// possibly lock + audit + return ErrInvalidCredentials.
		_, _ = s.repo.IncrementFailure(ctx, actorID, s.tenantID, s.cfg.LockoutThreshold, int(s.cfg.LockoutDuration.Seconds()))
		s.recordAudit(ctx, "auth.breakglass_login_failed", actorID, domain.ActorTypeUser, actorID,
			map[string]interface{}{
				"actor_id":         actorID,
				"failure_category": "wrong_password",
				"ip_address":       ip,
			})
		return nil, ErrInvalidCredentials
	}

	// Success. Reset counter, audit, mint session.
	_ = s.repo.ResetFailureCount(ctx, actorID, s.tenantID)
	s.recordAudit(ctx, "auth.breakglass_login_succeeded", actorID, domain.ActorTypeUser, actorID,
		map[string]interface{}{"actor_id": actorID, "ip_address": ip})

	if s.sessions == nil {
		// Test path / no session minter wired. Return zero result.
		return &AuthenticateResult{}, nil
	}
	cookie, csrf, mintErr := s.sessions.Create(ctx, actorID, string(domain.ActorTypeUser), ip, userAgent)
	if mintErr != nil {
		return nil, fmt.Errorf("breakglass: session mint: %w", mintErr)
	}
	return &AuthenticateResult{
		CookieValue: cookie,
		CSRFToken:   csrf,
	}, nil
}

// =============================================================================
// Unlock — admin-only; resets failure_count + clears locked_until.
// =============================================================================

// Unlock clears the lockout state for the named actor. Caller must
// hold auth.breakglass.admin. Audit row: auth.breakglass_unlocked.
func (s *Service) Unlock(ctx context.Context, callerActorID, targetActorID string) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	if strings.TrimSpace(callerActorID) == "" {
		return ErrUnauthenticated
	}
	if err := s.repo.ResetFailureCount(ctx, targetActorID, s.tenantID); err != nil {
		return fmt.Errorf("breakglass: unlock: %w", err)
	}
	s.recordAudit(ctx, "auth.breakglass_unlocked", callerActorID, domain.ActorTypeUser, targetActorID,
		map[string]interface{}{"caller_actor_id": callerActorID, "target_actor_id": targetActorID})
	return nil
}

// =============================================================================
// RemoveCredential — admin-only.
// =============================================================================

// RemoveCredential deletes the break-glass credential row for the
// named actor. Active sessions for that actor are NOT auto-revoked
// (separate concern; the operator can call SessionService.RevokeAll
// in lockstep). Audit row: auth.breakglass_credential_removed.
func (s *Service) RemoveCredential(ctx context.Context, callerActorID, targetActorID string) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	if strings.TrimSpace(callerActorID) == "" {
		return ErrUnauthenticated
	}
	if err := s.repo.Delete(ctx, targetActorID, s.tenantID); err != nil {
		return fmt.Errorf("breakglass: remove: %w", err)
	}
	s.recordAudit(ctx, "auth.breakglass_credential_removed", callerActorID, domain.ActorTypeUser, targetActorID,
		map[string]interface{}{"caller_actor_id": callerActorID, "target_actor_id": targetActorID})

	// Audit 2026-05-10 HIGH-1 closure — credential removal must also
	// revoke every active break-glass session for the target actor.
	// Best-effort with WARN on failure; the credential removal already
	// succeeded so we don't roll back.
	if s.sessions != nil {
		if rerr := s.sessions.RevokeAllForActor(ctx, targetActorID, string(domain.ActorTypeUser)); rerr != nil {
			slog.WarnContext(ctx, "breakglass: session revoke after credential remove failed",
				"target_actor_id", targetActorID, "err", rerr)
			s.recordAudit(ctx, "auth.breakglass_credential_removed", callerActorID, domain.ActorTypeUser, targetActorID,
				map[string]interface{}{
					"caller_actor_id": callerActorID,
					"target_actor_id": targetActorID,
					"outcome":         "session_revoke_failed",
				})
		}
	}
	return nil
}

// List returns the metadata for every break-glass credential in the
// tenant. Audit 2026-05-10 CRIT-4 closure — backs the GUI admin page
// that enumerates credentialed actors. Returns ErrDisabled when the
// service is off (callers map to 404 for surface invisibility).
//
// The returned rows DO include the password_hash field (the service
// boundary is the repo; the handler is responsible for stripping the
// hash from the wire response).
func (s *Service) List(ctx context.Context) ([]*bgdomain.BreakglassCredential, error) {
	if !s.Enabled() {
		return nil, ErrDisabled
	}
	out, err := s.repo.List(ctx, s.tenantID)
	if err != nil {
		return nil, fmt.Errorf("breakglass: list: %w", err)
	}
	return out, nil
}

// =============================================================================
// Helpers — Argon2id hash + verify, ID generation, audit, dummy verify.
// =============================================================================

// hashPassword runs Argon2id over plaintext + a fresh 16-byte random
// salt; returns the PHC-format string.
func (s *Service) hashPassword(plaintext string) (string, error) {
	salt := make([]byte, argon2SaltSize)
	if _, err := s.readRand(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(plaintext), salt,
		uint32(argon2Iterations), uint32(argon2Memory),
		uint8(argon2Parallelism), uint32(argon2OutputSize))
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2Memory, argon2Iterations, argon2Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// verifyPassword parses a PHC-format Argon2id hash, recomputes the hash
// over plaintext + the embedded salt + embedded params, and constant-
// time-compares. Returns (true, nil) on match; (false, nil) on mismatch;
// non-nil err only on hash-format-corruption (caller treats as auth fail).
func verifyPassword(plaintext, encoded string) (bool, error) {
	if !strings.HasPrefix(encoded, bgdomain.Argon2idPHCPrefix) {
		return false, fmt.Errorf("not an argon2id hash")
	}
	parts := strings.Split(encoded, "$")
	// Format: $argon2id$v=N$m=M,t=T,p=P$<salt-base64>$<hash-base64>
	// Split by $ → ["", "argon2id", "v=N", "m=M,t=T,p=P", "<salt>", "<hash>"]
	if len(parts) != 6 {
		return false, fmt.Errorf("malformed argon2id hash (parts=%d)", len(parts))
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("parse version: %w", err)
	}
	if version != argon2.Version {
		return false, fmt.Errorf("incompatible argon2id version: %d (want %d)", version, argon2.Version)
	}
	var memory, iters, parallelism uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iters, &parallelism); err != nil {
		return false, fmt.Errorf("parse params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}
	got := argon2.IDKey([]byte(plaintext), salt, iters, memory, uint8(parallelism), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// verifyDummy runs a real Argon2id pass against fixed params + a
// throwaway salt so the wrong-password / no-credential / locked-account
// paths take statistically indistinguishable time. The result is
// discarded.
func (s *Service) verifyDummy(plaintext string) bool {
	// Audit 2026-05-10 LOW-4 closure — was an all-zeros salt; while the
	// wall-clock cost matched a real verify (the 64MiB Argon2id
	// allocation dominates), cache/branch behavior differed enough to
	// give a subtle timing side channel. Use crypto/rand for the dummy
	// salt too. If RNG fails, fall back to all-zeros (the timing parity
	// is still preserved by the dominant Argon2id memory cost).
	dummySalt := make([]byte, argon2SaltSize)
	_, _ = s.readRand(dummySalt)
	_ = argon2.IDKey([]byte(plaintext), dummySalt,
		uint32(argon2Iterations), uint32(argon2Memory),
		uint8(argon2Parallelism), uint32(argon2OutputSize))
	return false
}

// newID returns `bg-<base64url-no-pad-of-16-random-bytes>`.
func (s *Service) newID() (string, error) {
	b := make([]byte, 16)
	if _, err := s.readRand(b); err != nil {
		return "", err
	}
	return "bg-" + base64.RawURLEncoding.EncodeToString(b), nil
}

// recordAudit is a thin wrapper that swallows audit errors (best-effort;
// a failed audit must not block a successful auth operation). Phase 8
// contract: every row event_category=auth.
func (s *Service) recordAudit(ctx context.Context, action, actor string, actorType domain.ActorType, resourceID string, details map[string]interface{}) {
	if s.audit == nil {
		return
	}
	// Audit 2026-05-10 HIGH-6 partial closure — emit WARN on audit-write
	// failure so a silent row-miss is observable. The transactional-leg
	// WithinTx refactor (action + audit row atomic) is a v3 follow-on.
	if err := s.audit.RecordEventWithCategory(ctx, actor, actorType, action,
		domain.EventCategoryAuth, "breakglass_credential", resourceID, details); err != nil {
		slog.WarnContext(ctx, "breakglass audit write failed (action committed; audit row may be missing)",
			"action", action,
			"actor_id", actor,
			"resource_id", resourceID,
			"err", err)
	}
}

// _ ensures authdomain import is live in case future service code needs
// the canonical permission constants.
var _ = authdomain.RoleIDAdmin
