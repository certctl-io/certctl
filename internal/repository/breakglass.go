package repository

import (
	"context"
	"errors"

	bgdomain "github.com/certctl-io/certctl/internal/auth/breakglass/domain"
)

// Sentinel errors for the BreakglassCredentialRepository. Postgres
// implementation translates SQLSTATE codes into these so handler /
// service code can branch via errors.Is.
var (
	// ErrBreakglassNotFound: GetByActor / Get found no row. The
	// service-layer Authenticate path treats this as "wrong password"
	// at the wire (uniform 401, identical timing) so the existence of
	// a break-glass credential for a given actor cannot be probed.
	ErrBreakglassNotFound = errors.New("breakglass: credential not found")

	// ErrBreakglassDuplicate: Create tripped the (actor_id) UNIQUE
	// constraint. SetPassword should use Upsert semantics; if a caller
	// invokes Create on an actor that already has a row, this surfaces
	// as a 409.
	ErrBreakglassDuplicate = errors.New("breakglass: credential already exists for actor")
)

// BreakglassCredentialRepository wraps the breakglass_credentials
// table. Auth Bundle 2 Phase 7.5 — see internal/auth/breakglass/service.go
// for the consumer.
type BreakglassCredentialRepository interface {
	// Create persists a new credential row. Caller MUST have called
	// c.Validate() and computed the Argon2id PHC-format password hash.
	// Returns ErrBreakglassDuplicate when (actor_id) UNIQUE fires.
	Create(ctx context.Context, c *bgdomain.BreakglassCredential) error

	// GetByActor returns the credential for the named actor. Returns
	// ErrBreakglassNotFound on miss.
	GetByActor(ctx context.Context, actorID, tenantID string) (*bgdomain.BreakglassCredential, error)

	// UpdatePasswordHash rotates the password hash + bumps
	// last_password_change_at. Resets failure_count + clears
	// locked_until (a fresh password starts unlocked).
	UpdatePasswordHash(ctx context.Context, actorID, tenantID, newHash string) error

	// IncrementFailure increments failure_count + sets last_failure_at;
	// when the new count crosses the threshold, sets locked_until.
	// Returns the updated row so the service can see the post-update
	// failure_count + locked_until without a re-read. Atomic single-
	// statement UPDATE so concurrent failed attempts can't race past
	// the threshold.
	IncrementFailure(ctx context.Context, actorID, tenantID string, threshold int, lockoutDurationSec int) (*bgdomain.BreakglassCredential, error)

	// ResetFailureCount clears failure_count + locked_until. Used on
	// successful Authenticate AND on admin-initiated Unlock.
	ResetFailureCount(ctx context.Context, actorID, tenantID string) error

	// Delete removes a credential row. Returns ErrBreakglassNotFound
	// on miss. Active sessions for the actor are NOT auto-revoked
	// (separate concern; the operator can call SessionService.RevokeAll
	// in lockstep).
	Delete(ctx context.Context, actorID, tenantID string) error

	// List returns the metadata for every break-glass credential in the
	// tenant. The password hash is NOT included in the returned rows —
	// the admin GUI uses this to render the credentialed-actor table
	// (audit 2026-05-10 CRIT-4 closure). Order: created_at ASC.
	List(ctx context.Context, tenantID string) ([]*bgdomain.BreakglassCredential, error)
}
