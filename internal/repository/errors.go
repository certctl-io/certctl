// Package repository defines the repository-layer error sentinels that
// handlers map to HTTP status codes via errors.Is.
//
// S-2 closure (cat-s6-efc7f6f6bd50): pre-S-2 every handler-side
// not-found dispatch was a `strings.Contains(err.Error(), "not found")`
// site (30+ across internal/api/handler/*.go), brittle to any
// repository-layer message change and untyped against the actual
// failure mode. Post-S-2 the dispatch is type-checked: repositories
// wrap sql.ErrNoRows via fmt.Errorf("...: %w", repository.ErrNotFound)
// and FK constraint violations via repository.ErrForeignKeyConstraint;
// handlers consume via errors.Is. The substring matching is preserved
// at the lib/pq boundary inside `errors.go::isFKError` because the
// PostgreSQL driver returns un-typed *pq.Error values whose codes are
// the canonical signal — but it's confined to one helper rather than
// scattered across every handler file. See unified-audit.md
// cat-s6-efc7f6f6bd50 for the closure rationale.
package repository

import (
	"errors"
	"strings"
)

// ErrNotFound is the canonical sentinel for repository methods that
// return after sql.ErrNoRows (or its wrapped form). Handlers that
// surface a 404 should `errors.Is(err, repository.ErrNotFound)`
// rather than substring-match.
var ErrNotFound = errors.New("repository: row not found")

// ErrForeignKeyConstraint is the canonical sentinel for PostgreSQL
// FK / RESTRICT violations bubbling up from a DELETE or UPDATE.
// Handlers that surface a 409 Conflict should
// `errors.Is(err, repository.ErrForeignKeyConstraint)`.
//
// The B-1 closure introduced ErrRenewalPolicyInUse as the per-entity
// FK sentinel for renewal_policies; future per-entity FK sentinels
// (ErrIssuerInUse, ErrTeamInUse, ErrOwnerInUse) can wrap this generic
// one via fmt.Errorf("...: %w", ErrForeignKeyConstraint) so handlers
// can choose between generic-409 and entity-specific 409 dispatch.
var ErrForeignKeyConstraint = errors.New("repository: foreign key constraint violation")

// IsForeignKeyError detects PostgreSQL FK violation errors from the
// lib/pq driver via the canonical error-text patterns it emits. The
// substring matching is intentionally confined to this helper —
// callers should use this once at the repo layer to wrap into the
// typed ErrForeignKeyConstraint sentinel, then handlers consume via
// errors.Is.
//
// Patterns recognised:
//   - "violates foreign key constraint" (the standard PG message)
//   - "violates restrict" / "RESTRICT" (DELETE blocked by ON DELETE RESTRICT)
//
// Returns false for nil err so callers can defensively chain it.
func IsForeignKeyError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "violates foreign key") ||
		strings.Contains(msg, "RESTRICT") ||
		strings.Contains(msg, "violates restrict")
}
