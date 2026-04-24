package handler

import (
	"errors"
	"net/http"

	"github.com/lib/pq"

	"github.com/shankar0123/certctl/internal/repository"
	"github.com/shankar0123/certctl/internal/service"
)

// errToStatus is the single choke point that maps a service-layer or
// repository-layer error to its HTTP status code. Before M-1 (P2), 42 switch
// branches across 11 handler files classified errors via
// `strings.Contains(err.Error(), ...)` substring matching — a pattern that
// made every HTTP status mapping one sentinel-message reword away from silent
// regression (see M-003 self-approval privilege boundary: a reword of
// ErrSelfApproval.Error() would have demoted 403 Forbidden to 500 Internal
// Server Error with no compile-time error, no test failure, and no observable
// external signal).
//
// All handler branches now route through this function via errors.Is and
// errors.As, which walks the wrap chain built by fmt.Errorf("%w: ...", ...).
// The generic sentinels live in internal/service/errors.go; domain-specific
// sentinels (ErrSelfApproval, ErrAgentIsSentinel, ErrBlockedByDependencies,
// ErrForceReasonRequired, ErrAgentNotFound) wrap those generics via %w so both
// errors.Is(err, ErrSelfApproval) and errors.Is(err, ErrForbidden) succeed on
// the same wrapped error.
//
// # Dispatch order
//
//  1. ErrAgentRetired → 410 Gone. Tested FIRST. It is deliberately NOT wrapped
//     under any generic sentinel — 410 Gone is semantically distinct from
//     403/404/409 (permanently-terminated resource identity that drives
//     deterministic agent-binary shutdown at cmd/agent/main.go:1291). Must
//     short-circuit before any generic check so wrapping can never demote it.
//  2. ErrNotFound → 404 Not Found. Both service.ErrNotFound and
//     repository.ErrNotFound route here — repositories wrap sql.ErrNoRows with
//     repository.ErrNotFound so a "row not found" escapes the repo layer as a
//     typed sentinel rather than an untyped fmt.Errorf string. Tested BEFORE
//     ErrForbidden so RFC 7235's preference for hiding resource existence from
//     unauthorized callers is preserved (a caller who cannot see a resource
//     should get 404, not 403).
//  3. ErrUnauthenticated → 401 Unauthorized. SCEP challenge-password mismatch
//     and similar credential failures.
//  4. ErrForbidden → 403 Forbidden. M-003 gate. Tested BEFORE ErrValidation so
//     double-wrapping (e.g., a future fmt.Errorf("%w: ctx", ErrSelfApproval)
//     in a wrapping call site) cannot demote 403 to 400.
//  5. ErrConflict / repository.ErrRenewalPolicyDuplicateName /
//     repository.ErrRenewalPolicyInUse → 409 Conflict. The repo-layer sentinels
//     are routed here explicitly so handlers do not need their own dispatch
//     tree for G-1's renewal-policy FK + unique-name violations.
//  6. ErrValidation → 400 Bad Request. Generic input validation / malformed
//     request bodies / invalid state transitions that the caller could correct
//     by changing their request.
//  7. ErrUnprocessable → 422 Unprocessable Entity. Distinct from
//     ErrValidation: ErrValidation is "caller sent bad input" (400), while
//     ErrUnprocessable is "caller's input was fine but our stored data can't
//     satisfy the operation" — e.g., an X.509 PEM in the inventory that fails
//     to decode. The pre-M-1 ExportPKCS12 handler pinned 422 on
//     strings.Contains(err.Error(), "cannot be parsed"); the sentinel makes
//     that dispatch survive message rewording.
//  8. ErrNotImplemented → 501 Not Implemented. Reserved for feature-flag-gated
//     code paths.
//  9. *pq.Error fallback on SQLSTATE 23503 (FK violation) / 23505 (unique
//     violation) → 409 Conflict. Final branch before the default 500. Anything
//     that reaches here is technically a code smell (the repository layer
//     should normally wrap driver errors into a typed sentinel) but the status
//     mapping is still correct.
//
// # Why a function, not a middleware
//
// Handlers must continue to call [Error] / [ErrorWithRequestID] with a
// caller-chosen human-readable message (sometimes the wrapped err.Error(),
// sometimes a redacted "internal error" for 500s per F-002). This function
// gives handlers the status code; the handler keeps control of the body.
func errToStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}

	switch {
	case errors.Is(err, service.ErrAgentRetired):
		return http.StatusGone // 410 — must short-circuit before generic dispatch
	case errors.Is(err, service.ErrNotFound),
		errors.Is(err, repository.ErrNotFound):
		return http.StatusNotFound // 404 — before ErrForbidden (RFC 7235 existence hiding)
	case errors.Is(err, service.ErrUnauthenticated):
		return http.StatusUnauthorized // 401
	case errors.Is(err, service.ErrForbidden):
		return http.StatusForbidden // 403 — before ErrValidation (preserves M-003 gate under double-wrap)
	case errors.Is(err, service.ErrConflict),
		errors.Is(err, repository.ErrRenewalPolicyDuplicateName),
		errors.Is(err, repository.ErrRenewalPolicyInUse):
		return http.StatusConflict // 409
	case errors.Is(err, service.ErrValidation):
		return http.StatusBadRequest // 400
	case errors.Is(err, service.ErrUnprocessable):
		return http.StatusUnprocessableEntity // 422 — stored-data-unparseable, not caller-input-bad
	case errors.Is(err, service.ErrNotImplemented):
		return http.StatusNotImplemented // 501
	}

	// Driver-level fallback. Raw *pq.Error escaping the repository layer is a
	// code smell but a real escape hatch today — we still want a correct 409
	// instead of a generic 500 for FK/unique violations.
	var pgErr *pq.Error
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23503", "23505":
			return http.StatusConflict
		}
	}

	return http.StatusInternalServerError
}
