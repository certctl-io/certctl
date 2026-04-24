package service

import "errors"

// M-1 (P2) coverage-gap closure: generic service-layer error sentinels.
//
// Before M-1, API handlers classified service errors by substring-matching the
// wrapped message text (`strings.Contains(err.Error(), "not found")` and
// friends). That made every HTTP status mapping one `fmt.Errorf` reword away
// from silently regressing — including the M-003 self-approval privilege
// boundary, where `handler/jobs.go:174/:220` ignored the already-defined
// ErrSelfApproval sentinel and relied on the literal string "cannot approve".
//
// These six generic sentinels form the type-safe surface the handler layer
// dispatches against via `errors.Is`. Domain-specific sentinels (ErrSelfApproval,
// ErrAgentIsSentinel, ErrBlockedByDependencies, ErrForceReasonRequired,
// ErrAgentNotFound) are declared in their own topical files (job.go,
// agent_retire.go, target.go) and wrap one of these generics via
// `fmt.Errorf("%w: ...", ErrForbidden)`. The wrap chain lets call sites continue
// to `errors.Is(err, ErrSelfApproval)` for domain-specific logic while the
// handler's single choke point in `api/handler/errors.go` can match on the
// generic sentinel to pick the HTTP status.
//
// Dispatch order in errToStatus matters — see the doc block at the top of
// `internal/api/handler/errors.go`.
//
// ErrAgentRetired is deliberately NOT wrapped here. 410 Gone is semantically
// distinct from 403/404/409 and must short-circuit the generic dispatch. Keep
// its standalone declaration in agent_retire.go untouched; errToStatus tests
// it first.
var (
	// ErrNotFound indicates a lookup for a resource that does not exist.
	// Handlers translate this to HTTP 404.
	ErrNotFound = errors.New("not found")

	// ErrValidation indicates malformed, missing, or out-of-range input from
	// the caller. Handlers translate this to HTTP 400.
	ErrValidation = errors.New("validation failed")

	// ErrConflict indicates a state conflict: unique-constraint violation,
	// foreign-key dependency, or a state machine transition that is not
	// allowed from the current state. Handlers translate this to HTTP 409.
	ErrConflict = errors.New("conflict")

	// ErrForbidden indicates an authorization / privilege-boundary denial.
	// The caller is authenticated but is not permitted to perform the action.
	// Handlers translate this to HTTP 403.
	ErrForbidden = errors.New("forbidden")

	// ErrUnauthenticated indicates the caller failed to authenticate — most
	// commonly a SCEP challenge-password mismatch, where the transport itself
	// is valid but the application-layer credential is wrong. Handlers
	// translate this to HTTP 401.
	ErrUnauthenticated = errors.New("unauthenticated")

	// ErrNotImplemented indicates the requested operation is defined but not
	// yet wired up — reserved for feature-flag-gated code paths. Handlers
	// translate this to HTTP 501.
	ErrNotImplemented = errors.New("not implemented")

	// ErrUnprocessable indicates the request was well-formed and the
	// referenced resource exists, but server-side stored data could not be
	// processed — e.g., a certificate PEM in inventory that fails X.509
	// decoding because the stored blob is corrupt or was inserted with the
	// wrong encoding. Distinct from ErrValidation: ErrValidation means the
	// caller sent bad input (400), while ErrUnprocessable means the caller's
	// input was fine but our own data cannot satisfy the operation (422
	// Unprocessable Entity). Today the only call site is ExportPKCS12's parse
	// path in internal/service/export.go; keeping the sentinel generic so
	// other "stored-data-unparseable" paths can reuse it without inventing a
	// second variant.
	ErrUnprocessable = errors.New("unprocessable")
)
