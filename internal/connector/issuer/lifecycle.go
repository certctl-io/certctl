package issuer

import "context"

// Lifecycle is an OPTIONAL extension interface for issuer connectors that
// need to run long-running background work bound to a context. Connectors
// that hold no background goroutines (almost all of them) do not implement
// this interface and the registry feature-detects via type assertion.
//
// Concrete users today (2026-05-03):
//   - VaultPKI: periodic POST /v1/auth/token/renew-self at TTL/2 cadence
//     so long-lived deploys don't hit token expiry.
//
// The lifecycle contract is deliberately small. Connectors that need
// per-tick state, retries, or cross-tick cancellation handle all of that
// internally; the registry's job is just "kick off background work
// once" and "block until it cleanly exits". Keeping the interface this
// small means new lifecycle-bearing connectors don't have to touch the
// registry plumbing — they implement Start/Stop and the existing
// IssuerRegistry.StartLifecycles / StopLifecycles wiring picks them up
// automatically.
//
// Start MUST be non-blocking — spawn a goroutine and return immediately.
// Returning an error means startup failed; the registry logs the error
// and continues. Stop MUST block until the goroutine has fully exited;
// callers rely on this for graceful shutdown ordering.
type Lifecycle interface {
	// Start kicks off any long-running background work bound to ctx.
	// Returns nil on successful startup; the goroutine continues until
	// ctx is cancelled or Stop is called. Returns a non-nil error if
	// startup itself failed (e.g. precondition not met) — the goroutine
	// did NOT start and Stop need not be called.
	Start(ctx context.Context) error

	// Stop blocks until the background work has fully exited. Safe to
	// call after Start returned an error or wasn't called at all.
	// Idempotent — multiple Stop calls return immediately after the
	// first.
	Stop()
}
