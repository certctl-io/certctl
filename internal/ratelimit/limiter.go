// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import "time"

// Limiter is the rate-limit primitive every caller in cmd/server +
// internal/api/handler + internal/service consumes. Two backends
// satisfy this interface:
//
//   - SlidingWindowLimiter (in-memory; the historical default;
//     declared in sliding_window.go).
//   - PostgresSlidingWindowLimiter (cross-replica-consistent;
//     declared in postgres_sliding_window.go; introduced in Phase 13
//     Sprint 13.2 for the ARCH-M1 substantive close).
//
// Sprint 13.3 (next) wires every call site through the operator-
// chosen backend via the CERTCTL_RATELIMIT_BACKEND={memory,postgres}
// env var. Until then, both backends compile + tests for both pass,
// but the production call sites still construct SlidingWindowLimiter
// directly.
//
// Sprint 13.2 signature note: the prompt template specified
// `Allow(key string) error`, but the actual repo signature has been
// `Allow(key string, now time.Time) error` since the EST RFC 7030
// hardening master bundle Phase 4.1 — the `now` parameter is what
// makes the memory limiter testable against synthetic time. The
// interface matches the actual signature so the existing
// SlidingWindowLimiter satisfies Limiter without a method-set change.
//
// Per CLAUDE.md "the repo is truth" principle, code grounded against
// the live signature (not the prompt's draft).
type Limiter interface {
	// Allow records a request at the given key/time and returns
	// ErrRateLimited if the configured cap is exceeded inside the
	// configured window. nil otherwise.
	//
	// Empty `key` short-circuits to nil (caller's defense-in-depth;
	// caller upstream validation should reject empty-key events
	// first — building a single shared bucket keyed by empty-key
	// would be a chokepoint for every empty-key event).
	//
	// Disabled limiters (maxN <= 0) return nil for every call.
	Allow(key string, now time.Time) error
}

// Compile-time interface satisfaction checks. Drift in either
// backend's Allow signature fails the build at this file before any
// caller breaks.
var (
	_ Limiter = (*SlidingWindowLimiter)(nil)
	_ Limiter = (*PostgresSlidingWindowLimiter)(nil)
)
