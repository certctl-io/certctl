package intune

import (
	"time"

	"github.com/certctl-io/certctl/internal/ratelimit"
)

// SCEP RFC 8894 + Intune master bundle Phase 8.6.
//
// PerDeviceRateLimiter is the second line of defense behind the replay
// cache from Phase 7. The replay cache catches the same challenge being
// submitted twice (within the challenge TTL); this rate limiter catches a
// compromised Connector signing key (or a stolen key+cert pair) issuing
// many DIFFERENT valid challenges for the same device subject in a short
// window.
//
// Threat model:
//
//   - Replay cache (Phase 7): nonce-keyed; catches duplicate submission.
//   - This limiter: (Subject, Issuer)-keyed; catches enrollment-flooding.
//
// EST RFC 7030 hardening master bundle Phase 4.1: the implementation that
// used to live in this file was extracted to internal/ratelimit (where it
// can be shared with EST per-principal + EST HTTP-Basic source-IP rate
// limiters). PerDeviceRateLimiter is now a thin wrapper around
// ratelimit.SlidingWindowLimiter that preserves the original
// (subject, issuer) → key composition in the Allow signature so existing
// SCEP/Intune callers don't have to change.
//
// New callers SHOULD use ratelimit.SlidingWindowLimiter directly. The
// EST RFC 7030 Phase 4.2 EST per-principal cap uses the shared package.

// ErrRateLimited is the typed error returned when the per-device rate
// limit fires. Aliased to ratelimit.ErrRateLimited so errors.Is matches
// against either name (the SCEP audit closure already pinned the
// "rate_limited" metric label against this sentinel; the alias preserves
// sentinel identity across the package boundary).
var ErrRateLimited = ratelimit.ErrRateLimited

// PerDeviceRateLimiter wraps ratelimit.SlidingWindowLimiter with the
// (subject, issuer)-composed-key Allow signature the Intune dispatcher
// uses. Concurrency-safe (the underlying limiter holds the mutex).
type PerDeviceRateLimiter struct {
	inner *ratelimit.SlidingWindowLimiter
}

// NewPerDeviceRateLimiter returns a limiter with the given per-key cap +
// window. maxN ≤ 0 disables the limiter (all Allow calls return nil);
// this is operator opt-out for the rare case where the per-device cap is
// undesirable (e.g. test harnesses, sketchpad deploys).
//
// Window defaults to 24h when zero. Map cap defaults to 100,000 when zero
// (matches the replay cache cap; see internal/scep/intune/replay.go).
func NewPerDeviceRateLimiter(maxN int, window time.Duration, mapCap int) *PerDeviceRateLimiter {
	return &PerDeviceRateLimiter{inner: ratelimit.NewSlidingWindowLimiter(maxN, window, mapCap)}
}

// Allow checks whether an enrollment for the given (subject, issuer)
// tuple is permitted right now. Returns nil when allowed (and records
// the timestamp in the bucket) or ErrRateLimited when the bucket is at
// maxN.
//
// Empty subject is treated as "skip the limiter" — the caller's claim
// validation should have rejected an empty-subject claim already; this
// is belt-and-suspenders to prevent a single empty-subject bucket from
// becoming a fleet-wide chokepoint.
func (l *PerDeviceRateLimiter) Allow(subject, issuer string, now time.Time) error {
	if subject == "" {
		// Empty-subject early return preserved from the pre-Phase-4.1
		// behavior: ratelimit.SlidingWindowLimiter also short-circuits
		// on empty key, but the explicit check here documents the
		// (subject, issuer) → empty-key contract and saves one call
		// frame in the hot path.
		return nil
	}
	key := subject + "|" + issuer
	return l.inner.Allow(key, now)
}

// Len returns the approximate number of distinct (subject, issuer) keys
// currently tracked. For observability + tests.
func (l *PerDeviceRateLimiter) Len() int { return l.inner.Len() }

// Disabled reports whether the limiter is in opt-out mode (maxN ≤ 0).
// Useful for handler-side gating + admin-endpoint observability.
func (l *PerDeviceRateLimiter) Disabled() bool { return l.inner.Disabled() }
