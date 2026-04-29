package intune

import (
	"errors"
	"sync"
	"time"
)

// SCEP RFC 8894 + Intune master bundle Phase 8.6.
//
// PerDeviceRateLimiter is the second line of defense behind the replay cache
// from Phase 7. The replay cache catches the same challenge being submitted
// twice (within the challenge TTL); this rate limiter catches a compromised
// Connector signing key (or a stolen key+cert pair) issuing many DIFFERENT
// valid challenges for the same device subject in a short window.
//
// Threat model:
//
//   - Replay cache (Phase 7): nonce-keyed; catches duplicate submission.
//   - This limiter: (Subject, Issuer)-keyed; catches enrollment-flooding.
//
// Default: 3 enrollments per (device GUID, Connector identity) per 24h.
//
// Sizing: 100,000 distinct device entries (matches the replay cache cap).
// At-cap: oldest entry evicted (small janitor pass) to avoid unbounded
// memory growth on a fleet that grows past the cap.
//
// Why a hand-rolled token bucket instead of pulling in golang.org/x/time/rate:
// the rate package is in go.sum as an indirect transitive but NOT a direct
// dep. Adding it would create a new direct dep relationship for ~30 LoC of
// state machine. The hand-rolled version below uses only stdlib (sync.Mutex
// + time.Time arithmetic) and is small enough to fit on one screen.
//
// Algorithm: each (Subject, Issuer) key maps to a bucket holding a window's
// worth of recent enrollment timestamps. On Allow, the bucket prunes
// timestamps older than (now - window) and either appends the current
// timestamp + returns true, or rejects + returns false when the post-prune
// count is already at the cap. This is the "sliding window log" rate
// limiter — exact (no token-leak rounding); O(N_per_key) per-call but N is
// bounded by the cap (3 by default), so effectively O(1).

// ErrRateLimited is the typed error returned when the per-device rate limit
// fires. The handler maps this to a CertRep FAILURE with badRequest failInfo
// + the `rate_limited` metric label.
var ErrRateLimited = errors.New("intune: per-device rate limit exceeded for this (subject, issuer) within the configured window")

// PerDeviceRateLimiter is a sliding-window-log rate limiter keyed by
// (Subject, Issuer) tuples derived from a parsed challenge claim.
//
// Concurrency: the limiter is safe for concurrent Allow calls. The internal
// map is guarded by a mutex; the per-key slices are mutated only while the
// mutex is held.
type PerDeviceRateLimiter struct {
	mu       sync.Mutex
	buckets  map[string][]time.Time // key → sliding window of timestamps
	maxN     int                    // max enrollments per window
	window   time.Duration          // window length (default 24h)
	cap      int                    // max keys before LRU eviction kicks in
	disabled bool                   // maxN == 0 → all Allow calls return nil
}

// NewPerDeviceRateLimiter returns a limiter with the given per-key cap +
// window. maxN ≤ 0 disables the limiter (all Allow calls return nil); this
// is operator opt-out for the rare case where the per-device cap is
// undesirable (e.g. test harnesses, sketchpad deploys).
//
// Window defaults to 24h when zero. Map cap defaults to 100,000 when zero
// (matches the replay cache cap; see internal/scep/intune/replay.go).
func NewPerDeviceRateLimiter(maxN int, window time.Duration, mapCap int) *PerDeviceRateLimiter {
	if window <= 0 {
		window = 24 * time.Hour
	}
	if mapCap <= 0 {
		mapCap = 100_000
	}
	return &PerDeviceRateLimiter{
		buckets:  make(map[string][]time.Time),
		maxN:     maxN,
		window:   window,
		cap:      mapCap,
		disabled: maxN <= 0,
	}
}

// Allow checks whether an enrollment for the given (subject, issuer) tuple
// is permitted right now. Returns nil when allowed (and records the timestamp
// in the bucket) or ErrRateLimited when the bucket is at maxN.
//
// Empty subject is treated as "skip the limiter" — the caller's claim
// validation should have rejected an empty-subject claim already; this is
// belt-and-suspenders to prevent a single empty-subject bucket from
// becoming a fleet-wide chokepoint. The Connector emits non-empty subject
// (device GUID) on every legitimate challenge.
func (l *PerDeviceRateLimiter) Allow(subject, issuer string, now time.Time) error {
	if l.disabled {
		return nil
	}
	if subject == "" {
		// Caller's claim validation should reject empty-subject upstream;
		// this short-circuit is defense-in-depth so a misconfigured
		// Connector can't DoS us via the rate-limit path.
		return nil
	}
	key := subject + "|" + issuer

	l.mu.Lock()
	defer l.mu.Unlock()

	// At-cap eviction: when the map is full, drop the oldest entry by
	// finding the bucket whose newest timestamp is the smallest. O(N) but
	// rarely fires; the prune-on-Allow path keeps most buckets short-lived.
	if len(l.buckets) >= l.cap {
		l.evictOldestLocked(now)
	}

	bucket := l.buckets[key]
	bucket = pruneOlderThan(bucket, now.Add(-l.window))

	if len(bucket) >= l.maxN {
		// Don't append; over the limit. Persist the pruned bucket so the
		// next call sees the most-recently-pruned state.
		l.buckets[key] = bucket
		return ErrRateLimited
	}

	bucket = append(bucket, now)
	l.buckets[key] = bucket
	return nil
}

// pruneOlderThan returns the slice with all entries strictly before
// `cutoff` removed. Preserves order (timestamps are appended in increasing
// time, so a single linear scan from the front suffices).
func pruneOlderThan(b []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(b) && b[i].Before(cutoff) {
		i++
	}
	if i == 0 {
		return b
	}
	// Copy-shrink to release the underlying-array memory eventually
	// (otherwise the slice would hold a reference to the older entries
	// indefinitely until a re-allocation).
	out := make([]time.Time, len(b)-i)
	copy(out, b[i:])
	return out
}

// evictOldestLocked drops the map entry whose newest timestamp is the
// oldest. Called under l.mu. O(N_keys) per eviction; at-cap is rare in
// practice (caps are sized for fleet steady-state).
func (l *PerDeviceRateLimiter) evictOldestLocked(now time.Time) {
	var (
		oldestKey string
		oldestTs  time.Time
		first     = true
	)
	for k, b := range l.buckets {
		if len(b) == 0 {
			// Empty bucket — drop it immediately, no candidate scan needed.
			delete(l.buckets, k)
			return
		}
		newest := b[len(b)-1]
		if first || newest.Before(oldestTs) {
			oldestKey = k
			oldestTs = newest
			first = false
		}
	}
	if oldestKey != "" {
		delete(l.buckets, oldestKey)
	}
	// Suppress unused-parameter warning for `now` in case the eviction
	// strategy changes (e.g. swap to LRU keyed by time of last Allow).
	_ = now
}

// Len returns the approximate number of distinct (subject, issuer) keys
// currently tracked. For observability + tests; not load-stable under
// concurrent Allow calls.
func (l *PerDeviceRateLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// Disabled reports whether the limiter is in opt-out mode (maxN ≤ 0).
// Useful for handler-side gating + admin-endpoint observability.
func (l *PerDeviceRateLimiter) Disabled() bool {
	return l.disabled
}
