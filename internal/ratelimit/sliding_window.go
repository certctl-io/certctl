// Package ratelimit provides shared rate-limit primitives used by
// authenticated-but-shared-credential code paths (SCEP/Intune
// per-device challenge enrollment, EST per-principal CSR enrollment,
// EST HTTP-Basic source-IP failed-auth limiter) where the threat
// model is "single legitimate identity could mint enrollments
// faster than any human/fleet workflow would."
//
// Origin: this package was extracted from
// internal/scep/intune/rate_limit.go in the EST RFC 7030 hardening
// master bundle Phase 4.1 — EST is the third caller after the
// Intune dispatcher (per-device-GUID cap on enrollment) and the EST
// per-principal cap (Phase 4.2). The original Intune-package type +
// constructor + ErrRateLimited sentinel are preserved as type
// aliases at internal/scep/intune/rate_limit.go so existing call
// sites compile unchanged. New callers SHOULD use this package
// directly.
//
// Algorithm: sliding window log. Each key maps to a bucket holding
// timestamps within the configured window. On Allow, the bucket
// prunes timestamps older than (now - window) and either appends +
// returns nil, or rejects + returns ErrRateLimited when the
// post-prune count is already at the cap. Exact (no token-leak
// rounding); O(N_per_key) per-call but N is bounded by the cap, so
// effectively O(1).
//
// Concurrency: safe for concurrent Allow calls. Internal map guarded
// by sync.Mutex; per-key slices mutated only while the mutex is
// held.
//
// Memory: bounded by the per-instance map cap (default 100,000 keys;
// configurable). At-cap eviction drops the oldest entry by newest
// timestamp — small janitor pass; rarely fires in practice because
// the prune-on-Allow path keeps most buckets short-lived.
package ratelimit

import (
	"errors"
	"sync"
	"time"
)

// ErrRateLimited is returned by SlidingWindowLimiter.Allow when the
// bucket for the given key is already at the cap. Callers can
// errors.Is against this sentinel; the underlying message is stable
// across the package's lifetime so test assertions can match on it.
var ErrRateLimited = errors.New("ratelimit: per-key cap exceeded for the configured window")

// SlidingWindowLimiter is the sliding-window-log rate limiter.
//
// Construct via NewSlidingWindowLimiter. The zero value is NOT
// usable — the buckets map needs initialisation.
type SlidingWindowLimiter struct {
	mu       sync.Mutex
	buckets  map[string][]time.Time // key → sliding window of timestamps
	maxN     int                    // max enrollments per window
	window   time.Duration          // window length (default 24h)
	cap      int                    // max keys before LRU eviction kicks in
	disabled bool                   // maxN <= 0 → all Allow calls return nil
}

// NewSlidingWindowLimiter returns a limiter with the given per-key
// cap + window. maxN <= 0 disables the limiter (all Allow calls
// return nil); this is operator opt-out for the rare case where the
// per-key cap is undesirable (test harnesses, sketchpad deploys).
//
// Window defaults to 24h when zero. Map cap defaults to 100,000 when
// zero (matches the SCEP/Intune replay cache cap).
func NewSlidingWindowLimiter(maxN int, window time.Duration, mapCap int) *SlidingWindowLimiter {
	if window <= 0 {
		window = 24 * time.Hour
	}
	if mapCap <= 0 {
		mapCap = 100_000
	}
	return &SlidingWindowLimiter{
		buckets:  make(map[string][]time.Time),
		maxN:     maxN,
		window:   window,
		cap:      mapCap,
		disabled: maxN <= 0,
	}
}

// Allow reports whether an event keyed by `key` is permitted right
// now. Returns nil when allowed (and records the timestamp in the
// bucket) or ErrRateLimited when the bucket is at maxN.
//
// Empty key is treated as "skip the limiter" — the caller's
// validation should have rejected an empty-key event already; this
// is belt-and-suspenders so a single empty-key bucket doesn't
// become a chokepoint for every empty-key event. SCEP/Intune
// callers compose the key as `subject + "|" + issuer`; EST callers
// compose `cn + "|" + sourceIP` or `sourceIP`-alone for the
// failed-auth limiter.
func (l *SlidingWindowLimiter) Allow(key string, now time.Time) error {
	if l.disabled {
		return nil
	}
	if key == "" {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// At-cap eviction: when the map is full, drop the oldest entry
	// by finding the bucket whose newest timestamp is the smallest.
	// O(N_keys) but rarely fires; the prune-on-Allow path keeps
	// most buckets short-lived.
	if len(l.buckets) >= l.cap {
		l.evictOldestLocked()
	}

	bucket := l.buckets[key]
	bucket = pruneOlderThan(bucket, now.Add(-l.window))

	if len(bucket) >= l.maxN {
		// Don't append; over the limit. Persist the pruned bucket so
		// the next call sees the most-recently-pruned state.
		l.buckets[key] = bucket
		return ErrRateLimited
	}

	bucket = append(bucket, now)
	l.buckets[key] = bucket
	return nil
}

// pruneOlderThan returns the slice with all entries strictly before
// `cutoff` removed. Preserves order (timestamps are appended in
// increasing time, so a single linear scan from the front suffices).
func pruneOlderThan(b []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(b) && b[i].Before(cutoff) {
		i++
	}
	if i == 0 {
		return b
	}
	// Copy-shrink to release the underlying-array memory eventually
	// (otherwise the slice would hold a reference to the older
	// entries indefinitely until a re-allocation).
	out := make([]time.Time, len(b)-i)
	copy(out, b[i:])
	return out
}

// evictOldestLocked drops the map entry whose newest timestamp is
// the oldest. Called under l.mu. O(N_keys) per eviction; at-cap is
// rare in practice (caps are sized for steady-state).
func (l *SlidingWindowLimiter) evictOldestLocked() {
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
}

// Len returns the approximate number of distinct keys currently
// tracked. For observability + tests; not load-stable under
// concurrent Allow calls.
func (l *SlidingWindowLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// Disabled reports whether the limiter is in opt-out mode (maxN <= 0).
// Useful for handler-side gating + admin-endpoint observability.
func (l *SlidingWindowLimiter) Disabled() bool {
	return l.disabled
}
