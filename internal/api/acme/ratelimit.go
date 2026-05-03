// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"errors"
	"sync"
	"time"
)

// Phase 5 — per-account rolling-hour rate limiter for ACME operations.
//
// Architecture:
//   - In-memory token-bucket per (key, action). Restart wipes the
//     buckets; orders/hour caps are eventual-consistency so this is
//     acceptable. Persistent rate limiting is a follow-up if production
//     telemetry shows abuse patterns we can't catch in a single restart
//     cycle (master prompt criterion #11 explicitly accepts this).
//   - Tokens-per-hour math: bucket capacity = perHour, refill rate =
//     perHour / 3600 tokens/sec. A fresh bucket starts full; an over-
//     limit caller drains it then has to wait for replenishment.
//   - Key shape is action-specific: orders use accountID; key-rollover
//     uses accountID; challenge-respond uses challengeID (so a flood
//     against one challenge doesn't burn the whole account's budget).
//
// Concurrency: the outer map is RWMutex-guarded for create-on-demand;
// per-bucket allow() takes a tiny per-bucket Mutex. Mirrors the
// existing internal/api/middleware/middleware.go::keyedRateLimiter
// pattern (different scope, same shape).

// RateLimiter is the per-action token-bucket pool. Construct with
// NewRateLimiter(); pass a single instance into ACMEService via
// SetRateLimiter so all entry points share the same buckets.
type RateLimiter struct {
	mu      sync.RWMutex
	buckets map[string]*rlBucket // keyed by "<action>|<keyID>"
	clock   func() time.Time     // injectable for tests
}

// NewRateLimiter returns an empty RateLimiter. Buckets are created on
// first reference, so a fresh limiter does no work until traffic
// arrives.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		buckets: make(map[string]*rlBucket),
		clock:   time.Now,
	}
}

// SetClock replaces the clock for tests. Production callers leave it
// pointing at time.Now (the constructor default).
func (r *RateLimiter) SetClock(now func() time.Time) {
	if now != nil {
		r.clock = now
	}
}

// Allow returns true when the (action, keyID) bucket has at least one
// token available — and consumes that token. perHour=0 disables the
// limit (always true). Negative perHour is treated as 0.
//
// On hit (first call → first token consumed → returns true). Once
// drained, further calls within the same hour return false until
// elapsed-time refills the bucket.
func (r *RateLimiter) Allow(action, keyID string, perHour int) bool {
	if perHour <= 0 {
		return true
	}
	bucketKey := action + "|" + keyID
	r.mu.RLock()
	b, ok := r.buckets[bucketKey]
	r.mu.RUnlock()
	if !ok {
		r.mu.Lock()
		b, ok = r.buckets[bucketKey]
		if !ok {
			b = &rlBucket{
				capacity:   float64(perHour),
				refillRate: float64(perHour) / 3600.0, // tokens/sec
				tokens:     float64(perHour),
				lastRefill: r.clock(),
			}
			r.buckets[bucketKey] = b
		}
		r.mu.Unlock()
	}
	return b.allow(r.clock)
}

// RetryAfter returns the duration the caller should wait before the
// (action, keyID) bucket has at least one token again. Returns 0 when
// at least one token is currently available. Used by the handler to
// emit a Retry-After header on rateLimited responses.
func (r *RateLimiter) RetryAfter(action, keyID string, perHour int) time.Duration {
	if perHour <= 0 {
		return 0
	}
	bucketKey := action + "|" + keyID
	r.mu.RLock()
	b, ok := r.buckets[bucketKey]
	r.mu.RUnlock()
	if !ok {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tokens >= 1 {
		return 0
	}
	missing := 1 - b.tokens
	if b.refillRate <= 0 {
		// Shouldn't happen (Allow rejects perHour<=0 before bucket
		// creation), but a divide-by-zero here would panic.
		return time.Hour
	}
	secs := missing / b.refillRate
	return time.Duration(secs * float64(time.Second))
}

// rlBucket is the per-(action, keyID) token bucket. Mirrors the shape
// of internal/api/middleware/middleware.go::tokenBucket but with a
// per-hour-shaped refill instead of per-second.
type rlBucket struct {
	mu         sync.Mutex
	capacity   float64
	refillRate float64 // tokens per second
	tokens     float64
	lastRefill time.Time
}

func (b *rlBucket) allow(clock func() time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := clock()
	// Monotonic-clock-safe via t.Sub(t) per Go time-package contract.
	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.refillRate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.lastRefill = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Action constants — keep one source of truth for the bucket-key
// `<action>|...` prefix. Using untyped consts (not iota) so they
// survive cross-process coordination if a follow-up adds shared-state
// rate-limiting.
const (
	ActionNewOrder         = "new_order"
	ActionKeyChange        = "key_change"
	ActionChallengeRespond = "challenge_respond"
)

// ErrRateLimited is the sentinel service-layer entry points return on
// a hit. Handler maps to RFC 7807 + RFC 8555 §6.7
// `urn:ietf:params:acme:error:rateLimited` with Retry-After.
var ErrRateLimited = errors.New("acme: rate limit exceeded")
