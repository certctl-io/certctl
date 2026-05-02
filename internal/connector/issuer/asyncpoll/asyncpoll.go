// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

// Package asyncpoll provides bounded polling for async-CA issuer
// connectors (DigiCert, Sectigo, Entrust, GlobalSign).
//
// Closes the #5 acquisition-readiness blocker from the 2026-05-01
// issuer coverage audit. Pre-fix, each async-CA connector had its own
// GetOrderStatus path that polled the upstream CA on every scheduler
// tick with no exponential backoff, no max-retry cap, and no deadline.
// The scheduler's tick rate (typically 30s) was the only throttle —
// an unready order got hit every 30s indefinitely, and a 429 from a
// rate-limited upstream produced "retry on the next tick" which
// re-fanned-out the same call.
//
// This package consolidates the four implementations behind a single
// Poller with:
//
//   - Exponential backoff: 5s → 15s → 45s → 2m → 5m capped (default).
//   - ±20% jitter at every wait so multiple certctl instances don't
//     synchronize on the upstream CA's rate-limit window.
//   - MaxWait deadline (default 10m) — a hard cap on how long a
//     single Poll call blocks before returning StillPending. The
//     scheduler can re-enqueue the job for a future tick if the
//     operator's policy allows further attempts.
//   - ctx-aware cancellation — propagates the caller's deadline /
//     cancel through every wait.
//
// Issuer-specific HTTP request shapes live in the PollFunc closure
// passed to Poll; the backoff math is shared.
package asyncpoll

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"
)

// Result is the outcome of one poll attempt.
type Result int

const (
	// StillPending — the upstream is still working on the order;
	// keep polling. The Poller waits, then invokes the PollFunc
	// again (subject to MaxWait).
	StillPending Result = iota

	// Done — the order succeeded. The Poller returns immediately
	// with the (Done, nil) tuple to the caller.
	Done

	// Failed — permanent failure (rejected, denied, malformed
	// response). The Poller returns immediately with (Failed, err)
	// to the caller; no further polling.
	Failed
)

// PollFunc runs ONE poll attempt and reports the outcome.
//
// Returning (StillPending, nil) signals "transient; keep polling"
// and the Poller waits with the backoff schedule.
//
// Returning (StillPending, err) ALSO keeps polling — useful when
// the upstream returned a transient HTTP error (5xx, network blip)
// that the caller wants logged but not treated as fatal.
//
// Returning (Done, nil) signals success.
//
// Returning (Failed, err) signals permanent failure; err must be
// non-nil so the caller can include it in the upstream-facing
// status message.
type PollFunc func(ctx context.Context) (Result, error)

// Config holds the backoff knobs. All fields are optional; zero
// values fall back to package defaults documented inline.
type Config struct {
	// MaxWait — hard cap on total wall-clock time inside Poll. After
	// this expires, Poll returns (StillPending, ErrMaxWait). Default
	// 10 minutes; tune via per-issuer Config.PollMaxWait.
	MaxWait time.Duration

	// InitialWait — first backoff (after the first poll attempt).
	// Default 5 seconds.
	InitialWait time.Duration

	// MaxBackoff — cap on per-iteration wait. Default 5 minutes.
	// Backoff schedule: InitialWait → 3× → 3× → ... capped at
	// MaxBackoff (so 5s → 15s → 45s → 2m15s → 5m → 5m → ... by
	// default).
	MaxBackoff time.Duration

	// JitterPct — fractional jitter applied to every wait, ±value.
	// Default 0.2 (i.e., ±20%). Set to 0 for deterministic timing
	// in tests.
	JitterPct float64
}

// ErrMaxWait is returned (alongside StillPending) when the total
// wall-clock time inside Poll exceeded Config.MaxWait. Callers can
// errors.Is against this sentinel to distinguish "deadline exhausted"
// from "fn errored".
var ErrMaxWait = errors.New("asyncpoll: MaxWait deadline exceeded")

// Defaults. Exported so per-issuer tests can reference the same
// schedule without duplicating constants.
const (
	DefaultMaxWait     = 10 * time.Minute
	DefaultInitialWait = 5 * time.Second
	DefaultMaxBackoff  = 5 * time.Minute
	DefaultJitterPct   = 0.2
)

// Poll runs fn with exponential backoff + jitter until Done, Failed,
// MaxWait, or ctx cancellation.
//
// On Done — returns (Done, nil). The cert is ready; caller proceeds.
//
// On Failed — returns (Failed, fnErr). Permanent; no retry.
//
// On MaxWait timeout — returns (StillPending, ErrMaxWait). The
// upstream isn't done yet but the deadline exhausted. Scheduler
// can re-enqueue.
//
// On ctx cancel — returns (StillPending, ctx.Err()). Caller's
// deadline / shutdown signal won.
//
// On fn returning (StillPending, transientErr) — the err is logged
// by the closure (not by Poll), and Poll continues with the
// backoff schedule. The transient err is preserved as the last
// error in case MaxWait or ctx-cancel later fires.
func Poll(ctx context.Context, cfg Config, fn PollFunc) (Result, error) {
	if cfg.MaxWait <= 0 {
		cfg.MaxWait = DefaultMaxWait
	}
	if cfg.InitialWait <= 0 {
		cfg.InitialWait = DefaultInitialWait
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = DefaultMaxBackoff
	}
	if cfg.JitterPct < 0 {
		cfg.JitterPct = 0
	}

	deadline := time.Now().Add(cfg.MaxWait)
	wait := cfg.InitialWait
	var lastErr error

	for {
		result, err := fn(ctx)
		switch result {
		case Done:
			return Done, nil
		case Failed:
			return Failed, err
		case StillPending:
			lastErr = err // may be nil (clean keep-polling) or a transient err
		default:
			return Failed, fmt.Errorf("asyncpoll: PollFunc returned unknown Result %d", result)
		}

		// Compute the next wait with jitter. wait is the cumulative
		// backoff base; jittered is what actually sleeps.
		jittered := jitterDuration(wait, cfg.JitterPct)

		// If the next wait would push us past the deadline, return
		// StillPending now rather than sleeping uselessly.
		now := time.Now()
		remaining := deadline.Sub(now)
		if remaining <= 0 {
			if lastErr != nil {
				return StillPending, fmt.Errorf("%w (last err: %v)", ErrMaxWait, lastErr)
			}
			return StillPending, ErrMaxWait
		}
		if jittered > remaining {
			jittered = remaining
		}

		// Sleep, but respect ctx cancellation.
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return StillPending, fmt.Errorf("%w (last err: %v)", ctx.Err(), lastErr)
			}
			return StillPending, ctx.Err()
		case <-time.After(jittered):
		}

		// Multiplicative backoff (3×) capped at MaxBackoff.
		wait *= 3
		if wait > cfg.MaxBackoff {
			wait = cfg.MaxBackoff
		}
	}
}

// jitterDuration applies ±pct jitter to base. Returned duration is
// always positive (a base of 0 returns 0 regardless of pct).
//
// Visible for testing — the test asserts the bounded envelope rather
// than the exact value.
func jitterDuration(base time.Duration, pct float64) time.Duration {
	if base <= 0 || pct <= 0 {
		return base
	}
	// rand/v2's Float64 returns [0, 1); we want [-pct, +pct].
	delta := (rand.Float64()*2 - 1) * pct
	jittered := time.Duration(float64(base) * (1 + delta))
	if jittered < 0 {
		jittered = 0
	}
	return jittered
}
