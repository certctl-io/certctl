// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package scheduler

import (
	"math/rand/v2"
	"time"
)

// JitteredTicker is a bounded-jitter wrapper around time.Timer that
// fires on C once per interval ± jitterPct, with the jitter drawn
// fresh on every tick. The base interval is the same as a bare
// time.NewTicker; only the per-tick envelope changes. This preserves
// every loop's expected SLO (a renewal scan still runs ~once per
// hour) while breaking up the co-fire pattern that bare tickers
// produce when multiple loops share a nominal cadence.
//
// Stop must be called by the caller (typically via defer) to release
// the goroutine. After Stop, the C channel is closed.
//
// Phase 6 SCALE-M5 (2026-05-14) introduced this wrapper. Pre-Phase-6
// the 15 scheduler loops in scheduler.go each used a bare
// time.NewTicker(interval); when multiple loops shared a nominal
// cadence (e.g. several loops on a 1h interval), they co-fired at
// the same wall-clock boundary post-server-start, producing visible
// CPU + DB spikes at every hour boundary. The renewal scan + the
// agent health check + the digest preview all firing within
// milliseconds of each other on a freshly-booted server could
// saturate the connection pool until they completed.
type JitteredTicker struct {
	// C is the channel a tick fires on. Read this in the loop's
	// select{} the same way you'd read time.Ticker.C.
	C chan time.Time

	stopCh chan struct{}
}

// NewJitteredTicker returns a ticker that fires on C every
// interval ± jitterPct (e.g. jitterPct=0.1 = ±10%). The first tick
// arrives one (jittered) interval after construction — same as
// time.NewTicker. jitterPct < 0 is treated as 0 (no jitter, equivalent
// to time.NewTicker). jitterPct ≥ 1 is clamped to 0.99 (avoid the
// degenerate "instant tick" case where the jitter consumes the
// entire interval).
//
// interval must be > 0. Callers passing 0 or negative get a panic
// from time.NewTimer, matching time.NewTicker's existing contract.
func NewJitteredTicker(interval time.Duration, jitterPct float64) *JitteredTicker {
	if jitterPct < 0 {
		jitterPct = 0
	}
	if jitterPct >= 1 {
		jitterPct = 0.99
	}

	jt := &JitteredTicker{
		C:      make(chan time.Time, 1),
		stopCh: make(chan struct{}),
	}

	go jt.run(interval, jitterPct)
	return jt
}

// run owns the per-tick scheduling loop. The fresh-per-tick jitter
// draw prevents drift from compounding (vs. computing the jittered
// interval once and reusing it).
func (jt *JitteredTicker) run(interval time.Duration, jitterPct float64) {
	defer close(jt.C)

	for {
		// Bounded-symmetric jitter around the interval. delta ∈
		// [-jitterPct, +jitterPct) drawn fresh per tick.
		delta := (rand.Float64()*2 - 1) * jitterPct
		next := time.Duration(float64(interval) * (1 + delta))
		// Floor at 1ns so we never feed a zero or negative
		// duration into time.NewTimer; the jitterPct clamp above
		// keeps next > 0 in normal use but a Float64 rounding
		// edge case could otherwise produce 0.
		if next < time.Nanosecond {
			next = time.Nanosecond
		}

		timer := time.NewTimer(next)
		select {
		case t := <-timer.C:
			select {
			case jt.C <- t:
				// emitted
			case <-jt.stopCh:
				return
			}
		case <-jt.stopCh:
			if !timer.Stop() {
				<-timer.C
			}
			return
		}
	}
}

// Stop releases the goroutine + closes C. Safe to call multiple
// times; subsequent calls are no-ops (the stopCh close is the
// only side effect, and re-closing a closed channel would panic,
// so we guard via a select+default).
func (jt *JitteredTicker) Stop() {
	select {
	case <-jt.stopCh:
		// already closed; no-op
	default:
		close(jt.stopCh)
	}
}

// DefaultSchedulerJitter is the jitter percentage applied to every
// scheduler-loop tick. ±10% is the industry-standard "spread but
// don't blur SLO" envelope used by Kubernetes controllers, AWS SDK
// retries, and Prometheus scrape intervals.
const DefaultSchedulerJitter = 0.10
