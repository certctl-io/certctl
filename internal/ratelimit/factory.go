// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"database/sql"
	"fmt"
	"time"
)

// Phase 13 Sprint 13.3 (2026-05-14, architecture diligence audit
// ARCH-M1): the backend-selector factory. Wires every
// `ratelimit.NewSlidingWindowLimiter(...)` call site in
// cmd/server/main.go through here so the operator-chosen backend
// (CERTCTL_RATE_LIMIT_BACKEND={memory,postgres}) gates the limiter
// type without each call site replicating the switch.
//
// Caller-visible behavior contract: NewLimiter(backend="memory", ...)
// returns a *SlidingWindowLimiter identical to a direct
// NewSlidingWindowLimiter call. NewLimiter(backend="postgres", ...)
// returns a *PostgresSlidingWindowLimiter with the same Allow(key, now)
// signature + the same ErrRateLimited sentinel + the same maxN<=0
// disabled semantics. Sprint 13.3's "no signature change" rule is
// what makes the swap drop-in.
//
// The mapCap argument is the in-memory backend's per-instance
// key-cap (LRU-evicted under pressure). Postgres backend has no
// equivalent — the table grows until the scheduler janitor sweeps
// stale rows; mapCap is accepted + ignored for that backend so the
// factory signature stays drop-in identical to NewSlidingWindowLimiter.

// NewLimiter returns a Limiter backed by either the in-memory
// SlidingWindowLimiter (backend="memory") or the
// PostgresSlidingWindowLimiter (backend="postgres").
//
// `backend` is validated by config.Validate() at startup; any other
// value here panics — config validation is the SoT, this is just
// defensive in case the call site somehow bypasses startup
// validation.
//
// `db` is required when backend="postgres" and ignored when
// backend="memory". The factory does not nil-check db for the
// memory branch because requiring a meaningful db handle for the
// memory path would couple every limiter call site to the database
// pool unnecessarily.
//
// `maxN <= 0` disables the limiter (both backends honor the
// opt-out — all Allow calls return nil).
func NewLimiter(backend string, db *sql.DB, maxN int, window time.Duration, mapCap int) Limiter {
	switch backend {
	case "memory":
		return NewSlidingWindowLimiter(maxN, window, mapCap)
	case "postgres":
		if db == nil {
			panic("ratelimit.NewLimiter: backend=postgres requires a non-nil *sql.DB (config.Validate should have caught this earlier)")
		}
		return NewPostgresSlidingWindowLimiter(db, maxN, window)
	default:
		// Defensive — config.Validate() rejects anything else at
		// startup. Reaching this branch implies a coding error in a
		// future call site that bypasses validation.
		panic(fmt.Sprintf("ratelimit.NewLimiter: unknown backend %q (must be memory or postgres)", backend))
	}
}
