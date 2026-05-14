// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package service

import (
	"context"
	"fmt"
	"sync/atomic"
)

// Phase 9 ARCH-M2 closure Sprint 9 (2026-05-14): extracted from
// internal/service/acme.go via the Option B sibling-file pattern.
// Package stays `service`; every external caller of
// `service.ACMEService.GarbageCollect(...)` resolves the same way —
// pure mechanical relocation.
//
// This file holds the Phase 5 ACME GC sweep concern: the scheduler-
// invoked GarbageCollect entry point plus the atomicAddUint64
// counter helper (only consumed inside the sweep body for the
// rows-affected-N case the default `bump` doesn't cover).

// GarbageCollect runs a single ACME GC sweep. Phase 5 — the scheduler
// invokes this every cfg.GCInterval. Three independent sweeps:
//
//  1. Delete used / expired nonces.
//  2. Transition expired pending authzs to `expired`.
//  3. Transition expired pending/ready/processing orders to `invalid`.
//
// Each sweep is a single SQL statement (no per-row transactions) so a
// large reap is one atomic write per sweep. Per-sweep errors are
// logged-and-continued: a failing nonces sweep doesn't block the
// authzs sweep. Returns the first error encountered (for caller
// telemetry); per-sweep counts are recorded on metrics regardless.
//
// Idempotent — repeated runs are safe; the second run finds 0 rows.
func (s *ACMEService) GarbageCollect(ctx context.Context) error {
	s.metrics.bump(&s.metrics.GCRunsTotal)
	var firstErr error

	if n, err := s.repo.GCExpiredNonces(ctx); err != nil {
		s.metrics.bump(&s.metrics.GCRunFailuresTotal)
		if firstErr == nil {
			firstErr = fmt.Errorf("acme gc: nonces: %w", err)
		}
	} else if n > 0 {
		atomicAddUint64(&s.metrics.GCNoncesReapedTotal, uint64(n))
	}

	if n, err := s.repo.GCExpireAuthorizations(ctx); err != nil {
		s.metrics.bump(&s.metrics.GCRunFailuresTotal)
		if firstErr == nil {
			firstErr = fmt.Errorf("acme gc: authzs: %w", err)
		}
	} else if n > 0 {
		atomicAddUint64(&s.metrics.GCAuthzsExpiredTotal, uint64(n))
	}

	if n, err := s.repo.GCInvalidateExpiredOrders(ctx); err != nil {
		s.metrics.bump(&s.metrics.GCRunFailuresTotal)
		if firstErr == nil {
			firstErr = fmt.Errorf("acme gc: orders: %w", err)
		}
	} else if n > 0 {
		atomicAddUint64(&s.metrics.GCOrdersInvalidatedTotal, uint64(n))
	}

	return firstErr
}

// atomicAddUint64 adds delta to the counter. The metrics struct exposes
// only `bump` (add 1) by default; this helper covers the
// rows-affected-N case the GC needs.
func atomicAddUint64(c *atomic.Uint64, delta uint64) { c.Add(delta) }
