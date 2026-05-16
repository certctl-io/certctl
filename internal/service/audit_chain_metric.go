// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package service

import (
	"sync/atomic"
	"time"
)

// AuditChainCounter is the metric-side companion to the Sprint 6
// COMP-001-HASH chain verifier. The scheduler's auditChainVerifyLoop
// calls RecordSuccess on every clean walk and RecordBreak on
// detection; the Prometheus metrics handler reads the snapshot.
//
// Wire shape:
//
//	scheduler.AuditChainVerifier  →  *postgres.AuditRepository
//	                                 (calls audit_events_verify_chain SQL func)
//	scheduler.AuditChainBreakRecorder → *AuditChainCounter (this file)
//	handler.MetricsHandler         →  reads Snapshot() / LastBreakID() / ...
//
// Three counters get surfaced (matching the existing
// /api/v1/metrics/prometheus naming conventions):
//
//	certctl_audit_chain_break_detected_total counter (cumulative)
//	certctl_audit_chain_verify_total          counter (every walk)
//	certctl_audit_chain_rows                  gauge   (last walk's row count)
//
// Plus three info-label fields (broken_at_id, broken_at_pos,
// last_verified_at_unix) so operators can render a
// "last walk: clean, 1.2M rows, T-37m" panel.
//
// The counters use atomic.Uint64 so writes from the scheduler
// goroutine and reads from the HTTP handler goroutine don't need a
// mutex. The string fields (broken_at_id) are guarded by a
// dedicated mutex because atomic.Pointer would force the caller to
// re-allocate on every set.
type AuditChainCounter struct {
	breaksDetected atomic.Uint64
	walksCompleted atomic.Uint64
	lastRowCount   atomic.Uint64
	lastVerifiedAt atomic.Int64 // unix seconds; 0 = never

	// brokenAtID / brokenAtPos are sticky — they record the *first*
	// detected break, not the most recent walk's data. Operators
	// reset by restarting the process (or a future Phase 2 reset
	// endpoint behind auth.audit.admin).
	brokenAtID  atomic.Value // string
	brokenAtPos atomic.Int64
}

// NewAuditChainCounter returns a zero-state counter. Wire from
// cmd/server/main.go and pass to both the scheduler
// (SetAuditChainBreakRecorder) and the metrics handler
// (SetAuditChainCounter).
func NewAuditChainCounter() *AuditChainCounter {
	c := &AuditChainCounter{}
	c.brokenAtID.Store("")
	c.brokenAtPos.Store(-1)
	return c
}

// RecordSuccess marks a clean walk. The scheduler calls this on every
// tick where VerifyHashChain returned brokenAtID == "".
func (c *AuditChainCounter) RecordSuccess(rowCount int) {
	c.walksCompleted.Add(1)
	if rowCount < 0 {
		rowCount = 0
	}
	c.lastRowCount.Store(uint64(rowCount))
	c.lastVerifiedAt.Store(time.Now().Unix())
}

// RecordBreak marks a detected break. Sticky: subsequent breaks do not
// overwrite the (brokenAtID, brokenAtPos) fields — the first detection
// is the actionable signal. The breaksDetected counter still
// increments on every observation so operators can tell whether the
// tampering is ongoing or one-shot.
func (c *AuditChainCounter) RecordBreak(brokenAtID string, brokenAtPos int) {
	c.breaksDetected.Add(1)
	c.walksCompleted.Add(1)
	c.lastVerifiedAt.Store(time.Now().Unix())
	// Sticky-first-detection — only record if the field is still empty.
	if cur, _ := c.brokenAtID.Load().(string); cur == "" {
		c.brokenAtID.Store(brokenAtID)
		c.brokenAtPos.Store(int64(brokenAtPos))
	}
}

// Snapshot returns the current counter state for the Prometheus
// exposer. Reads use atomic loads — no mutex.
type AuditChainSnapshot struct {
	BreaksDetected uint64
	WalksCompleted uint64
	LastRowCount   uint64
	// LastVerifiedAtUnix is 0 if the loop has never run; otherwise the
	// unix-epoch second of the most recent walk (clean or break).
	LastVerifiedAtUnix int64
	// BrokenAtID is "" if no break has ever been recorded.
	BrokenAtID  string
	BrokenAtPos int64
}

// Snapshot returns a point-in-time view of every counter. The metrics
// handler renders this into Prometheus exposition format.
func (c *AuditChainCounter) Snapshot() AuditChainSnapshot {
	id, _ := c.brokenAtID.Load().(string)
	return AuditChainSnapshot{
		BreaksDetected:     c.breaksDetected.Load(),
		WalksCompleted:     c.walksCompleted.Load(),
		LastRowCount:       c.lastRowCount.Load(),
		LastVerifiedAtUnix: c.lastVerifiedAt.Load(),
		BrokenAtID:         id,
		BrokenAtPos:        c.brokenAtPos.Load(),
	}
}
