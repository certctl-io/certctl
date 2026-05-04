package service

import (
	"math"
	"sort"
	"sync"
	"sync/atomic"
)

// ApprovalMetrics is a thread-safe counter table for the issuance
// approval-workflow dispatch path. Rank 7 of the 2026-05-03 deep-research
// deep-research deliverable. Mirrors the ExpiryAlertMetrics +
// VaultRenewalMetrics shape: cmd/server/main.go constructs ONE instance,
// passes it to ApprovalService (recording side) AND metricsHandler
// (exposing side) so the snapshotter is the single source of truth.
//
// Dimensions:
//
//	outcome    — closed enum from internal/domain/approval.go:
//	              "approved"  — Approve transitioned a pending request.
//	              "rejected"  — Reject transitioned a pending request.
//	              "expired"   — scheduler reaper transitioned a stale
//	                            pending request via ExpireStale.
//	              "bypassed"  — CERTCTL_APPROVAL_BYPASS=true short-
//	                            circuited RequestApproval. Production
//	                            deploys MUST have zero rows of this
//	                            outcome.
//	profile_id — CertificateProfile.ID that drove the gate. Bounded
//	             cardinality (operators have <100 profiles in production).
//
// Cardinality bound: 4 outcomes × N profiles. With N=100, that's 400
// series — well within Prometheus's per-target series budget for a
// well-bounded label.
//
// Pending-age histogram: ObservePendingAge records the seconds-since-
// creation of a pending approval at the moment of decision. Operators
// alert when the p99 hits hours/days (compliance has a deadline).
// Bucket boundaries: 60, 300, 1800, 3600, 21600, 86400, +Inf — 1
// minute, 5 minutes, 30 minutes, 1 hour, 6 hours, 24 hours, beyond.
type ApprovalMetrics struct {
	mu       sync.RWMutex
	counters map[approvalKey]*atomic.Uint64

	pendingAgeHist *approvalDurationHistogram
}

type approvalKey struct {
	Outcome   string
	ProfileID string
}

// NewApprovalMetrics returns a zero-value ApprovalMetrics ready for
// concurrent use. The caller MUST register the same instance on both
// the ApprovalService (recording) and the MetricsHandler (exposing)
// sides.
func NewApprovalMetrics() *ApprovalMetrics {
	return &ApprovalMetrics{
		counters:       make(map[approvalKey]*atomic.Uint64),
		pendingAgeHist: newApprovalDurationHistogram(),
	}
}

// RecordDecision bumps the (outcome, profile_id) counter by one. Called
// from ApprovalService.Approve / Reject / ExpireStale and from the
// bypass-mode short-circuit inside RequestApproval.
func (m *ApprovalMetrics) RecordDecision(outcome, profileID string) {
	if m == nil {
		return
	}
	key := approvalKey{Outcome: outcome, ProfileID: profileID}

	m.mu.RLock()
	c, ok := m.counters[key]
	m.mu.RUnlock()

	if !ok {
		m.mu.Lock()
		c, ok = m.counters[key]
		if !ok {
			c = &atomic.Uint64{}
			m.counters[key] = c
		}
		m.mu.Unlock()
	}
	c.Add(1)
}

// ObservePendingAge records the seconds-since-creation of a pending
// approval at the moment of decision (Approve / Reject / Expire).
func (m *ApprovalMetrics) ObservePendingAge(seconds float64) {
	if m == nil {
		return
	}
	m.pendingAgeHist.observe(seconds)
}

// SnapshotApprovalDecisions returns the current decision counter table
// as a sorted slice for deterministic Prometheus exposition. Sort key
// is (outcome, profile_id).
type ApprovalDecisionEntry struct {
	Outcome   string
	ProfileID string
	Count     uint64
}

func (m *ApprovalMetrics) SnapshotApprovalDecisions() []ApprovalDecisionEntry {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	out := make([]ApprovalDecisionEntry, 0, len(m.counters))
	for k, c := range m.counters {
		out = append(out, ApprovalDecisionEntry{
			Outcome:   k.Outcome,
			ProfileID: k.ProfileID,
			Count:     c.Load(),
		})
	}
	m.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Outcome != out[j].Outcome {
			return out[i].Outcome < out[j].Outcome
		}
		return out[i].ProfileID < out[j].ProfileID
	})
	return out
}

// SnapshotApprovalPendingAgeHistogram returns the current bucket counts
// + sum + total count for the pending-age histogram. Format suits the
// Prometheus histogram exposition (le buckets + _sum + _count).
type ApprovalPendingAgeSnapshot struct {
	BucketBounds []float64 // [60, 300, 1800, 3600, 21600, 86400] — exclusive of +Inf
	BucketCounts []uint64  // cumulative counts per bucket; len = len(BucketBounds) + 1 (last is +Inf)
	Sum          float64
	Count        uint64
}

func (m *ApprovalMetrics) SnapshotApprovalPendingAgeHistogram() ApprovalPendingAgeSnapshot {
	if m == nil {
		return ApprovalPendingAgeSnapshot{}
	}
	return m.pendingAgeHist.snapshot()
}

// approvalDurationHistogram is a tiny lock-free histogram with fixed
// bucket boundaries for approval-pending-age. Atomic counters per
// bucket + sum stored as uint64-bits-of-float64 atomic.
type approvalDurationHistogram struct {
	bounds  []float64
	buckets []*atomic.Uint64 // len = len(bounds) + 1; last is +Inf
	sumBits *atomic.Uint64   // float64 bits stored atomically
	count   *atomic.Uint64
}

func newApprovalDurationHistogram() *approvalDurationHistogram {
	bounds := []float64{60, 300, 1800, 3600, 21600, 86400}
	buckets := make([]*atomic.Uint64, len(bounds)+1)
	for i := range buckets {
		buckets[i] = &atomic.Uint64{}
	}
	return &approvalDurationHistogram{
		bounds:  bounds,
		buckets: buckets,
		sumBits: &atomic.Uint64{},
		count:   &atomic.Uint64{},
	}
}

func (h *approvalDurationHistogram) observe(seconds float64) {
	if h == nil {
		return
	}
	// Find the first bucket whose bound is >= seconds.
	idx := len(h.bounds) // default to +Inf bucket
	for i, b := range h.bounds {
		if seconds <= b {
			idx = i
			break
		}
	}
	h.buckets[idx].Add(1)
	h.count.Add(1)
	// Atomic float64 add via CAS loop.
	for {
		oldBits := h.sumBits.Load()
		old := math.Float64frombits(oldBits)
		newBits := math.Float64bits(old + seconds)
		if h.sumBits.CompareAndSwap(oldBits, newBits) {
			return
		}
	}
}

func (h *approvalDurationHistogram) snapshot() ApprovalPendingAgeSnapshot {
	if h == nil {
		return ApprovalPendingAgeSnapshot{}
	}
	counts := make([]uint64, len(h.buckets))
	cumulative := uint64(0)
	for i, b := range h.buckets {
		cumulative += b.Load()
		counts[i] = cumulative
	}
	return ApprovalPendingAgeSnapshot{
		BucketBounds: append([]float64(nil), h.bounds...),
		BucketCounts: counts,
		Sum:          math.Float64frombits(h.sumBits.Load()),
		Count:        h.count.Load(),
	}
}
