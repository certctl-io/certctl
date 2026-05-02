// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package service

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// IssuanceCounterEntry is one (issuer_type, outcome, count) tuple
// emitted by the per-issuer-type issuance counter table. Closes the
// #4 acquisition-readiness blocker from the 2026-05-01 issuer coverage
// audit (per-issuer-type metrics).
type IssuanceCounterEntry struct {
	IssuerType string
	Outcome    string // "success" | "failure"
	Count      uint64
}

// IssuanceFailureEntry is one (issuer_type, error_class, count) tuple
// emitted by the issuance-failure counter table. error_class is a
// closed enum of eight values (timeout, auth, rate_limited,
// validation, upstream_5xx, upstream_4xx, network, other) — cardinality
// discipline keeps this metric tractable.
type IssuanceFailureEntry struct {
	IssuerType string
	ErrorClass string
	Count      uint64
}

// IssuanceDurationEntry is one (issuer_type, bucket-counts, sum, count)
// tuple emitted by the issuance-duration histogram. Buckets carries
// cumulative counts in the order matching the BucketBoundaries
// reported by the snapshotter; Sum is total observed seconds; Count
// is total observations (matches the +Inf bucket).
type IssuanceDurationEntry struct {
	IssuerType string
	Buckets    []uint64
	Sum        float64
	Count      uint64
}

// IssuanceMetricsSnapshotter is the surface MetricsHandler consumes
// for per-issuer-type issuance metrics. The handler imports this
// interface so the snapshot types stay in the service package
// (avoids an import cycle: handler imports service for the
// admin_est / admin_scep_intune handlers, so the reverse direction
// can't import handler).
//
// *IssuanceMetrics satisfies this interface; the production wiring
// in cmd/server/main.go passes the same instance into both the
// IssuerRegistry (for adapter-side recording) and the MetricsHandler
// (for Prometheus exposition).
type IssuanceMetricsSnapshotter interface {
	SnapshotCounters() []IssuanceCounterEntry
	SnapshotFailures() []IssuanceFailureEntry
	SnapshotDurations() []IssuanceDurationEntry
	BucketBoundaries() []float64
}

// DefaultIssuanceBucketBoundaries covers the local-issuer fast path
// (sub-100ms signing) through the async-CA slow path (DigiCert /
// Sectigo / Entrust polling can take minutes). The +Inf bucket is
// appended by the Prometheus exposer; we don't include it here.
//
// Boundaries chosen for operator alerting: 0.05s catches when the
// local issuer's signer has gone non-cooperative; 30s catches when
// an async CA is slow but not stuck; 120s catches when polling has
// effectively stalled.
var DefaultIssuanceBucketBoundaries = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120}

// IssuanceMetrics is a thread-safe in-memory counter + histogram table
// for per-issuer-type issuance signals. Closes the #4 acquisition-
// readiness blocker from the 2026-05-01 issuer coverage audit
// (per-issuer-type metrics).
//
// Three independent views — counter, failures, durations — are exposed
// via the Snapshot* methods so handler.IssuanceMetricsSnapshotter is
// satisfied.
//
// Cardinality is bounded by:
//   - Closed enum of issuer types (12 currently)
//   - "success" / "failure" outcome strings (2)
//   - 8-value error_class enum (timeout, auth, rate_limited,
//     validation, upstream_5xx, upstream_4xx, network, other)
//   - Fixed bucket boundaries (11 + implicit +Inf in exposer)
//
// Underlying maps grow to a fixed upper bound and stop. A new issuer
// type appears once and never explodes the cardinality.
type IssuanceMetrics struct {
	bucketBoundaries []float64

	mu        sync.RWMutex
	counters  map[counterKey]*atomic.Uint64
	failures  map[failureKey]*atomic.Uint64
	durations map[string]*durationState // key: issuer_type
}

type counterKey struct{ IssuerType, Outcome string }
type failureKey struct{ IssuerType, ErrorClass string }

type durationState struct {
	buckets []atomic.Uint64
	// sumMillis stores the sum in milliseconds (uint64-encoded) so we
	// can use atomic adds; the snapshot converts back to float seconds.
	sumMillis atomic.Uint64
	count     atomic.Uint64
}

// NewIssuanceMetrics constructs a fresh IssuanceMetrics with the given
// bucket boundaries. Pass DefaultIssuanceBucketBoundaries unless tests
// need a different shape.
func NewIssuanceMetrics(buckets []float64) *IssuanceMetrics {
	cp := make([]float64, len(buckets))
	copy(cp, buckets)
	return &IssuanceMetrics{
		bucketBoundaries: cp,
		counters:         make(map[counterKey]*atomic.Uint64),
		failures:         make(map[failureKey]*atomic.Uint64),
		durations:        make(map[string]*durationState),
	}
}

// RecordIssuance bumps the (issuer_type, outcome) counter and observes
// the duration into the (issuer_type) histogram. outcome is
// "success" or "failure"; pass "" only if you intend to record neither
// (the call returns without effect).
func (m *IssuanceMetrics) RecordIssuance(issuerType, outcome string, duration time.Duration) {
	if issuerType == "" || outcome == "" {
		return
	}
	m.bumpCounter(counterKey{IssuerType: issuerType, Outcome: outcome})
	m.observeDuration(issuerType, duration)
}

// RecordFailure bumps the (issuer_type, error_class) failure counter.
// Caller is responsible for classifying the error via ClassifyError;
// passing an off-enum value will silently grow the cardinality
// (closed-enum discipline is the caller's contract).
func (m *IssuanceMetrics) RecordFailure(issuerType, errorClass string) {
	if issuerType == "" || errorClass == "" {
		return
	}
	m.bumpFailure(failureKey{IssuerType: issuerType, ErrorClass: errorClass})
}

func (m *IssuanceMetrics) bumpCounter(k counterKey) {
	m.mu.RLock()
	c, ok := m.counters[k]
	m.mu.RUnlock()
	if !ok {
		m.mu.Lock()
		c, ok = m.counters[k]
		if !ok {
			c = new(atomic.Uint64)
			m.counters[k] = c
		}
		m.mu.Unlock()
	}
	c.Add(1)
}

func (m *IssuanceMetrics) bumpFailure(k failureKey) {
	m.mu.RLock()
	c, ok := m.failures[k]
	m.mu.RUnlock()
	if !ok {
		m.mu.Lock()
		c, ok = m.failures[k]
		if !ok {
			c = new(atomic.Uint64)
			m.failures[k] = c
		}
		m.mu.Unlock()
	}
	c.Add(1)
}

func (m *IssuanceMetrics) observeDuration(issuerType string, duration time.Duration) {
	m.mu.RLock()
	state, ok := m.durations[issuerType]
	m.mu.RUnlock()
	if !ok {
		m.mu.Lock()
		state, ok = m.durations[issuerType]
		if !ok {
			state = &durationState{
				buckets: make([]atomic.Uint64, len(m.bucketBoundaries)),
			}
			m.durations[issuerType] = state
		}
		m.mu.Unlock()
	}

	seconds := duration.Seconds()
	// Cumulative buckets: bump every bucket whose boundary >= seconds.
	for i, le := range m.bucketBoundaries {
		if seconds <= le {
			state.buckets[i].Add(1)
		}
	}
	// sumMillis: store the duration in milliseconds (uint64) to keep
	// atomic. Snapshot converts back to seconds.
	state.sumMillis.Add(uint64(duration.Milliseconds()))
	state.count.Add(1)
}

// SnapshotCounters returns a stable copy of the (issuer_type, outcome,
// count) tuples. Safe to call concurrently with RecordIssuance.
func (m *IssuanceMetrics) SnapshotCounters() []IssuanceCounterEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]IssuanceCounterEntry, 0, len(m.counters))
	for k, v := range m.counters {
		out = append(out, IssuanceCounterEntry{
			IssuerType: k.IssuerType,
			Outcome:    k.Outcome,
			Count:      v.Load(),
		})
	}
	return out
}

// SnapshotFailures returns a stable copy of the (issuer_type,
// error_class, count) tuples. Safe to call concurrently.
func (m *IssuanceMetrics) SnapshotFailures() []IssuanceFailureEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]IssuanceFailureEntry, 0, len(m.failures))
	for k, v := range m.failures {
		out = append(out, IssuanceFailureEntry{
			IssuerType: k.IssuerType,
			ErrorClass: k.ErrorClass,
			Count:      v.Load(),
		})
	}
	return out
}

// SnapshotDurations returns a stable copy of the (issuer_type, buckets,
// sum, count) tuples. The buckets slice is in the order matching
// BucketBoundaries(); sum is in seconds. Safe to call concurrently.
func (m *IssuanceMetrics) SnapshotDurations() []IssuanceDurationEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]IssuanceDurationEntry, 0, len(m.durations))
	for issuerType, state := range m.durations {
		buckets := make([]uint64, len(state.buckets))
		for i := range state.buckets {
			buckets[i] = state.buckets[i].Load()
		}
		out = append(out, IssuanceDurationEntry{
			IssuerType: issuerType,
			Buckets:    buckets,
			Sum:        float64(state.sumMillis.Load()) / 1000.0,
			Count:      state.count.Load(),
		})
	}
	return out
}

// BucketBoundaries returns a copy of the bucket boundaries used by
// this IssuanceMetrics. Used by the Prometheus exposer to label the
// histogram buckets.
func (m *IssuanceMetrics) BucketBoundaries() []float64 {
	out := make([]float64, len(m.bucketBoundaries))
	copy(out, m.bucketBoundaries)
	return out
}

// Compile-time guard: *IssuanceMetrics satisfies
// IssuanceMetricsSnapshotter.
var _ IssuanceMetricsSnapshotter = (*IssuanceMetrics)(nil)

// ClassifyError maps an arbitrary error to one of eight closed-enum
// error_class values. The classification is deterministic and runs in
// constant time (no regex compilation, no reflection beyond
// errors.Is / errors.As).
//
// Closed enum: timeout, auth, rate_limited, validation, upstream_5xx,
// upstream_4xx, network, other. Adding a ninth value is a deliberate
// change that requires updating the docs/metrics.md enum list and
// any operator alerting rules that pin specific labels — do NOT
// expand the enum casually; classify edge cases as "other" and
// document the case if it matters.
func ClassifyError(err error) string {
	if err == nil {
		return "" // caller should not invoke us with nil
	}

	// 1. Context deadline / cancellation → timeout (the operator
	//    alerts on slow upstream CAs via this label).
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}

	// 2. Network-layer errors (connection refused, DNS, TLS handshake)
	//    → network. Detected via *net.OpError or strings the stdlib
	//    uses for these conditions.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "network"
	}

	msg := strings.ToLower(err.Error())

	// 3. Substring matches against the most common upstream-CA error
	//    shapes. Order matters — auth and rate-limited need to win
	//    over generic 4xx, and 5xx needs to win over generic
	//    "internal" matches.
	switch {
	case strings.Contains(msg, "deadline exceeded"),
		strings.Contains(msg, "timeout"),
		strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case strings.Contains(msg, "401"),
		strings.Contains(msg, "unauthorized"),
		strings.Contains(msg, "accessdenied"),
		strings.Contains(msg, "access denied"),
		strings.Contains(msg, "forbidden"):
		return "auth"
	case strings.Contains(msg, "429"),
		strings.Contains(msg, "ratelimit"),
		strings.Contains(msg, "rate limit"),
		strings.Contains(msg, "throttl"):
		return "rate_limited"
	case strings.Contains(msg, "csr"),
		strings.Contains(msg, "validate"),
		strings.Contains(msg, "validation"),
		strings.Contains(msg, "invalid"),
		strings.Contains(msg, "malformed"):
		return "validation"
	case strings.Contains(msg, "500"),
		strings.Contains(msg, "502"),
		strings.Contains(msg, "503"),
		strings.Contains(msg, "504"),
		strings.Contains(msg, "5xx"),
		strings.Contains(msg, "serviceunavailable"),
		strings.Contains(msg, "service unavailable"),
		strings.Contains(msg, "internalerror"),
		strings.Contains(msg, "internal server error"):
		return "upstream_5xx"
	case strings.Contains(msg, "404"),
		strings.Contains(msg, "400"),
		strings.Contains(msg, "4xx"),
		strings.Contains(msg, "notfound"),
		strings.Contains(msg, "not found"),
		strings.Contains(msg, "badrequest"),
		strings.Contains(msg, "bad request"):
		return "upstream_4xx"
	case strings.Contains(msg, "no such host"),
		strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "tls handshake"),
		strings.Contains(msg, "network"),
		strings.Contains(msg, "dial tcp"),
		strings.Contains(msg, "broken pipe"):
		return "network"
	}
	return "other"
}
