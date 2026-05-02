// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package service

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// TestIssuanceMetrics_RecordAndSnapshot exercises the happy-path
// counter + histogram + failure recording. Asserts:
//   - SnapshotCounters returns the expected (issuer_type, outcome, count) tuples
//   - SnapshotDurations returns cumulative bucket counts
//   - SnapshotFailures returns the expected (issuer_type, error_class, count) tuples
//   - BucketBoundaries returns a copy that doesn't share backing storage
func TestIssuanceMetrics_RecordAndSnapshot(t *testing.T) {
	m := NewIssuanceMetrics(DefaultIssuanceBucketBoundaries)

	// Record three issuances: two success (one fast, one slow), one failure.
	m.RecordIssuance("local", "success", 50*time.Millisecond) // 0.05 bucket
	m.RecordIssuance("local", "success", 2*time.Second)       // 2.5 bucket
	m.RecordIssuance("digicert", "failure", 90*time.Second)   // 120 bucket
	m.RecordFailure("digicert", "rate_limited")

	counters := m.SnapshotCounters()
	if len(counters) != 2 {
		t.Fatalf("expected 2 counter entries, got %d", len(counters))
	}
	for _, c := range counters {
		switch {
		case c.IssuerType == "local" && c.Outcome == "success":
			if c.Count != 2 {
				t.Errorf("local/success: want 2, got %d", c.Count)
			}
		case c.IssuerType == "digicert" && c.Outcome == "failure":
			if c.Count != 1 {
				t.Errorf("digicert/failure: want 1, got %d", c.Count)
			}
		default:
			t.Errorf("unexpected counter entry: %+v", c)
		}
	}

	failures := m.SnapshotFailures()
	if len(failures) != 1 {
		t.Fatalf("expected 1 failure entry, got %d", len(failures))
	}
	if failures[0].IssuerType != "digicert" || failures[0].ErrorClass != "rate_limited" || failures[0].Count != 1 {
		t.Errorf("unexpected failure entry: %+v", failures[0])
	}

	durations := m.SnapshotDurations()
	if len(durations) != 2 {
		t.Fatalf("expected 2 duration entries, got %d", len(durations))
	}

	// BucketBoundaries: returned slice must be a copy.
	b1 := m.BucketBoundaries()
	b2 := m.BucketBoundaries()
	if &b1[0] == &b2[0] {
		t.Error("BucketBoundaries should return a copy, not shared storage")
	}
}

// TestIssuanceMetrics_HistogramCumulative pins the cumulative-buckets
// contract. Prometheus histograms require buckets to be cumulative —
// `le=0.5` includes everything <= 0.5, including <= 0.05 and <= 0.1.
// Off-by-one here corrupts every quantile query downstream.
func TestIssuanceMetrics_HistogramCumulative(t *testing.T) {
	m := NewIssuanceMetrics([]float64{0.1, 0.5, 1.0})

	// Observe 100ms (= 0.1s exactly).
	m.RecordIssuance("local", "success", 100*time.Millisecond)

	durs := m.SnapshotDurations()
	if len(durs) != 1 {
		t.Fatalf("expected 1 duration entry, got %d", len(durs))
	}

	// Boundaries: [0.1, 0.5, 1.0]. 100ms falls into 0.1 bucket and
	// every larger bucket (cumulative). Sum = 0.1, count = 1.
	want := []uint64{1, 1, 1}
	for i, w := range want {
		if durs[0].Buckets[i] != w {
			t.Errorf("bucket[%d]: want %d, got %d", i, w, durs[0].Buckets[i])
		}
	}
	if durs[0].Sum < 0.099 || durs[0].Sum > 0.101 {
		t.Errorf("sum: want ~0.1, got %v", durs[0].Sum)
	}
	if durs[0].Count != 1 {
		t.Errorf("count: want 1, got %d", durs[0].Count)
	}

	// Observe 750ms — falls into 1.0 bucket only (>0.1, >0.5).
	m.RecordIssuance("local", "success", 750*time.Millisecond)

	durs = m.SnapshotDurations()
	want = []uint64{1, 1, 2} // 100ms in all 3, 750ms in only the 1.0 bucket
	for i, w := range want {
		if durs[0].Buckets[i] != w {
			t.Errorf("after 750ms — bucket[%d]: want %d, got %d", i, w, durs[0].Buckets[i])
		}
	}
}

// TestIssuanceMetrics_Concurrency stresses RecordIssuance under 100
// goroutines × 1000 ops to assert atomic counter integrity. Race-
// detector clean is non-optional for this test (the whole point of
// IssuanceMetrics is concurrent recording from many service
// goroutines).
func TestIssuanceMetrics_Concurrency(t *testing.T) {
	m := NewIssuanceMetrics(DefaultIssuanceBucketBoundaries)

	const goroutines = 100
	const opsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				m.RecordIssuance("local", "success", 50*time.Millisecond)
			}
		}()
	}
	wg.Wait()

	counters := m.SnapshotCounters()
	if len(counters) != 1 {
		t.Fatalf("expected 1 counter entry, got %d", len(counters))
	}
	wantTotal := uint64(goroutines * opsPerGoroutine)
	if counters[0].Count != wantTotal {
		t.Errorf("counter under contention: want %d, got %d", wantTotal, counters[0].Count)
	}

	durs := m.SnapshotDurations()
	if durs[0].Count != wantTotal {
		t.Errorf("histogram count under contention: want %d, got %d", wantTotal, durs[0].Count)
	}
}

// TestClassifyError exercises every branch of the closed-enum
// classifier. The classification logic is the load-bearing piece of
// the failure metric — misclassification doesn't break operators, but
// it makes their alerts noisier. Each enum value has at least one
// representative input.
func TestClassifyError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"context_canceled", context.Canceled, "timeout"},
		{"context_deadline", context.DeadlineExceeded, "timeout"},
		{"timeout_substring", errors.New("operation deadline exceeded"), "timeout"},
		{"i_o_timeout", errors.New("read tcp: i/o timeout"), "timeout"},
		{"net_op_error", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, "network"},
		{"unauthorized_4xx", errors.New("DigiCert: 401 Unauthorized"), "auth"},
		{"access_denied_aws", errors.New("AccessDeniedException: not authorized"), "auth"},
		{"forbidden_403", errors.New("forbidden: insufficient permissions"), "auth"},
		{"rate_limited_429", errors.New("Sectigo: 429 too many requests"), "rate_limited"},
		{"throttled", errors.New("ThrottlingException: rate exceeded"), "rate_limited"},
		{"validation_csr", errors.New("malformed CSR: invalid PEM block"), "validation"},
		{"validation_invalid", errors.New("invalid signing algorithm"), "validation"},
		{"upstream_503", errors.New("ServiceUnavailable: 503"), "upstream_5xx"},
		{"upstream_500_internal", errors.New("Internal Server Error: 500"), "upstream_5xx"},
		{"upstream_404", errors.New("NotFound: 404 cert not found"), "upstream_4xx"},
		{"network_no_host", errors.New("dial tcp: no such host"), "network"},
		{"other_unmatched", errors.New("something completely unexpected happened"), "other"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyError(tc.err)
			if got != tc.want {
				t.Errorf("ClassifyError(%q): want %q, got %q", tc.err.Error(), tc.want, got)
			}
		})
	}

	// Special case: nil → "" so callers that accidentally call us
	// with a nil err don't bump the failure counter.
	if got := ClassifyError(nil); got != "" {
		t.Errorf("ClassifyError(nil): want \"\", got %q", got)
	}
}
