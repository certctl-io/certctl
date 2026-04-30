package service

import (
	"sync"
	"testing"
)

// Production hardening II Phase 1+8 — OCSPCounters direct tests.
//
// Pin every label name + every Inc* method + the Snapshot copy
// invariant. The labels feed the Phase 8 Prometheus exposer
// (handler/metrics.go::SetOCSPCounters); a typo in either side
// would silently drop the counter from /metrics/prometheus, so
// these tests act as the cross-package contract.

func TestOCSPCounters_NewIsZero(t *testing.T) {
	c := NewOCSPCounters()
	snap := c.Snapshot()
	for label, v := range snap {
		if v != 0 {
			t.Errorf("fresh counter[%q] = %d, want 0", label, v)
		}
	}
}

func TestOCSPCounters_EveryIncTicksItsLabel(t *testing.T) {
	cases := []struct {
		name  string
		inc   func(*OCSPCounters)
		label string
	}{
		{"RequestGET", (*OCSPCounters).IncRequestGET, "request_get"},
		{"RequestPOST", (*OCSPCounters).IncRequestPOST, "request_post"},
		{"RequestSuccess", (*OCSPCounters).IncRequestSuccess, "request_success"},
		{"RequestInvalid", (*OCSPCounters).IncRequestInvalid, "request_invalid"},
		{"IssuerNotFound", (*OCSPCounters).IncIssuerNotFound, "issuer_not_found"},
		{"CertNotFound", (*OCSPCounters).IncCertNotFound, "cert_not_found"},
		{"SigningFailed", (*OCSPCounters).IncSigningFailed, "signing_failed"},
		{"NonceEchoed", (*OCSPCounters).IncNonceEchoed, "nonce_echoed"},
		{"NonceMalformed", (*OCSPCounters).IncNonceMalformed, "nonce_malformed"},
		{"RateLimited", (*OCSPCounters).IncRateLimited, "rate_limited"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewOCSPCounters()
			tc.inc(c)
			tc.inc(c)
			tc.inc(c)
			snap := c.Snapshot()
			if got := snap[tc.label]; got != 3 {
				t.Errorf("label %q = %d after 3 ticks, want 3", tc.label, got)
			}
			// All other labels stay at zero — pin the no-cross-bleed invariant.
			for label, v := range snap {
				if label == tc.label {
					continue
				}
				if v != 0 {
					t.Errorf("Inc%s leaked into label %q (=%d)", tc.name, label, v)
				}
			}
		})
	}
}

func TestOCSPCounters_SnapshotIsCopy(t *testing.T) {
	// Mutating the snapshot must NOT affect the underlying counters.
	c := NewOCSPCounters()
	c.IncRequestSuccess()
	snap := c.Snapshot()
	snap["request_success"] = 999
	if again := c.Snapshot()["request_success"]; again != 1 {
		t.Errorf("counter mutated through snapshot: got %d, want 1", again)
	}
}

func TestOCSPCounters_ConcurrentTicksRace(t *testing.T) {
	// Race-detector smoke: every Inc* method should be safe under
	// concurrent callers (sync/atomic primitives are the contract).
	c := NewOCSPCounters()
	const goroutines = 10
	const ticksPerG = 100
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < ticksPerG; j++ {
				c.IncRequestSuccess()
				c.IncNonceEchoed()
			}
		}()
	}
	wg.Wait()
	snap := c.Snapshot()
	want := uint64(goroutines * ticksPerG)
	if snap["request_success"] != want {
		t.Errorf("request_success = %d, want %d", snap["request_success"], want)
	}
	if snap["nonce_echoed"] != want {
		t.Errorf("nonce_echoed = %d, want %d", snap["nonce_echoed"], want)
	}
}
