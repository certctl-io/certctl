package service

import (
	"sort"
	"sync"
	"sync/atomic"
)

// ExpiryAlertMetrics is a thread-safe counter table for the per-policy
// multi-channel expiry-alert dispatch path. Rank 4 of the 2026-05-03
// deep-research deliverable
// (cowork/deep-research-results-2026-05-03.md Part 5). Closes the
// procurement-checklist gap where a customer who configured PagerDuty
// for cert-expiry pages got silent nothing — ExpirationWarning shipped
// only to Email pre-fix.
//
// Dimensions:
//
//	channel   — closed-enum NotificationChannel value (Email, Slack,
//	            Teams, PagerDuty, OpsGenie, Webhook). Off-enum
//	            channels are silently dropped at the dispatch site
//	            BEFORE this counter sees them, so cardinality stays
//	            bounded.
//	threshold — int days-until-expiry the alert fired for (e.g. 30,
//	            14, 7, 0). Custom-thresholds policies can grow this
//	            dimension; production deploys with the standard 4
//	            thresholds give 4 distinct values.
//	result    — closed enum:
//	              "success"   — the channel's notifier accepted the
//	                            send. (Underlying delivery may still
//	                            fail if e.g. SMTP queue is broken;
//	                            those failures surface via the
//	                            existing I-005 retry/DLQ machinery.)
//	              "failure"   — the channel's notifier returned an
//	                            error, OR the notification row failed
//	                            to persist. Operators alert on
//	                            sustained {result="failure"} > 0.
//	              "deduped"   — a prior (cert, threshold, channel)
//	                            notification was already in
//	                            persistence; today's loop skipped the
//	                            send. Useful for detecting
//	                            "everything is healthy and steady-
//	                            state" — high deduped counts mean
//	                            the daily loop is doing its job.
//
// Cardinality bound: 6 channels × 4 thresholds × 3 results = 72 series.
// A custom-thresholds policy can grow this; bound is operator-controlled.
//
// Wiring: cmd/server/main.go constructs ONE instance of
// *ExpiryAlertMetrics, calls notificationService.SetExpiryAlertMetrics
// to register the recording side, AND
// metricsHandler.SetExpiryAlerts to register the exposing side.
// Mirror of the VaultRenewalMetrics shape from the 2026-05-03
// audit fix #5 (commit `ceca364`) for operator-symmetry — same
// snapshot interface, same atomic-counters-under-RW-mutex pattern.
type ExpiryAlertMetrics struct {
	mu       sync.RWMutex
	counters map[expiryAlertKey]*atomic.Uint64
}

type expiryAlertKey struct {
	Channel   string
	Threshold int
	Result    string
}

// NewExpiryAlertMetrics constructs a fresh ExpiryAlertMetrics with all
// counters at zero. Pass to NotificationService.SetExpiryAlertMetrics
// (recording side) and MetricsHandler.SetExpiryAlerts (exposing side).
func NewExpiryAlertMetrics() *ExpiryAlertMetrics {
	return &ExpiryAlertMetrics{
		counters: make(map[expiryAlertKey]*atomic.Uint64),
	}
}

// RecordExpiryAlert bumps the (channel, threshold, result) counter.
// Implements service.ExpiryAlertRecorder (from notification.go) so
// NotificationService can call this on every dispatch outcome without
// importing the metrics package.
//
// Off-enum result values silently no-op (closed-enum discipline; we
// don't dynamic-cardinality-grow the Prometheus exposition on a
// caller typo).
func (m *ExpiryAlertMetrics) RecordExpiryAlert(channel string, threshold int, result string) {
	if m == nil {
		return
	}
	switch result {
	case "success", "failure", "deduped":
		// ok
	default:
		return
	}

	key := expiryAlertKey{Channel: channel, Threshold: threshold, Result: result}

	m.mu.RLock()
	c, ok := m.counters[key]
	m.mu.RUnlock()
	if ok {
		c.Add(1)
		return
	}

	m.mu.Lock()
	if c, ok := m.counters[key]; ok {
		// Lost the race; another goroutine inserted while we were
		// upgrading the lock.
		m.mu.Unlock()
		c.Add(1)
		return
	}
	c = &atomic.Uint64{}
	c.Add(1)
	m.counters[key] = c
	m.mu.Unlock()
}

// ExpiryAlertSnapshotEntry is one row in the snapshot result. The
// Prometheus exposer iterates these to produce the
// certctl_expiry_alerts_total{channel, threshold, result} series.
type ExpiryAlertSnapshotEntry struct {
	Channel   string
	Threshold int
	Result    string
	Count     uint64
}

// SnapshotExpiryAlerts returns a point-in-time read of every
// (channel, threshold, result) counter. The slice is sorted by
// (channel, threshold, result) so the Prometheus exposition is
// stable across requests.
//
// Implements handler.ExpiryAlertSnapshotter for the metrics emitter.
func (m *ExpiryAlertMetrics) SnapshotExpiryAlerts() []ExpiryAlertSnapshotEntry {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]ExpiryAlertSnapshotEntry, 0, len(m.counters))
	for k, v := range m.counters {
		out = append(out, ExpiryAlertSnapshotEntry{
			Channel:   k.Channel,
			Threshold: k.Threshold,
			Result:    k.Result,
			Count:     v.Load(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Channel != out[j].Channel {
			return out[i].Channel < out[j].Channel
		}
		if out[i].Threshold != out[j].Threshold {
			return out[i].Threshold < out[j].Threshold
		}
		return out[i].Result < out[j].Result
	})
	return out
}
