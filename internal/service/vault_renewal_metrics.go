package service

import "sync/atomic"

// VaultRenewalMetrics is a thread-safe counter table for the
// Vault PKI token-renewal loop. Top-10 fix #5 of the 2026-05-03
// issuer-coverage audit. Closes the operator-observability gap
// where long-lived deploys would silently lose Vault auth at TTL
// expiry.
//
// Cardinality is fixed at three series — result is a closed enum:
//
//	{success}        — the renew-self call succeeded.
//	{failure}        — the renew-self call returned a non-2xx,
//	                   parse failure, or HTTP error. Loop keeps
//	                   ticking; transient blips don't kill it.
//	{not_renewable}  — Vault returned renewable=false (or returned
//	                   it at startup lookup-self). Loop has exited;
//	                   operator must rotate the token before its
//	                   current TTL expires.
//
// One instance is shared across every Vault PKI Connector built by
// IssuerRegistry.Rebuild — the recorder pointer is wired by
// IssuerRegistry.SetVaultRenewalMetrics + the post-factory wiring
// step inside Rebuild. The same instance is also wired into
// MetricsHandler.SetVaultRenewals so the Prometheus exposer emits
// certctl_vault_token_renewals_total{result=...}.
type VaultRenewalMetrics struct {
	success      atomic.Uint64
	failure      atomic.Uint64
	notRenewable atomic.Uint64
}

// NewVaultRenewalMetrics constructs a fresh VaultRenewalMetrics
// with all counters at zero. Pass to IssuerRegistry.SetVaultRenewalMetrics
// (and to MetricsHandler.SetVaultRenewals) to wire up the renewal
// loop's metric path.
func NewVaultRenewalMetrics() *VaultRenewalMetrics {
	return &VaultRenewalMetrics{}
}

// RecordRenewal bumps the (result) counter. Implements
// vault.RenewalRecorder. Off-enum result values silently no-op
// (closed-enum discipline matches the IssuanceMetrics pattern;
// we don't dynamically grow the cardinality on a typo).
func (m *VaultRenewalMetrics) RecordRenewal(result string) {
	if m == nil {
		return
	}
	switch result {
	case "success":
		m.success.Add(1)
	case "failure":
		m.failure.Add(1)
	case "not_renewable":
		m.notRenewable.Add(1)
	}
}

// VaultRenewalSnapshot is the per-result counter view returned by
// Snapshot. Pinned in this package so the handler can consume it
// via VaultRenewalSnapshotter without cross-importing connector
// state. Field names are stable — operator dashboards alert on
// the corresponding {result=...} label values.
type VaultRenewalSnapshot struct {
	Success      uint64
	Failure      uint64
	NotRenewable uint64
}

// Snapshot returns a point-in-time read of all three counters.
// Used by tests that need to assert post-tick state. The
// Prometheus exposer in internal/api/handler/metrics.go uses
// SnapshotVaultRenewals (3-tuple form) instead, to avoid an
// import cycle on a shared struct type.
func (m *VaultRenewalMetrics) Snapshot() VaultRenewalSnapshot {
	if m == nil {
		return VaultRenewalSnapshot{}
	}
	return VaultRenewalSnapshot{
		Success:      m.success.Load(),
		Failure:      m.failure.Load(),
		NotRenewable: m.notRenewable.Load(),
	}
}

// SnapshotVaultRenewals returns the three counter values directly
// as a tuple. Implements handler.VaultRenewalSnapshotter; used by
// the Prometheus exposer. Order is fixed: success, failure,
// not_renewable.
func (m *VaultRenewalMetrics) SnapshotVaultRenewals() (success, failure, notRenewable uint64) {
	if m == nil {
		return 0, 0, 0
	}
	return m.success.Load(), m.failure.Load(), m.notRenewable.Load()
}
