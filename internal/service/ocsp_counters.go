package service

import "sync/atomic"

// Production hardening II Phase 1.3 — OCSP per-request counters.
//
// Mirrors the pattern in est_counters.go and scep_counters.go:
// sync/atomic primitives keep the hot path lock-free, while a snapshot
// accessor produces a stable map for the Prometheus exposition handler
// (Phase 8).
//
// Counter labels are stable strings — the Prometheus phase converts
// them into `certctl_ocsp_<label>_total` metric names. Adding a new
// label here without also adding it to the Prometheus exposer would
// be a "silent counter" bug; the exposer test in Phase 8 enumerates
// the labels to defend against drift.

// OCSPCounters is the shared counter table for OCSP request processing.
// A single instance lives on the certificate service (or the OCSP
// cache service when present) and ticks every OCSP request through
// its lifecycle:
//
//   - request_get / request_post — incremented per inbound request
//     by transport.
//   - request_success — incremented when a signed OCSP response is
//     written to the wire (regardless of cert status: good / revoked
//     / unknown all count as success).
//   - request_invalid — malformed request body (ocsp.ParseRequest
//     failure) or path-extraction failure.
//   - issuer_not_found — request's issuer_id doesn't resolve to a
//     known issuer connector.
//   - cert_not_found — request's serial doesn't resolve to any
//     issued cert.
//   - signing_failed — issuer connector returned an error.
//   - nonce_echoed — request carried a well-formed nonce extension
//     and the response echoed it (RFC 6960 §4.4.1 happy path).
//   - nonce_malformed — request carried a nonce extension that was
//     too long (>32 bytes, per CA/B Forum guidance) or empty. The
//     response is unauthorized (status 6).
//   - rate_limited — Phase 3 limiter tripped; the response is
//     unauthorized (status 6) plus a Retry-After hint.
//
// New labels MUST also be added to OCSPCounters.Snapshot AND to the
// Prometheus exposer in Phase 8.
type OCSPCounters struct {
	requestGET     atomic.Uint64
	requestPOST    atomic.Uint64
	requestSuccess atomic.Uint64
	requestInvalid atomic.Uint64
	issuerNotFound atomic.Uint64
	certNotFound   atomic.Uint64
	signingFailed  atomic.Uint64
	nonceEchoed    atomic.Uint64
	nonceMalformed atomic.Uint64
	rateLimited    atomic.Uint64
}

// NewOCSPCounters constructs a zero-value counter table. The caller
// holds it for the process lifetime; counters are never reset.
func NewOCSPCounters() *OCSPCounters {
	return &OCSPCounters{}
}

// IncRequestGET ticks the GET-form request counter.
func (c *OCSPCounters) IncRequestGET() { c.requestGET.Add(1) }

// IncRequestPOST ticks the POST-form request counter.
func (c *OCSPCounters) IncRequestPOST() { c.requestPOST.Add(1) }

// IncRequestSuccess ticks the response-written counter.
func (c *OCSPCounters) IncRequestSuccess() { c.requestSuccess.Add(1) }

// IncRequestInvalid ticks the parse-failure counter.
func (c *OCSPCounters) IncRequestInvalid() { c.requestInvalid.Add(1) }

// IncIssuerNotFound ticks the unknown-issuer counter.
func (c *OCSPCounters) IncIssuerNotFound() { c.issuerNotFound.Add(1) }

// IncCertNotFound ticks the unknown-serial counter.
func (c *OCSPCounters) IncCertNotFound() { c.certNotFound.Add(1) }

// IncSigningFailed ticks the issuer-error counter.
func (c *OCSPCounters) IncSigningFailed() { c.signingFailed.Add(1) }

// IncNonceEchoed ticks the well-formed-nonce-echoed counter.
func (c *OCSPCounters) IncNonceEchoed() { c.nonceEchoed.Add(1) }

// IncNonceMalformed ticks the bad-nonce-rejected counter.
func (c *OCSPCounters) IncNonceMalformed() { c.nonceMalformed.Add(1) }

// IncRateLimited ticks the limiter-tripped counter.
func (c *OCSPCounters) IncRateLimited() { c.rateLimited.Add(1) }

// Snapshot returns a stable map of label → counter value for the
// Prometheus exposer (Phase 8). The returned map is a copy; concurrent
// counter ticks during the snapshot read are not reflected.
func (c *OCSPCounters) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"request_get":      c.requestGET.Load(),
		"request_post":     c.requestPOST.Load(),
		"request_success":  c.requestSuccess.Load(),
		"request_invalid":  c.requestInvalid.Load(),
		"issuer_not_found": c.issuerNotFound.Load(),
		"cert_not_found":   c.certNotFound.Load(),
		"signing_failed":   c.signingFailed.Load(),
		"nonce_echoed":     c.nonceEchoed.Load(),
		"nonce_malformed":  c.nonceMalformed.Load(),
		"rate_limited":     c.rateLimited.Load(),
	}
}
