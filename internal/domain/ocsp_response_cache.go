package domain

import "time"

// OCSPResponseCacheEntry is one row in the ocsp_response_cache table —
// a pre-signed OCSP response for a specific (issuer_id, serial_hex)
// pair. The HTTP handler at /.well-known/pki/ocsp/{issuer_id}/...
// reads from this cache rather than triggering a fresh signature per
// request. Production hardening II Phase 2.
//
// Schema lives in migrations/000024_ocsp_response_cache.up.sql.
type OCSPResponseCacheEntry struct {
	IssuerID         string    `json:"issuer_id"`
	SerialHex        string    `json:"serial_hex"`
	ResponseDER      []byte    `json:"-"` // raw DER, omitted from admin JSON to keep responses lean
	CertStatus       string    `json:"cert_status"`                  // "good" | "revoked" | "unknown"
	RevocationReason int       `json:"revocation_reason,omitempty"`  // only set when CertStatus == "revoked"
	RevokedAt        time.Time `json:"revoked_at,omitempty"`         // only set when CertStatus == "revoked"
	ThisUpdate       time.Time `json:"this_update"`
	NextUpdate       time.Time `json:"next_update"`
	GeneratedAt      time.Time `json:"generated_at"`
}

// IsStale returns true when next_update is at or before now — the
// cached response's promised validity window has elapsed. Callers fall
// through to live signing on stale + write the fresh response back to
// cache (read-through facade).
func (e *OCSPResponseCacheEntry) IsStale(now time.Time) bool {
	return !now.Before(e.NextUpdate)
}
