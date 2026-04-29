package domain

import "time"

// CRLCacheEntry is one row in the crl_cache table — a CRL that the
// scheduler has pre-generated for a specific issuer. The HTTP handler
// at /.well-known/pki/crl/{issuer_id} reads from this cache rather
// than triggering a fresh generation per request.
//
// Schema lives in migrations/000019_crl_cache.up.sql.
type CRLCacheEntry struct {
	IssuerID           string        `json:"issuer_id"`
	CRLDER             []byte        `json:"-"`                        // raw DER, omitted from JSON to avoid bloating admin responses
	CRLDERBase64       string        `json:"crl_der_base64,omitempty"` // populated by repository.Get when callers want the bytes JSON-shaped
	CRLNumber          int64         `json:"crl_number"`               // monotonic per RFC 5280 §5.2.3
	ThisUpdate         time.Time     `json:"this_update"`
	NextUpdate         time.Time     `json:"next_update"`
	GeneratedAt        time.Time     `json:"generated_at"`
	GenerationDuration time.Duration `json:"generation_duration"`
	RevokedCount       int           `json:"revoked_count"`
}

// IsStale returns true when next_update is in the past — the cached CRL
// is no longer trustworthy according to its own thisUpdate/nextUpdate
// promise. The cache service uses this to decide whether to serve from
// cache or trigger an immediate regeneration.
//
// A small grace window (configurable upstream; defaults to 5 minutes)
// lets the scheduler refresh proactively before the cache hits hard
// staleness. Callers that want the strict definition pass time.Time{}
// or now (no grace).
func (e *CRLCacheEntry) IsStale(now time.Time) bool {
	return !now.Before(e.NextUpdate)
}

// CRLGenerationEvent records one (re)generation attempt for ops visibility.
// Persisted to crl_generation_events. Both successful and failed
// generations get an event so operators can grep for "why is this issuer's
// CRL not refreshing." On failure, the Error field carries the wrapped
// error string from the issuer connector.
type CRLGenerationEvent struct {
	ID           int64         `json:"id,omitempty"` // bigserial, set by DB
	IssuerID     string        `json:"issuer_id"`
	CRLNumber    int64         `json:"crl_number"` // 0 if generation failed before assigning a number
	Duration     time.Duration `json:"duration"`
	RevokedCount int           `json:"revoked_count"`
	StartedAt    time.Time     `json:"started_at"`
	Succeeded    bool          `json:"succeeded"`
	Error        string        `json:"error,omitempty"`
}
