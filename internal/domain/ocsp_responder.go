package domain

import "time"

// OCSPResponder represents the dedicated OCSP-signing cert + key pair
// for one issuer. Per RFC 6960 §2.6 + §4.2.2.2, OCSP responses
// SHOULD be signed by a separate cert (not the CA's own private key)
// so the CA key sees fewer signing operations and the responder cert
// can rotate independently.
//
// Schema lives in migrations/000020_ocsp_responder.up.sql.
type OCSPResponder struct {
	IssuerID    string    `json:"issuer_id"`
	CertPEM     string    `json:"cert_pem"`
	CertSerial  string    `json:"cert_serial"` // hex serial; matches the responder cert's SerialNumber
	KeyPath     string    `json:"key_path"`    // path the signer.Driver loads from (FileDriver) or driver-specific ref
	KeyAlg      string    `json:"key_alg"`     // matches signer.Algorithm enum (e.g., "ECDSA-P256")
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	RotatedFrom string    `json:"rotated_from,omitempty"` // previous CertSerial when this row replaced an earlier one
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// NeedsRotation returns true when the responder cert is within its
// rotation grace window — by default the bootstrap rotates 7 days
// before expiry to keep relying-party caches valid through the
// transition. Callers passing time.Time{} get the strict definition
// (only rotate when expired).
//
// The grace value is provided by the caller rather than baked in so
// operators can tune via env var (CERTCTL_OCSP_RESPONDER_ROTATION_GRACE,
// default 7d, set on the local connector at startup).
func (r *OCSPResponder) NeedsRotation(now time.Time, grace time.Duration) bool {
	if r == nil {
		return true
	}
	return !now.Add(grace).Before(r.NotAfter)
}
