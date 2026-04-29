package domain

import "time"

// NetworkScanTarget defines a network range to scan for TLS certificates.
type NetworkScanTarget struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	CIDRs              []string   `json:"cidrs"`
	Ports              []int64    `json:"ports"`
	Enabled            bool       `json:"enabled"`
	ScanIntervalHours  int        `json:"scan_interval_hours"`
	TimeoutMs          int        `json:"timeout_ms"`
	LastScanAt         *time.Time `json:"last_scan_at,omitempty"`
	LastScanDurationMs *int       `json:"last_scan_duration_ms,omitempty"`
	LastScanCertsFound *int       `json:"last_scan_certs_found,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// NetworkScanResult holds the outcome of scanning a single endpoint.
type NetworkScanResult struct {
	Address   string // "ip:port"
	Certs     []DiscoveredCertEntry
	Error     string
	LatencyMs int
}

// SCEPProbeResult is the per-target output of an SCEP probe — a
// capability/posture snapshot of an SCEP server (RFC 8894 §3.5.1
// GetCACaps + §3.5.1 GetCACert). Used for pre-migration assessment
// (operators about to switch from EJBCA / NDES to certctl run the
// scanner against their existing SCEP server first) and compliance
// posture audits.
//
// SCEP RFC 8894 + Intune master bundle Phase 11.5.
//
// The probe deliberately does NOT POST a CSR — that would consume slot
// allocations on the target server and create audit noise. Reachability
// + capability + CA-cert metadata is the value this returns.
//
// Persistence: instances are stored in scep_probe_results (migration
// 000021) so the operator's GUI can show recent probe history.
type SCEPProbeResult struct {
	ID                    string    `json:"id"`
	TargetURL             string    `json:"target_url"`
	Reachable             bool      `json:"reachable"`
	AdvertisedCaps        []string  `json:"advertised_caps"`           // GetCACaps response, parsed
	SupportsRFC8894       bool      `json:"supports_rfc8894"`          // GetCACaps contains "SCEPStandard"
	SupportsAES           bool      `json:"supports_aes"`              // contains "AES"
	SupportsPOSTOperation bool      `json:"supports_post_operation"`   // contains "POSTPKIOperation"
	SupportsRenewal       bool      `json:"supports_renewal"`          // contains "Renewal"
	SupportsSHA256        bool      `json:"supports_sha256"`           // contains "SHA-256"
	SupportsSHA512        bool      `json:"supports_sha512"`           // contains "SHA-512"
	CACertSubject         string    `json:"ca_cert_subject,omitempty"` // GetCACert leaf cert subject DN
	CACertIssuer          string    `json:"ca_cert_issuer,omitempty"`  // leaf cert issuer DN
	CACertNotBefore       time.Time `json:"ca_cert_not_before,omitempty"`
	CACertNotAfter        time.Time `json:"ca_cert_not_after,omitempty"`
	CACertExpired         bool      `json:"ca_cert_expired"`
	CACertDaysToExpiry    int       `json:"ca_cert_days_to_expiry"`
	CACertAlgorithm       string    `json:"ca_cert_algorithm,omitempty"` // "RSA-2048", "ECDSA-P256", etc.
	CACertChainLength     int       `json:"ca_cert_chain_length"`        // 1 = single cert, >1 = full chain returned
	ProbedAt              time.Time `json:"probed_at"`
	ProbeDurationMs       int64     `json:"probe_duration_ms"`
	Error                 string    `json:"error,omitempty"`
	CreatedAt             time.Time `json:"created_at,omitempty"`
}
