package domain

import "time"

// NetworkScanTarget defines a network range to scan for TLS certificates.
type NetworkScanTarget struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	CIDRs              []string  `json:"cidrs"`
	Ports              []int     `json:"ports"`
	Enabled            bool      `json:"enabled"`
	ScanIntervalHours  int       `json:"scan_interval_hours"`
	TimeoutMs          int       `json:"timeout_ms"`
	LastScanAt         *time.Time `json:"last_scan_at,omitempty"`
	LastScanDurationMs *int      `json:"last_scan_duration_ms,omitempty"`
	LastScanCertsFound *int      `json:"last_scan_certs_found,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// NetworkScanResult holds the outcome of scanning a single endpoint.
type NetworkScanResult struct {
	Address   string // "ip:port"
	Certs     []DiscoveredCertEntry
	Error     string
	LatencyMs int
}
