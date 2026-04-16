package domain

import (
	"context"
	"time"
)

// DiscoveryStatus represents the triage state of a discovered certificate.
type DiscoveryStatus string

const (
	// DiscoveryStatusUnmanaged indicates a discovered cert not yet linked to a managed cert.
	DiscoveryStatusUnmanaged DiscoveryStatus = "Unmanaged"
	// DiscoveryStatusManaged indicates a discovered cert linked to a managed cert.
	DiscoveryStatusManaged DiscoveryStatus = "Managed"
	// DiscoveryStatusDismissed indicates a cert the operator chose to ignore.
	DiscoveryStatusDismissed DiscoveryStatus = "Dismissed"
)

// IsValidDiscoveryStatus returns true if the status is a recognized discovery status.
func IsValidDiscoveryStatus(s string) bool {
	switch DiscoveryStatus(s) {
	case DiscoveryStatusUnmanaged, DiscoveryStatusManaged, DiscoveryStatusDismissed:
		return true
	}
	return false
}

// DiscoveredCertificate represents a certificate found on an agent's filesystem.
type DiscoveredCertificate struct {
	ID                   string          `json:"id"`
	FingerprintSHA256    string          `json:"fingerprint_sha256"`
	CommonName           string          `json:"common_name"`
	SANs                 []string        `json:"sans"`
	SerialNumber         string          `json:"serial_number"`
	IssuerDN             string          `json:"issuer_dn"`
	SubjectDN            string          `json:"subject_dn"`
	NotBefore            *time.Time      `json:"not_before,omitempty"`
	NotAfter             *time.Time      `json:"not_after,omitempty"`
	KeyAlgorithm         string          `json:"key_algorithm"`
	KeySize              int             `json:"key_size"`
	IsCA                 bool            `json:"is_ca"`
	PEMData              string          `json:"pem_data,omitempty"`
	SourcePath           string          `json:"source_path"`
	SourceFormat         string          `json:"source_format"`
	AgentID              string          `json:"agent_id"`
	DiscoveryScanID      string          `json:"discovery_scan_id,omitempty"`
	ManagedCertificateID string          `json:"managed_certificate_id,omitempty"`
	Status               DiscoveryStatus `json:"status"`
	FirstSeenAt          time.Time       `json:"first_seen_at"`
	LastSeenAt           time.Time       `json:"last_seen_at"`
	DismissedAt          *time.Time      `json:"dismissed_at,omitempty"`
	CreatedAt            time.Time       `json:"created_at"`
	UpdatedAt            time.Time       `json:"updated_at"`
}

// IsExpired returns true if the discovered certificate has expired.
func (d *DiscoveredCertificate) IsExpired() bool {
	if d.NotAfter == nil {
		return false
	}
	return d.NotAfter.Before(time.Now())
}

// DaysUntilExpiry returns the number of days until the certificate expires.
// Returns -1 if NotAfter is not set.
func (d *DiscoveredCertificate) DaysUntilExpiry() int {
	if d.NotAfter == nil {
		return -1
	}
	hours := time.Until(*d.NotAfter).Hours()
	return int(hours / 24)
}

// DiscoveryScan represents a single discovery scan run by an agent.
type DiscoveryScan struct {
	ID                string     `json:"id"`
	AgentID           string     `json:"agent_id"`
	Directories       []string   `json:"directories"`
	CertificatesFound int        `json:"certificates_found"`
	CertificatesNew   int        `json:"certificates_new"`
	ErrorsCount       int        `json:"errors_count"`
	ScanDurationMs    int        `json:"scan_duration_ms"`
	StartedAt         time.Time  `json:"started_at"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
}

// DiscoveryReport is the payload an agent sends after scanning its filesystem.
type DiscoveryReport struct {
	AgentID        string                `json:"agent_id"`
	Directories    []string              `json:"directories"`
	Certificates   []DiscoveredCertEntry `json:"certificates"`
	Errors         []string              `json:"errors,omitempty"`
	ScanDurationMs int                   `json:"scan_duration_ms"`
}

// DiscoveredCertEntry represents a single certificate found during a filesystem scan.
// This is the agent-side representation (no server-side IDs yet).
type DiscoveredCertEntry struct {
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	CommonName        string   `json:"common_name"`
	SANs              []string `json:"sans"`
	SerialNumber      string   `json:"serial_number"`
	IssuerDN          string   `json:"issuer_dn"`
	SubjectDN         string   `json:"subject_dn"`
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after"`
	KeyAlgorithm      string   `json:"key_algorithm"`
	KeySize           int      `json:"key_size"`
	IsCA              bool     `json:"is_ca"`
	PEMData           string   `json:"pem_data"`
	SourcePath        string   `json:"source_path"`
	SourceFormat      string   `json:"source_format"`
}

// DiscoverySource defines the interface for pluggable certificate discovery sources.
// Each source (filesystem, network, cloud) implements this interface to discover
// certificates from a specific backend and produce a DiscoveryReport.
type DiscoverySource interface {
	// Name returns a human-readable name for this discovery source (e.g., "AWS Secrets Manager").
	Name() string
	// Type returns a short type identifier (e.g., "aws-sm", "azure-kv", "gcp-sm").
	Type() string
	// Discover scans the source and returns a DiscoveryReport with found certificates.
	Discover(ctx context.Context) (*DiscoveryReport, error)
	// ValidateConfig checks that the source is properly configured.
	ValidateConfig() error
}
