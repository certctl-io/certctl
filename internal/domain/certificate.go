package domain

import (
	"time"
)

// ManagedCertificate represents a certificate managed by the control plane.
type ManagedCertificate struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	CommonName           string            `json:"common_name"`
	SANs                 []string          `json:"sans"`
	Environment          string            `json:"environment"`
	OwnerID              string            `json:"owner_id"`
	TeamID               string            `json:"team_id"`
	IssuerID             string            `json:"issuer_id"`
	TargetIDs            []string          `json:"target_ids"`
	RenewalPolicyID      string            `json:"renewal_policy_id"`
	CertificateProfileID string            `json:"certificate_profile_id,omitempty"`
	Status               CertificateStatus `json:"status"`
	ExpiresAt            time.Time         `json:"expires_at"`
	Tags                 map[string]string `json:"tags"`
	LastRenewalAt        *time.Time        `json:"last_renewal_at,omitempty"`
	LastDeploymentAt     *time.Time        `json:"last_deployment_at,omitempty"`
	RevokedAt            *time.Time        `json:"revoked_at,omitempty"`
	RevocationReason     string            `json:"revocation_reason,omitempty"`
	CreatedAt            time.Time         `json:"created_at"`
	UpdatedAt            time.Time         `json:"updated_at"`

	// Source tags how this managed certificate was created. EST RFC 7030
	// hardening master bundle Phase 11.1 — operators bulk-revoke
	// EST-issued certs by filtering on Source=EST. Empty value preserves
	// the v2.X.0 behavior (the bulk-revoke handler treats empty as
	// equivalent to legacy/manual; new EST issuances stamp Source=EST,
	// new SCEP issuances will eventually stamp Source=SCEP under a
	// future bundle).
	Source CertificateSource `json:"source,omitempty"`
}

// CertificateSource is the enum of provenance values stamped on each
// managed-certificate row when it's created. The empty string is the
// back-compat default — pre-Phase-11 rows have it set to "" by the
// migration's DEFAULT clause; the bulk-revoke filter treats empty as
// "any source" so existing call paths see no behavior change.
//
// EST RFC 7030 hardening master bundle Phase 11.1.
type CertificateSource string

const (
	// CertificateSourceUnspecified preserves the v2.X.0 default ("").
	CertificateSourceUnspecified CertificateSource = ""
	// CertificateSourceEST stamps every cert issued through one of the
	// EST endpoints (simpleenroll / simplereenroll / serverkeygen).
	CertificateSourceEST CertificateSource = "EST"
	// CertificateSourceSCEP / API / Agent reserve future provenance
	// values — not stamped today; SCEP-issued certs continue to land
	// with Source="" until a follow-up bundle wires the stamp at the
	// SCEP service layer.
	CertificateSourceSCEP  CertificateSource = "SCEP"
	CertificateSourceAPI   CertificateSource = "API"
	CertificateSourceAgent CertificateSource = "Agent"
)

// CertificateVersion represents a specific version of a certificate.
type CertificateVersion struct {
	ID                string    `json:"id"`
	CertificateID     string    `json:"certificate_id"`
	SerialNumber      string    `json:"serial_number"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	PEMChain          string    `json:"pem_chain"`
	CSRPEM            string    `json:"csr_pem"`
	KeyAlgorithm      string    `json:"key_algorithm,omitempty"`
	KeySize           int       `json:"key_size,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

// CertificateStatus represents the lifecycle status of a managed certificate.
type CertificateStatus string

const (
	CertificateStatusPending           CertificateStatus = "Pending"
	CertificateStatusActive            CertificateStatus = "Active"
	CertificateStatusExpiring          CertificateStatus = "Expiring"
	CertificateStatusExpired           CertificateStatus = "Expired"
	CertificateStatusRenewalInProgress CertificateStatus = "RenewalInProgress"
	CertificateStatusFailed            CertificateStatus = "Failed"
	CertificateStatusRevoked           CertificateStatus = "Revoked"
	CertificateStatusArchived          CertificateStatus = "Archived"
)

// RenewalPolicy defines renewal parameters for a managed certificate.
type RenewalPolicy struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	RenewalWindowDays    int       `json:"renewal_window_days"`
	AutoRenew            bool      `json:"auto_renew"`
	MaxRetries           int       `json:"max_retries"`
	RetryInterval        int       `json:"retry_interval_seconds"`
	AlertThresholdsDays  []int     `json:"alert_thresholds_days"`
	CertificateProfileID string    `json:"certificate_profile_id,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// DefaultAlertThresholds returns the standard alert thresholds when none are configured.
func DefaultAlertThresholds() []int {
	return []int{30, 14, 7, 0}
}

// EffectiveAlertThresholds returns the configured thresholds or defaults if empty.
func (p *RenewalPolicy) EffectiveAlertThresholds() []int {
	if len(p.AlertThresholdsDays) > 0 {
		return p.AlertThresholdsDays
	}
	return DefaultAlertThresholds()
}
