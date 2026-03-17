package domain

import (
	"time"
)

// ManagedCertificate represents a certificate managed by the control plane.
type ManagedCertificate struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	CommonName       string            `json:"common_name"`
	SANs             []string          `json:"sans"`
	Environment      string            `json:"environment"`
	OwnerID          string            `json:"owner_id"`
	TeamID           string            `json:"team_id"`
	IssuerID         string            `json:"issuer_id"`
	TargetIDs        []string          `json:"target_ids"`
	RenewalPolicyID  string            `json:"renewal_policy_id"`
	Status           CertificateStatus `json:"status"`
	ExpiresAt        time.Time         `json:"expires_at"`
	Tags             map[string]string `json:"tags"`
	LastRenewalAt    *time.Time        `json:"last_renewal_at,omitempty"`
	LastDeploymentAt *time.Time        `json:"last_deployment_at,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

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
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	RenewalWindowDays   int       `json:"renewal_window_days"`
	AutoRenew           bool      `json:"auto_renew"`
	MaxRetries          int       `json:"max_retries"`
	RetryInterval       int       `json:"retry_interval_seconds"`
	AlertThresholdsDays []int     `json:"alert_thresholds_days"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
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
