package domain

import (
	"encoding/json"
	"time"
)

// PolicyRule defines enforcement rules for certificate management.
type PolicyRule struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Type      PolicyType      `json:"type"`
	Config    json.RawMessage `json:"config"`
	Enabled   bool            `json:"enabled"`
	Severity  PolicySeverity  `json:"severity"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// PolicyType represents the category of policy enforcement.
type PolicyType string

const (
	PolicyTypeAllowedIssuers       PolicyType = "AllowedIssuers"
	PolicyTypeAllowedDomains       PolicyType = "AllowedDomains"
	PolicyTypeRequiredMetadata     PolicyType = "RequiredMetadata"
	PolicyTypeAllowedEnvironments  PolicyType = "AllowedEnvironments"
	PolicyTypeRenewalLeadTime      PolicyType = "RenewalLeadTime"
	PolicyTypeCertificateLifetime  PolicyType = "CertificateLifetime"
)

// PolicyViolation records an instance of a certificate violating a policy rule.
type PolicyViolation struct {
	ID            string         `json:"id"`
	CertificateID string         `json:"certificate_id"`
	RuleID        string         `json:"rule_id"`
	Message       string         `json:"message"`
	Severity      PolicySeverity `json:"severity"`
	CreatedAt     time.Time      `json:"created_at"`
}

// PolicySeverity indicates the impact level of a policy violation.
type PolicySeverity string

const (
	PolicySeverityWarning  PolicySeverity = "Warning"
	PolicySeverityError    PolicySeverity = "Error"
	PolicySeverityCritical PolicySeverity = "Critical"
)
