package domain

import "time"

// RevocationReason represents the reason for revoking a certificate.
// Values align with RFC 5280 Section 5.3.1 CRL reason codes.
type RevocationReason string

const (
	RevocationReasonUnspecified          RevocationReason = "unspecified"
	RevocationReasonKeyCompromise        RevocationReason = "keyCompromise"
	RevocationReasonCACompromise         RevocationReason = "caCompromise"
	RevocationReasonAffiliationChanged   RevocationReason = "affiliationChanged"
	RevocationReasonSuperseded           RevocationReason = "superseded"
	RevocationReasonCessationOfOperation RevocationReason = "cessationOfOperation"
	RevocationReasonCertificateHold      RevocationReason = "certificateHold"
	RevocationReasonPrivilegeWithdrawn   RevocationReason = "privilegeWithdrawn"
)

// ValidRevocationReasons contains all valid revocation reason strings.
var ValidRevocationReasons = map[RevocationReason]int{
	RevocationReasonUnspecified:          0,
	RevocationReasonKeyCompromise:        1,
	RevocationReasonCACompromise:         2,
	RevocationReasonAffiliationChanged:   3,
	RevocationReasonSuperseded:           4,
	RevocationReasonCessationOfOperation: 5,
	RevocationReasonCertificateHold:      6,
	RevocationReasonPrivilegeWithdrawn:   9,
}

// IsValidRevocationReason checks whether a reason string is a valid RFC 5280 reason code.
func IsValidRevocationReason(reason string) bool {
	_, ok := ValidRevocationReasons[RevocationReason(reason)]
	return ok
}

// CRLReasonCode returns the RFC 5280 integer reason code for a revocation reason.
func CRLReasonCode(reason RevocationReason) int {
	if code, ok := ValidRevocationReasons[reason]; ok {
		return code
	}
	return 0 // unspecified
}

// BulkRevocationCriteria defines the filter criteria for bulk certificate revocation.
// At least one field must be set — empty criteria is rejected as a safety guard.
type BulkRevocationCriteria struct {
	ProfileID      string   `json:"profile_id,omitempty"`
	OwnerID        string   `json:"owner_id,omitempty"`
	AgentID        string   `json:"agent_id,omitempty"`
	IssuerID       string   `json:"issuer_id,omitempty"`
	TeamID         string   `json:"team_id,omitempty"`
	CertificateIDs []string `json:"certificate_ids,omitempty"`
}

// IsEmpty returns true if no filter criteria are set.
func (c BulkRevocationCriteria) IsEmpty() bool {
	return c.ProfileID == "" && c.OwnerID == "" && c.AgentID == "" &&
		c.IssuerID == "" && c.TeamID == "" && len(c.CertificateIDs) == 0
}

// BulkRevocationResult contains the outcome of a bulk revocation operation.
type BulkRevocationResult struct {
	TotalMatched int                    `json:"total_matched"`
	TotalRevoked int                    `json:"total_revoked"`
	TotalSkipped int                    `json:"total_skipped"`
	TotalFailed  int                    `json:"total_failed"`
	Errors       []BulkRevocationError  `json:"errors,omitempty"`
}

// BulkRevocationError records a per-certificate revocation failure.
type BulkRevocationError struct {
	CertificateID string `json:"certificate_id"`
	Error         string `json:"error"`
}

// CertificateRevocation records the revocation of a specific certificate version.
// Used as the authoritative source for CRL generation.
type CertificateRevocation struct {
	ID             string    `json:"id"`
	CertificateID  string    `json:"certificate_id"`
	SerialNumber   string    `json:"serial_number"`
	Reason         string    `json:"reason"`
	RevokedBy      string    `json:"revoked_by"`
	RevokedAt      time.Time `json:"revoked_at"`
	IssuerID       string    `json:"issuer_id"`
	IssuerNotified bool      `json:"issuer_notified"`
	CreatedAt      time.Time `json:"created_at"`
}
