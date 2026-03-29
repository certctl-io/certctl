package issuer

import (
	"context"
	"encoding/json"
	"math/big"
	"time"
)

// Connector defines the interface for certificate issuance operations.
type Connector interface {
	// ValidateConfig validates the issuer configuration.
	ValidateConfig(ctx context.Context, config json.RawMessage) error

	// IssueCertificate issues a new certificate.
	IssueCertificate(ctx context.Context, request IssuanceRequest) (*IssuanceResult, error)

	// RenewCertificate renews an existing certificate.
	RenewCertificate(ctx context.Context, request RenewalRequest) (*IssuanceResult, error)

	// RevokeCertificate revokes a certificate.
	RevokeCertificate(ctx context.Context, request RevocationRequest) error

	// GetOrderStatus retrieves the status of an issuance or renewal order.
	GetOrderStatus(ctx context.Context, orderID string) (*OrderStatus, error)

	// GenerateCRL generates a DER-encoded X.509 CRL signed by this issuer.
	// Returns nil if the issuer does not support CRL generation (e.g., ACME).
	GenerateCRL(ctx context.Context, revokedCerts []RevokedCertEntry) ([]byte, error)

	// SignOCSPResponse signs an OCSP response for the given certificate serial.
	// Returns nil if the issuer does not support OCSP (e.g., ACME).
	SignOCSPResponse(ctx context.Context, req OCSPSignRequest) ([]byte, error)

	// GetCACertPEM returns the PEM-encoded CA certificate chain for this issuer.
	// Used by the EST /cacerts endpoint. Returns empty string if not available.
	GetCACertPEM(ctx context.Context) (string, error)

	// GetRenewalInfo retrieves ACME Renewal Information (ARI) per RFC 9702 for a certificate.
	// certPEM is the PEM-encoded certificate. Returns nil, nil if the CA does not support ARI.
	GetRenewalInfo(ctx context.Context, certPEM string) (*RenewalInfoResult, error)
}

// RenewalInfoResult holds the ACME ARI response from a CA.
type RenewalInfoResult struct {
	SuggestedWindowStart time.Time
	SuggestedWindowEnd   time.Time
	RetryAfter           time.Time
	ExplanationURL       string
}

// IssuanceRequest contains the parameters for issuing a new certificate.
type IssuanceRequest struct {
	CommonName string   `json:"common_name"`
	SANs       []string `json:"sans"`
	CSRPEM     string   `json:"csr_pem"`
	EKUs       []string `json:"ekus,omitempty"` // e.g., "serverAuth", "clientAuth", "emailProtection"
}

// IssuanceResult contains the result of a successful certificate issuance.
type IssuanceResult struct {
	CertPEM   string    `json:"cert_pem"`
	ChainPEM  string    `json:"chain_pem"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	OrderID   string    `json:"order_id"`
}

// RenewalRequest contains the parameters for renewing a certificate.
type RenewalRequest struct {
	CommonName string   `json:"common_name"`
	SANs       []string `json:"sans"`
	CSRPEM     string   `json:"csr_pem"`
	EKUs       []string `json:"ekus,omitempty"` // e.g., "serverAuth", "clientAuth", "emailProtection"
	OrderID    *string  `json:"order_id,omitempty"`
}

// RevocationRequest contains the parameters for revoking a certificate.
type RevocationRequest struct {
	Serial string  `json:"serial"`
	Reason *string `json:"reason,omitempty"`
}

// OrderStatus contains the status of a pending issuance or renewal order.
type OrderStatus struct {
	OrderID   string     `json:"order_id"`
	Status    string     `json:"status"`
	Message   *string    `json:"message,omitempty"`
	CertPEM   *string    `json:"cert_pem,omitempty"`
	ChainPEM  *string    `json:"chain_pem,omitempty"`
	Serial    *string    `json:"serial,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	NotAfter  *time.Time `json:"not_after,omitempty"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// RevokedCertEntry represents a revoked certificate for CRL generation.
type RevokedCertEntry struct {
	SerialNumber *big.Int
	RevokedAt    time.Time
	ReasonCode   int
}

// OCSPSignRequest contains the parameters for signing an OCSP response.
type OCSPSignRequest struct {
	CertSerial       *big.Int
	CertStatus       int // 0=good, 1=revoked, 2=unknown
	RevokedAt        time.Time
	RevocationReason int
	ThisUpdate       time.Time
	NextUpdate       time.Time
}
