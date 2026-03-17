package issuer

import (
	"context"
	"encoding/json"
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
}

// IssuanceRequest contains the parameters for issuing a new certificate.
type IssuanceRequest struct {
	CommonName string   `json:"common_name"`
	SANs       []string `json:"sans"`
	CSRPEM     string   `json:"csr_pem"`
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
