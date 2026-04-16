// Package entrust implements the issuer.Connector interface for Entrust Certificate Services.
//
// Entrust Certificate Services provides enterprise certificate authority offerings via
// the Entrust CA Gateway REST API. Unlike synchronous issuers (Vault, step-ca), Entrust
// uses an asynchronous order model: submit an enrollment, receive a tracking ID, then
// poll for completion. This connector maps to certctl's existing job state machine:
//   - IssueCertificate submits the enrollment; if status is "ISSUED", returns cert immediately.
//     If status is pending, returns OrderID with empty CertPEM — the job system polls
//     via GetOrderStatus.
//   - GetOrderStatus polls the enrollment; when status becomes "ISSUED", returns the cert.
//
// Authentication: mTLS client certificate loaded from disk (X509 key pair).
// No API key header — uses mutual TLS authentication at the transport layer.
//
// Entrust CA Gateway REST API used:
//
//	POST /v1/certificate-authorities/{caId}/enrollments                - Submit enrollment
//	GET  /v1/certificate-authorities/{caId}/enrollments/{trackingId}  - Check enrollment status
//	PUT  /v1/certificate-authorities/{caId}/certificates/{serial}/revoke - Revoke certificate
//	GET  /v1/certificate-authorities/{caId}                            - Validate CA access
package entrust

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
)

// Config represents the Entrust Certificate Services issuer connector configuration.
type Config struct {
	// APIUrl is the base URL for the Entrust CA Gateway REST API.
	// Required. Set via CERTCTL_ENTRUST_API_URL environment variable.
	APIUrl string `json:"api_url"`

	// ClientCertPath is the path to the client certificate PEM file for mTLS.
	// Required. Set via CERTCTL_ENTRUST_CLIENT_CERT_PATH environment variable.
	ClientCertPath string `json:"client_cert_path"`

	// ClientKeyPath is the path to the client private key PEM file for mTLS.
	// Required. Set via CERTCTL_ENTRUST_CLIENT_KEY_PATH environment variable.
	ClientKeyPath string `json:"client_key_path"`

	// CAId is the Entrust Certificate Authority ID.
	// Required. Set via CERTCTL_ENTRUST_CA_ID environment variable.
	CAId string `json:"ca_id"`

	// ProfileId is the optional Entrust enrollment profile ID.
	// If set, constrains enrollments to use this profile.
	// Set via CERTCTL_ENTRUST_PROFILE_ID environment variable.
	ProfileId string `json:"profile_id,omitempty"`
}

// Connector implements the issuer.Connector interface for Entrust Certificate Services.
type Connector struct {
	config     *Config
	logger     *slog.Logger
	httpClient *http.Client
}

// New creates a new Entrust Certificate Services connector with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	return &Connector{
		config: config,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewWithHTTPClient creates a new Entrust connector with a custom HTTP client (for testing).
func NewWithHTTPClient(config *Config, logger *slog.Logger, client *http.Client) *Connector {
	return &Connector{
		config:     config,
		logger:     logger,
		httpClient: client,
	}
}

// enrollmentRequest is the JSON body for Entrust enrollment submission.
type enrollmentRequest struct {
	CSR                 string `json:"csr"`
	ProfileId           string `json:"profileId,omitempty"`
	SubjectAltNames     []san  `json:"subjectAltNames,omitempty"`
	CertificateAuthority string `json:"certificateAuthority,omitempty"`
}

type san struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// enrollmentResponse is the JSON response from an enrollment submission.
type enrollmentResponse struct {
	TrackingId  string `json:"trackingId"`
	Status      string `json:"status"`
	Certificate string `json:"certificate,omitempty"`
	Chain       string `json:"chain,omitempty"`
}

// enrollmentStatusResponse is the JSON response from an enrollment status check.
type enrollmentStatusResponse struct {
	TrackingId  string `json:"trackingId"`
	Status      string `json:"status"`
	Certificate string `json:"certificate,omitempty"`
	Chain       string `json:"chain,omitempty"`
}

// revocationRequest is the JSON body for revocation submission.
type revocationRequest struct {
	RevocationReason string `json:"revocationReason"`
}

// ValidateConfig checks that the Entrust configuration is valid and mTLS access works.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid Entrust config: %w", err)
	}

	if cfg.APIUrl == "" {
		return fmt.Errorf("Entrust api_url is required")
	}

	if cfg.ClientCertPath == "" {
		return fmt.Errorf("Entrust client_cert_path is required")
	}

	if cfg.ClientKeyPath == "" {
		return fmt.Errorf("Entrust client_key_path is required")
	}

	if cfg.CAId == "" {
		return fmt.Errorf("Entrust ca_id is required")
	}

	// Test mTLS access via CA info endpoint
	caURL := fmt.Sprintf("%s/v1/certificate-authorities/%s", cfg.APIUrl, cfg.CAId)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, caURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create CA info request: %w", err)
	}

	// Build mTLS client for this test request
	tlsConfig, err := loadMTLSConfig(cfg.ClientCertPath, cfg.ClientKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load mTLS credentials: %w", err)
	}

	testClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	resp, err := testClient.Do(req)
	if err != nil {
		return fmt.Errorf("Entrust CA Gateway not reachable at %s: %w", cfg.APIUrl, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Entrust CA info returned status %d: %s", resp.StatusCode, string(body))
	}

	c.config = &cfg
	c.httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	c.logger.Info("Entrust Certificate Services configuration validated",
		"api_url", cfg.APIUrl,
		"ca_id", cfg.CAId)

	return nil
}

// IssueCertificate submits a certificate enrollment to Entrust.
// If the certificate is issued immediately, returns the cert.
// If pending, returns OrderID with empty CertPEM for polling.
func (c *Connector) IssueCertificate(ctx context.Context, request issuer.IssuanceRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing Entrust issuance request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	// Build SANs list
	var sansList []san
	for _, s := range request.SANs {
		sansList = append(sansList, san{
			Type:  "dNSName",
			Value: s,
		})
	}

	enrollReq := enrollmentRequest{
		CSR:             request.CSRPEM,
		SubjectAltNames: sansList,
	}

	if c.config.ProfileId != "" {
		enrollReq.ProfileId = c.config.ProfileId
	}

	body, err := json.Marshal(enrollReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal enrollment request: %w", err)
	}

	enrollURL := fmt.Sprintf("%s/v1/certificate-authorities/%s/enrollments", c.config.APIUrl, c.config.CAId)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, enrollURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create enrollment request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Entrust enrollment request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read enrollment response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("Entrust enrollment returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var enrollResp enrollmentResponse
	if err := json.Unmarshal(respBody, &enrollResp); err != nil {
		return nil, fmt.Errorf("failed to parse enrollment response: %w", err)
	}

	c.logger.Info("Entrust enrollment submitted",
		"tracking_id", enrollResp.TrackingId,
		"status", enrollResp.Status)

	// If issued immediately, return the certificate
	if enrollResp.Status == "ISSUED" && enrollResp.Certificate != "" {
		serial, notBefore, notAfter, err := parseCertMetadata(enrollResp.Certificate)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate metadata: %w", err)
		}

		c.logger.Info("Entrust certificate issued immediately",
			"tracking_id", enrollResp.TrackingId,
			"serial", serial)

		return &issuer.IssuanceResult{
			CertPEM:   enrollResp.Certificate,
			ChainPEM:  enrollResp.Chain,
			Serial:    serial,
			NotBefore: notBefore,
			NotAfter:  notAfter,
			OrderID:   enrollResp.TrackingId,
		}, nil
	}

	// Pending — return OrderID for polling via GetOrderStatus
	c.logger.Info("Entrust enrollment pending",
		"tracking_id", enrollResp.TrackingId,
		"status", enrollResp.Status)

	return &issuer.IssuanceResult{
		OrderID: enrollResp.TrackingId,
	}, nil
}

// RenewCertificate renews a certificate by submitting a new enrollment.
func (c *Connector) RenewCertificate(ctx context.Context, request issuer.RenewalRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing Entrust renewal request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	return c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: request.CommonName,
		SANs:       request.SANs,
		CSRPEM:     request.CSRPEM,
		EKUs:       request.EKUs,
	})
}

// RevokeCertificate revokes a certificate at Entrust.
func (c *Connector) RevokeCertificate(ctx context.Context, request issuer.RevocationRequest) error {
	c.logger.Info("processing Entrust revocation request", "serial", request.Serial)

	// Map reason to Entrust reason string
	reason := mapRevocationReason(request.Reason)

	revokeBody := revocationRequest{
		RevocationReason: reason,
	}

	body, err := json.Marshal(revokeBody)
	if err != nil {
		return fmt.Errorf("failed to marshal revoke request: %w", err)
	}

	revokeURL := fmt.Sprintf("%s/v1/certificate-authorities/%s/certificates/%s/revoke",
		c.config.APIUrl, c.config.CAId, request.Serial)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, revokeURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Entrust revoke request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Entrust revoke returned status %d: %s", resp.StatusCode, string(respBody))
	}

	c.logger.Info("Entrust certificate revoked", "serial", request.Serial, "reason", reason)
	return nil
}

// GetOrderStatus checks the status of an Entrust enrollment.
// If the enrollment is "ISSUED", returns the certificate.
// If still pending, returns pending status for continued polling.
func (c *Connector) GetOrderStatus(ctx context.Context, orderID string) (*issuer.OrderStatus, error) {
	c.logger.Debug("checking Entrust enrollment status", "tracking_id", orderID)

	statusURL := fmt.Sprintf("%s/v1/certificate-authorities/%s/enrollments/%s",
		c.config.APIUrl, c.config.CAId, orderID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create status request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Entrust status request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read status response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Entrust enrollment status returned %d: %s", resp.StatusCode, string(respBody))
	}

	var statusResp enrollmentStatusResponse
	if err := json.Unmarshal(respBody, &statusResp); err != nil {
		return nil, fmt.Errorf("failed to parse status response: %w", err)
	}

	now := time.Now()

	switch statusResp.Status {
	case "ISSUED":
		if statusResp.Certificate == "" {
			return nil, fmt.Errorf("enrollment is ISSUED but certificate is missing")
		}

		serial, notBefore, notAfter, err := parseCertMetadata(statusResp.Certificate)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate metadata: %w", err)
		}

		c.logger.Info("Entrust enrollment completed",
			"tracking_id", orderID,
			"serial", serial)

		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "completed",
			CertPEM:   &statusResp.Certificate,
			ChainPEM:  &statusResp.Chain,
			Serial:    &serial,
			NotBefore: &notBefore,
			NotAfter:  &notAfter,
			UpdatedAt: now,
		}, nil

	case "PENDING", "PROCESSING", "AWAITING_APPROVAL":
		msg := fmt.Sprintf("enrollment %s is %s", orderID, statusResp.Status)
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "pending",
			Message:   &msg,
			UpdatedAt: now,
		}, nil

	case "REJECTED", "DENIED", "FAILED":
		msg := fmt.Sprintf("enrollment %s was %s", orderID, statusResp.Status)
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "failed",
			Message:   &msg,
			UpdatedAt: now,
		}, nil

	default:
		msg := fmt.Sprintf("unknown enrollment status: %s", statusResp.Status)
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "pending",
			Message:   &msg,
			UpdatedAt: now,
		}, nil
	}
}

// GenerateCRL is not supported because Entrust manages CRL distribution.
func (c *Connector) GenerateCRL(ctx context.Context, revokedCerts []issuer.RevokedCertEntry) ([]byte, error) {
	return nil, fmt.Errorf("Entrust manages CRL distribution; use Entrust's CRL endpoints")
}

// SignOCSPResponse is not supported because Entrust manages OCSP.
func (c *Connector) SignOCSPResponse(ctx context.Context, req issuer.OCSPSignRequest) ([]byte, error) {
	return nil, fmt.Errorf("Entrust manages OCSP; use Entrust's OCSP responder")
}

// GetCACertPEM returns the Entrust intermediate certificate.
func (c *Connector) GetCACertPEM(ctx context.Context) (string, error) {
	// Entrust intermediate certificates come with each certificate issuance
	return "", fmt.Errorf("Entrust intermediate certificates are included with each issued certificate")
}

// GetRenewalInfo returns nil, nil as Entrust does not support ACME Renewal Information (ARI).
func (c *Connector) GetRenewalInfo(ctx context.Context, certPEM string) (*issuer.RenewalInfoResult, error) {
	return nil, nil
}

// Helper functions

// loadMTLSConfig loads the client certificate and key from files and returns a TLS config.
func loadMTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate/key: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

// parseCertMetadata extracts serial number and validity dates from a PEM certificate.
func parseCertMetadata(certPEM string) (serial string, notBefore time.Time, notAfter time.Time, err error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		err = fmt.Errorf("failed to decode certificate PEM")
		return
	}

	cert, parseErr := x509.ParseCertificate(block.Bytes)
	if parseErr != nil {
		err = fmt.Errorf("failed to parse certificate: %w", parseErr)
		return
	}

	serial = cert.SerialNumber.String()
	notBefore = cert.NotBefore
	notAfter = cert.NotAfter
	return
}

// mapRevocationReason maps RFC 5280 reason strings to Entrust reason strings.
func mapRevocationReason(reason *string) string {
	if reason == nil || *reason == "" {
		return "Unspecified"
	}

	switch *reason {
	case "unspecified":
		return "Unspecified"
	case "keyCompromise":
		return "KeyCompromise"
	case "caCompromise":
		return "CACompromise"
	case "affiliationChanged":
		return "AffiliationChanged"
	case "superseded":
		return "Superseded"
	case "cessationOfOperation":
		return "CessationOfOperation"
	case "certificateHold":
		return "CertificateHold"
	case "privilegeWithdrawn":
		return "PrivilegeWithdrawn"
	default:
		return "Unspecified"
	}
}

// Ensure Connector implements the issuer.Connector interface.
var _ issuer.Connector = (*Connector)(nil)
