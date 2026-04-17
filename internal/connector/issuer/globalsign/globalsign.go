// Package globalsign implements the issuer.Connector interface for GlobalSign Atlas HVCA.
//
// GlobalSign Atlas HVCA (Hosted Validation CA) is an enterprise certificate authority
// offering DV and OV certificates. Unlike synchronous issuers (Vault, step-ca), GlobalSign
// uses an asynchronous order model with serial number polling: submit a certificate order,
// receive a serial number immediately, then poll to check when the cert is available.
//
// This connector maps to certctl's existing job state machine:
//   - IssueCertificate submits the order and returns the serial number. The cert PEM
//     is typically available within seconds for DV certs.
//   - GetOrderStatus polls via the serial number to retrieve the cert when ready.
//
// Authentication: mTLS client certificate (mutual TLS handshake) PLUS API key/secret
// headers on every request. This is a "double auth" pattern.
//   - TLS client certificate: loaded from disk via tls.LoadX509KeyPair()
//   - API key/secret: sent as custom HTTP headers (ApiKey, ApiSecret)
//
// GlobalSign Atlas HVCA API used:
//
//	POST /v2/certificates           - Submit certificate order, returns serial number
//	GET  /v2/certificates/{serial}  - Get certificate PEM by serial number
//	PUT  /v2/certificates/{serial}/revoke - Revoke certificate (no reason code required)
//	GET  /v2/certificates           - List certificates (for config validation)
package globalsign

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
	"os"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
)

// Config represents the GlobalSign Atlas HVCA issuer connector configuration.
type Config struct {
	// APIUrl is the GlobalSign Atlas HVCA API base URL (region-aware).
	// Examples: https://emea.api.hvca.globalsign.com:8443/v2/ (EMEA region)
	// Required. Set via CERTCTL_GLOBALSIGN_API_URL environment variable.
	APIUrl string `json:"api_url"`

	// APIKey is the GlobalSign API key for request authentication.
	// Required. Set via CERTCTL_GLOBALSIGN_API_KEY environment variable.
	APIKey string `json:"api_key"`

	// APISecret is the GlobalSign API secret for request authentication.
	// Required. Set via CERTCTL_GLOBALSIGN_API_SECRET environment variable.
	APISecret string `json:"api_secret"`

	// ClientCertPath is the filesystem path to the mTLS client certificate PEM file.
	// The certificate must be signed by GlobalSign and loaded for TLS handshake.
	// Required. Set via CERTCTL_GLOBALSIGN_CLIENT_CERT_PATH environment variable.
	ClientCertPath string `json:"client_cert_path"`

	// ClientKeyPath is the filesystem path to the mTLS client private key PEM file.
	// Must match the certificate in ClientCertPath.
	// Required. Set via CERTCTL_GLOBALSIGN_CLIENT_KEY_PATH environment variable.
	ClientKeyPath string `json:"client_key_path"`

	// ServerCAPath is the filesystem path to a PEM file containing the CA
	// certificate(s) used to verify the GlobalSign Atlas HVCA API server certificate.
	// Optional. If empty, the system trust store is used. This option exists for
	// private/lab deployments of GlobalSign Atlas that terminate TLS with an
	// internal CA not present in the host's default trust bundle.
	// Set via CERTCTL_GLOBALSIGN_SERVER_CA_PATH environment variable.
	ServerCAPath string `json:"server_ca_path,omitempty"`
}

// Connector implements the issuer.Connector interface for GlobalSign Atlas HVCA.
type Connector struct {
	config     *Config
	logger     *slog.Logger
	httpClient *http.Client
}

// New creates a new GlobalSign Atlas HVCA connector with the given configuration and logger.
// The connector will load the mTLS client certificate from the config paths on each API call.
func New(config *Config, logger *slog.Logger) *Connector {
	return &Connector{
		config: config,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewWithHTTPClient creates a new GlobalSign connector with a custom HTTP client.
// Used for testing with mocked HTTP responses. The client is used directly instead of
// loading mTLS certificates, allowing tests to bypass TLS setup.
func NewWithHTTPClient(config *Config, logger *slog.Logger, client *http.Client) *Connector {
	return &Connector{
		config:     config,
		logger:     logger,
		httpClient: client,
	}
}

// certificateRequest is the JSON body for GlobalSign certificate order submission.
type certificateRequest struct {
	CSR      string            `json:"csr"`
	SubjectDN subjectDNRequest `json:"subject_dn"`
	SAN      sanRequest        `json:"san,omitempty"`
}

type subjectDNRequest struct {
	CommonName string `json:"common_name"`
}

type sanRequest struct {
	DNSNames []string `json:"dns_names,omitempty"`
}

// certificateResponse is the JSON response from a certificate order submission or retrieval.
type certificateResponse struct {
	SerialNumber string `json:"serial_number"`
	Status       string `json:"status"`
	Certificate  string `json:"certificate,omitempty"`
	Chain        string `json:"chain,omitempty"`
	IssuedAt     string `json:"issued_at,omitempty"`
}

// ValidateConfig checks that the GlobalSign configuration is valid and mTLS connection works.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid GlobalSign config: %w", err)
	}

	if cfg.APIUrl == "" {
		return fmt.Errorf("GlobalSign api_url is required")
	}

	if cfg.APIKey == "" {
		return fmt.Errorf("GlobalSign api_key is required")
	}

	if cfg.APISecret == "" {
		return fmt.Errorf("GlobalSign api_secret is required")
	}

	if cfg.ClientCertPath == "" {
		return fmt.Errorf("GlobalSign client_cert_path is required")
	}

	if cfg.ClientKeyPath == "" {
		return fmt.Errorf("GlobalSign client_key_path is required")
	}

	// Load the client certificate and key for mTLS validation
	cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load GlobalSign client certificate: %w", err)
	}

	// Build a verifying mTLS TLS config. If ServerCAPath is set, that PEM
	// bundle is used as the trust anchor for the server certificate;
	// otherwise the system trust store is used. TLS 1.2 is the minimum.
	tlsConfig, err := buildServerTLSConfig(&cfg, cert)
	if err != nil {
		return fmt.Errorf("failed to build GlobalSign TLS config: %w", err)
	}

	validationClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 10 * time.Second,
	}

	// Test API access via GET /v2/certificates (list, requires auth headers)
	listURL := strings.TrimSuffix(cfg.APIUrl, "/") + "/v2/certificates"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create API test request: %w", err)
	}

	// Add both authentication layers
	req.Header.Set("ApiKey", cfg.APIKey)
	req.Header.Set("ApiSecret", cfg.APISecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := validationClient.Do(req)
	if err != nil {
		return fmt.Errorf("GlobalSign API not reachable at %s: %w", cfg.APIUrl, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("GlobalSign API credentials are invalid (status %d)", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadRequest {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GlobalSign API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	c.config = &cfg
	c.logger.Info("GlobalSign Atlas HVCA configuration validated",
		"api_url", cfg.APIUrl)

	return nil
}

// getHTTPClient returns the HTTP client to use, creating one with mTLS if needed.
// If the connector was created with NewWithHTTPClient (test mode), uses that client directly.
// Otherwise, creates a fresh mTLS client with the configured certificate.
func (c *Connector) getHTTPClient(ctx context.Context) (*http.Client, error) {
	// Check if we're in test mode (httpClient was explicitly provided and has non-nil transport)
	if c.httpClient != nil && c.httpClient.Transport != nil {
		return c.httpClient, nil
	}

	// For tests with default client (nil or minimal), check if cert paths are available
	if c.config.ClientCertPath == "" || c.config.ClientKeyPath == "" {
		// Test mode: use httpClient as-is (won't load certs)
		return c.httpClient, nil
	}

	// Production mode: load mTLS certificate
	cert, err := tls.LoadX509KeyPair(c.config.ClientCertPath, c.config.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load GlobalSign client certificate: %w", err)
	}

	tlsConfig, err := buildServerTLSConfig(c.config, cert)
	if err != nil {
		return nil, fmt.Errorf("failed to build GlobalSign TLS config: %w", err)
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 30 * time.Second,
	}, nil
}

// buildServerTLSConfig returns a TLS configuration for the GlobalSign Atlas
// HVCA API client. It always verifies the server certificate. When
// cfg.ServerCAPath is set, the PEM bundle at that path is used as the
// trust anchor (enables pinning a private/lab CA); otherwise the host's
// system trust store is used. TLS 1.2 is the minimum protocol version.
//
// This helper is the single source of truth for both the ValidateConfig
// probe client and the steady-state getHTTPClient production client, so
// any future TLS policy change applies uniformly.
func buildServerTLSConfig(cfg *Config, clientCert tls.Certificate) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS12,
	}

	if cfg.ServerCAPath != "" {
		caPEM, err := os.ReadFile(cfg.ServerCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read server CA bundle at %s: %w", cfg.ServerCAPath, err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid PEM certificates found in server CA bundle at %s", cfg.ServerCAPath)
		}

		tlsConfig.RootCAs = pool
	}

	return tlsConfig, nil
}

// IssueCertificate submits a certificate order to GlobalSign Atlas HVCA.
// Returns the serial number immediately; typically the cert is available within seconds (DV) to minutes (OV).
func (c *Connector) IssueCertificate(ctx context.Context, request issuer.IssuanceRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing GlobalSign issuance request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	client, err := c.getHTTPClient(ctx)
	if err != nil {
		return nil, err
	}

	certReq := certificateRequest{
		CSR: request.CSRPEM,
		SubjectDN: subjectDNRequest{
			CommonName: request.CommonName,
		},
	}

	if len(request.SANs) > 0 {
		certReq.SAN = sanRequest{
			DNSNames: request.SANs,
		}
	}

	body, err := json.Marshal(certReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate request: %w", err)
	}

	certURL := strings.TrimSuffix(c.config.APIUrl, "/") + "/v2/certificates"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, certURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	// Apply double auth: mTLS + headers
	req.Header.Set("ApiKey", c.config.APIKey)
	req.Header.Set("ApiSecret", c.config.APISecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GlobalSign certificate request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("GlobalSign certificate submission returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var certResp certificateResponse
	if err := json.Unmarshal(respBody, &certResp); err != nil {
		return nil, fmt.Errorf("failed to parse certificate response: %w", err)
	}

	c.logger.Info("GlobalSign certificate order submitted",
		"serial", certResp.SerialNumber,
		"status", certResp.Status)

	// If certificate is available immediately, return it.
	// Otherwise, return just the serial number for polling via GetOrderStatus.
	if certResp.Status == "issued" && certResp.Certificate != "" {
		notBefore, notAfter, err := parseCertDates(certResp.Certificate)
		if err != nil {
			c.logger.Warn("failed to parse certificate dates", "error", err)
		}

		return &issuer.IssuanceResult{
			CertPEM:   certResp.Certificate,
			ChainPEM:  certResp.Chain,
			Serial:    certResp.SerialNumber,
			NotBefore: notBefore,
			NotAfter:  notAfter,
			OrderID:   certResp.SerialNumber,
		}, nil
	}

	// Pending — return serial number as OrderID for polling
	c.logger.Info("GlobalSign certificate order pending",
		"serial", certResp.SerialNumber,
		"status", certResp.Status)

	return &issuer.IssuanceResult{
		OrderID: certResp.SerialNumber,
	}, nil
}

// RenewCertificate renews a certificate by submitting a new order.
// GlobalSign uses serial number polling, so renewal is treated as a new issuance.
func (c *Connector) RenewCertificate(ctx context.Context, request issuer.RenewalRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing GlobalSign renewal request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	return c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: request.CommonName,
		SANs:       request.SANs,
		CSRPEM:     request.CSRPEM,
		EKUs:       request.EKUs,
	})
}

// RevokeCertificate revokes a certificate at GlobalSign Atlas HVCA.
// GlobalSign revocation does not require a reason code.
func (c *Connector) RevokeCertificate(ctx context.Context, request issuer.RevocationRequest) error {
	c.logger.Info("processing GlobalSign revocation request", "serial", request.Serial)

	client, err := c.getHTTPClient(ctx)
	if err != nil {
		return err
	}

	// GlobalSign revocation endpoint: PUT /v2/certificates/{serial}/revoke
	// No request body or reason code required.
	revokeURL := strings.TrimSuffix(c.config.APIUrl, "/") + fmt.Sprintf("/v2/certificates/%s/revoke", request.Serial)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, revokeURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %w", err)
	}

	req.Header.Set("ApiKey", c.config.APIKey)
	req.Header.Set("ApiSecret", c.config.APISecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GlobalSign revoke request failed: %w", err)
	}
	defer resp.Body.Close()

	// GlobalSign returns 200 OK on successful revocation
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GlobalSign revoke returned status %d: %s", resp.StatusCode, string(respBody))
	}

	c.logger.Info("GlobalSign certificate revoked", "serial", request.Serial)
	return nil
}

// GetOrderStatus checks the status of a GlobalSign certificate order by serial number.
// Polls the certificate endpoint; when status is "issued", downloads and returns the cert.
func (c *Connector) GetOrderStatus(ctx context.Context, orderID string) (*issuer.OrderStatus, error) {
	c.logger.Debug("checking GlobalSign certificate status", "serial", orderID)

	client, err := c.getHTTPClient(ctx)
	if err != nil {
		return nil, err
	}

	// GlobalSign status endpoint: GET /v2/certificates/{serial}
	statusURL := strings.TrimSuffix(c.config.APIUrl, "/") + fmt.Sprintf("/v2/certificates/%s", orderID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create status request: %w", err)
	}

	req.Header.Set("ApiKey", c.config.APIKey)
	req.Header.Set("ApiSecret", c.config.APISecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GlobalSign status request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read status response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GlobalSign certificate status returned %d: %s", resp.StatusCode, string(respBody))
	}

	var certResp certificateResponse
	if err := json.Unmarshal(respBody, &certResp); err != nil {
		return nil, fmt.Errorf("failed to parse status response: %w", err)
	}

	now := time.Now()

	switch certResp.Status {
	case "issued":
		if certResp.Certificate == "" {
			return nil, fmt.Errorf("certificate status is issued but certificate PEM is missing")
		}

		notBefore, notAfter, err := parseCertDates(certResp.Certificate)
		if err != nil {
			c.logger.Warn("failed to parse certificate dates", "error", err)
		}

		c.logger.Info("GlobalSign certificate ready",
			"serial", orderID)

		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "completed",
			CertPEM:   &certResp.Certificate,
			ChainPEM:  &certResp.Chain,
			Serial:    &certResp.SerialNumber,
			NotBefore: &notBefore,
			NotAfter:  &notAfter,
			UpdatedAt: now,
		}, nil

	case "pending", "processing":
		msg := fmt.Sprintf("certificate %s is %s", orderID, certResp.Status)
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "pending",
			Message:   &msg,
			UpdatedAt: now,
		}, nil

	case "rejected", "denied", "failed":
		msg := fmt.Sprintf("certificate %s was %s", orderID, certResp.Status)
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "failed",
			Message:   &msg,
			UpdatedAt: now,
		}, nil

	default:
		msg := fmt.Sprintf("unknown certificate status: %s", certResp.Status)
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "pending",
			Message:   &msg,
			UpdatedAt: now,
		}, nil
	}
}

// parseCertDates extracts NotBefore and NotAfter from a PEM-encoded certificate.
func parseCertDates(certPEM string) (time.Time, time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, time.Time{}, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.NotBefore, cert.NotAfter, nil
}

// GenerateCRL is not supported because GlobalSign manages CRL distribution.
func (c *Connector) GenerateCRL(ctx context.Context, revokedCerts []issuer.RevokedCertEntry) ([]byte, error) {
	return nil, fmt.Errorf("GlobalSign manages CRL distribution; use GlobalSign's CRL endpoints")
}

// SignOCSPResponse is not supported because GlobalSign manages OCSP.
func (c *Connector) SignOCSPResponse(ctx context.Context, req issuer.OCSPSignRequest) ([]byte, error) {
	return nil, fmt.Errorf("GlobalSign manages OCSP; use GlobalSign's OCSP responder")
}

// GetCACertPEM is not directly supported. GlobalSign intermediate certificates
// come with each certificate issuance as part of the chain response.
func (c *Connector) GetCACertPEM(ctx context.Context) (string, error) {
	return "", fmt.Errorf("GlobalSign intermediate certificates are included with each issued certificate")
}

// GetRenewalInfo returns nil, nil as GlobalSign does not support ACME Renewal Information (ARI).
func (c *Connector) GetRenewalInfo(ctx context.Context, certPEM string) (*issuer.RenewalInfoResult, error) {
	return nil, nil
}

// Ensure Connector implements the issuer.Connector interface.
var _ issuer.Connector = (*Connector)(nil)
