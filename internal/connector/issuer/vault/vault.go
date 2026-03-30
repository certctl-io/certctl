// Package vault implements the issuer.Connector interface for HashiCorp Vault PKI
// secrets engine.
//
// Vault PKI provides a full-featured private CA with certificate signing, revocation,
// CRL, and OCSP capabilities. This connector uses the Vault HTTP API to sign CSRs
// via the /v1/{mount}/sign/{role} endpoint, authenticated with a Vault token.
//
// Vault issues certificates synchronously (like step-ca), so GetOrderStatus always
// returns "completed". CRL and OCSP are delegated to Vault's own endpoints.
//
// Authentication: Vault token via X-Vault-Token header.
//
// Vault API used:
//
//	GET  /v1/sys/health                      - Health check
//	POST /v1/{mount}/sign/{role}             - Sign CSR
//	POST /v1/{mount}/revoke                  - Revoke certificate
//	GET  /v1/{mount}/ca/pem                  - Get CA certificate
package vault

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
)

// Config represents the Vault PKI issuer connector configuration.
type Config struct {
	// Addr is the Vault server address (e.g., "https://vault.example.com:8200").
	// Required. Set via CERTCTL_VAULT_ADDR environment variable.
	Addr string `json:"addr"`

	// Token is the Vault token for authentication.
	// Required. Set via CERTCTL_VAULT_TOKEN environment variable.
	Token string `json:"token"`

	// Mount is the PKI secrets engine mount path.
	// Default: "pki". Set via CERTCTL_VAULT_MOUNT environment variable.
	Mount string `json:"mount"`

	// Role is the PKI role name used for signing certificates.
	// Required. Set via CERTCTL_VAULT_ROLE environment variable.
	Role string `json:"role"`

	// TTL is the requested certificate TTL (e.g., "8760h" for 1 year).
	// Default: "8760h". Set via CERTCTL_VAULT_TTL environment variable.
	TTL string `json:"ttl"`
}

// Connector implements the issuer.Connector interface for Vault PKI.
type Connector struct {
	config     *Config
	logger     *slog.Logger
	httpClient *http.Client
}

// New creates a new Vault PKI connector with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	if config != nil {
		if config.Mount == "" {
			config.Mount = "pki"
		}
		if config.TTL == "" {
			config.TTL = "8760h"
		}
	}

	return &Connector{
		config: config,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// vaultResponse is the standard Vault API response wrapper.
type vaultResponse struct {
	Data    json.RawMessage `json:"data"`
	Errors  []string        `json:"errors,omitempty"`
	Warnings []string       `json:"warnings,omitempty"`
}

// signData holds the data returned from the /sign endpoint.
type signData struct {
	Certificate  string   `json:"certificate"`
	IssuingCA    string   `json:"issuing_ca"`
	CAChain      []string `json:"ca_chain"`
	SerialNumber string   `json:"serial_number"`
	Expiration   int64    `json:"expiration"`
}

// ValidateConfig checks that the Vault configuration is valid and the server is reachable.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid Vault config: %w", err)
	}

	if cfg.Addr == "" {
		return fmt.Errorf("Vault addr is required")
	}

	if cfg.Token == "" {
		return fmt.Errorf("Vault token is required")
	}

	if cfg.Role == "" {
		return fmt.Errorf("Vault role is required")
	}

	if cfg.Mount == "" {
		cfg.Mount = "pki"
	}
	if cfg.TTL == "" {
		cfg.TTL = "8760h"
	}

	// Health check
	healthURL := cfg.Addr + "/v1/sys/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Vault not reachable at %s: %w", cfg.Addr, err)
	}
	defer resp.Body.Close()

	// Vault health returns 200 for initialized+unsealed, 429 for standby, 472 for DR secondary,
	// 473 for perf standby, 501 for uninitialized, 503 for sealed
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusTooManyRequests {
		return fmt.Errorf("Vault health check returned status %d", resp.StatusCode)
	}

	c.config = &cfg
	c.logger.Info("Vault PKI configuration validated",
		"addr", cfg.Addr,
		"mount", cfg.Mount,
		"role", cfg.Role)

	return nil
}

// IssueCertificate submits a CSR to Vault PKI for signing.
func (c *Connector) IssueCertificate(ctx context.Context, request issuer.IssuanceRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing Vault PKI issuance request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	// Build the sign request body
	signBody := map[string]interface{}{
		"csr":         request.CSRPEM,
		"common_name": request.CommonName,
		"ttl":         c.config.TTL,
	}

	if len(request.SANs) > 0 {
		signBody["alt_names"] = strings.Join(request.SANs, ",")
	}

	body, err := json.Marshal(signBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sign request: %w", err)
	}

	// POST /v1/{mount}/sign/{role}
	signURL := fmt.Sprintf("%s/v1/%s/sign/%s", c.config.Addr, c.config.Mount, c.config.Role)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, signURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create sign request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", c.config.Token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Vault sign request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read sign response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var vaultResp vaultResponse
		if jsonErr := json.Unmarshal(respBody, &vaultResp); jsonErr == nil && len(vaultResp.Errors) > 0 {
			return nil, fmt.Errorf("Vault sign returned status %d: %s", resp.StatusCode, strings.Join(vaultResp.Errors, "; "))
		}
		return nil, fmt.Errorf("Vault sign returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse the Vault response
	var vaultResp vaultResponse
	if err := json.Unmarshal(respBody, &vaultResp); err != nil {
		return nil, fmt.Errorf("failed to parse Vault response: %w", err)
	}

	var data signData
	if err := json.Unmarshal(vaultResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse Vault sign data: %w", err)
	}

	if data.Certificate == "" {
		return nil, fmt.Errorf("no certificate in Vault sign response")
	}

	// Parse the leaf certificate to extract metadata
	certPEM := data.Certificate
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM from Vault")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Build chain PEM from ca_chain or issuing_ca
	var chainPEM string
	if len(data.CAChain) > 0 {
		chainPEM = strings.Join(data.CAChain, "\n")
	} else if data.IssuingCA != "" {
		chainPEM = data.IssuingCA
	}

	// Normalize serial: Vault uses colon-separated hex (e.g., "aa:bb:cc"), convert to plain string
	serial := normalizeSerial(data.SerialNumber)

	orderID := fmt.Sprintf("vault-%s", serial)

	c.logger.Info("Vault PKI certificate issued",
		"common_name", request.CommonName,
		"serial", serial,
		"not_after", cert.NotAfter)

	return &issuer.IssuanceResult{
		CertPEM:   certPEM,
		ChainPEM:  chainPEM,
		Serial:    serial,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		OrderID:   orderID,
	}, nil
}

// RenewCertificate renews a certificate by creating a new signing request.
// For Vault PKI, renewal is functionally identical to issuance (new cert signed from CSR).
func (c *Connector) RenewCertificate(ctx context.Context, request issuer.RenewalRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing Vault PKI renewal request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	return c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: request.CommonName,
		SANs:       request.SANs,
		CSRPEM:     request.CSRPEM,
		EKUs:       request.EKUs,
	})
}

// RevokeCertificate revokes a certificate at Vault PKI.
func (c *Connector) RevokeCertificate(ctx context.Context, request issuer.RevocationRequest) error {
	c.logger.Info("processing Vault PKI revocation request", "serial", request.Serial)

	revokeBody := map[string]interface{}{
		"serial_number": request.Serial,
	}

	body, err := json.Marshal(revokeBody)
	if err != nil {
		return fmt.Errorf("failed to marshal revoke request: %w", err)
	}

	revokeURL := fmt.Sprintf("%s/v1/%s/revoke", c.config.Addr, c.config.Mount)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, revokeURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", c.config.Token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Vault revoke request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Vault revoke returned status %d: %s", resp.StatusCode, string(respBody))
	}

	c.logger.Info("Vault PKI certificate revoked", "serial", request.Serial)
	return nil
}

// GetOrderStatus returns the status of a Vault PKI order.
// Vault signs synchronously, so orders are always "completed" immediately.
func (c *Connector) GetOrderStatus(ctx context.Context, orderID string) (*issuer.OrderStatus, error) {
	return &issuer.OrderStatus{
		OrderID:   orderID,
		Status:    "completed",
		UpdatedAt: time.Now(),
	}, nil
}

// GenerateCRL is not supported because Vault serves CRL directly at /v1/{mount}/crl.
func (c *Connector) GenerateCRL(ctx context.Context, revokedCerts []issuer.RevokedCertEntry) ([]byte, error) {
	return nil, fmt.Errorf("Vault serves CRL directly at /v1/%s/crl; use Vault's endpoint", c.config.Mount)
}

// SignOCSPResponse is not supported because Vault serves OCSP directly at /v1/{mount}/ocsp.
func (c *Connector) SignOCSPResponse(ctx context.Context, req issuer.OCSPSignRequest) ([]byte, error) {
	return nil, fmt.Errorf("Vault serves OCSP directly at /v1/%s/ocsp; use Vault's endpoint", c.config.Mount)
}

// GetCACertPEM retrieves the CA certificate from Vault PKI.
func (c *Connector) GetCACertPEM(ctx context.Context) (string, error) {
	caURL := fmt.Sprintf("%s/v1/%s/ca/pem", c.config.Addr, c.config.Mount)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, caURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create CA cert request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.config.Token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Vault CA cert request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Vault CA cert returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read CA cert response: %w", err)
	}

	return string(body), nil
}

// GetRenewalInfo returns nil, nil as Vault does not support ACME Renewal Information (ARI).
func (c *Connector) GetRenewalInfo(ctx context.Context, certPEM string) (*issuer.RenewalInfoResult, error) {
	return nil, nil
}

// normalizeSerial converts Vault's colon-separated hex serial (e.g., "aa:bb:cc:dd")
// to a plain string representation suitable for storage.
func normalizeSerial(serial string) string {
	return strings.ReplaceAll(serial, ":", "-")
}

// Ensure Connector implements the issuer.Connector interface.
var _ issuer.Connector = (*Connector)(nil)
