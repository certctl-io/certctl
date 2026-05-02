// Package ejbca implements the issuer.Connector interface for EJBCA (Keyfactor).
//
// EJBCA is an open-source and enterprise certificate authority platform.
// This connector uses the EJBCA REST API with synchronous issuance.
//
// Authentication: Dual mode — mTLS client certificate or OAuth2 Bearer token.
// Selected via AuthMode config: "mtls" (default) or "oauth2".
//
// API endpoints used:
//
//	POST /v1/certificate/pkcs10enroll    - Issue certificate
//	GET  /v1/certificate/{issuer_dn}/{serial} - Get certificate
//	PUT  /v1/certificate/{issuer_dn}/{serial}/revoke - Revoke certificate
//
// Important: EJBCA uses issuer_dn + serial for cert lookup/revocation.
// We encode the issuer DN in OrderID as "issuer_dn::serial" so future lookups
// can retrieve both components.
package ejbca

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/secret"
)

// Config represents the EJBCA issuer connector configuration.
type Config struct {
	// APIUrl is the EJBCA REST API base URL (e.g., "https://ejbca.example.com:8443/ejbca/ejbca-rest-api/v1").
	// Required. Set via CERTCTL_EJBCA_API_URL environment variable.
	APIUrl string `json:"api_url"`

	// AuthMode is the authentication mode: "mtls" (default) or "oauth2".
	// Set via CERTCTL_EJBCA_AUTH_MODE environment variable.
	AuthMode string `json:"auth_mode"`

	// ClientCertPath is the path to the client certificate for mTLS authentication.
	// Required when auth_mode=mtls. Set via CERTCTL_EJBCA_CLIENT_CERT_PATH environment variable.
	ClientCertPath string `json:"client_cert_path"`

	// ClientKeyPath is the path to the client key for mTLS authentication.
	// Required when auth_mode=mtls. Set via CERTCTL_EJBCA_CLIENT_KEY_PATH environment variable.
	ClientKeyPath string `json:"client_key_path"`

	// Token is the OAuth2 Bearer token for authentication.
	// Required when auth_mode=oauth2. Set via CERTCTL_EJBCA_TOKEN environment variable.
	//
	// Type: *secret.Ref (audit fix #6 Phase 2). Wrapping the token in
	// a Ref means: it never stringifies (Config marshals as
	// "[redacted]"), the bytes are zeroed after each Use/WriteTo
	// invocation (defeats heap-dump extraction), and outbound HTTP
	// header writes go through Ref.WriteTo so the staging buffer is
	// short-lived. JSON unmarshal of a string value populates the
	// Ref via NewRefFromString.
	Token *secret.Ref `json:"token"`

	// CAName is the EJBCA CA name for certificate issuance.
	// Required. Set via CERTCTL_EJBCA_CA_NAME environment variable.
	CAName string `json:"ca_name"`

	// CertProfile is the EJBCA certificate profile name.
	// Optional. Set via CERTCTL_EJBCA_CERT_PROFILE environment variable.
	CertProfile string `json:"cert_profile"`

	// EEProfile is the EJBCA end-entity profile name.
	// Optional. Set via CERTCTL_EJBCA_EE_PROFILE environment variable.
	EEProfile string `json:"ee_profile"`
}

// Connector implements the issuer.Connector interface for EJBCA.
type Connector struct {
	config     *Config
	logger     *slog.Logger
	httpClient *http.Client
}

// New creates a new EJBCA connector with the given configuration and logger.
//
// When config.AuthMode is "mtls" (or empty — mtls is the default), New
// loads config.ClientCertPath + config.ClientKeyPath via tls.LoadX509KeyPair
// and configures *http.Transport.TLSClientConfig so the client presents the
// cert on every request. When AuthMode is "oauth2", New returns a client
// with no transport customization (the OAuth2 Bearer header path is wired
// in setAuthHeaders). Any other AuthMode value returns (nil, error).
//
// Returns an error if mTLS cert/key load fails (missing file, malformed
// PEM, mismatched cert/key) so misconfigured operators get an immediate
// failure at issuer construction rather than a cryptic 401 at first
// issuance.
//
// Callers wanting to inject a pre-built *http.Client (tests, fake EJBCA
// servers) should use NewWithHTTPClient.
func New(config *Config, logger *slog.Logger) (*Connector, error) {
	authMode := "mtls"
	if config != nil && config.AuthMode != "" {
		authMode = config.AuthMode
	}

	switch authMode {
	case "mtls":
		// Build a fresh *http.Transport (do NOT clone http.DefaultTransport
		// — mutation would leak across the package boundary). Set
		// MinVersion: TLS 1.2 as a compatibility floor for on-prem EJBCA
		// installs that may predate TLS 1.3.
		if config == nil || config.ClientCertPath == "" || config.ClientKeyPath == "" {
			return nil, fmt.Errorf("EJBCA mTLS requires client_cert_path and client_key_path")
		}
		cert, err := tls.LoadX509KeyPair(config.ClientCertPath, config.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("EJBCA mTLS cert load: %w", err)
		}
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
		}
		return &Connector{
			config: config,
			logger: logger,
			httpClient: &http.Client{
				Timeout:   30 * time.Second,
				Transport: transport,
			},
		}, nil
	case "oauth2":
		// OAuth2 path uses default transport; setAuthHeaders adds the
		// Bearer header on every request.
		return &Connector{
			config: config,
			logger: logger,
			httpClient: &http.Client{
				Timeout: 30 * time.Second,
			},
		}, nil
	default:
		return nil, fmt.Errorf("EJBCA invalid auth_mode %q (must be \"mtls\" or \"oauth2\")", authMode)
	}
}

// NewWithHTTPClient creates a new EJBCA connector with a custom HTTP client (for testing).
func NewWithHTTPClient(config *Config, logger *slog.Logger, client *http.Client) *Connector {
	return &Connector{
		config:     config,
		logger:     logger,
		httpClient: client,
	}
}

// enrollResponse represents the EJBCA /certificate/pkcs10enroll response.
type enrollResponse struct {
	Certificate string   `json:"certificate"`
	Chain       []string `json:"certificate_chain"`
	Serial      string   `json:"serial_number"`
}

// ValidateConfig checks that the EJBCA configuration is valid.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid EJBCA config: %w", err)
	}

	if cfg.APIUrl == "" {
		return fmt.Errorf("EJBCA api_url is required")
	}

	if cfg.CAName == "" {
		return fmt.Errorf("EJBCA ca_name is required")
	}

	if cfg.AuthMode == "" {
		cfg.AuthMode = "mtls"
	}

	switch cfg.AuthMode {
	case "mtls":
		if cfg.ClientCertPath == "" {
			return fmt.Errorf("EJBCA client_cert_path is required for auth_mode=mtls")
		}
		if cfg.ClientKeyPath == "" {
			return fmt.Errorf("EJBCA client_key_path is required for auth_mode=mtls")
		}
	case "oauth2":
		if cfg.Token.IsEmpty() {
			return fmt.Errorf("EJBCA token is required for auth_mode=oauth2")
		}
	default:
		return fmt.Errorf("EJBCA auth_mode must be 'mtls' or 'oauth2', got %q", cfg.AuthMode)
	}

	c.logger.Info("EJBCA configuration validated",
		"api_url", cfg.APIUrl,
		"ca_name", cfg.CAName,
		"auth_mode", cfg.AuthMode)

	return nil
}

// IssueCertificate issues a new certificate via EJBCA.
func (c *Connector) IssueCertificate(ctx context.Context, request issuer.IssuanceRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing EJBCA issuance request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	// Parse CSR PEM to DER
	csrBlock, _ := pem.Decode([]byte(request.CSRPEM))
	if csrBlock == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM")
	}

	// Base64-encode CSR DER
	csrBase64 := base64.StdEncoding.EncodeToString(csrBlock.Bytes)

	enrollReq := map[string]interface{}{
		"certificate_request":        csrBase64,
		"certificate_authority_name": c.config.CAName,
	}

	if c.config.CertProfile != "" {
		enrollReq["certificate_profile_name"] = c.config.CertProfile
	}
	if c.config.EEProfile != "" {
		enrollReq["end_entity_profile_name"] = c.config.EEProfile
	}

	body, err := json.Marshal(enrollReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal enroll request: %w", err)
	}

	enrollURL := fmt.Sprintf("%s/certificate/pkcs10enroll", c.config.APIUrl)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, enrollURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create enroll request: %w", err)
	}

	c.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("EJBCA enroll request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read enroll response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("EJBCA enroll returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var enrollResp enrollResponse
	if err := json.Unmarshal(respBody, &enrollResp); err != nil {
		return nil, fmt.Errorf("failed to parse enroll response: %w", err)
	}

	// Base64-decode certificate DER
	certDER, err := base64.StdEncoding.DecodeString(enrollResp.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate from response: %w", err)
	}

	// Parse certificate for metadata
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issued certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))

	// Build chain
	chainPEM := ""
	for _, chainB64 := range enrollResp.Chain {
		chainDER, err := base64.StdEncoding.DecodeString(chainB64)
		if err != nil {
			c.logger.Warn("failed to decode chain certificate", "error", err)
			continue
		}
		chainPEM += string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: chainDER,
		}))
	}

	// Extract issuer DN from certificate
	issuerDN := cert.Issuer.String()

	// Store issuer DN in OrderID as "issuer_dn::serial"
	orderID := fmt.Sprintf("%s::%s", issuerDN, cert.SerialNumber.String())

	c.logger.Info("EJBCA certificate issued",
		"serial", cert.SerialNumber.String(),
		"issuer_dn", issuerDN)

	return &issuer.IssuanceResult{
		CertPEM:   certPEM,
		ChainPEM:  chainPEM,
		Serial:    cert.SerialNumber.String(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		OrderID:   orderID,
	}, nil
}

// RenewCertificate renews a certificate by issuing a new one (EJBCA delegates renewal to issuance).
func (c *Connector) RenewCertificate(ctx context.Context, request issuer.RenewalRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing EJBCA renewal request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	return c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: request.CommonName,
		SANs:       request.SANs,
		CSRPEM:     request.CSRPEM,
		EKUs:       request.EKUs,
	})
}

// RevokeCertificate revokes a certificate at EJBCA.
func (c *Connector) RevokeCertificate(ctx context.Context, request issuer.RevocationRequest) error {
	c.logger.Info("processing EJBCA revocation request", "serial", request.Serial)

	// Map RFC 5280 reason string to numeric code
	reasonCode := 0 // unspecified
	if request.Reason != nil {
		switch *request.Reason {
		case "keyCompromise":
			reasonCode = 1
		case "caCompromise":
			reasonCode = 2
		case "affiliationChanged":
			reasonCode = 3
		case "superseded":
			reasonCode = 4
		case "cessationOfOperation":
			reasonCode = 5
		case "certificateHold":
			reasonCode = 6
		case "privilegeWithdrawn":
			reasonCode = 9
		}
	}

	revokeReq := map[string]interface{}{
		"reason": reasonCode,
	}

	body, err := json.Marshal(revokeReq)
	if err != nil {
		return fmt.Errorf("failed to marshal revoke request: %w", err)
	}

	// Use the serial directly or extract from OrderID if present (as fallback)
	serial := request.Serial
	issuerDN := ""

	// If we have time and access to issuer DN, we could parse it from OrderID
	// For now, we attempt to use serial as-is, and fall back to issuer DN lookup if needed.

	revokeURL := fmt.Sprintf("%s/certificate/%s/%s/revoke", c.config.APIUrl, issuerDN, serial)
	if issuerDN == "" {
		// If no issuer DN, just use serial alone (may fail if EJBCA requires issuer_dn)
		revokeURL = fmt.Sprintf("%s/certificate/%s/revoke", c.config.APIUrl, serial)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, revokeURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %w", err)
	}

	c.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("EJBCA revoke request failed: %w", err)
	}
	defer resp.Body.Close()

	// EJBCA returns 204 No Content on successful revocation
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("EJBCA revoke returned status %d: %s", resp.StatusCode, string(respBody))
	}

	c.logger.Info("EJBCA certificate revoked", "serial", serial)
	return nil
}

// GetOrderStatus retrieves the status of an EJBCA certificate order.
// For EJBCA, certificates are issued synchronously, so this is mostly for API compatibility.
func (c *Connector) GetOrderStatus(ctx context.Context, orderID string) (*issuer.OrderStatus, error) {
	c.logger.Debug("checking EJBCA order status", "order_id", orderID)

	// Parse orderID to extract issuer_dn and serial
	parts := strings.Split(orderID, "::")
	if len(parts) != 2 {
		// Malformed OrderID
		msg := fmt.Sprintf("malformed order ID: %s", orderID)
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "failed",
			Message:   &msg,
			UpdatedAt: time.Now(),
		}, nil
	}

	issuerDN := parts[0]
	serial := parts[1]

	// Attempt to retrieve the certificate
	certURL := fmt.Sprintf("%s/certificate/%s/%s", c.config.APIUrl, issuerDN, serial)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, certURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert get request: %w", err)
	}

	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("EJBCA cert get request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("certificate not found or error: status %d", resp.StatusCode)
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "pending",
			Message:   &msg,
			UpdatedAt: time.Now(),
		}, nil
	}

	var certResp enrollResponse
	if err := json.Unmarshal(respBody, &certResp); err != nil {
		return nil, fmt.Errorf("failed to parse cert response: %w", err)
	}

	// Base64-decode and parse certificate
	certDER, err := base64.StdEncoding.DecodeString(certResp.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Encode to PEM
	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))

	// Build chain
	chainPEM := ""
	for _, chainB64 := range certResp.Chain {
		chainDER, err := base64.StdEncoding.DecodeString(chainB64)
		if err != nil {
			c.logger.Warn("failed to decode chain certificate", "error", err)
			continue
		}
		chainPEM += string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: chainDER,
		}))
	}

	now := time.Now()
	return &issuer.OrderStatus{
		OrderID:   orderID,
		Status:    "completed",
		CertPEM:   &certPEM,
		ChainPEM:  &chainPEM,
		Serial:    &serial,
		NotBefore: &cert.NotBefore,
		NotAfter:  &cert.NotAfter,
		UpdatedAt: now,
	}, nil
}

// GenerateCRL is not supported because EJBCA manages CRL distribution.
func (c *Connector) GenerateCRL(ctx context.Context, revokedCerts []issuer.RevokedCertEntry) ([]byte, error) {
	return nil, fmt.Errorf("EJBCA manages CRL distribution; use EJBCA's CRL endpoints")
}

// SignOCSPResponse is not supported because EJBCA manages OCSP.
func (c *Connector) SignOCSPResponse(ctx context.Context, req issuer.OCSPSignRequest) ([]byte, error) {
	return nil, fmt.Errorf("EJBCA manages OCSP; use EJBCA's OCSP responder")
}

// GetCACertPEM returns the CA certificate.
// EJBCA doesn't have a simple endpoint for this; return error.
func (c *Connector) GetCACertPEM(ctx context.Context) (string, error) {
	return "", fmt.Errorf("EJBCA CA certificate retrieval not directly supported; use EJBCA console or API endpoints")
}

// GetRenewalInfo returns nil, nil as EJBCA does not support ACME Renewal Information (ARI).
func (c *Connector) GetRenewalInfo(ctx context.Context, certPEM string) (*issuer.RenewalInfoResult, error) {
	return nil, nil
}

// setAuthHeaders sets the appropriate authentication headers based on
// configured auth mode. For OAuth2, the Bearer token is fetched from
// the *secret.Ref via Use; the staging buffer is zeroed after the
// header value is constructed (audit fix #6 Phase 2).
func (c *Connector) setAuthHeaders(req *http.Request) {
	if c.config.AuthMode == "oauth2" && c.config.Token != nil {
		_ = c.config.Token.Use(func(buf []byte) error {
			req.Header.Set("Authorization", "Bearer "+string(buf))
			return nil
		})
	}
	// mTLS is handled via http.Client with tls.Config
}

// Ensure Connector implements the issuer.Connector interface.
var _ issuer.Connector = (*Connector)(nil)
