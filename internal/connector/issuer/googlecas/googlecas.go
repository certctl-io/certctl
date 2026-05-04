// Package googlecas implements the issuer.Connector interface for
// Google Cloud Certificate Authority Service (CAS).
//
// Google CAS is a managed private CA service on GCP. This connector
// uses the CAS REST API (privateca.googleapis.com/v1) with OAuth2
// service account authentication. Certificates are issued synchronously.
//
// Authentication: OAuth2 service account via JWT → access token exchange.
// No Google SDK dependency — uses stdlib crypto/rsa + net/http.
//
// API endpoints used:
//
//	POST /v1/{parent}/certificates         - Issue certificate
//	POST /v1/{name}:revoke                 - Revoke certificate
//	POST /v1/{caPool}:fetchCaCerts         - Get CA certificate chain
package googlecas

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/certctl-io/certctl/internal/connector/issuer"
)

// Config represents the Google CAS issuer connector configuration.
type Config struct {
	// Project is the GCP project ID.
	// Required. Set via CERTCTL_GOOGLE_CAS_PROJECT environment variable.
	Project string `json:"project"`

	// Location is the GCP region (e.g., "us-central1").
	// Required. Set via CERTCTL_GOOGLE_CAS_LOCATION environment variable.
	Location string `json:"location"`

	// CAPool is the Certificate Authority pool name.
	// Required. Set via CERTCTL_GOOGLE_CAS_CA_POOL environment variable.
	CAPool string `json:"ca_pool"`

	// Credentials is the path to the service account JSON credentials file.
	// Required. Set via CERTCTL_GOOGLE_CAS_CREDENTIALS environment variable.
	Credentials string `json:"credentials"`

	// TTL is the requested certificate TTL (e.g., "8760h" for 1 year).
	// Default: "8760h". Set via CERTCTL_GOOGLE_CAS_TTL environment variable.
	TTL string `json:"ttl"`

	// BaseURL overrides the Google CAS API base URL (for testing).
	// Default: "https://privateca.googleapis.com/v1".
	BaseURL string `json:"base_url,omitempty"`

	// TokenURL overrides the OAuth2 token endpoint (for testing).
	// Default: "https://oauth2.googleapis.com/token".
	TokenURL string `json:"token_url,omitempty"`
}

// serviceAccountKey represents the relevant fields from a Google service account JSON file.
type serviceAccountKey struct {
	Type        string `json:"type"`
	ProjectID   string `json:"project_id"`
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
	TokenURI    string `json:"token_uri"`
}

// cachedToken holds an OAuth2 access token and its expiry.
type cachedToken struct {
	token     string
	expiresAt time.Time
}

// Connector implements the issuer.Connector interface for Google CAS.
type Connector struct {
	config     *Config
	logger     *slog.Logger
	httpClient *http.Client

	// OAuth2 token caching
	mu         sync.Mutex
	tokenCache *cachedToken
	saKey      *serviceAccountKey
	rsaKey     *rsa.PrivateKey
}

// New creates a new Google CAS connector with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	if config != nil {
		if config.TTL == "" {
			config.TTL = "8760h"
		}
		if config.BaseURL == "" {
			config.BaseURL = "https://privateca.googleapis.com/v1"
		}
		if config.TokenURL == "" {
			config.TokenURL = "https://oauth2.googleapis.com/token"
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

// parentPath returns the CAS resource parent path.
func (c *Connector) parentPath() string {
	return fmt.Sprintf("projects/%s/locations/%s/caPools/%s",
		c.config.Project, c.config.Location, c.config.CAPool)
}

// certificateCreateResponse represents the Google CAS create certificate response.
type certificateCreateResponse struct {
	Name                string   `json:"name"`
	PEMCertificate      string   `json:"pemCertificate"`
	PEMCertificateChain []string `json:"pemCertificateChain"`
}

// fetchCACertsResponse represents the Google CAS fetchCaCerts response.
type fetchCACertsResponse struct {
	CACerts []caCertChain `json:"caCerts"`
}

type caCertChain struct {
	Certificates []string `json:"certificates"`
}

// googleAPIError represents a Google API error response.
type googleAPIError struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

// ValidateConfig checks that the Google CAS configuration is valid.
// Verifies required fields and that the credentials file is parseable.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid Google CAS config: %w", err)
	}

	if cfg.Project == "" {
		return fmt.Errorf("Google CAS project is required")
	}
	if cfg.Location == "" {
		return fmt.Errorf("Google CAS location is required")
	}
	if cfg.CAPool == "" {
		return fmt.Errorf("Google CAS CA pool is required")
	}
	if cfg.Credentials == "" {
		return fmt.Errorf("Google CAS credentials path is required")
	}

	// Verify credentials file exists and is valid
	saKey, _, err := loadServiceAccountKey(cfg.Credentials)
	if err != nil {
		return fmt.Errorf("Google CAS credentials invalid: %w", err)
	}

	if saKey.ClientEmail == "" {
		return fmt.Errorf("Google CAS credentials missing client_email")
	}
	if saKey.PrivateKey == "" {
		return fmt.Errorf("Google CAS credentials missing private_key")
	}

	if cfg.TTL == "" {
		cfg.TTL = "8760h"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://privateca.googleapis.com/v1"
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = "https://oauth2.googleapis.com/token"
	}

	c.config = &cfg
	c.logger.Info("Google CAS configuration validated",
		"project", cfg.Project,
		"location", cfg.Location,
		"ca_pool", cfg.CAPool)

	return nil
}

// loadServiceAccountKey reads and parses a service account JSON file.
func loadServiceAccountKey(path string) (*serviceAccountKey, *rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read credentials file: %w", err)
	}

	var saKey serviceAccountKey
	if err := json.Unmarshal(data, &saKey); err != nil {
		return nil, nil, fmt.Errorf("cannot parse credentials JSON: %w", err)
	}

	if saKey.PrivateKey == "" {
		return &saKey, nil, nil
	}

	// Parse the RSA private key
	block, _ := pem.Decode([]byte(saKey.PrivateKey))
	if block == nil {
		return nil, nil, fmt.Errorf("cannot decode private key PEM")
	}

	// Try PKCS#8 first, then PKCS#1
	var rsaKey *rsa.PrivateKey
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		rsaKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("private key is not RSA")
		}
	} else if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		rsaKey = key
	} else {
		return nil, nil, fmt.Errorf("cannot parse private key: not PKCS#8 or PKCS#1")
	}

	return &saKey, rsaKey, nil
}

// getAccessToken returns a valid OAuth2 access token, refreshing if needed.
func (c *Connector) getAccessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return cached token if still valid (5 min buffer)
	if c.tokenCache != nil && time.Now().Add(5*time.Minute).Before(c.tokenCache.expiresAt) {
		return c.tokenCache.token, nil
	}

	// Load credentials if not cached
	if c.saKey == nil || c.rsaKey == nil {
		saKey, rsaKey, err := loadServiceAccountKey(c.config.Credentials)
		if err != nil {
			return "", fmt.Errorf("failed to load credentials: %w", err)
		}
		c.saKey = saKey
		c.rsaKey = rsaKey
	}

	// Build JWT
	now := time.Now()
	header := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))

	claims, err := json.Marshal(map[string]interface{}{
		"iss":   c.saKey.ClientEmail,
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud":   c.config.TokenURL,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT claims: %w", err)
	}
	payload := base64URLEncode(claims)

	// Sign
	signingInput := header + "." + payload
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.rsaKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	jwt := signingInput + "." + base64URLEncode(sig)

	// Exchange JWT for access token
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {jwt},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access token in response")
	}

	// Cache token
	c.tokenCache = &cachedToken{
		token:     tokenResp.AccessToken,
		expiresAt: now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}

	return tokenResp.AccessToken, nil
}

// doAuthenticatedRequest performs an HTTP request with OAuth2 bearer token.
func (c *Connector) doAuthenticatedRequest(ctx context.Context, method, urlStr string, body interface{}) ([]byte, int, error) {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get access token: %w", err)
	}

	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// extractAPIError extracts an error message from a Google API error response.
func extractAPIError(body []byte) string {
	var apiErr googleAPIError
	if err := json.Unmarshal(body, &apiErr); err == nil && apiErr.Error.Message != "" {
		return fmt.Sprintf("%s (%s)", apiErr.Error.Message, apiErr.Error.Status)
	}
	return string(body)
}

// IssueCertificate issues a new certificate via Google CAS.
func (c *Connector) IssueCertificate(ctx context.Context, request issuer.IssuanceRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing Google CAS issuance request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	// Convert TTL to seconds string
	ttlDuration, err := time.ParseDuration(c.config.TTL)
	if err != nil {
		return nil, fmt.Errorf("invalid TTL %q: %w", c.config.TTL, err)
	}
	lifetimeSeconds := fmt.Sprintf("%ds", int(ttlDuration.Seconds()))

	// Generate unique certificate ID
	certID := fmt.Sprintf("certctl-%d-%s", time.Now().Unix(), randomHex(4))

	// Build request
	createURL := fmt.Sprintf("%s/%s/certificates?certificateId=%s",
		c.config.BaseURL, c.parentPath(), certID)

	createBody := map[string]interface{}{
		"lifetime": lifetimeSeconds,
		"pemCsr":   request.CSRPEM,
	}

	respBody, statusCode, err := c.doAuthenticatedRequest(ctx, http.MethodPost, createURL, createBody)
	if err != nil {
		return nil, fmt.Errorf("Google CAS create certificate failed: %w", err)
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("Google CAS create certificate returned status %d: %s",
			statusCode, extractAPIError(respBody))
	}

	// Parse response
	var certResp certificateCreateResponse
	if err := json.Unmarshal(respBody, &certResp); err != nil {
		return nil, fmt.Errorf("failed to parse Google CAS response: %w", err)
	}

	if certResp.PEMCertificate == "" {
		return nil, fmt.Errorf("no certificate in Google CAS response")
	}

	// Parse leaf cert to extract metadata
	block, _ := pem.Decode([]byte(certResp.PEMCertificate))
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM from Google CAS")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Build chain PEM
	chainPEM := strings.Join(certResp.PEMCertificateChain, "\n")

	serial := formatSerial(cert.SerialNumber)

	// Store full resource name as OrderID for revocation lookup
	orderID := certResp.Name

	c.logger.Info("Google CAS certificate issued",
		"common_name", request.CommonName,
		"serial", serial,
		"name", certResp.Name,
		"not_after", cert.NotAfter)

	return &issuer.IssuanceResult{
		CertPEM:   certResp.PEMCertificate,
		ChainPEM:  chainPEM,
		Serial:    serial,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		OrderID:   orderID,
	}, nil
}

// RenewCertificate renews a certificate by creating a new one.
// For Google CAS, renewal is functionally identical to issuance.
func (c *Connector) RenewCertificate(ctx context.Context, request issuer.RenewalRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing Google CAS renewal request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	return c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: request.CommonName,
		SANs:       request.SANs,
		CSRPEM:     request.CSRPEM,
		EKUs:       request.EKUs,
	})
}

// RevokeCertificate revokes a certificate at Google CAS.
// The serial field should contain the full certificate resource name (set as OrderID at issuance).
func (c *Connector) RevokeCertificate(ctx context.Context, request issuer.RevocationRequest) error {
	c.logger.Info("processing Google CAS revocation request", "serial", request.Serial)

	// Determine the certificate resource name.
	// If serial starts with "projects/", it's a full resource name (from OrderID).
	// Otherwise, construct a best-effort path.
	var certName string
	if strings.HasPrefix(request.Serial, "projects/") {
		certName = request.Serial
	} else {
		certName = fmt.Sprintf("%s/certificates/%s", c.parentPath(), request.Serial)
	}

	reason := mapRevocationReason(request.Reason)

	revokeURL := fmt.Sprintf("%s/%s:revoke", c.config.BaseURL, certName)
	revokeBody := map[string]interface{}{
		"reason": reason,
	}

	respBody, statusCode, err := c.doAuthenticatedRequest(ctx, http.MethodPost, revokeURL, revokeBody)
	if err != nil {
		return fmt.Errorf("Google CAS revoke failed: %w", err)
	}

	if statusCode != http.StatusOK {
		return fmt.Errorf("Google CAS revoke returned status %d: %s",
			statusCode, extractAPIError(respBody))
	}

	c.logger.Info("Google CAS certificate revoked", "name", certName, "reason", reason)
	return nil
}

// GetOrderStatus returns the status of a Google CAS order.
// Google CAS signs synchronously, so orders are always "completed" immediately.
func (c *Connector) GetOrderStatus(ctx context.Context, orderID string) (*issuer.OrderStatus, error) {
	return &issuer.OrderStatus{
		OrderID:   orderID,
		Status:    "completed",
		UpdatedAt: time.Now(),
	}, nil
}

// GenerateCRL is not supported because Google CAS manages CRL directly.
func (c *Connector) GenerateCRL(ctx context.Context, revokedCerts []issuer.RevokedCertEntry) ([]byte, error) {
	return nil, fmt.Errorf("Google CAS manages CRL directly; not supported via certctl")
}

// SignOCSPResponse is not supported because Google CAS manages OCSP directly.
func (c *Connector) SignOCSPResponse(ctx context.Context, req issuer.OCSPSignRequest) ([]byte, error) {
	return nil, fmt.Errorf("Google CAS manages OCSP directly; not supported via certctl")
}

// GetCACertPEM retrieves the CA certificate chain from Google CAS.
func (c *Connector) GetCACertPEM(ctx context.Context) (string, error) {
	fetchURL := fmt.Sprintf("%s/%s:fetchCaCerts", c.config.BaseURL, c.parentPath())

	respBody, statusCode, err := c.doAuthenticatedRequest(ctx, http.MethodPost, fetchURL, map[string]interface{}{})
	if err != nil {
		return "", fmt.Errorf("Google CAS fetchCaCerts failed: %w", err)
	}

	if statusCode != http.StatusOK {
		return "", fmt.Errorf("Google CAS fetchCaCerts returned status %d: %s",
			statusCode, extractAPIError(respBody))
	}

	var resp fetchCACertsResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("failed to parse fetchCaCerts response: %w", err)
	}

	if len(resp.CACerts) == 0 || len(resp.CACerts[0].Certificates) == 0 {
		return "", fmt.Errorf("no CA certificates in response")
	}

	// Join all certificates from the first CA cert chain
	return strings.Join(resp.CACerts[0].Certificates, "\n"), nil
}

// GetRenewalInfo returns nil, nil as Google CAS does not support ACME Renewal Information (ARI).
func (c *Connector) GetRenewalInfo(ctx context.Context, certPEM string) (*issuer.RenewalInfoResult, error) {
	return nil, nil
}

// mapRevocationReason maps certctl RFC 5280 reason strings to Google CAS enum values.
func mapRevocationReason(reason *string) string {
	if reason == nil {
		return "REVOCATION_REASON_UNSPECIFIED"
	}

	switch strings.ToLower(*reason) {
	case "keycompromise":
		return "KEY_COMPROMISE"
	case "cacompromise":
		return "CERTIFICATE_AUTHORITY_COMPROMISE"
	case "affiliationchanged":
		return "AFFILIATION_CHANGED"
	case "superseded":
		return "SUPERSEDED"
	case "cessationofoperation":
		return "CESSATION_OF_OPERATION"
	case "certificatehold":
		return "CERTIFICATE_HOLD"
	case "privilegewithdrawn":
		return "PRIVILEGE_WITHDRAWN"
	default:
		return "REVOCATION_REASON_UNSPECIFIED"
	}
}

// formatSerial converts a *big.Int serial number to a hex string.
func formatSerial(serial *big.Int) string {
	return serial.Text(16)
}

// randomHex generates n random bytes and returns them as a hex string.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// base64URLEncode encodes data using base64url without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Ensure Connector implements the issuer.Connector interface.
var _ issuer.Connector = (*Connector)(nil)
