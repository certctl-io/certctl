// Package azurekv implements the domain.DiscoverySource interface for
// Azure Key Vault certificate discovery.
//
// Azure Key Vault is a cloud-based secret and certificate management service.
// This connector discovers certificates stored in an Azure Key Vault using the
// Azure Key Vault REST API with OAuth2 client credentials authentication.
//
// No Azure SDK dependency — uses stdlib net/http + OAuth2 for authentication.
//
// API endpoints used:
//
//	GET /certificates?api-version=7.4         - List certificates
//	GET /certificates/{name}/{version}?api-version=7.4  - Get certificate details
//
// Authentication: OAuth2 client credentials flow via Azure AD.
// Token is cached with 5-minute refresh buffer.
package azurekv

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
)

// Config represents the Azure Key Vault discovery configuration.
type Config struct {
	// VaultURL is the Azure Key Vault URL (e.g., "https://myvault.vault.azure.net").
	// Required. Set via CERTCTL_AZURE_KV_VAULT_URL environment variable.
	VaultURL string `json:"vault_url"`

	// TenantID is the Azure AD tenant ID (e.g., "00000000-0000-0000-0000-000000000000").
	// Required. Set via CERTCTL_AZURE_KV_TENANT_ID environment variable.
	TenantID string `json:"tenant_id"`

	// ClientID is the Azure AD application (client) ID.
	// Required. Set via CERTCTL_AZURE_KV_CLIENT_ID environment variable.
	ClientID string `json:"client_id"`

	// ClientSecret is the Azure AD application secret or certificate.
	// Required. Set via CERTCTL_AZURE_KV_CLIENT_SECRET environment variable.
	ClientSecret string `json:"client_secret"`
}

// cachedToken holds an OAuth2 access token and its expiry time.
type cachedToken struct {
	token     string
	expiresAt time.Time
}

// certificateListResponse represents the Azure Key Vault list certificates response.
type certificateListResponse struct {
	Value []struct {
		ID         string `json:"id"`
		Attributes struct {
			Enabled int64 `json:"enabled"`
			Created int64 `json:"created"`
			Updated int64 `json:"updated"`
			Exp     int64 `json:"exp"`
		} `json:"attributes,omitempty"`
		Tags map[string]string `json:"tags,omitempty"`
	} `json:"value"`
	NextLink string `json:"nextLink"`
}

// certificateBundle represents the Azure Key Vault certificate details response.
type certificateBundle struct {
	ID         string `json:"id"`
	CER        string `json:"cer"`
	Attributes struct {
		Enabled int64 `json:"enabled"`
		Created int64 `json:"created"`
		Updated int64 `json:"updated"`
		Exp     int64 `json:"exp"`
	} `json:"attributes,omitempty"`
}

// KVClient is an interface for Azure Key Vault operations, allowing injection for testing.
type KVClient interface {
	// ListCertificates retrieves the list of certificates in the vault.
	ListCertificates(ctx context.Context, vaultURL string) ([]struct {
		ID         string
		Attributes struct {
			Exp int64
		}
	}, error)
	// GetCertificate retrieves a specific certificate version.
	GetCertificate(ctx context.Context, vaultURL, certName, version string) (*certificateBundle, error)
}

// Source implements domain.DiscoverySource for Azure Key Vault.
type Source struct {
	config Config
	logger *slog.Logger
	client KVClient
}

// New creates a new Azure Key Vault discovery source with real HTTP client.
func New(cfg Config, logger *slog.Logger) *Source {
	return &Source{
		config: cfg,
		logger: logger,
		client: &httpKVClient{
			config:     cfg,
			httpClient: &http.Client{Timeout: 30 * time.Second},
		},
	}
}

// NewWithClient creates a new Azure Key Vault discovery source with injected client (for testing).
func NewWithClient(cfg Config, client KVClient, logger *slog.Logger) *Source {
	return &Source{
		config: cfg,
		logger: logger,
		client: client,
	}
}

// Name returns a human-readable name for this discovery source.
func (s *Source) Name() string {
	return "Azure Key Vault"
}

// Type returns the short type identifier for this discovery source.
func (s *Source) Type() string {
	return "azure-kv"
}

// ValidateConfig checks that the Azure Key Vault configuration is valid.
func (s *Source) ValidateConfig() error {
	if s.config.VaultURL == "" {
		return fmt.Errorf("Azure Key Vault URL is required")
	}
	if s.config.TenantID == "" {
		return fmt.Errorf("Azure Key Vault tenant ID is required")
	}
	if s.config.ClientID == "" {
		return fmt.Errorf("Azure Key Vault client ID is required")
	}
	if s.config.ClientSecret == "" {
		return fmt.Errorf("Azure Key Vault client secret is required")
	}

	// Basic URL validation
	if !strings.HasPrefix(s.config.VaultURL, "https://") {
		return fmt.Errorf("Azure Key Vault URL must use HTTPS")
	}

	return nil
}

// Discover scans the Azure Key Vault and returns a DiscoveryReport.
func (s *Source) Discover(ctx context.Context) (*domain.DiscoveryReport, error) {
	s.logger.Info("starting Azure Key Vault discovery", "vault_url", s.config.VaultURL)

	report := &domain.DiscoveryReport{
		AgentID:      "cloud-azure-kv",
		Directories:  []string{fmt.Sprintf("azure-kv://%s/", s.config.VaultURL)},
		Certificates: []domain.DiscoveredCertEntry{},
		Errors:       []string{},
	}

	startTime := time.Now()

	// List certificates
	certs, err := s.client.ListCertificates(ctx, s.config.VaultURL)
	if err != nil {
		s.logger.Error("failed to list Azure Key Vault certificates", "error", err)
		report.Errors = append(report.Errors, fmt.Sprintf("list certificates failed: %v", err))
		return report, nil
	}

	// Process each certificate
	for _, cert := range certs {
		// Extract certificate name and version from ID
		// ID format: https://myvault.vault.azure.net/certificates/mycert/version123
		certName, version, err := extractCertNameAndVersion(cert.ID)
		if err != nil {
			s.logger.Warn("failed to parse certificate ID", "id", cert.ID, "error", err)
			report.Errors = append(report.Errors, fmt.Sprintf("parse cert ID failed: %v", err))
			continue
		}

		// Get certificate details
		certBundle, err := s.client.GetCertificate(ctx, s.config.VaultURL, certName, version)
		if err != nil {
			s.logger.Warn("failed to get certificate details", "name", certName, "version", version, "error", err)
			report.Errors = append(report.Errors, fmt.Sprintf("get cert %s/%s failed: %v", certName, version, err))
			continue
		}

		// Decode the base64-encoded DER certificate
		if certBundle.CER == "" {
			s.logger.Warn("empty certificate data", "name", certName, "version", version)
			continue
		}

		derBytes, err := base64.StdEncoding.DecodeString(certBundle.CER)
		if err != nil {
			s.logger.Warn("failed to decode certificate", "name", certName, "version", version, "error", err)
			report.Errors = append(report.Errors, fmt.Sprintf("decode cert %s/%s failed: %v", certName, version, err))
			continue
		}

		// Parse certificate
		x509Cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			s.logger.Warn("failed to parse certificate", "name", certName, "version", version, "error", err)
			report.Errors = append(report.Errors, fmt.Sprintf("parse cert %s/%s failed: %v", certName, version, err))
			continue
		}

		// Extract certificate metadata
		entry := extractCertMetadata(x509Cert, certName, version)

		// Encode as PEM for inclusion in report
		certPEM := encodeCertPEM(derBytes)
		entry.PEMData = certPEM

		report.Certificates = append(report.Certificates, entry)
		s.logger.Info("discovered certificate",
			"name", certName,
			"common_name", entry.CommonName,
			"serial", entry.SerialNumber,
			"not_after", entry.NotAfter)
	}

	report.ScanDurationMs = int(time.Since(startTime).Milliseconds())

	s.logger.Info("Azure Key Vault discovery completed",
		"certs_found", len(report.Certificates),
		"errors", len(report.Errors),
		"duration_ms", report.ScanDurationMs)

	return report, nil
}

// httpKVClient implements KVClient using Azure Key Vault REST API.
type httpKVClient struct {
	config     Config
	httpClient *http.Client

	// OAuth2 token caching
	mu         sync.Mutex
	tokenCache *cachedToken
}

// ListCertificates retrieves the list of certificates in the vault.
func (c *httpKVClient) ListCertificates(ctx context.Context, vaultURL string) ([]struct {
	ID         string
	Attributes struct {
		Exp int64
	}
}, error) {
	var results []struct {
		ID         string
		Attributes struct {
			Exp int64
		}
	}

	listURL := fmt.Sprintf("%s/certificates?api-version=7.4", strings.TrimSuffix(vaultURL, "/"))

	for listURL != "" {
		token, err := c.getAccessToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get access token: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("list request failed: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("list certificates returned status %d: %s", resp.StatusCode, string(body))
		}

		var listResp certificateListResponse
		if err := json.Unmarshal(body, &listResp); err != nil {
			return nil, fmt.Errorf("failed to parse list response: %w", err)
		}

		for _, cert := range listResp.Value {
			results = append(results, struct {
				ID         string
				Attributes struct {
					Exp int64
				}
			}{
				ID: cert.ID,
				Attributes: struct {
					Exp int64
				}{Exp: cert.Attributes.Exp},
			})
		}

		// Handle pagination
		if listResp.NextLink == "" {
			break
		}
		listURL = listResp.NextLink
	}

	return results, nil
}

// GetCertificate retrieves a specific certificate version from the vault.
func (c *httpKVClient) GetCertificate(ctx context.Context, vaultURL, certName, version string) (*certificateBundle, error) {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	// Ensure vaultURL has no trailing slash
	vaultURL = strings.TrimSuffix(vaultURL, "/")

	// Build the certificate URL
	// Format: https://myvault.vault.azure.net/certificates/mycert/version123?api-version=7.4
	certURL := fmt.Sprintf("%s/certificates/%s/%s?api-version=7.4",
		vaultURL, url.PathEscape(certName), url.PathEscape(version))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, certURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get certificate request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get certificate returned status %d: %s", resp.StatusCode, string(body))
	}

	var certBundle certificateBundle
	if err := json.Unmarshal(body, &certBundle); err != nil {
		return nil, fmt.Errorf("failed to parse certificate response: %w", err)
	}

	return &certBundle, nil
}

// getAccessToken returns a valid OAuth2 access token, refreshing if needed.
func (c *httpKVClient) getAccessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return cached token if still valid (5 min buffer)
	if c.tokenCache != nil && time.Now().Add(5*time.Minute).Before(c.tokenCache.expiresAt) {
		return c.tokenCache.token, nil
	}

	// Exchange client credentials for access token
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token",
		url.PathEscape(c.config.TenantID))

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.config.ClientID},
		"client_secret": {c.config.ClientSecret},
		"scope":         {"https://vault.azure.net/.default"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request returned status %d: %s", resp.StatusCode, string(body))
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
		expiresAt: time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}

	return tokenResp.AccessToken, nil
}

// extractCertNameAndVersion extracts the certificate name and version from the Azure ID.
// ID format: https://myvault.vault.azure.net/certificates/mycert/version123
func extractCertNameAndVersion(id string) (name, version string, err error) {
	// Use regex to extract name and version from the ID URL
	// Pattern: /certificates/{name}/{version}
	re := regexp.MustCompile(`/certificates/([^/]+)/([^/]+)$`)
	matches := re.FindStringSubmatch(id)

	if len(matches) != 3 {
		return "", "", fmt.Errorf("cannot parse certificate ID: %s", id)
	}

	return matches[1], matches[2], nil
}

// extractCertMetadata extracts metadata from a parsed X.509 certificate.
func extractCertMetadata(cert *x509.Certificate, certName, version string) domain.DiscoveredCertEntry {
	// Extract Subject Alternative Names (DNS names and email addresses)
	sans := []string{}
	sans = append(sans, cert.DNSNames...)

	// Extract key algorithm
	keyAlgo := "unknown"
	keySize := 0

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keyAlgo = "RSA"
		keySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		keyAlgo = "ECDSA"
		keySize = pub.Curve.Params().BitSize
	}

	// Compute SHA-256 fingerprint
	fp := sha256.Sum256(cert.Raw)
	fingerprint := fmt.Sprintf("%X", fp)

	// Format times as RFC3339
	notBefore := cert.NotBefore.UTC().Format(time.RFC3339)
	notAfter := cert.NotAfter.UTC().Format(time.RFC3339)

	return domain.DiscoveredCertEntry{
		FingerprintSHA256: fingerprint,
		CommonName:        cert.Subject.CommonName,
		SANs:              sans,
		SerialNumber:      fmt.Sprintf("%x", cert.SerialNumber),
		IssuerDN:          cert.Issuer.String(),
		SubjectDN:         cert.Subject.String(),
		NotBefore:         notBefore,
		NotAfter:          notAfter,
		KeyAlgorithm:      keyAlgo,
		KeySize:           keySize,
		IsCA:              cert.IsCA,
		SourcePath:        fmt.Sprintf("azure-kv://%s/%s", certName, version),
		SourceFormat:      "DER",
	}
}

// encodeCertPEM encodes a DER certificate as PEM.
func encodeCertPEM(derBytes []byte) string {
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	return buf.String()
}

// Ensure Source implements domain.DiscoverySource.
var _ domain.DiscoverySource = (*Source)(nil)
