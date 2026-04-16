// Package gcpsm implements the domain.DiscoverySource interface for GCP Secret Manager.
//
// GCP Secret Manager is a Google Cloud service for securely storing and managing secrets,
// including certificates. This discovery source scans Secret Manager for certificates stored
// as secrets, filters by configured tags, and reports discovered certificate metadata
// back to the control plane for triage and management.
//
// Discovery approach:
// 1. Authenticate using service account JSON credentials (JWT → OAuth2 token exchange)
// 2. List all secrets in the configured GCP project
// 3. Filter by label "type=certificate"
// 4. For each secret, retrieve the latest version's data
// 5. Base64-decode the secret value, then attempt PEM or DER parsing
// 6. Extract certificate metadata (CN, SANs, serial, validity, key algorithm, etc.)
// 7. Report findings with sentinel agent ID "cloud-gcp-sm" and source path "gcp-sm://{project}/{secret-name}"
//
// Authentication: OAuth2 service account via JWT assertion. The service account
// credentials must be provided in a JSON file. The connector loads the private key,
// builds a JWT, exchanges it for an access token, then uses Bearer token auth for
// all subsequent Secret Manager API calls.
//
// GCP Secret Manager API operations used:
//
//	GET /v1/projects/{project}/secrets - List secrets with filtering
//	GET /v1/projects/{project}/secrets/{name}/versions/latest:access - Access secret data
package gcpsm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shankar0123/certctl/internal/config"
	"github.com/shankar0123/certctl/internal/domain"
)

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

// SMClient defines the interface for interacting with GCP Secret Manager.
// This allows for dependency injection and testing with mock clients.
type SMClient interface {
	// ListSecrets lists secrets in the project, filtered by the "type=certificate" label.
	ListSecrets(ctx context.Context, project string) ([]SecretEntry, error)

	// AccessSecretVersion retrieves the latest version data for a secret.
	AccessSecretVersion(ctx context.Context, project, secretName string) ([]byte, error)
}

// SecretEntry represents metadata about a secret from ListSecrets.
type SecretEntry struct {
	Name   string // Full resource name: projects/{project}/secrets/{name}
	Labels map[string]string
}

// Source represents a GCP Secret Manager discovery source.
type Source struct {
	cfg *config.GCPSecretMgrDiscoveryConfig

	// For real HTTP client
	httpClient *http.Client

	// For test injection
	client SMClient

	logger *slog.Logger

	// OAuth2 token caching
	mu         sync.Mutex
	tokenCache *cachedToken
	saKey      *serviceAccountKey
	rsaKey     *rsa.PrivateKey
}

// New creates a new GCP Secret Manager discovery source with the given configuration.
// It uses the real HTTP client for authenticating with GCP.
func New(cfg *config.GCPSecretMgrDiscoveryConfig, logger *slog.Logger) *Source {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg == nil {
		cfg = &config.GCPSecretMgrDiscoveryConfig{}
	}

	return &Source{
		cfg:    cfg,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewWithClient creates a new GCP Secret Manager discovery source with an injected client.
// This is primarily for testing.
func NewWithClient(cfg *config.GCPSecretMgrDiscoveryConfig, client SMClient, logger *slog.Logger) *Source {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg == nil {
		cfg = &config.GCPSecretMgrDiscoveryConfig{}
	}

	return &Source{
		cfg:    cfg,
		client: client,
		logger: logger,
	}
}

// Name returns a human-readable name for this discovery source.
func (s *Source) Name() string {
	return "GCP Secret Manager"
}

// Type returns the short type identifier for this discovery source.
func (s *Source) Type() string {
	return "gcp-sm"
}

// ValidateConfig checks that the source is properly configured.
func (s *Source) ValidateConfig() error {
	if s.cfg == nil {
		return fmt.Errorf("gcp secret manager discovery config is nil")
	}
	if s.cfg.Project == "" {
		return fmt.Errorf("gcp secret manager project is required")
	}
	if s.cfg.Credentials == "" {
		return fmt.Errorf("gcp secret manager credentials path is required")
	}

	// Verify credentials file exists and is valid
	_, _, err := loadServiceAccountKey(s.cfg.Credentials)
	if err != nil {
		return fmt.Errorf("gcp secret manager credentials invalid: %w", err)
	}

	return nil
}

// Discover scans GCP Secret Manager for certificates and returns a DiscoveryReport.
func (s *Source) Discover(ctx context.Context) (*domain.DiscoveryReport, error) {
	if err := s.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid gcp secret manager config: %w", err)
	}

	startTime := time.Now()
	report := &domain.DiscoveryReport{
		AgentID:      "cloud-gcp-sm",
		Directories:  []string{fmt.Sprintf("gcp-sm://%s/", s.cfg.Project)},
		Certificates: []domain.DiscoveredCertEntry{},
		Errors:       []string{},
	}

	// Get or create client (use injected mock for testing, real client otherwise)
	var client SMClient
	if s.client != nil {
		client = s.client
	} else {
		client = &httpSMClient{
			source: s,
			logger: s.logger,
		}
	}

	// List secrets in GCP Secret Manager
	s.logger.Debug("listing secrets in gcp secret manager", "project", s.cfg.Project)
	secrets, err := client.ListSecrets(ctx, s.cfg.Project)
	if err != nil {
		errMsg := fmt.Sprintf("failed to list secrets: %v", err)
		report.Errors = append(report.Errors, errMsg)
		s.logger.Error(errMsg)
		return report, err
	}

	s.logger.Debug("found secrets", "count", len(secrets))

	// Process each secret
	for _, secret := range secrets {
		// Extract secret name from full resource name: projects/{project}/secrets/{name}
		parts := strings.Split(secret.Name, "/")
		if len(parts) < 2 {
			report.Errors = append(report.Errors, fmt.Sprintf("invalid secret name format: %s", secret.Name))
			continue
		}
		secretName := parts[len(parts)-1]

		// Access the latest version of the secret
		data, err := client.AccessSecretVersion(ctx, s.cfg.Project, secretName)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("failed to access secret %s: %v", secretName, err))
			s.logger.Warn("failed to access secret", "secret", secretName, "error", err)
			continue
		}

		// Try to parse the data as a certificate (PEM or DER)
		cert, err := parseCertificate(data)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("failed to parse certificate in secret %s: %v", secretName, err))
			s.logger.Warn("failed to parse certificate", "secret", secretName, "error", err)
			continue
		}

		// Extract certificate metadata
		entry := s.extractCertificateMetadata(cert, secretName)
		report.Certificates = append(report.Certificates, entry)
	}

	report.ScanDurationMs = int(time.Since(startTime).Milliseconds())
	s.logger.Info("gcp secret manager discovery completed",
		"project", s.cfg.Project,
		"certificates_found", len(report.Certificates),
		"errors", len(report.Errors),
		"duration_ms", report.ScanDurationMs)

	return report, nil
}

// extractCertificateMetadata extracts certificate metadata from an x509.Certificate.
func (s *Source) extractCertificateMetadata(cert *x509.Certificate, secretName string) domain.DiscoveredCertEntry {
	// Compute SHA-256 fingerprint
	certDER := cert.Raw
	hash := sha256.Sum256(certDER)
	fingerprint := strings.ToUpper(fmt.Sprintf("%x", hash[:]))

	// Extract SANs
	var sans []string
	sans = append(sans, cert.DNSNames...)
	sans = append(sans, cert.EmailAddresses...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	// Determine key algorithm and size
	keyAlgo := "unknown"
	keySize := 0

	switch pk := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keyAlgo = "RSA"
		keySize = pk.N.BitLen()
	case *ecdsa.PublicKey:
		keyAlgo = "ECDSA"
		switch pk.Curve.Params().Name {
		case "P-256":
			keySize = 256
		case "P-384":
			keySize = 384
		case "P-521":
			keySize = 521
		default:
			keySize = pk.X.BitLen()
		}
	case ed25519.PublicKey:
		keyAlgo = "Ed25519"
		keySize = 253
	}

	// Format timestamps
	notBeforeStr := cert.NotBefore.UTC().Format(time.RFC3339)
	notAfterStr := cert.NotAfter.UTC().Format(time.RFC3339)

	// Build PEM representation
	pemData := encodeCertificatePEM(cert)

	// Source path: gcp-sm://{project}/{secret-name}
	sourcePath := fmt.Sprintf("gcp-sm://%s/%s", s.cfg.Project, secretName)

	return domain.DiscoveredCertEntry{
		FingerprintSHA256: fingerprint,
		CommonName:        cert.Subject.CommonName,
		SANs:              sans,
		SerialNumber:      fmt.Sprintf("%x", cert.SerialNumber),
		IssuerDN:          cert.Issuer.String(),
		SubjectDN:         cert.Subject.String(),
		NotBefore:         notBeforeStr,
		NotAfter:          notAfterStr,
		KeyAlgorithm:      keyAlgo,
		KeySize:           keySize,
		IsCA:              cert.IsCA,
		PEMData:           pemData,
		SourcePath:        sourcePath,
		SourceFormat:      "PEM",
	}
}

// parseCertificate parses a certificate from data that may be PEM or base64-encoded DER.
func parseCertificate(data []byte) (*x509.Certificate, error) {
	// First try PEM
	block, _ := pem.Decode(data)
	if block != nil && block.Type == "CERTIFICATE" {
		return x509.ParseCertificate(block.Bytes)
	}

	// Try base64-decode and then DER
	decoded, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(data)))
	if err == nil {
		if cert, err := x509.ParseCertificate(decoded); err == nil {
			return cert, nil
		}
	}

	// Try raw DER
	if cert, err := x509.ParseCertificate(data); err == nil {
		return cert, nil
	}

	return nil, fmt.Errorf("failed to parse certificate from any format (PEM, base64 DER, or DER)")
}

// encodeCertificatePEM encodes an x509.Certificate as PEM.
func encodeCertificatePEM(cert *x509.Certificate) string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return string(pem.EncodeToMemory(block))
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
func (s *Source) getAccessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Return cached token if still valid (5 min buffer)
	if s.tokenCache != nil && time.Now().Add(5*time.Minute).Before(s.tokenCache.expiresAt) {
		return s.tokenCache.token, nil
	}

	// Load credentials if not cached
	if s.saKey == nil || s.rsaKey == nil {
		saKey, rsaKey, err := loadServiceAccountKey(s.cfg.Credentials)
		if err != nil {
			return "", fmt.Errorf("failed to load credentials: %w", err)
		}
		s.saKey = saKey
		s.rsaKey = rsaKey
	}

	// Build JWT
	now := time.Now()
	header := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))

	claims, err := json.Marshal(map[string]interface{}{
		"iss":   s.saKey.ClientEmail,
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud":   s.saKey.TokenURI,
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
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.rsaKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	jwt := signingInput + "." + base64URLEncode(sig)

	// Exchange JWT for access token
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {jwt},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.saKey.TokenURI,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
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
	s.tokenCache = &cachedToken{
		token:     tokenResp.AccessToken,
		expiresAt: now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}

	return tokenResp.AccessToken, nil
}

// httpSMClient implements SMClient using the real GCP Secret Manager HTTP API.
type httpSMClient struct {
	source *Source
	logger *slog.Logger
}

// ListSecrets lists all secrets in the project, filtered by "type=certificate" label.
func (c *httpSMClient) ListSecrets(ctx context.Context, project string) ([]SecretEntry, error) {
	token, err := c.source.getAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	// Build the list request URL with filter
	// Filter for secrets with label "type=certificate"
	filter := `labels.type=certificate`
	listURL := fmt.Sprintf("https://secretmanager.googleapis.com/v1/projects/%s/secrets?filter=%s",
		url.QueryEscape(project), url.QueryEscape(filter))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create list request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.source.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list secrets request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read list response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list secrets returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var listResp struct {
		Secrets []struct {
			Name   string            `json:"name"`
			Labels map[string]string `json:"labels"`
		} `json:"secrets"`
		NextPageToken string `json:"nextPageToken"`
	}

	if err := json.Unmarshal(body, &listResp); err != nil {
		return nil, fmt.Errorf("failed to parse list response: %w", err)
	}

	var secrets []SecretEntry
	for _, s := range listResp.Secrets {
		secrets = append(secrets, SecretEntry{
			Name:   s.Name,
			Labels: s.Labels,
		})
	}

	// TODO: handle pagination with nextPageToken if needed for large secret managers
	// For now, just return the first page results

	return secrets, nil
}

// AccessSecretVersion retrieves the latest version of a secret's data.
func (c *httpSMClient) AccessSecretVersion(ctx context.Context, project, secretName string) ([]byte, error) {
	token, err := c.source.getAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	// Build the access request URL
	accessURL := fmt.Sprintf("https://secretmanager.googleapis.com/v1/projects/%s/secrets/%s/versions/latest:access",
		url.QueryEscape(project), url.QueryEscape(secretName))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, accessURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create access request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.source.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("access secret request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read access response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("access secret returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response to extract the payload data field
	var accessResp struct {
		Payload struct {
			Data string `json:"data"` // base64-encoded secret data
		} `json:"payload"`
	}

	if err := json.Unmarshal(body, &accessResp); err != nil {
		return nil, fmt.Errorf("failed to parse access response: %w", err)
	}

	// Decode the base64-encoded data
	data, err := base64.StdEncoding.DecodeString(accessResp.Payload.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode secret data: %w", err)
	}

	return data, nil
}

// base64URLEncode encodes data using base64url without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Ensure Source implements the domain.DiscoverySource interface.
var _ domain.DiscoverySource = (*Source)(nil)
