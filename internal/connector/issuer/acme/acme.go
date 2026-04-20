package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/shankar0123/certctl/internal/connector/issuer"
)

// Config represents the ACME issuer connector configuration.
type Config struct {
	DirectoryURL string `json:"directory_url"`       // ACME directory URL (e.g., https://acme-staging-v02.api.letsencrypt.org/directory)
	Email        string `json:"email"`               // Contact email for the ACME account
	EABKid       string `json:"eab_kid,omitempty"`   // External Account Binding Key ID (for some CAs)
	EABHmac      string `json:"eab_hmac,omitempty"`  // External Account Binding HMAC Key
	HTTPPort     int    `json:"http_port,omitempty"` // Port for HTTP-01 challenge server (default: 80)

	// ChallengeType selects the ACME challenge method: "http-01" (default), "dns-01", or "dns-persist-01".
	// DNS-01 is required for wildcard certificates (*.example.com).
	// DNS-PERSIST-01 uses a standing TXT record (set once, reused forever) — no per-renewal DNS updates.
	ChallengeType string `json:"challenge_type,omitempty"`

	// DNSPresentScript is the path to a script that creates DNS TXT records (dns-01 and dns-persist-01).
	// The script receives CERTCTL_DNS_DOMAIN, CERTCTL_DNS_FQDN, CERTCTL_DNS_VALUE, CERTCTL_DNS_TOKEN.
	DNSPresentScript string `json:"dns_present_script,omitempty"`

	// DNSCleanUpScript is the path to a script that removes DNS TXT records (dns-01 only).
	// Optional — if not set, records are not cleaned up automatically.
	// Not used by dns-persist-01 (records are permanent).
	DNSCleanUpScript string `json:"dns_cleanup_script,omitempty"`

	// DNSPropagationWait is how long to wait (in seconds) after creating the TXT record
	// before telling the CA to validate. Defaults to 30 seconds.
	DNSPropagationWait int `json:"dns_propagation_wait,omitempty"`

	// DNSPersistIssuerDomain is the CA's issuer domain name for dns-persist-01 records.
	// Used to construct the TXT record value: "<issuer-domain>; accounturi=<account-uri>".
	// Required when ChallengeType is "dns-persist-01". For Let's Encrypt, use "letsencrypt.org".
	DNSPersistIssuerDomain string `json:"dns_persist_issuer_domain,omitempty"`

	// Profile selects the ACME certificate profile for the newOrder request.
	// Let's Encrypt supports "tlsserver" (standard TLS, default) and "shortlived" (6-day certs).
	// Leave empty for the CA's default profile (backward-compatible).
	// See: https://letsencrypt.org/2025/01/09/acme-profiles.html
	Profile string `json:"profile,omitempty"`

	// ARIEnabled enables ACME Renewal Information (RFC 9773) support per CERTCTL_ACME_ARI_ENABLED.
	// When enabled, the connector queries the CA's ARI endpoint to get CA-directed renewal timing.
	ARIEnabled bool `json:"ari_enabled,omitempty"`

	// Insecure skips TLS certificate verification when connecting to the ACME directory.
	// Only use for testing with self-signed ACME servers like Pebble.
	Insecure bool `json:"insecure,omitempty"`
}

// Connector implements the issuer.Connector interface for ACME-compatible CAs
// (Let's Encrypt, Sectigo, ZeroSSL, etc.).
//
// It supports HTTP-01 challenge solving via a built-in temporary HTTP server.
// The challenge server starts when needed and stops after validation completes.
//
// For HTTP-01 to work, the domain(s) being validated must resolve to the machine
// running this connector, and the configured HTTP port must be reachable from the internet.
type Connector struct {
	config     *Config
	logger     *slog.Logger
	client     *acme.Client
	accountKey *ecdsa.PrivateKey

	// HTTP-01 challenge solver state
	challengeMu     sync.RWMutex
	challengeTokens map[string]string // token → key authorization

	// DNS-01 challenge solver (nil if using HTTP-01)
	dnsSolver DNSSolver
}

// New creates a new ACME connector with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	if config != nil {
		if config.HTTPPort == 0 {
			config.HTTPPort = 80
		}
		if config.ChallengeType == "" {
			config.ChallengeType = "http-01"
		}
		if config.DNSPropagationWait == 0 {
			config.DNSPropagationWait = 30
		}
	}

	c := &Connector{
		config:          config,
		logger:          logger,
		challengeTokens: make(map[string]string),
	}

	// Initialize DNS solver if dns-01 or dns-persist-01 challenge type is configured
	if config != nil && (config.ChallengeType == "dns-01" || config.ChallengeType == "dns-persist-01") && config.DNSPresentScript != "" {
		c.dnsSolver = NewScriptDNSSolver(config.DNSPresentScript, config.DNSCleanUpScript, logger)
		logger.Info("DNS challenge solver configured",
			"challenge_type", config.ChallengeType,
			"present_script", config.DNSPresentScript,
			"cleanup_script", config.DNSCleanUpScript)
	}

	return c
}

// httpClient returns an HTTP client configured for the ACME connector.
// When Insecure is true (e.g., for Pebble test servers), TLS verification is skipped.
func (c *Connector) httpClient() *http.Client {
	client := &http.Client{Timeout: 30 * time.Second}
	if c.config != nil && c.config.Insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // Intentional for test ACME servers (Pebble)
		}
	}
	return client
}

// ValidateConfig checks that the ACME directory URL is reachable and valid.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid ACME config: %w", err)
	}

	if cfg.DirectoryURL == "" {
		return fmt.Errorf("ACME directory_url is required")
	}

	if cfg.Email == "" {
		return fmt.Errorf("ACME email is required")
	}

	c.logger.Info("validating ACME configuration", "directory_url", cfg.DirectoryURL, "insecure", cfg.Insecure)

	// Apply config so httpClient() can use it for the directory probe.
	// This persists across the function — if validation fails early, the config
	// will still be set, but that's fine since a failed ValidateConfig means
	// the connector won't be used.
	c.config = &cfg

	// Verify that the directory URL is reachable
	httpClient := c.httpClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.DirectoryURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to reach ACME directory: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ACME directory returned status %d", resp.StatusCode)
	}

	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = 80
	}

	if cfg.ChallengeType == "" {
		cfg.ChallengeType = "http-01"
	}

	// Validate challenge type
	if cfg.ChallengeType != "http-01" && cfg.ChallengeType != "dns-01" && cfg.ChallengeType != "dns-persist-01" {
		return fmt.Errorf("invalid challenge_type: %s (must be http-01, dns-01, or dns-persist-01)", cfg.ChallengeType)
	}

	// Validate profile if set (alphanumeric + hyphens only)
	if cfg.Profile != "" {
		for _, ch := range cfg.Profile {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return fmt.Errorf("invalid profile: %q (must contain only alphanumeric characters and hyphens)", cfg.Profile)
			}
		}
	}

	// DNS-01 and DNS-PERSIST-01 require a present script
	if (cfg.ChallengeType == "dns-01" || cfg.ChallengeType == "dns-persist-01") && cfg.DNSPresentScript == "" {
		return fmt.Errorf("dns_present_script is required for %s challenge type", cfg.ChallengeType)
	}

	// DNS-PERSIST-01 requires an issuer domain
	if cfg.ChallengeType == "dns-persist-01" && cfg.DNSPersistIssuerDomain == "" {
		return fmt.Errorf("dns_persist_issuer_domain is required for dns-persist-01 challenge type (e.g., \"letsencrypt.org\")")
	}

	if cfg.DNSPropagationWait == 0 {
		cfg.DNSPropagationWait = 30
	}

	c.config = &cfg

	// Re-initialize DNS solver if switching to dns-01 or dns-persist-01
	if (cfg.ChallengeType == "dns-01" || cfg.ChallengeType == "dns-persist-01") && cfg.DNSPresentScript != "" {
		c.dnsSolver = NewScriptDNSSolver(cfg.DNSPresentScript, cfg.DNSCleanUpScript, c.logger)
	}

	c.logger.Info("ACME configuration validated",
		"challenge_type", cfg.ChallengeType)
	return nil
}

// ensureClient initializes the ACME client and account key if not already done.
func (c *Connector) ensureClient(ctx context.Context) error {
	if c.client != nil {
		return nil
	}

	// Generate an ECDSA P-256 account key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate account key: %w", err)
	}
	c.accountKey = key

	c.client = &acme.Client{
		Key:          key,
		DirectoryURL: c.config.DirectoryURL,
		HTTPClient:   c.httpClient(),
	}

	// Register or retrieve the ACME account
	acct := &acme.Account{
		Contact: []string{"mailto:" + c.config.Email},
	}

	// Auto-fetch EAB credentials from ZeroSSL if directory URL is ZeroSSL and no EAB provided.
	// ZeroSSL offers a public endpoint that returns EAB credentials given an email address,
	// so users don't need to visit the ZeroSSL dashboard manually.
	if c.config.EABKid == "" && c.config.EABHmac == "" && isZeroSSL(c.config.DirectoryURL) {
		kid, hmac, eabErr := fetchZeroSSLEAB(ctx, c.config.Email)
		if eabErr != nil {
			return fmt.Errorf("failed to auto-fetch ZeroSSL EAB credentials: %w", eabErr)
		}
		c.config.EABKid = kid
		c.config.EABHmac = hmac
		c.logger.Info("auto-fetched EAB credentials from ZeroSSL", "eab_kid", kid)
	}

	// External Account Binding (required by ZeroSSL, Google Trust Services, SSL.com, etc.)
	if c.config.EABKid != "" && c.config.EABHmac != "" {
		hmacKey, decodeErr := base64.RawURLEncoding.DecodeString(c.config.EABHmac)
		if decodeErr != nil {
			return fmt.Errorf("failed to decode EAB HMAC key (expected base64url): %w", decodeErr)
		}
		acct.ExternalAccountBinding = &acme.ExternalAccountBinding{
			KID: c.config.EABKid,
			Key: hmacKey,
		}
		c.logger.Info("using External Account Binding for ACME registration", "eab_kid", c.config.EABKid)
	}

	_, err = c.client.Register(ctx, acct, acme.AcceptTOS)
	if err != nil {
		// Account may already exist, try to get it
		_, getErr := c.client.GetReg(ctx, "")
		if getErr != nil {
			return fmt.Errorf("failed to register ACME account: %w (get existing: %v)", err, getErr)
		}
		c.logger.Info("using existing ACME account")
	} else {
		c.logger.Info("registered new ACME account", "email", c.config.Email)
	}

	return nil
}

// zeroSSLEABEndpoint is the ZeroSSL API endpoint for auto-generating EAB credentials.
// Variable (not const) to allow test overrides.
var zeroSSLEABEndpoint = "https://api.zerossl.com/acme/eab-credentials-email"

// isZeroSSL returns true if the ACME directory URL points to ZeroSSL.
func isZeroSSL(directoryURL string) bool {
	return strings.Contains(strings.ToLower(directoryURL), "zerossl.com")
}

// fetchZeroSSLEAB retrieves EAB credentials from ZeroSSL's public API endpoint.
// ZeroSSL provides this so users don't need to visit the dashboard manually.
// Returns (kid, hmac_key, error). The HMAC key is already base64url-encoded.
func fetchZeroSSLEAB(ctx context.Context, email string) (string, string, error) {
	if email == "" {
		return "", "", fmt.Errorf("email is required for ZeroSSL EAB auto-fetch")
	}

	form := url.Values{"email": {email}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, zeroSSLEABEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("ZeroSSL API returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Success  bool   `json:"success"`
		EABKid   string `json:"eab_kid"`
		EABHmac  string `json:"eab_hmac_key"`
		ErrorMsg string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", fmt.Errorf("parse response: %w", err)
	}

	if !result.Success || result.EABKid == "" || result.EABHmac == "" {
		errDetail := result.ErrorMsg
		if errDetail == "" {
			errDetail = string(body)
		}
		return "", "", fmt.Errorf("ZeroSSL EAB generation failed: %s", errDetail)
	}

	return result.EABKid, result.EABHmac, nil
}

// IssueCertificate submits a certificate issuance request to the ACME CA.
//
// Flow:
// 1. Create a new order with the CA for the requested identifiers
// 2. Solve HTTP-01 challenges for each authorization
// 3. Finalize the order by submitting the CSR
// 4. Download the issued certificate and chain
func (c *Connector) IssueCertificate(ctx context.Context, request issuer.IssuanceRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing ACME issuance request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	if err := c.ensureClient(ctx); err != nil {
		return nil, fmt.Errorf("ACME client init: %w", err)
	}

	// Build the list of identifiers (domains)
	identifiers := buildIdentifiers(request.CommonName, request.SANs)

	// Step 1: Create order (with optional profile for CAs that support it)
	order, err := c.authorizeOrderWithProfile(ctx, identifiers, c.config.Profile)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME order: %w", err)
	}
	c.logger.Info("ACME order created", "order_url", order.URI, "status", order.Status)

	// Save FinalizeURL and URI before WaitOrder — WaitOrder returns a new Order
	// object that may have empty FinalizeURL and URI fields (Go's crypto/acme
	// WaitOrder doesn't populate Order.URI on the returned struct).
	finalizeURL := order.FinalizeURL
	orderURI := order.URI

	// Step 2: Solve authorizations (HTTP-01 challenges)
	if order.Status == acme.StatusPending {
		if err := c.solveAuthorizations(ctx, order.AuthzURLs); err != nil {
			return nil, fmt.Errorf("failed to solve challenges: %w", err)
		}

		// Wait for the order to be ready
		order, err = c.client.WaitOrder(ctx, orderURI)
		if err != nil {
			return nil, fmt.Errorf("order failed after challenge: %w", err)
		}
		// Update finalizeURL from the waited order if it has one
		if order.FinalizeURL != "" {
			finalizeURL = order.FinalizeURL
		}
		// Preserve orderURI — WaitOrder doesn't populate Order.URI
		if order.URI != "" {
			orderURI = order.URI
		}
	}

	if order.Status != acme.StatusReady {
		return nil, fmt.Errorf("order not ready, status: %s", order.Status)
	}

	// Step 3: Parse CSR and finalize order
	csrDER, err := parseCSRPEM(request.CSRPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	if finalizeURL == "" {
		return nil, fmt.Errorf("ACME order has no finalize URL (order URI: %s, status: %s)", order.URI, order.Status)
	}

	// Step 3b: Finalize the order and fetch the certificate.
	// CreateOrderCert POSTs the CSR to the finalize URL and attempts to retrieve
	// the certificate. Some ACME servers (notably Pebble) return the order object
	// per RFC 8555 rather than redirecting to the cert, which can cause
	// CreateOrderCert's internal cert URL resolution to fail. In that case, we
	// fall back to WaitOrder (to get the CertURL) + FetchCert.
	derChain, _, err := c.client.CreateOrderCert(ctx, finalizeURL, csrDER, true)
	if err != nil {
		c.logger.Warn("CreateOrderCert failed, attempting manual certificate fetch",
			"error", err, "order_uri", orderURI)

		// The finalize POST likely succeeded (the CA issued the cert) but cert
		// retrieval failed. WaitOrder returns the order in "valid" state with
		// CertURL populated.
		validOrder, waitErr := c.client.WaitOrder(ctx, orderURI)
		if waitErr != nil {
			return nil, fmt.Errorf("failed to finalize order: %w (wait fallback: %v)", err, waitErr)
		}

		if validOrder.CertURL == "" {
			return nil, fmt.Errorf("order finalized but no certificate URL returned (original error: %w)", err)
		}

		c.logger.Info("fetching certificate via fallback", "cert_url", validOrder.CertURL)
		fetchedChain, fetchErr := c.client.FetchCert(ctx, validOrder.CertURL, true)
		if fetchErr != nil {
			return nil, fmt.Errorf("failed to fetch certificate: %w (original finalize error: %v)", fetchErr, err)
		}
		derChain = fetchedChain
	}

	if len(derChain) == 0 {
		return nil, fmt.Errorf("ACME returned empty certificate chain")
	}

	// Step 4: Convert DER chain to PEM
	certPEM, chainPEM, serial, notBefore, notAfter, err := parseDERChain(derChain)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate chain: %w", err)
	}

	c.logger.Info("ACME certificate issued",
		"common_name", request.CommonName,
		"serial", serial,
		"not_after", notAfter)

	return &issuer.IssuanceResult{
		CertPEM:   certPEM,
		ChainPEM:  chainPEM,
		Serial:    serial,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		OrderID:   orderURI,
	}, nil
}

// RenewCertificate renews a certificate by creating a new ACME order.
// The process is identical to issuance — ACME doesn't distinguish between new and renewal.
func (c *Connector) RenewCertificate(ctx context.Context, request issuer.RenewalRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing ACME renewal request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	return c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: request.CommonName,
		SANs:       request.SANs,
		CSRPEM:     request.CSRPEM,
	})
}

// RevokeCertificate revokes a certificate at the ACME CA.
func (c *Connector) RevokeCertificate(ctx context.Context, request issuer.RevocationRequest) error {
	c.logger.Info("processing ACME revocation request", "serial", request.Serial)

	if err := c.ensureClient(ctx); err != nil {
		return fmt.Errorf("ACME client init: %w", err)
	}

	// ACME revocation requires the certificate DER, not just the serial.
	// For now, log a warning. Full revocation requires storing the cert DER
	// or re-fetching it from the order.
	c.logger.Warn("ACME revocation requires certificate DER bytes; serial-only revocation not supported in V1",
		"serial", request.Serial)
	return fmt.Errorf("ACME revocation by serial not supported in V1; provide certificate DER")
}

// GetOrderStatus retrieves the current status of an ACME order.
func (c *Connector) GetOrderStatus(ctx context.Context, orderID string) (*issuer.OrderStatus, error) {
	c.logger.Info("fetching ACME order status", "order_id", orderID)

	if err := c.ensureClient(ctx); err != nil {
		return nil, fmt.Errorf("ACME client init: %w", err)
	}

	order, err := c.client.GetOrder(ctx, orderID)
	if err != nil {
		return nil, fmt.Errorf("failed to get order: %w", err)
	}

	status := &issuer.OrderStatus{
		OrderID:   orderID,
		Status:    string(order.Status),
		UpdatedAt: time.Now(),
	}

	return status, nil
}

// solveAuthorizations processes all authorization URLs and solves their challenges.
// Supports HTTP-01, DNS-01, and DNS-PERSIST-01 challenge types based on configuration.
func (c *Connector) solveAuthorizations(ctx context.Context, authzURLs []string) error {
	switch c.config.ChallengeType {
	case "dns-01":
		return c.solveAuthorizationsDNS01(ctx, authzURLs)
	case "dns-persist-01":
		return c.solveAuthorizationsDNSPersist01(ctx, authzURLs)
	default:
		return c.solveAuthorizationsHTTP01(ctx, authzURLs)
	}
}

// solveAuthorizationsHTTP01 solves challenges using the HTTP-01 method.
func (c *Connector) solveAuthorizationsHTTP01(ctx context.Context, authzURLs []string) error {
	// Start the challenge server
	srv, err := c.startChallengeServer()
	if err != nil {
		return fmt.Errorf("failed to start challenge server: %w", err)
	}
	defer func() {
		// Derive the challenge-server shutdown context from the parent ctx so
		// values (trace IDs, deadlines) propagate, but detach from its
		// cancellation so Shutdown always gets its full budget even when the
		// parent was cancelled (M-2 / D-3).
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		c.logger.Debug("challenge server stopped")
	}()

	for _, authzURL := range authzURLs {
		authz, err := c.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("failed to get authorization %s: %w", authzURL, err)
		}

		if authz.Status == acme.StatusValid {
			continue
		}

		// Find the HTTP-01 challenge
		var httpChallenge *acme.Challenge
		for _, ch := range authz.Challenges {
			if ch.Type == "http-01" {
				httpChallenge = ch
				break
			}
		}

		if httpChallenge == nil {
			return fmt.Errorf("no HTTP-01 challenge found for %s", authz.Identifier.Value)
		}

		// Compute the key authorization
		keyAuth, err := c.client.HTTP01ChallengeResponse(httpChallenge.Token)
		if err != nil {
			return fmt.Errorf("failed to compute key authorization: %w", err)
		}

		// Store it for the challenge server to serve
		c.challengeMu.Lock()
		c.challengeTokens[httpChallenge.Token] = keyAuth
		c.challengeMu.Unlock()

		c.logger.Info("accepting HTTP-01 challenge",
			"domain", authz.Identifier.Value,
			"token", httpChallenge.Token)

		// Tell the CA we're ready
		if _, err := c.client.Accept(ctx, httpChallenge); err != nil {
			return fmt.Errorf("failed to accept challenge: %w", err)
		}

		// Wait for authorization to be valid
		if _, err := c.client.WaitAuthorization(ctx, authzURL); err != nil {
			return fmt.Errorf("authorization failed for %s: %w", authz.Identifier.Value, err)
		}

		c.logger.Info("authorization validated", "domain", authz.Identifier.Value)

		// Clean up token
		c.challengeMu.Lock()
		delete(c.challengeTokens, httpChallenge.Token)
		c.challengeMu.Unlock()
	}

	return nil
}

// solveAuthorizationsDNS01 solves challenges using the DNS-01 method.
// DNS-01 is required for wildcard certificates (*.example.com) and works
// when the server is not publicly reachable on port 80.
func (c *Connector) solveAuthorizationsDNS01(ctx context.Context, authzURLs []string) error {
	if c.dnsSolver == nil {
		return fmt.Errorf("DNS-01 challenge type configured but no DNS solver available")
	}

	for _, authzURL := range authzURLs {
		authz, err := c.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("failed to get authorization %s: %w", authzURL, err)
		}

		if authz.Status == acme.StatusValid {
			continue
		}

		// Find the DNS-01 challenge
		var dnsChallenge *acme.Challenge
		for _, ch := range authz.Challenges {
			if ch.Type == "dns-01" {
				dnsChallenge = ch
				break
			}
		}

		if dnsChallenge == nil {
			return fmt.Errorf("no DNS-01 challenge found for %s", authz.Identifier.Value)
		}

		// Compute the DNS-01 key authorization (base64url-encoded SHA-256 digest)
		keyAuth, err := c.client.DNS01ChallengeRecord(dnsChallenge.Token)
		if err != nil {
			return fmt.Errorf("failed to compute DNS-01 key authorization: %w", err)
		}

		domain := authz.Identifier.Value

		c.logger.Info("presenting DNS-01 challenge",
			"domain", domain,
			"token", dnsChallenge.Token)

		// Create the DNS TXT record
		if err := c.dnsSolver.Present(ctx, domain, dnsChallenge.Token, keyAuth); err != nil {
			return fmt.Errorf("failed to present DNS record for %s: %w", domain, err)
		}

		// Wait for DNS propagation (ctx-aware so graceful shutdown can interrupt — F-003)
		propagationWait := time.Duration(c.config.DNSPropagationWait) * time.Second
		c.logger.Info("waiting for DNS propagation",
			"domain", domain,
			"wait_seconds", c.config.DNSPropagationWait)
		select {
		case <-ctx.Done():
			_ = c.dnsSolver.CleanUp(ctx, domain, dnsChallenge.Token, keyAuth)
			return ctx.Err()
		case <-time.After(propagationWait):
		}

		// Tell the CA we're ready
		if _, err := c.client.Accept(ctx, dnsChallenge); err != nil {
			// Clean up even on failure
			_ = c.dnsSolver.CleanUp(ctx, domain, dnsChallenge.Token, keyAuth)
			return fmt.Errorf("failed to accept DNS-01 challenge: %w", err)
		}

		// Wait for authorization to be valid
		if _, err := c.client.WaitAuthorization(ctx, authzURL); err != nil {
			_ = c.dnsSolver.CleanUp(ctx, domain, dnsChallenge.Token, keyAuth)
			return fmt.Errorf("DNS-01 authorization failed for %s: %w", domain, err)
		}

		c.logger.Info("DNS-01 authorization validated", "domain", domain)

		// Clean up the DNS record
		if err := c.dnsSolver.CleanUp(ctx, domain, dnsChallenge.Token, keyAuth); err != nil {
			c.logger.Warn("failed to clean up DNS record (non-fatal)",
				"domain", domain,
				"error", err)
		}
	}

	return nil
}

// solveAuthorizationsDNSPersist01 solves challenges using the DNS-PERSIST-01 method.
// DNS-PERSIST-01 uses a standing TXT record at _validation-persist.<domain> that persists
// across renewals. The record contains the CA's issuer domain and the ACME account URI,
// authorizing unlimited future issuances without per-renewal DNS updates.
//
// Flow:
// 1. For each authorization, check if it's already valid (standing record exists)
// 2. If pending, find the dns-persist-01 challenge
// 3. Build the TXT record value: "<issuer-domain>; accounturi=<account-uri>"
// 4. Create the _validation-persist TXT record via the present script (one-time)
// 5. Wait for propagation, then accept the challenge
// 6. No cleanup — the record is permanent by design
//
// See: draft-ietf-acme-dns-persist (IETF), CA/Browser Forum ballot SC-088v3
func (c *Connector) solveAuthorizationsDNSPersist01(ctx context.Context, authzURLs []string) error {
	if c.dnsSolver == nil {
		return fmt.Errorf("dns-persist-01 challenge type configured but no DNS solver available")
	}

	// Get the account URI for the TXT record value
	if err := c.ensureClient(ctx); err != nil {
		return fmt.Errorf("ACME client init for dns-persist-01: %w", err)
	}
	acct, err := c.client.GetReg(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to get ACME account URI for dns-persist-01: %w", err)
	}

	for _, authzURL := range authzURLs {
		authz, err := c.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("failed to get authorization %s: %w", authzURL, err)
		}

		// If already valid (standing record recognized), skip
		if authz.Status == acme.StatusValid {
			c.logger.Info("dns-persist-01 authorization already valid (standing record recognized)",
				"domain", authz.Identifier.Value)
			continue
		}

		// Find the dns-persist-01 challenge
		var persistChallenge *acme.Challenge
		for _, ch := range authz.Challenges {
			if ch.Type == "dns-persist-01" {
				persistChallenge = ch
				break
			}
		}

		// Fallback: if the CA doesn't offer dns-persist-01 yet, try dns-01
		if persistChallenge == nil {
			c.logger.Warn("dns-persist-01 challenge not offered by CA, falling back to dns-01",
				"domain", authz.Identifier.Value)
			return c.solveAuthorizationsDNS01(ctx, authzURLs)
		}

		domain := authz.Identifier.Value

		// Build the persistent TXT record value per draft-ietf-acme-dns-persist:
		// "<issuer-domain>; accounturi=<account-uri>"
		recordValue := fmt.Sprintf("%s; accounturi=%s", c.config.DNSPersistIssuerDomain, acct.URI)

		c.logger.Info("creating persistent DNS validation record",
			"domain", domain,
			"fqdn", "_validation-persist."+domain,
			"issuer_domain", c.config.DNSPersistIssuerDomain,
			"account_uri", acct.URI)

		// Create the standing TXT record via the present script.
		// The script receives CERTCTL_DNS_FQDN="_validation-persist.<domain>"
		// and CERTCTL_DNS_VALUE="<issuer-domain>; accounturi=<account-uri>".
		if err := c.presentPersistRecord(ctx, domain, persistChallenge.Token, recordValue); err != nil {
			return fmt.Errorf("failed to create persistent DNS record for %s: %w", domain, err)
		}

		// Wait for DNS propagation (ctx-aware so graceful shutdown can interrupt — F-003)
		propagationWait := time.Duration(c.config.DNSPropagationWait) * time.Second
		c.logger.Info("waiting for DNS propagation",
			"domain", domain,
			"wait_seconds", c.config.DNSPropagationWait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(propagationWait):
		}

		// Tell the CA we're ready
		if _, err := c.client.Accept(ctx, persistChallenge); err != nil {
			return fmt.Errorf("failed to accept dns-persist-01 challenge: %w", err)
		}

		// Wait for authorization to be valid
		if _, err := c.client.WaitAuthorization(ctx, authzURL); err != nil {
			return fmt.Errorf("dns-persist-01 authorization failed for %s: %w", domain, err)
		}

		c.logger.Info("dns-persist-01 authorization validated (record is now permanent)",
			"domain", domain)

		// No cleanup — the record is permanent by design.
		// Future renewals will skip challenge solving entirely (authz.Status == StatusValid).
	}

	return nil
}

// presentPersistRecord creates a _validation-persist TXT record using the DNS solver.
// Unlike dns-01 which uses _acme-challenge, dns-persist-01 uses _validation-persist.
func (c *Connector) presentPersistRecord(ctx context.Context, domain, token, recordValue string) error {
	if c.dnsSolver == nil {
		return fmt.Errorf("DNS solver not configured")
	}

	// Use PresentPersist if available (ScriptDNSSolver) — targets _validation-persist prefix.
	if solver, ok := c.dnsSolver.(*ScriptDNSSolver); ok {
		return solver.PresentPersist(ctx, domain, token, recordValue)
	}

	// For other DNSSolver implementations, fall back to Present.
	// Custom implementations should read CERTCTL_DNS_FQDN to determine the record name.
	return c.dnsSolver.Present(ctx, domain, token, recordValue)
}

// startChallengeServer starts an HTTP server that responds to ACME HTTP-01 challenges.
// It listens on the configured HTTP port and serves challenge tokens at
// /.well-known/acme-challenge/{token}.
func (c *Connector) startChallengeServer() (*http.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Path[len("/.well-known/acme-challenge/"):]

		c.challengeMu.RLock()
		keyAuth, ok := c.challengeTokens[token]
		c.challengeMu.RUnlock()

		if !ok {
			c.logger.Warn("unknown challenge token", "token", token)
			http.NotFound(w, r)
			return
		}

		c.logger.Debug("serving challenge response", "token", token)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte(keyAuth))
	})

	addr := fmt.Sprintf(":%d", c.config.HTTPPort)
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	go func() {
		c.logger.Info("challenge server started", "address", addr)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			c.logger.Error("challenge server error", "error", err)
		}
	}()

	return srv, nil
}

// buildIdentifiers constructs ACME domain identifiers from common name and SANs.
func buildIdentifiers(commonName string, sans []string) []acme.AuthzID {
	seen := make(map[string]bool)
	var ids []acme.AuthzID

	// Add CN first
	if commonName != "" {
		seen[commonName] = true
		ids = append(ids, acme.AuthzID{Type: "dns", Value: commonName})
	}

	// Add SANs, deduplicating
	for _, san := range sans {
		if san != "" && !seen[san] {
			seen[san] = true
			ids = append(ids, acme.AuthzID{Type: "dns", Value: san})
		}
	}

	return ids
}

// parseCSRPEM decodes a PEM-encoded CSR to DER bytes.
func parseCSRPEM(csrPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("unexpected PEM type: %s (expected CERTIFICATE REQUEST)", block.Type)
	}
	return block.Bytes, nil
}

// parseDERChain converts a DER certificate chain to PEM strings and extracts metadata.
func parseDERChain(derChain [][]byte) (certPEM string, chainPEM string, serial string, notBefore time.Time, notAfter time.Time, err error) {
	if len(derChain) == 0 {
		err = fmt.Errorf("empty certificate chain")
		return
	}

	// First cert is the leaf
	leafCert, parseErr := x509.ParseCertificate(derChain[0])
	if parseErr != nil {
		err = fmt.Errorf("failed to parse leaf certificate: %w", parseErr)
		return
	}

	serial = leafCert.SerialNumber.String()
	notBefore = leafCert.NotBefore
	notAfter = leafCert.NotAfter

	// Encode leaf to PEM
	certPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derChain[0],
	}))

	// Encode remaining chain certs to PEM
	for i := 1; i < len(derChain); i++ {
		chainPEM += string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derChain[i],
		}))
	}

	return
}

// GenerateCRL is not supported by ACME issuers.
func (c *Connector) GenerateCRL(ctx context.Context, revokedCerts []issuer.RevokedCertEntry) ([]byte, error) {
	return nil, fmt.Errorf("ACME issuers do not support CRL generation")
}

// SignOCSPResponse is not supported by ACME issuers.
func (c *Connector) SignOCSPResponse(ctx context.Context, req issuer.OCSPSignRequest) ([]byte, error) {
	return nil, fmt.Errorf("ACME issuers do not support OCSP response signing")
}

// GetCACertPEM is not supported by ACME issuers (the CA chain is returned per-issuance).
func (c *Connector) GetCACertPEM(ctx context.Context) (string, error) {
	return "", fmt.Errorf("ACME issuers do not provide a static CA certificate; chain is returned per-issuance")
}
