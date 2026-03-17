package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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
}

// New creates a new ACME connector with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	if config != nil && config.HTTPPort == 0 {
		config.HTTPPort = 80
	}
	return &Connector{
		config:          config,
		logger:          logger,
		challengeTokens: make(map[string]string),
	}
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

	c.logger.Info("validating ACME configuration", "directory_url", cfg.DirectoryURL)

	// Verify that the directory URL is reachable
	httpClient := &http.Client{Timeout: 10 * time.Second}
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

	c.config = &cfg
	c.logger.Info("ACME configuration validated")
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
	}

	// Register or retrieve the ACME account
	acct := &acme.Account{
		Contact: []string{"mailto:" + c.config.Email},
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

	// Step 1: Create order
	order, err := c.client.AuthorizeOrder(ctx, identifiers)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME order: %w", err)
	}
	c.logger.Info("ACME order created", "order_url", order.URI, "status", order.Status)

	// Step 2: Solve authorizations (HTTP-01 challenges)
	if order.Status == acme.StatusPending {
		if err := c.solveAuthorizations(ctx, order.AuthzURLs); err != nil {
			return nil, fmt.Errorf("failed to solve challenges: %w", err)
		}

		// Wait for the order to be ready
		order, err = c.client.WaitOrder(ctx, order.URI)
		if err != nil {
			return nil, fmt.Errorf("order failed after challenge: %w", err)
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

	derChain, _, err := c.client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize order: %w", err)
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
		OrderID:   order.URI,
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

// solveAuthorizations processes all authorization URLs and solves their HTTP-01 challenges.
func (c *Connector) solveAuthorizations(ctx context.Context, authzURLs []string) error {
	// Start the challenge server
	srv, err := c.startChallengeServer()
	if err != nil {
		return fmt.Errorf("failed to start challenge server: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
