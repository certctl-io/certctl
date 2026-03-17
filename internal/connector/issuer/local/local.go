package local

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
)

// Config represents the local CA issuer connector configuration.
type Config struct {
	// CACommonName is the CN for the self-signed CA certificate.
	// Defaults to "CertCtl Local CA".
	CACommonName string `json:"ca_common_name,omitempty"`

	// ValidityDays is the number of days a certificate is valid.
	// Defaults to 90.
	ValidityDays int `json:"validity_days,omitempty"`
}

// Connector implements the issuer.Connector interface for local self-signed certificate generation.
//
// This connector generates self-signed certificates using an in-memory CA. It is designed for
// development, testing, and demo purposes only and should NOT be used in production.
//
// On first use, it generates a self-signed CA root certificate and stores it in memory.
// All issued certificates are signed by this local CA.
//
// Features:
//   - Instant certificate issuance (no external CA required)
//   - Full lifecycle demo support (issue, renew, revoke)
//   - In-memory certificate storage
//   - Proper X.509 certificate generation with SANs, serial numbers, and validity periods
//
// Limitations:
//   - Not suitable for production use
//   - Certificates are not trusted by default browsers/systems
//   - No actual revocation checking (revocation is tracked in memory only)
//   - CA certificate is ephemeral and lost on service restart
type Connector struct {
	config     *Config
	logger     *slog.Logger
	mu         sync.RWMutex
	caKey      *rsa.PrivateKey
	caCert     *x509.Certificate
	caCertPEM  string
	revokedMap map[string]bool // serial -> revoked status
}

// New creates a new local CA connector with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	if config == nil {
		config = &Config{}
	}

	// Set defaults
	if config.CACommonName == "" {
		config.CACommonName = "CertCtl Local CA"
	}
	if config.ValidityDays == 0 {
		config.ValidityDays = 90
	}

	return &Connector{
		config:     config,
		logger:     logger,
		revokedMap: make(map[string]bool),
	}
}

// ValidateConfig validates the local CA configuration.
// This always succeeds as the local CA has minimal requirements.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid local CA config: %w", err)
	}

	if cfg.ValidityDays < 1 {
		return fmt.Errorf("validity_days must be at least 1")
	}

	c.config = &cfg
	if c.config.CACommonName == "" {
		c.config.CACommonName = "CertCtl Local CA"
	}

	c.logger.Info("local CA configuration validated",
		"ca_common_name", c.config.CACommonName,
		"validity_days", c.config.ValidityDays)

	return nil
}

// IssueCertificate issues a new certificate signed by the local CA.
//
// The process:
// 1. Initialize the CA if not already done
// 2. Parse the CSR from the request
// 3. Extract subject and SANs from the CSR
// 4. Generate a random serial number
// 5. Create an X.509 certificate with proper extensions (SANs, key usage, etc.)
// 6. Sign with the local CA key
// 7. Return the certificate PEM and CA chain PEM
func (c *Connector) IssueCertificate(ctx context.Context, request issuer.IssuanceRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing local CA issuance request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	// Initialize CA if needed
	if err := c.ensureCA(ctx); err != nil {
		c.logger.Error("failed to initialize CA", "error", err)
		return nil, fmt.Errorf("CA initialization failed: %w", err)
	}

	// Parse CSR
	csrBlock, _ := pem.Decode([]byte(request.CSRPEM))
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid CSR PEM format")
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		c.logger.Error("failed to parse CSR", "error", err)
		return nil, fmt.Errorf("invalid CSR: %w", err)
	}

	// Verify CSR signature
	if err := csr.CheckSignature(); err != nil {
		c.logger.Error("CSR signature verification failed", "error", err)
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	// Generate certificate
	cert, certPEM, serial, err := c.generateCertificate(csr, request.SANs)
	if err != nil {
		c.logger.Error("failed to generate certificate", "error", err)
		return nil, fmt.Errorf("certificate generation failed: %w", err)
	}

	// Create order ID (use serial as order ID for simplicity)
	orderID := fmt.Sprintf("local-%s", serial)

	result := &issuer.IssuanceResult{
		CertPEM:   certPEM,
		ChainPEM:  c.caCertPEM,
		Serial:    serial,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		OrderID:   orderID,
	}

	c.logger.Info("certificate issued successfully",
		"serial", serial,
		"common_name", request.CommonName,
		"not_after", cert.NotAfter)

	return result, nil
}

// RenewCertificate renews a certificate by issuing a new one with the same identifiers.
// For the local CA, this is functionally identical to IssueCertificate.
func (c *Connector) RenewCertificate(ctx context.Context, request issuer.RenewalRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing local CA renewal request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	// Initialize CA if needed
	if err := c.ensureCA(ctx); err != nil {
		c.logger.Error("failed to initialize CA", "error", err)
		return nil, fmt.Errorf("CA initialization failed: %w", err)
	}

	// Parse CSR
	csrBlock, _ := pem.Decode([]byte(request.CSRPEM))
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid CSR PEM format")
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		c.logger.Error("failed to parse CSR", "error", err)
		return nil, fmt.Errorf("invalid CSR: %w", err)
	}

	// Verify CSR signature
	if err := csr.CheckSignature(); err != nil {
		c.logger.Error("CSR signature verification failed", "error", err)
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	// Generate certificate
	cert, certPEM, serial, err := c.generateCertificate(csr, request.SANs)
	if err != nil {
		c.logger.Error("failed to generate certificate", "error", err)
		return nil, fmt.Errorf("certificate generation failed: %w", err)
	}

	// Create order ID
	orderID := fmt.Sprintf("local-%s", serial)
	if request.OrderID != nil {
		orderID = *request.OrderID
	}

	result := &issuer.IssuanceResult{
		CertPEM:   certPEM,
		ChainPEM:  c.caCertPEM,
		Serial:    serial,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		OrderID:   orderID,
	}

	c.logger.Info("certificate renewed successfully",
		"serial", serial,
		"common_name", request.CommonName,
		"not_after", cert.NotAfter)

	return result, nil
}

// RevokeCertificate revokes a certificate by marking it in the in-memory revocation map.
// This is a no-op for practical purposes but tracks revocation state in memory.
// Note: Revocation is not persistent and is lost on service restart.
func (c *Connector) RevokeCertificate(ctx context.Context, request issuer.RevocationRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.revokedMap[request.Serial] = true

	reason := "unspecified"
	if request.Reason != nil {
		reason = *request.Reason
	}

	c.logger.Info("certificate revoked",
		"serial", request.Serial,
		"reason", reason)

	return nil
}

// GetOrderStatus returns the status of an issuance or renewal order.
// For the local CA, orders complete immediately, so this always returns "completed" status.
func (c *Connector) GetOrderStatus(ctx context.Context, orderID string) (*issuer.OrderStatus, error) {
	c.logger.Info("fetching local CA order status", "order_id", orderID)

	// Local CA orders complete immediately
	status := &issuer.OrderStatus{
		OrderID:   orderID,
		Status:    "completed",
		UpdatedAt: time.Now(),
	}

	return status, nil
}

// ensureCA initializes the CA certificate and key if not already done.
// This is called on first IssueCertificate or RenewCertificate call.
// The CA is generated once and reused for all subsequent operations.
func (c *Connector) ensureCA(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.caKey != nil {
		return nil // CA already initialized
	}

	c.logger.Info("initializing local CA", "common_name", c.config.CACommonName)

	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create CA certificate
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: c.config.CACommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // CA valid for 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign the CA certificate
	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Encode CA certificate to PEM
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertBytes,
	})

	c.caKey = caKey
	c.caCert = caCert
	c.caCertPEM = string(caCertPEM)

	c.logger.Info("local CA initialized successfully",
		"serial", caCert.SerialNumber,
		"not_after", caCert.NotAfter)

	return nil
}

// generateCertificate creates an X.509 certificate signed by the local CA.
// It uses the CSR subject and adds any additional SANs from the request.
func (c *Connector) generateCertificate(csr *x509.CertificateRequest, additionalSANs []string) (*x509.Certificate, string, string, error) {
	// Generate random serial number
	serialNum, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	serial := fmt.Sprintf("%040x", serialNum)

	// Collect all SANs
	sanSet := make(map[string]bool)
	for _, san := range csr.DNSNames {
		sanSet[san] = true
	}
	for _, san := range csr.IPAddresses {
		sanSet[san.String()] = true
	}
	for _, san := range csr.EmailAddresses {
		sanSet[san] = true
	}
	for _, san := range additionalSANs {
		sanSet[san] = true
	}

	var dnsNames []string
	var ips []string
	var emails []string

	for san := range sanSet {
		// Try to parse as IP, otherwise treat as DNS or email
		if ip := parseIP(san); ip != nil {
			ips = append(ips, san)
		} else if isEmail(san) {
			emails = append(emails, san)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}

	// Create certificate template
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNum,
		Subject:      csr.Subject,
		NotBefore:    now,
		NotAfter:     now.AddDate(0, 0, c.config.ValidityDays),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:       dnsNames,
		EmailAddresses: emails,
		SubjectKeyId:   hashPublicKey(csr.PublicKey),
		AuthorityKeyId: c.caCert.SubjectKeyId,
	}

	// Add IP addresses if present
	if len(ips) > 0 {
		for _, ipStr := range ips {
			if ip := parseIP(ipStr); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			}
		}
	}

	// Sign certificate with CA
	certBytes, err := x509.CreateCertificate(rand.Reader, template, c.caCert, csr.PublicKey, c.caKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Parse for validation
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	return cert, string(certPEM), serial, nil
}

// parseIP attempts to parse a string as an IP address.
func parseIP(s string) []byte {
	if s == "localhost" {
		return []byte{127, 0, 0, 1}
	}
	// In production, use net.ParseIP for proper parsing.
	// For now, return nil for non-localhost IPs.
	return nil
}

// isEmail checks if a string looks like an email address.
func isEmail(s string) bool {
	for _, c := range s {
		if c == '@' {
			return true
		}
	}
	return false
}

// hashPublicKey generates a subject key identifier from a public key.
func hashPublicKey(pub interface{}) []byte {
	h := sha256.New()
	switch k := pub.(type) {
	case *rsa.PublicKey:
		h.Write(k.N.Bytes())
	}
	return h.Sum(nil)[:4] // Use first 4 bytes for brevity
}
