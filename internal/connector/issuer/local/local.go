package local

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/shankar0123/certctl/internal/connector/issuer"
)

// Config represents the local CA issuer connector configuration.
type Config struct {
	// CACommonName is the CN for the self-signed CA certificate.
	// Defaults to "CertCtl Local CA". Ignored in sub-CA mode.
	CACommonName string `json:"ca_common_name,omitempty"`

	// ValidityDays is the number of days a certificate is valid.
	// Defaults to 90.
	ValidityDays int `json:"validity_days,omitempty"`

	// CACertPath is the path to a PEM-encoded CA certificate file.
	// When set along with CAKeyPath, the connector operates in sub-CA mode:
	// it loads the CA cert+key from disk instead of generating a self-signed root.
	// The loaded CA cert should be signed by an upstream CA (e.g., ADCS).
	// All issued certificates will chain to the upstream root.
	CACertPath string `json:"ca_cert_path,omitempty"`

	// CAKeyPath is the path to a PEM-encoded CA private key file (RSA or ECDSA).
	// Required when CACertPath is set.
	CAKeyPath string `json:"ca_key_path,omitempty"`
}

// Connector implements the issuer.Connector interface for local certificate generation.
//
// It supports two modes:
//
// Self-signed mode (default):
//   - Generates an ephemeral self-signed CA root on first use
//   - Designed for development, testing, and demo purposes
//   - CA certificate is lost on service restart
//
// Sub-CA mode (when CACertPath + CAKeyPath are set):
//   - Loads a pre-signed CA cert+key from disk
//   - The CA cert should be signed by an upstream CA (e.g., ADCS, enterprise root)
//   - All issued certificates chain to the upstream root
//   - Suitable for production when the upstream CA is trusted
//
// Features:
//   - Instant certificate issuance (no external CA required)
//   - Full lifecycle support (issue, renew, revoke)
//   - Proper X.509 certificate generation with SANs, serial numbers, and validity periods
//
// Limitations:
//   - Revocation is tracked in memory only (not persistent)
//   - In self-signed mode, CA is ephemeral
type Connector struct {
	config     *Config
	logger     *slog.Logger
	mu         sync.RWMutex
	caKey      crypto.Signer // RSA or ECDSA private key
	caCert     *x509.Certificate
	caCertPEM  string
	subCA      bool                // true when loaded from disk (sub-CA mode)
	revokedMap map[string]bool     // serial -> revoked status
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
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid local CA config: %w", err)
	}

	if cfg.ValidityDays < 1 {
		return fmt.Errorf("validity_days must be at least 1")
	}

	// Sub-CA mode: both paths must be set or neither
	if (cfg.CACertPath != "") != (cfg.CAKeyPath != "") {
		return fmt.Errorf("ca_cert_path and ca_key_path must both be set for sub-CA mode")
	}

	// Validate paths exist if set
	if cfg.CACertPath != "" {
		if _, err := os.Stat(cfg.CACertPath); err != nil {
			return fmt.Errorf("ca_cert_path not accessible: %w", err)
		}
		if _, err := os.Stat(cfg.CAKeyPath); err != nil {
			return fmt.Errorf("ca_key_path not accessible: %w", err)
		}
	}

	c.config = &cfg
	if c.config.CACommonName == "" {
		c.config.CACommonName = "CertCtl Local CA"
	}

	mode := "self-signed"
	if cfg.CACertPath != "" {
		mode = "sub-CA"
	}
	c.logger.Info("local CA configuration validated",
		"mode", mode,
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

	// Generate certificate with EKUs from request
	cert, certPEM, serial, err := c.generateCertificate(csr, request.SANs, request.EKUs)
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

	// Generate certificate with EKUs from request
	cert, certPEM, serial, err := c.generateCertificate(csr, request.SANs, request.EKUs)
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
// In sub-CA mode (CACertPath + CAKeyPath set), loads from disk.
// Otherwise, generates an ephemeral self-signed CA.
func (c *Connector) ensureCA(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.caKey != nil {
		return nil // CA already initialized
	}

	if c.config.CACertPath != "" && c.config.CAKeyPath != "" {
		return c.loadCAFromDisk()
	}

	return c.generateSelfSignedCA()
}

// loadCAFromDisk loads a CA certificate and private key from PEM files on disk.
// This enables sub-CA mode where certctl operates as a subordinate CA under an
// enterprise root (e.g., ADCS). The loaded cert should have IsCA=true and
// KeyUsageCertSign set by the upstream CA.
func (c *Connector) loadCAFromDisk() error {
	c.logger.Info("loading CA from disk (sub-CA mode)",
		"cert_path", c.config.CACertPath,
		"key_path", c.config.CAKeyPath)

	// Load CA certificate
	certPEM, err := os.ReadFile(c.config.CACertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid CA certificate PEM (expected CERTIFICATE block)")
	}

	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Validate CA certificate properties
	if !caCert.IsCA {
		return fmt.Errorf("loaded certificate is not a CA (BasicConstraints.IsCA=false)")
	}
	if caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("loaded CA certificate does not have KeyUsageCertSign")
	}

	// Load CA private key (supports RSA and ECDSA)
	keyPEM, err := os.ReadFile(c.config.CAKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read CA private key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("invalid CA private key PEM")
	}

	caKey, err := parsePrivateKey(keyBlock)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Encode CA cert PEM for chain responses
	c.caKey = caKey
	c.caCert = caCert
	c.caCertPEM = string(certPEM)
	c.subCA = true

	c.logger.Info("sub-CA initialized from disk",
		"subject", caCert.Subject.CommonName,
		"issuer", caCert.Issuer.CommonName,
		"serial", caCert.SerialNumber,
		"not_after", caCert.NotAfter,
		"is_self_signed", caCert.Issuer.CommonName == caCert.Subject.CommonName)

	return nil
}

// generateSelfSignedCA creates an ephemeral self-signed CA for development/demo.
func (c *Connector) generateSelfSignedCA() error {
	c.logger.Info("generating self-signed CA (ephemeral mode)", "common_name", c.config.CACommonName)

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

	c.logger.Info("self-signed CA initialized",
		"serial", caCert.SerialNumber,
		"not_after", caCert.NotAfter)

	return nil
}

// parsePrivateKey parses a PEM block into an RSA or ECDSA private key.
func parsePrivateKey(block *pem.Block) (crypto.Signer, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		// PKCS#8 — can contain RSA or ECDSA
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 key: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not a signing key")
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %s (expected RSA PRIVATE KEY, EC PRIVATE KEY, or PRIVATE KEY)", block.Type)
	}
}

// generateCertificate creates an X.509 certificate signed by the local CA.
// It uses the CSR subject and adds any additional SANs from the request.
// If ekus is non-empty, those EKUs are used instead of the default serverAuth+clientAuth.
func (c *Connector) generateCertificate(csr *x509.CertificateRequest, additionalSANs []string, ekus []string) (*x509.Certificate, string, string, error) {
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

	// Resolve EKUs: use provided list or fall back to default TLS EKUs
	resolvedEKUs, keyUsage := resolveEKUsAndKeyUsage(ekus)

	// Create certificate template
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:   serialNum,
		Subject:        csr.Subject,
		NotBefore:      now,
		NotAfter:       now.AddDate(0, 0, c.config.ValidityDays),
		KeyUsage:       keyUsage,
		ExtKeyUsage:    resolvedEKUs,
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
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	// Prefer 4-byte representation for IPv4
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
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

// ekuNameToX509 maps EKU string names (from domain.ValidEKUs) to x509.ExtKeyUsage constants.
var ekuNameToX509 = map[string]x509.ExtKeyUsage{
	"serverAuth":      x509.ExtKeyUsageServerAuth,
	"clientAuth":      x509.ExtKeyUsageClientAuth,
	"codeSigning":     x509.ExtKeyUsageCodeSigning,
	"emailProtection": x509.ExtKeyUsageEmailProtection,
	"timeStamping":    x509.ExtKeyUsageTimeStamping,
}

// resolveEKUsAndKeyUsage maps EKU string names to x509.ExtKeyUsage constants and computes
// appropriate KeyUsage flags. If ekus is empty/nil, falls back to default TLS EKUs.
//
// Key usage selection:
//   - TLS (serverAuth/clientAuth): DigitalSignature | KeyEncipherment
//   - S/MIME (emailProtection): DigitalSignature | ContentCommitment (for non-repudiation)
//   - Mixed: union of both
func resolveEKUsAndKeyUsage(ekus []string) ([]x509.ExtKeyUsage, x509.KeyUsage) {
	if len(ekus) == 0 {
		// Default: TLS server + client
		return []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}

	var resolved []x509.ExtKeyUsage
	hasEmail := false
	hasTLS := false

	for _, name := range ekus {
		if eku, ok := ekuNameToX509[name]; ok {
			resolved = append(resolved, eku)
			if name == "emailProtection" {
				hasEmail = true
			}
			if name == "serverAuth" || name == "clientAuth" {
				hasTLS = true
			}
		}
	}

	// If no valid EKUs were resolved, fall back to default
	if len(resolved) == 0 {
		return []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}

	// Compute KeyUsage based on EKU mix
	keyUsage := x509.KeyUsageDigitalSignature
	if hasTLS {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	if hasEmail {
		keyUsage |= x509.KeyUsageContentCommitment // non-repudiation for S/MIME
	}

	return resolved, keyUsage
}

// hashPublicKey generates a subject key identifier from a public key.
func hashPublicKey(pub interface{}) []byte {
	h := sha256.New()
	switch k := pub.(type) {
	case *rsa.PublicKey:
		h.Write(k.N.Bytes())
	case *ecdsa.PublicKey:
		h.Write(elliptic.Marshal(k.Curve, k.X, k.Y))
	}
	return h.Sum(nil)[:4] // Use first 4 bytes for brevity
}

// GenerateCRL generates a DER-encoded X.509 CRL signed by this local CA.
func (c *Connector) GenerateCRL(ctx context.Context, revokedCerts []issuer.RevokedCertEntry) ([]byte, error) {
	if err := c.ensureCA(ctx); err != nil {
		return nil, fmt.Errorf("CA initialization failed: %w", err)
	}

	now := time.Now()
	revokedEntries := make([]x509.RevocationListEntry, 0, len(revokedCerts))
	for _, cert := range revokedCerts {
		revokedEntries = append(revokedEntries, x509.RevocationListEntry{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: cert.RevokedAt,
			ReasonCode:     cert.ReasonCode,
		})
	}

	template := &x509.RevocationList{
		RevokedCertificateEntries: revokedEntries,
		Number:                    big.NewInt(time.Now().Unix()),
		ThisUpdate:                now,
		NextUpdate:                now.Add(24 * time.Hour),
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, c.caCert, c.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL: %w", err)
	}

	c.logger.Info("CRL generated",
		"entries", len(revokedCerts),
		"next_update", template.NextUpdate)

	return crlBytes, nil
}

// SignOCSPResponse signs an OCSP response for the given certificate.
func (c *Connector) SignOCSPResponse(ctx context.Context, req issuer.OCSPSignRequest) ([]byte, error) {
	if err := c.ensureCA(ctx); err != nil {
		return nil, fmt.Errorf("CA initialization failed: %w", err)
	}

	// Import OCSP after we confirm golang.org/x/crypto is available
	// This will be added to imports below
	template := ocsp.Response{
		SerialNumber: req.CertSerial,
		ThisUpdate:   req.ThisUpdate,
		NextUpdate:   req.NextUpdate,
		Certificate:  c.caCert,
	}

	switch req.CertStatus {
	case 0: // good
		template.Status = ocsp.Good
	case 1: // revoked
		template.Status = ocsp.Revoked
		template.RevokedAt = req.RevokedAt
		template.RevocationReason = req.RevocationReason
	default: // unknown
		template.Status = ocsp.Unknown
	}

	respBytes, err := ocsp.CreateResponse(c.caCert, c.caCert, template, c.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP response: %w", err)
	}

	c.logger.Info("OCSP response signed",
		"serial", req.CertSerial,
		"status", req.CertStatus)

	return respBytes, nil
}

// GetCACertPEM returns the PEM-encoded CA certificate for this issuer.
// Used by the EST /cacerts endpoint to distribute the CA trust chain.
func (c *Connector) GetCACertPEM(ctx context.Context) (string, error) {
	if err := c.ensureCA(ctx); err != nil {
		return "", fmt.Errorf("CA initialization failed: %w", err)
	}
	return c.caCertPEM, nil
}

// GetRenewalInfo returns nil, nil as the Local CA does not support ACME Renewal Information (ARI).
func (c *Connector) GetRenewalInfo(ctx context.Context, certPEM string) (*issuer.RenewalInfoResult, error) {
	return nil, nil
}
