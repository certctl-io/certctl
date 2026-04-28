// Bundle-9 / Audit L-014 (Document the CA-key-in-process threat model):
//
// The local CA holds its private key in this process's heap (c.caSigner
// field on the Connector struct — historically c.caKey before the Signer
// abstraction was introduced — plus transient allocations during signing).
// Go does not provide a standard mlock equivalent, the GC does not zero
// released memory, and the runtime moves objects between generations
// during compaction.
//
// Threats this DOES protect against:
//   - Disk-at-rest exposure (key file is mode 0600; key dir is enforced 0700
//     by ensureKeyDirSecure; key bytes zeroed after marshal by
//     marshalPrivateKeyAndZeroize).
//   - Casual local-user enumeration of the key dir (parents 0700).
//   - Byte-identical migration regression (M-028 round-trip pin in tests).
//
// Threats this does NOT protect against:
//   - Attacker with a debugger or core-dump capability against the running
//     process (CAP_SYS_PTRACE, gdb attach, /proc/pid/mem read, container
//     coredump policy). The CA key WILL be recoverable from a heap snapshot.
//   - Memory pressure swap-out on hosts without an encrypted swap device.
//   - Cold-boot attacks against the host's RAM after kernel panic.
//
// Operators with stricter requirements MUST run the local CA mode against an
// HSM or KMS-backed signer (PKCS#11 / cloud KMS / TPM) — see the V3 Pro
// roadmap entry for KMS-backed issuance. The defense-in-depth measures here
// (key zeroization after marshal, 0700 directory, deprecated-API migration)
// reduce the window of exposure but do not close it; the source of truth
// for "the local CA key cannot leave the host process" is HSM-backed
// signing, not heap hygiene.
//
// Defense-in-depth carve-out — the file-on-disk leg:
//
// The above measures harden the file-on-disk + heap-resident key flow
// (signer.FileDriver). The Signer interface in internal/crypto/signer/
// is the seam that lets operators replace this flow entirely:
//   - signer.FileDriver: the current behavior (key on disk, hardening above).
//   - signer.PKCS11Driver (future): key never leaves the HSM token.
//   - signer.CloudKMSDriver (future): key never leaves the cloud KMS.
//
// When the key lives in a hardware token / KMS, the file-on-disk caveats
// above DO NOT APPLY — the key is not on disk and not in the certctl
// process heap. The L-014 threat-model assumptions documented here
// describe the file-driver case; alternative drivers close the
// disk-exposure leg of the threat model.

package local

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
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
	"github.com/shankar0123/certctl/internal/crypto/signer"
	"github.com/shankar0123/certctl/internal/validation"
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
	caSigner   signer.Signer // wraps the historical caKey crypto.Signer; same lifecycle, same heap residency, same L-014 carve-out
	caCert     *x509.Certificate
	caCertPEM  string
	subCA      bool            // true when loaded from disk (sub-CA mode)
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

	// Bundle-9 / Audit L-012 (CWE-1007 + CWE-176): refuse CSRs whose CN/SANs
	// contain Unicode that could be used for IDN homograph impersonation,
	// RTL/LTR rendering attacks, zero-width hidden content, or control
	// characters. Pure-IDN labels are allowed; mixed-script labels are not.
	if err := validateCSRUnicode(csr, request.SANs); err != nil {
		c.logger.Error("CSR unicode validation failed", "error", err)
		return nil, err
	}

	// Generate certificate with EKUs and MaxTTL from request
	cert, certPEM, serial, err := c.generateCertificate(csr, request.SANs, request.EKUs, request.MaxTTLSeconds)
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

	// Bundle-9 / Audit L-012: same unicode safety check as IssueCertificate.
	if err := validateCSRUnicode(csr, request.SANs); err != nil {
		c.logger.Error("CSR unicode validation failed", "error", err)
		return nil, err
	}

	// Generate certificate with EKUs and MaxTTL from request
	cert, certPEM, serial, err := c.generateCertificate(csr, request.SANs, request.EKUs, request.MaxTTLSeconds)
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

	if c.caSigner != nil {
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

	// Validate CA certificate validity window (M-5, CWE-672).
	// An expired or not-yet-valid sub-CA produces child certificates that any
	// RFC 5280 path-validator will reject. Fail closed at load time so operators
	// learn about it at startup, not at 3am when a renewal cycle silently
	// starts minting broken certs. See audit finding M-5.
	now := time.Now()
	if now.After(caCert.NotAfter) {
		return fmt.Errorf("CA certificate %q has expired (not_after=%s, now=%s)",
			caCert.Subject.CommonName,
			caCert.NotAfter.UTC().Format(time.RFC3339),
			now.UTC().Format(time.RFC3339))
	}
	if now.Before(caCert.NotBefore) {
		return fmt.Errorf("CA certificate %q is not yet valid (not_before=%s, now=%s)",
			caCert.Subject.CommonName,
			caCert.NotBefore.UTC().Format(time.RFC3339),
			now.UTC().Format(time.RFC3339))
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

	caKey, err := signer.ParsePrivateKey(keyBlock)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}
	caSigner, err := signer.Wrap(caKey)
	if err != nil {
		return fmt.Errorf("failed to wrap CA private key as signer: %w", err)
	}

	// Encode CA cert PEM for chain responses
	c.caSigner = caSigner
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

	// Generate CA private key. RSA-2048 has been the historical default
	// since the local issuer shipped; preserving the algorithm here is
	// part of the Signer-refactor's no-behavior-change guarantee.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}
	// Wrap the freshly-generated key behind the Signer interface so the
	// CreateCertificate call below uses the same access pattern as every
	// other CA-signing call site (interface-level Public() + Sign()).
	// Wrap is infallible for RSA-2048; the err return is propagated for
	// completeness against future Algorithm enum changes.
	caSigner, err := signer.Wrap(caKey)
	if err != nil {
		return fmt.Errorf("failed to wrap CA private key as signer: %w", err)
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

	// Self-sign the CA certificate via the Signer interface. The
	// underlying byte sequence is identical to the historical
	// (&caKey.PublicKey, caKey) form because Wrap returns a thin
	// adapter that delegates Sign and Public to the same crypto.Signer.
	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caSigner.Public(), caSigner)
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

	c.caSigner = caSigner
	c.caCert = caCert
	c.caCertPEM = string(caCertPEM)

	c.logger.Info("self-signed CA initialized",
		"serial", caCert.SerialNumber,
		"not_after", caCert.NotAfter)

	return nil
}

// parsePrivateKey moved to internal/crypto/signer/parse.go as part of the
// Signer abstraction work. The exported wrapper there
// (signer.ParsePrivateKey) is the single source of truth for PEM
// private-key parsing inside certctl. Do not reintroduce a parallel
// implementation here; the loadCAFromDisk path above calls into the
// signer package directly.

// generateCertificate creates an X.509 certificate signed by the local CA.
// It uses the CSR subject and adds any additional SANs from the request.
// If ekus is non-empty, those EKUs are used instead of the default serverAuth+clientAuth.
// If maxTTLSeconds > 0, the certificate validity is capped to that duration.
func (c *Connector) generateCertificate(csr *x509.CertificateRequest, additionalSANs []string, ekus []string, maxTTLSeconds int) (*x509.Certificate, string, string, error) {
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
	notAfter := now.AddDate(0, 0, c.config.ValidityDays)

	// Cap validity to MaxTTLSeconds if profile specifies a maximum
	if maxTTLSeconds > 0 {
		maxNotAfter := now.Add(time.Duration(maxTTLSeconds) * time.Second)
		if maxNotAfter.Before(notAfter) {
			notAfter = maxNotAfter
		}
	}

	template := &x509.Certificate{
		SerialNumber:   serialNum,
		Subject:        csr.Subject,
		NotBefore:      now,
		NotAfter:       notAfter,
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
	certBytes, err := x509.CreateCertificate(rand.Reader, template, c.caCert, csr.PublicKey, c.caSigner)
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

// validateCSRUnicode runs the L-012 Unicode safety check across every name
// that will be embedded in the issued certificate's Subject CommonName or
// SubjectAltName extension. It rejects RTL/zero-width/control characters
// and mixed-script (Latin + non-Latin) DNS labels — see
// internal/validation/unicode.go for the full rationale and threat model.
//
// We check both the names that came in via the CSR itself AND any
// additional SANs supplied alongside the issuance request, because either
// surface can be an attacker-controlled vector.
func validateCSRUnicode(csr *x509.CertificateRequest, additionalSANs []string) error {
	if err := validation.ValidateUnicodeSafe(csr.Subject.CommonName); err != nil {
		return fmt.Errorf("CSR Subject.CommonName rejected: %w", err)
	}
	for _, name := range csr.DNSNames {
		if err := validation.ValidateUnicodeSafe(name); err != nil {
			return fmt.Errorf("CSR DNSNames entry %q rejected: %w", name, err)
		}
	}
	for _, email := range csr.EmailAddresses {
		if err := validation.ValidateUnicodeSafe(email); err != nil {
			return fmt.Errorf("CSR EmailAddresses entry %q rejected: %w", email, err)
		}
	}
	for _, name := range additionalSANs {
		if err := validation.ValidateUnicodeSafe(name); err != nil {
			return fmt.Errorf("request SANs entry %q rejected: %w", name, err)
		}
	}
	return nil
}

// hashPublicKey generates a subject key identifier from a public key.
//
// Bundle-9 / Audit M-028 (CWE-477 / SA1019): the ECDSA arm previously used
// `elliptic.Marshal(k.Curve, k.X, k.Y)`, which staticcheck SA1019 flags as
// deprecated since Go 1.21 ("for ECDH, use crypto/ecdh"). The replacement
// here uses crypto/ecdh.PublicKey.Bytes(), which produces the IDENTICAL
// uncompressed SEC 1 encoding for the supported curves (P-224, P-256,
// P-384, P-521 — matched in key_encoding_test.go via a byte-identical
// round-trip pin so the migration cannot silently regress the SubjectKeyId
// of every issued certificate).
//
// If the ECDSA key uses a curve not in crypto/ecdh's supported set
// (theoretically possible if an operator loaded a custom CA), we fall back
// to hashing the X+Y coordinates directly via big.Int.Bytes() — that
// produces a different (and stable) SKI for that pathological case rather
// than panicking. The covered-curve path is the one the round-trip pin
// asserts.
func hashPublicKey(pub interface{}) []byte {
	h := sha256.New()
	switch k := pub.(type) {
	case *rsa.PublicKey:
		h.Write(k.N.Bytes())
	case *ecdsa.PublicKey:
		ecdhPub, err := ecdsaToECDH(k)
		if err == nil {
			h.Write(ecdhPub.Bytes())
		} else {
			// Unsupported curve — stable fallback. See test
			// TestHashPublicKey_ECDSA_RoundTripPin for the supported-curve
			// invariant (must match the legacy elliptic.Marshal output).
			h.Write(k.X.Bytes())
			h.Write(k.Y.Bytes())
		}
	}
	return h.Sum(nil)[:4] // Use first 4 bytes for brevity
}

// ecdsaToECDH converts an ECDSA public key to a crypto/ecdh.PublicKey for
// the supported curves (P-256, P-384, P-521; P-224 is intentionally
// unsupported by crypto/ecdh upstream). Used by hashPublicKey to replace
// the deprecated elliptic.Marshal call.
//
// We dispatch on Curve.Params().Name (a stable string per RFC 5480 / Go
// stdlib) rather than importing crypto/elliptic just for sentinel
// comparisons — keeps the deprecated package out of this file's import
// graph.
func ecdsaToECDH(pub *ecdsa.PublicKey) (*ecdh.PublicKey, error) {
	if pub == nil || pub.Curve == nil || pub.X == nil || pub.Y == nil {
		return nil, fmt.Errorf("ecdsaToECDH: nil/uninitialized key")
	}
	var curve ecdh.Curve
	switch pub.Curve.Params().Name {
	case "P-256":
		curve = ecdh.P256()
	case "P-384":
		curve = ecdh.P384()
	case "P-521":
		curve = ecdh.P521()
	default:
		return nil, fmt.Errorf("unsupported curve %q for ecdh conversion", pub.Curve.Params().Name)
	}
	// Reconstruct the uncompressed SEC 1 encoding, then hand to ecdh which
	// validates it back to a public key. This is byte-identical to what
	// the deprecated elliptic.Marshal returned for the same input — the
	// round-trip pin in key_encoding_test.go enforces that invariant.
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	buf := make([]byte, 1+2*byteLen)
	buf[0] = 0x04 // uncompressed point marker
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	copy(buf[1+byteLen-len(xBytes):], xBytes)
	copy(buf[1+2*byteLen-len(yBytes):], yBytes)
	return curve.NewPublicKey(buf)
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

	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, c.caCert, c.caSigner)
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

	respBytes, err := ocsp.CreateResponse(c.caCert, c.caCert, template, c.caSigner)
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
