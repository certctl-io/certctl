// Package openssl implements the issuer.Connector interface for custom CA integrations.
//
// This connector delegates certificate signing to user-provided scripts/commands.
// It allows operators to use their existing CA tooling (OpenSSL, cfssl, custom scripts, etc.)
// as the signing backend for certctl.
//
// Configuration:
//
//	SignScript: path to a script/command that signs CSRs.
//	  Called as: <sign_script> <csr_file> <cert_output_file>
//	  The script receives the CSR PEM as a temp file, and must write the signed cert PEM to the output file.
//	  Exit 0 = success, non-zero = failure (stderr captured as error message).
//
//	RevokeScript: path to a script/command that revokes certificates (optional).
//	  Called as: <revoke_script> <serial> <reason>
//	  Optional — if empty, revocation returns "not supported".
//
//	CRLScript: path to a script/command that generates a CRL (optional).
//	  Called as: <crl_script> <revoked_serials_json_file> <crl_output_file>
//	  Optional — if empty, CRL generation returns nil.
//
//	TimeoutSeconds: max time to wait for script execution (default 30).
package openssl

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/validation"
)

// Config represents the OpenSSL/Custom CA issuer connector configuration.
type Config struct {
	// SignScript is the path to a script/command that signs CSRs.
	// Called as: <sign_script> <csr_file> <cert_output_file>
	// The script receives the CSR PEM as a temp file, and must write the signed cert PEM to the output file.
	// Exit 0 = success, non-zero = failure (stderr captured as error message).
	SignScript string `json:"sign_script"`

	// RevokeScript is the path to a script/command that revokes certificates.
	// Called as: <revoke_script> <serial> <reason>
	// Optional — if empty, revocation returns "not supported".
	RevokeScript string `json:"revoke_script,omitempty"`

	// CRLScript is the path to a script/command that generates a CRL.
	// Called as: <crl_script> <revoked_serials_json_file> <crl_output_file>
	// Optional — if empty, CRL generation returns nil.
	CRLScript string `json:"crl_script,omitempty"`

	// TimeoutSeconds is the max time to wait for script execution.
	// Defaults to 30.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// Connector implements the issuer.Connector interface for custom CA signing via scripts.
type Connector struct {
	config  *Config
	logger  *slog.Logger
	timeout time.Duration
}

// New creates a new OpenSSL/Custom CA connector with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	if config == nil {
		config = &Config{}
	}

	timeout := time.Duration(config.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &Connector{
		config:  config,
		logger:  logger,
		timeout: timeout,
	}
}

// ValidateConfig validates the OpenSSL/Custom CA configuration.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid OpenSSL/Custom CA config: %w", err)
	}

	// SignScript is required
	if cfg.SignScript == "" {
		return fmt.Errorf("sign_script is required")
	}

	// Verify sign_script exists and is a regular file
	if info, err := os.Stat(cfg.SignScript); err != nil {
		return fmt.Errorf("sign_script not accessible: %w", err)
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("sign_script must be a regular file, got %s", info.Mode())
	}

	// Verify revoke_script exists and is a regular file if specified
	if cfg.RevokeScript != "" {
		if info, err := os.Stat(cfg.RevokeScript); err != nil {
			return fmt.Errorf("revoke_script not accessible: %w", err)
		} else if !info.Mode().IsRegular() {
			return fmt.Errorf("revoke_script must be a regular file, got %s", info.Mode())
		}
	}

	// Verify crl_script exists and is a regular file if specified
	if cfg.CRLScript != "" {
		if info, err := os.Stat(cfg.CRLScript); err != nil {
			return fmt.Errorf("crl_script not accessible: %w", err)
		} else if !info.Mode().IsRegular() {
			return fmt.Errorf("crl_script must be a regular file, got %s", info.Mode())
		}
	}

	// Update connector config
	c.config = &cfg
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	c.timeout = timeout

	c.logger.Info("OpenSSL/Custom CA configuration validated",
		"sign_script", cfg.SignScript,
		"has_revoke_script", cfg.RevokeScript != "",
		"has_crl_script", cfg.CRLScript != "",
		"timeout_seconds", c.timeout.Seconds())

	return nil
}

// IssueCertificate issues a new certificate by calling the sign script.
func (c *Connector) IssueCertificate(ctx context.Context, request issuer.IssuanceRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing custom CA issuance request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	// Write CSR to a temporary file
	csrFile, err := c.writeTempFile([]byte(request.CSRPEM), "csr-")
	if err != nil {
		c.logger.Error("failed to write CSR temp file", "error", err)
		return nil, fmt.Errorf("failed to write CSR temp file: %w", err)
	}
	defer os.Remove(csrFile)

	// Create temp file for cert output
	certFile := filepath.Join(filepath.Dir(csrFile), "cert-"+filepath.Base(csrFile))
	defer os.Remove(certFile)

	// Call sign script
	if err := c.callSignScript(ctx, csrFile, certFile); err != nil {
		c.logger.Error("sign script failed", "error", err)
		return nil, fmt.Errorf("sign script failed: %w", err)
	}

	// Read the signed certificate
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		c.logger.Error("failed to read signed certificate", "error", err)
		return nil, fmt.Errorf("failed to read signed certificate: %w", err)
	}

	// Parse the certificate to extract metadata
	cert, serial, err := c.parseCertificate(certPEM)
	if err != nil {
		c.logger.Error("failed to parse signed certificate", "error", err)
		return nil, fmt.Errorf("failed to parse signed certificate: %w", err)
	}

	orderID := fmt.Sprintf("openssl-%s", serial)

	result := &issuer.IssuanceResult{
		CertPEM:   string(certPEM),
		ChainPEM:  "", // Custom CA connectors typically don't provide chain; operators must configure separately
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
// For custom CA connectors, this is functionally identical to IssueCertificate.
func (c *Connector) RenewCertificate(ctx context.Context, request issuer.RenewalRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing custom CA renewal request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	// Write CSR to a temporary file
	csrFile, err := c.writeTempFile([]byte(request.CSRPEM), "csr-")
	if err != nil {
		c.logger.Error("failed to write CSR temp file", "error", err)
		return nil, fmt.Errorf("failed to write CSR temp file: %w", err)
	}
	defer os.Remove(csrFile)

	// Create temp file for cert output
	certFile := filepath.Join(filepath.Dir(csrFile), "cert-"+filepath.Base(csrFile))
	defer os.Remove(certFile)

	// Call sign script
	if err := c.callSignScript(ctx, csrFile, certFile); err != nil {
		c.logger.Error("sign script failed", "error", err)
		return nil, fmt.Errorf("sign script failed: %w", err)
	}

	// Read the signed certificate
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		c.logger.Error("failed to read signed certificate", "error", err)
		return nil, fmt.Errorf("failed to read signed certificate: %w", err)
	}

	// Parse the certificate to extract metadata
	cert, serial, err := c.parseCertificate(certPEM)
	if err != nil {
		c.logger.Error("failed to parse signed certificate", "error", err)
		return nil, fmt.Errorf("failed to parse signed certificate: %w", err)
	}

	// Preserve order ID if provided
	orderID := fmt.Sprintf("openssl-%s", serial)
	if request.OrderID != nil {
		orderID = *request.OrderID
	}

	result := &issuer.IssuanceResult{
		CertPEM:   string(certPEM),
		ChainPEM:  "",
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

// hexSerialRegex validates that a serial number contains only hexadecimal characters.
// Certificate serial numbers are integers represented in hex (RFC 5280).
var hexSerialRegex = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// validateSerial validates a certificate serial number for safe use in shell commands.
// Serial numbers must be non-empty, hex-only strings with no shell metacharacters.
func validateSerial(serial string) error {
	if serial == "" {
		return fmt.Errorf("serial number cannot be empty")
	}
	if !hexSerialRegex.MatchString(serial) {
		return fmt.Errorf("serial number %q contains non-hex characters (expected ^[0-9a-fA-F]+$)", serial)
	}
	if err := validation.ValidateShellCommand(serial); err != nil {
		return fmt.Errorf("serial number failed shell safety validation: %w", err)
	}
	return nil
}

// validateRevocationReason validates a revocation reason against RFC 5280 reason codes.
func validateRevocationReason(reason string) error {
	if !domain.IsValidRevocationReason(reason) {
		return fmt.Errorf("invalid revocation reason %q (must be a valid RFC 5280 reason code)", reason)
	}
	if err := validation.ValidateShellCommand(reason); err != nil {
		return fmt.Errorf("revocation reason failed shell safety validation: %w", err)
	}
	return nil
}

// RevokeCertificate revokes a certificate by calling the revoke script if configured.
func (c *Connector) RevokeCertificate(ctx context.Context, request issuer.RevocationRequest) error {
	if c.config.RevokeScript == "" {
		c.logger.Warn("revocation not supported (revoke_script not configured)", "serial", request.Serial)
		return nil // No-op if revoke script not configured
	}

	reason := "unspecified"
	if request.Reason != nil {
		reason = *request.Reason
	}

	// Validate serial number (hex-only) and reason code (RFC 5280) before shell execution
	if err := validateSerial(request.Serial); err != nil {
		return fmt.Errorf("revocation input validation failed: %w", err)
	}
	if err := validateRevocationReason(reason); err != nil {
		return fmt.Errorf("revocation input validation failed: %w", err)
	}

	c.logger.Info("revoking certificate via revoke script",
		"serial", request.Serial,
		"reason", reason)

	// Call revoke script: <revoke_script> <serial> <reason>
	cmd := exec.CommandContext(ctx, c.config.RevokeScript, request.Serial, reason)
	cmd.Env = os.Environ() // Inherit environment

	if err := cmd.Run(); err != nil {
		// Log but don't fail — revocation is best-effort
		c.logger.Warn("revoke script completed with error",
			"serial", request.Serial,
			"error", err)
		// Return nil to indicate best-effort success
	}

	c.logger.Info("certificate revoked",
		"serial", request.Serial,
		"reason", reason)

	return nil
}

// GetOrderStatus returns the status of an issuance or renewal order.
// For custom CA connectors, orders complete immediately, so this always returns "completed" status.
func (c *Connector) GetOrderStatus(ctx context.Context, orderID string) (*issuer.OrderStatus, error) {
	c.logger.Info("fetching custom CA order status", "order_id", orderID)

	// Custom CA orders complete immediately
	status := &issuer.OrderStatus{
		OrderID:   orderID,
		Status:    "completed",
		UpdatedAt: time.Now(),
	}

	return status, nil
}

// GenerateCRL generates a DER-encoded X.509 CRL by calling the CRL script if configured.
// Returns nil if the CRL script is not configured.
func (c *Connector) GenerateCRL(ctx context.Context, revokedCerts []issuer.RevokedCertEntry) ([]byte, error) {
	if c.config.CRLScript == "" {
		c.logger.Debug("CRL generation not supported (crl_script not configured)")
		return nil, nil
	}

	c.logger.Info("generating CRL via crl script", "revoked_count", len(revokedCerts))

	// Write revoked serials to a temporary JSON file
	serialsJSON, err := c.marshalRevokedSerials(revokedCerts)
	if err != nil {
		c.logger.Error("failed to marshal revoked serials", "error", err)
		return nil, fmt.Errorf("failed to marshal revoked serials: %w", err)
	}

	serialsFile, err := c.writeTempFile(serialsJSON, "serials-")
	if err != nil {
		c.logger.Error("failed to write revoked serials temp file", "error", err)
		return nil, fmt.Errorf("failed to write revoked serials temp file: %w", err)
	}
	defer os.Remove(serialsFile)

	// Create temp file for CRL output
	crlFile := filepath.Join(filepath.Dir(serialsFile), "crl-"+filepath.Base(serialsFile))
	defer os.Remove(crlFile)

	// Call CRL script: <crl_script> <revoked_serials_json_file> <crl_output_file>
	cmd := exec.CommandContext(ctx, c.config.CRLScript, serialsFile, crlFile)
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		c.logger.Error("crl script failed", "error", err)
		return nil, fmt.Errorf("crl script failed: %w", err)
	}

	// Read the generated CRL
	crlDER, err := os.ReadFile(crlFile)
	if err != nil {
		c.logger.Error("failed to read generated CRL", "error", err)
		return nil, fmt.Errorf("failed to read generated CRL: %w", err)
	}

	c.logger.Info("CRL generated successfully", "crl_size", len(crlDER))

	return crlDER, nil
}

// SignOCSPResponse signs an OCSP response.
// Custom CA connectors don't support OCSP, so this returns nil.
func (c *Connector) SignOCSPResponse(ctx context.Context, req issuer.OCSPSignRequest) ([]byte, error) {
	c.logger.Debug("OCSP signing not supported by custom CA connector")
	return nil, nil
}

// GetCACertPEM is not supported by the custom CA connector (no CA cert access).
func (c *Connector) GetCACertPEM(ctx context.Context) (string, error) {
	return "", fmt.Errorf("custom CA connector does not provide CA certificate access")
}

// GetRenewalInfo returns nil, nil as the custom CA connector does not support ACME Renewal Information (ARI).
func (c *Connector) GetRenewalInfo(ctx context.Context, certPEM string) (*issuer.RenewalInfoResult, error) {
	return nil, nil
}

// --- Helper Methods ---

// writeTempFile writes data to a temporary file and returns its path.
func (c *Connector) writeTempFile(data []byte, prefix string) (string, error) {
	f, err := os.CreateTemp("", prefix+"*.pem")
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		os.Remove(f.Name())
		return "", err
	}

	return f.Name(), nil
}

// callSignScript calls the sign script with CSR and cert output file paths.
// Returns the script's error message if execution fails.
func (c *Connector) callSignScript(ctx context.Context, csrFile, certFile string) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// Call sign script: <sign_script> <csr_file> <cert_output_file>
	cmd := exec.CommandContext(ctx, c.config.SignScript, csrFile, certFile)
	cmd.Env = os.Environ() // Inherit environment

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("script exited with error: %w (output: %s)", err, string(output))
	}

	return nil
}

// parseCertificate parses a PEM-encoded certificate and extracts serial and X.509 cert.
func (c *Connector) parseCertificate(certPEM []byte) (*x509.Certificate, string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, "", fmt.Errorf("invalid certificate PEM format")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	serial := cert.SerialNumber.String()
	return cert, serial, nil
}

// marshalRevokedSerials converts revoked certs to JSON format for the CRL script.
// Format: [{"serial": "...", "revoked_at": "...", "reason_code": ...}, ...]
func (c *Connector) marshalRevokedSerials(revokedCerts []issuer.RevokedCertEntry) ([]byte, error) {
	type RevokedEntry struct {
		Serial      string `json:"serial"`
		RevokedAt   string `json:"revoked_at"`
		ReasonCode  int    `json:"reason_code"`
	}

	entries := make([]RevokedEntry, len(revokedCerts))
	for i, rc := range revokedCerts {
		entries[i] = RevokedEntry{
			Serial:     rc.SerialNumber.String(),
			RevokedAt:  rc.RevokedAt.Format(time.RFC3339),
			ReasonCode: rc.ReasonCode,
		}
	}

	return json.MarshalIndent(entries, "", "  ")
}
