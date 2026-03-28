package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// verifyDeployment probes the live TLS endpoint for a deployment target and verifies
// that the deployed certificate matches what we expect.
//
// Parameters:
//   - targetHost: the hostname or IP of the target (extracted from target config)
//   - targetPort: the TLS port of the target (e.g., 443)
//   - expectedCertPEM: the PEM-encoded certificate that was deployed
//   - delay: wait time before probing (e.g., 2 seconds for reload to take effect)
//   - timeout: overall timeout for TLS connection attempt (e.g., 10 seconds)
//
// Returns:
//   - A VerificationResult if probing succeeded (even if cert doesn't match)
//   - An error if the probe itself failed (network error, timeout, etc.)
//
// The function compares the SHA-256 fingerprints of the expected and actual certificates.
// If the certificate served at the endpoint differs, Verified will be false but no error
// is returned — this is an expected verification failure, not a probe failure.
func verifyDeployment(
	ctx context.Context,
	targetHost string,
	targetPort int,
	expectedCertPEM string,
	delay time.Duration,
	timeout time.Duration,
	logger *slog.Logger,
) (*VerificationResult, error) {
	// Wait for reload to take effect
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Parse expected certificate to compute its fingerprint
	expectedFp, err := computeCertificateFingerprint(expectedCertPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expected certificate: %w", err)
	}

	// Connect to the target's TLS endpoint
	address := fmt.Sprintf("%s:%d", targetHost, targetPort)
	logger.Debug("probing TLS endpoint for verification",
		"address", address,
		"expected_fingerprint", expectedFp)

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		InsecureSkipVerify: true, // We accept any cert (expired, self-signed, etc.)
		ServerName:        targetHost, // For SNI
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	defer conn.Close()

	// Extract the leaf certificate from the TLS connection
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates presented by %s", address)
	}

	leafCert := state.PeerCertificates[0]
	actualFp := fmt.Sprintf("%x", sha256.Sum256(leafCert.Raw))

	logger.Debug("received certificate from endpoint",
		"address", address,
		"cn", leafCert.Subject.CommonName,
		"actual_fingerprint", actualFp)

	// Compare fingerprints
	verified := actualFp == expectedFp
	if !verified {
		logger.Warn("certificate fingerprint mismatch at endpoint",
			"address", address,
			"expected_fingerprint", expectedFp,
			"actual_fingerprint", actualFp)
	} else {
		logger.Info("certificate verification succeeded",
			"address", address,
			"fingerprint", actualFp)
	}

	return &VerificationResult{
		ExpectedFingerprint: expectedFp,
		ActualFingerprint:   actualFp,
		Verified:            verified,
		VerifiedAt:          time.Now().UTC(),
	}, nil
}

// VerificationResult represents the outcome of verifying a deployed certificate.
type VerificationResult struct {
	ExpectedFingerprint string    `json:"expected_fingerprint"`
	ActualFingerprint   string    `json:"actual_fingerprint"`
	Verified            bool      `json:"verified"`
	VerifiedAt          time.Time `json:"verified_at"`
	Error               string    `json:"error,omitempty"`
}

// computeCertificateFingerprint computes the SHA-256 fingerprint of a PEM-encoded certificate.
func computeCertificateFingerprint(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse x509 certificate: %w", err)
	}

	fp := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", fp), nil
}

// reportVerificationResult submits the verification result back to the control plane.
// This is a best-effort operation — a failure to report doesn't block agent progress.
func (a *Agent) reportVerificationResult(
	ctx context.Context,
	jobID string,
	targetID string,
	result *VerificationResult,
) error {
	if jobID == "" || targetID == "" || result == nil {
		return fmt.Errorf("missing required fields for verification report")
	}

	// Build the request payload
	payload := map[string]interface{}{
		"target_id":             targetID,
		"expected_fingerprint":  result.ExpectedFingerprint,
		"actual_fingerprint":    result.ActualFingerprint,
		"verified":              result.Verified,
		"error":                 result.Error,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal verification result: %w", err)
	}

	// POST to /api/v1/jobs/{id}/verify
	url := fmt.Sprintf("%s/api/v1/jobs/%s/verify", a.config.ServerURL, jobID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create verification request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.config.APIKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send verification result: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("verification reporting failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	a.logger.Debug("verification result reported to control plane",
		"job_id", jobID,
		"verified", result.Verified)

	return nil
}

// extractTargetHostAndPort extracts the host and port from target configuration.
// Common target configs include "host" or "hostname" and "port" fields.
func extractTargetHostAndPort(configJSON json.RawMessage) (string, int, error) {
	var config map[string]interface{}
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return "", 0, fmt.Errorf("invalid target config JSON: %w", err)
	}

	// Try common field names for hostname
	var host string
	for _, key := range []string{"host", "hostname", "target", "address"} {
		if h, ok := config[key].(string); ok && h != "" {
			host = h
			break
		}
	}
	if host == "" {
		return "", 0, fmt.Errorf("target config missing host/hostname field")
	}

	// Try common field names for port, default to 443
	port := 443
	if p, ok := config["port"].(float64); ok {
		port = int(p)
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port: %d", port)
	}

	return host, port, nil
}

// verifyAndReportDeployment performs TLS endpoint verification and reports the result.
// This is a best-effort operation — failures are logged but don't affect deployment status.
func (a *Agent) verifyAndReportDeployment(
	ctx context.Context,
	job JobItem,
	targetHost string,
	targetPort int,
	certPEM string,
) {
	// Perform verification with configured timeout and delay
	result, err := verifyDeployment(ctx, targetHost, targetPort, certPEM,
		2*time.Second, // delay before probing
		10*time.Second, // timeout for TLS connection
		a.logger)

	if err != nil {
		a.logger.Warn("verification probe failed",
			"job_id", job.ID,
			"target_host", targetHost,
			"target_port", targetPort,
			"error", err)
		// Probe failure: report error but continue
		result = &VerificationResult{
			Error: err.Error(),
			VerifiedAt: time.Now().UTC(),
		}
	}

	// Report result to control plane
	if job.TargetID == nil {
		a.logger.Warn("cannot report verification: target_id is nil", "job_id", job.ID)
		return
	}

	if err := a.reportVerificationResult(ctx, job.ID, *job.TargetID, result); err != nil {
		a.logger.Warn("failed to report verification result",
			"job_id", job.ID,
			"error", err)
		// Non-blocking: continue even if report fails
	}
}
