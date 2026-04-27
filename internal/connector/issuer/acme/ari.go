package acme

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
)

// GetRenewalInfo retrieves ACME Renewal Information (ARI) per RFC 9773 for a certificate.
// certPEM is the PEM-encoded certificate. Returns nil, nil if the CA does not support ARI.
func (c *Connector) GetRenewalInfo(ctx context.Context, certPEM string) (*issuer.RenewalInfoResult, error) {
	if !c.config.ARIEnabled {
		return nil, nil
	}

	if err := c.ensureClient(ctx); err != nil {
		return nil, fmt.Errorf("ACME client init: %w", err)
	}

	// Parse the certificate to compute the ARI certificate ID
	certID, err := computeARICertID(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to compute ARI cert ID: %w", err)
	}

	c.logger.Debug("retrieving ARI for certificate",
		"cert_id", certID)

	// Fetch the ACME directory to find the renewalInfo endpoint
	renewalInfoURL, err := c.getARIEndpoint(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("failed to construct ARI endpoint: %w", err)
	}

	c.logger.Debug("querying ARI endpoint", "url", renewalInfoURL)

	// Make GET request to the ARI endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, renewalInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create ARI request: %w", err)
	}

	httpClient := &http.Client{Timeout: c.ariHTTPTimeout()}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ARI request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read ARI response: %w", err)
	}

	// 404 means the CA doesn't support ARI or the cert doesn't exist
	if resp.StatusCode == http.StatusNotFound {
		c.logger.Debug("ARI not supported by CA or cert not found")
		return nil, nil
	}

	// Other non-2xx errors
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ARI endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the ARI response
	var ariResp struct {
		SuggestedWindow struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"suggestedWindow"`
		RetryAfter     time.Time `json:"retryAfter,omitempty"`
		ExplanationURL string    `json:"explanationURL,omitempty"`
	}

	if err := json.Unmarshal(body, &ariResp); err != nil {
		return nil, fmt.Errorf("parse ARI response: %w", err)
	}

	if ariResp.SuggestedWindow.Start.IsZero() || ariResp.SuggestedWindow.End.IsZero() {
		return nil, fmt.Errorf("invalid ARI response: missing or empty suggestedWindow")
	}

	c.logger.Info("retrieved ARI",
		"window_start", ariResp.SuggestedWindow.Start,
		"window_end", ariResp.SuggestedWindow.End)

	return &issuer.RenewalInfoResult{
		SuggestedWindowStart: ariResp.SuggestedWindow.Start,
		SuggestedWindowEnd:   ariResp.SuggestedWindow.End,
		RetryAfter:           ariResp.RetryAfter,
		ExplanationURL:       ariResp.ExplanationURL,
	}, nil
}

// computeARICertID computes the ARI certificate ID as defined in RFC 9773.
// The cert ID is base64url(SHA256(DER encoding of the certificate)).
func computeARICertID(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", fmt.Errorf("invalid PEM: no certificate block found")
	}

	hash := sha256.Sum256(block.Bytes)
	certID := base64.RawURLEncoding.EncodeToString(hash[:])
	return certID, nil
}

// ariHTTPTimeout returns the per-request timeout for ARI HTTP calls. Bundle C
// / Audit M-019: configurable via Config.ARIHTTPTimeoutSeconds (env var
// CERTCTL_ACME_ARI_HTTP_TIMEOUT_SECONDS), defaults to 15 seconds.
func (c *Connector) ariHTTPTimeout() time.Duration {
	if c.config != nil && c.config.ARIHTTPTimeoutSeconds > 0 {
		return time.Duration(c.config.ARIHTTPTimeoutSeconds) * time.Second
	}
	return 15 * time.Second
}

// getARIEndpoint constructs the ARI endpoint URL from the ACME directory.
// It fetches the directory JSON and extracts the "renewalInfo" field if available.
// Falls back to a standard URL pattern if the directory doesn't advertise renewalInfo.
func (c *Connector) getARIEndpoint(ctx context.Context, certID string) (string, error) {
	// Try to fetch and parse the directory
	httpClient := &http.Client{Timeout: c.ariHTTPTimeout()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.DirectoryURL, nil)
	if err != nil {
		return "", fmt.Errorf("create directory request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		// If we can't fetch the directory, try the standard Let's Encrypt pattern
		return constructARIURLFallback(c.config.DirectoryURL, certID), nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return constructARIURLFallback(c.config.DirectoryURL, certID), nil
	}

	var dir struct {
		RenewalInfo string `json:"renewalInfo,omitempty"`
	}

	if err := json.Unmarshal(body, &dir); err != nil {
		// Malformed directory; use fallback
		return constructARIURLFallback(c.config.DirectoryURL, certID), nil
	}

	if dir.RenewalInfo != "" {
		// Directory advertises renewalInfo endpoint
		return dir.RenewalInfo + "/" + certID, nil
	}

	// No renewalInfo in directory; use standard fallback
	return constructARIURLFallback(c.config.DirectoryURL, certID), nil
}

// constructARIURLFallback builds an ARI endpoint URL using a standard pattern.
// It replaces "/directory" with "/renewalInfo" in the URL.
func constructARIURLFallback(directoryURL, certID string) string {
	// Replace "/directory" with "/renewalInfo/{certID}"
	// For Let's Encrypt: https://acme-v02.api.letsencrypt.org/directory
	// becomes: https://acme-v02.api.letsencrypt.org/renewalInfo/{certID}
	baseURL := strings.TrimSuffix(directoryURL, "/directory")
	return baseURL + "/renewalInfo/" + certID
}
