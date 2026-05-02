// Package digicert implements the issuer.Connector interface for DigiCert CertCentral.
//
// DigiCert CertCentral is an enterprise certificate authority offering DV, OV, and EV
// certificates. Unlike synchronous issuers (Vault, step-ca), DigiCert uses an
// asynchronous order model: submit an order, receive an order ID, then poll for
// completion. OV/EV certificates require organization validation which may take hours
// or days; DV certificates may be issued immediately.
//
// This connector maps to certctl's existing job state machine:
//   - IssueCertificate submits the order; if status is "issued", returns cert immediately.
//     If status is "pending", returns OrderID with empty CertPEM — the job system polls
//     via GetOrderStatus.
//   - GetOrderStatus polls the order; when status becomes "issued", downloads and
//     parses the PEM bundle.
//
// Authentication: API key via X-DC-DEVKEY header.
//
// DigiCert CertCentral API used:
//
//	POST /order/certificate/{product_type}          - Submit certificate order
//	GET  /order/certificate/{order_id}              - Check order status
//	GET  /certificate/{certificate_id}/download/format/pem_all - Download cert bundle
//	PUT  /certificate/{certificate_id}/revoke       - Revoke certificate
//	GET  /user/me                                   - Validate API credentials
package digicert

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/asyncpoll"
)

// Config represents the DigiCert CertCentral issuer connector configuration.
type Config struct {
	// APIKey is the CertCentral API key for authentication.
	// Required. Set via CERTCTL_DIGICERT_API_KEY environment variable.
	APIKey string `json:"api_key"`

	// OrgID is the DigiCert organization ID for certificate orders.
	// Required. Set via CERTCTL_DIGICERT_ORG_ID environment variable.
	OrgID string `json:"org_id"`

	// ProductType is the DigiCert product type for certificate orders.
	// Default: "ssl_basic". Set via CERTCTL_DIGICERT_PRODUCT_TYPE environment variable.
	// Common values: "ssl_basic", "ssl_wildcard", "ssl_ev_basic", "ssl_plus", "ssl_multi_domain".
	ProductType string `json:"product_type"`

	// BaseURL is the DigiCert CertCentral API base URL.
	// Default: "https://www.digicert.com/services/v2".
	// Set via CERTCTL_DIGICERT_BASE_URL environment variable.
	BaseURL string `json:"base_url"`

	// PollMaxWaitSeconds caps how long GetOrderStatus blocks doing
	// internal exponential-backoff polling before returning
	// StillPending to the caller. Default 600 (10 minutes); 0 falls
	// back to the asyncpoll package default. Bound only on the
	// per-call wall-clock; the caller (scheduler) can re-invoke on
	// the next tick if its policy allows.
	//
	// Set via CERTCTL_DIGICERT_POLL_MAX_WAIT_SECONDS. Audit fix #5.
	PollMaxWaitSeconds int `json:"poll_max_wait_seconds,omitempty"`
}

// pollMaxWait returns the configured PollMaxWait as a time.Duration,
// or the asyncpoll package default if unset.
func (c *Config) pollMaxWait() time.Duration {
	if c.PollMaxWaitSeconds <= 0 {
		return asyncpoll.DefaultMaxWait
	}
	return time.Duration(c.PollMaxWaitSeconds) * time.Second
}

// Connector implements the issuer.Connector interface for DigiCert CertCentral.
type Connector struct {
	config     *Config
	logger     *slog.Logger
	httpClient *http.Client
}

// New creates a new DigiCert CertCentral connector with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	if config != nil {
		if config.ProductType == "" {
			config.ProductType = "ssl_basic"
		}
		if config.BaseURL == "" {
			config.BaseURL = "https://www.digicert.com/services/v2"
		}
	}

	return &Connector{
		config: config,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// orderRequest is the JSON body for DigiCert certificate order submission.
type orderRequest struct {
	Certificate   orderCert `json:"certificate"`
	Organization  orderOrg  `json:"organization"`
	ValidityYears int       `json:"validity_years"`
}

type orderCert struct {
	CommonName string   `json:"common_name"`
	CSR        string   `json:"csr"`
	DNSNames   []string `json:"dns_names,omitempty"`
}

type orderOrg struct {
	ID json.Number `json:"id"`
}

// orderResponse is the JSON response from a certificate order submission.
type orderResponse struct {
	ID            int    `json:"id"`
	Status        string `json:"status"`
	CertificateID int    `json:"certificate_id,omitempty"`
}

// orderStatusResponse is the JSON response from an order status check.
type orderStatusResponse struct {
	ID          int    `json:"id"`
	Status      string `json:"status"`
	Certificate struct {
		ID         int    `json:"id"`
		CommonName string `json:"common_name"`
	} `json:"certificate"`
}

// ValidateConfig checks that the DigiCert configuration is valid and API access works.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid DigiCert config: %w", err)
	}

	if cfg.APIKey == "" {
		return fmt.Errorf("DigiCert api_key is required")
	}

	if cfg.OrgID == "" {
		return fmt.Errorf("DigiCert org_id is required")
	}

	if cfg.ProductType == "" {
		cfg.ProductType = "ssl_basic"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://www.digicert.com/services/v2"
	}

	// Test API access via /user/me
	meURL := cfg.BaseURL + "/user/me"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create API test request: %w", err)
	}
	req.Header.Set("X-DC-DEVKEY", cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("DigiCert API not reachable at %s: %w", cfg.BaseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("DigiCert API key is invalid (status %d)", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("DigiCert API returned status %d", resp.StatusCode)
	}

	c.config = &cfg
	c.logger.Info("DigiCert CertCentral configuration validated",
		"base_url", cfg.BaseURL,
		"product_type", cfg.ProductType)

	return nil
}

// IssueCertificate submits a certificate order to DigiCert CertCentral.
// If the certificate is issued immediately (DV certs), returns the cert.
// If pending (OV/EV certs), returns OrderID with empty CertPEM for polling.
func (c *Connector) IssueCertificate(ctx context.Context, request issuer.IssuanceRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing DigiCert issuance request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs),
		"product_type", c.config.ProductType)

	orderReq := orderRequest{
		Certificate: orderCert{
			CommonName: request.CommonName,
			CSR:        request.CSRPEM,
			DNSNames:   request.SANs,
		},
		Organization: orderOrg{
			ID: json.Number(c.config.OrgID),
		},
		ValidityYears: 1,
	}

	body, err := json.Marshal(orderReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal order request: %w", err)
	}

	orderURL := fmt.Sprintf("%s/order/certificate/%s", c.config.BaseURL, c.config.ProductType)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, orderURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create order request: %w", err)
	}
	req.Header.Set("X-DC-DEVKEY", c.config.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DigiCert order request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read order response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("DigiCert order returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var orderResp orderResponse
	if err := json.Unmarshal(respBody, &orderResp); err != nil {
		return nil, fmt.Errorf("failed to parse order response: %w", err)
	}

	orderID := fmt.Sprintf("%d", orderResp.ID)

	c.logger.Info("DigiCert order submitted",
		"order_id", orderID,
		"status", orderResp.Status)

	// If issued immediately (DV certs), download the certificate
	if orderResp.Status == "issued" && orderResp.CertificateID > 0 {
		certPEM, chainPEM, serial, notBefore, notAfter, err := c.downloadCertificate(ctx, orderResp.CertificateID)
		if err != nil {
			return nil, fmt.Errorf("failed to download certificate: %w", err)
		}

		c.logger.Info("DigiCert certificate issued immediately",
			"order_id", orderID,
			"serial", serial)

		return &issuer.IssuanceResult{
			CertPEM:   certPEM,
			ChainPEM:  chainPEM,
			Serial:    serial,
			NotBefore: notBefore,
			NotAfter:  notAfter,
			OrderID:   orderID,
		}, nil
	}

	// Pending — return OrderID for polling via GetOrderStatus
	c.logger.Info("DigiCert order pending validation",
		"order_id", orderID,
		"status", orderResp.Status)

	return &issuer.IssuanceResult{
		OrderID: orderID,
	}, nil
}

// RenewCertificate renews a certificate by submitting a new order.
// DigiCert uses reissue for renewal, but for simplicity we submit a new order
// (reissue requires the original order ID which may not be available).
func (c *Connector) RenewCertificate(ctx context.Context, request issuer.RenewalRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing DigiCert renewal request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	return c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: request.CommonName,
		SANs:       request.SANs,
		CSRPEM:     request.CSRPEM,
		EKUs:       request.EKUs,
	})
}

// RevokeCertificate revokes a certificate at DigiCert CertCentral.
// DigiCert revocation uses certificate_id, so we extract it from the serial
// by looking up the order. For simplicity, we use the serial as the cert ID
// (the caller should provide the DigiCert certificate ID).
func (c *Connector) RevokeCertificate(ctx context.Context, request issuer.RevocationRequest) error {
	c.logger.Info("processing DigiCert revocation request", "serial", request.Serial)

	reason := "unspecified"
	if request.Reason != nil {
		reason = *request.Reason
	}

	revokeBody := map[string]interface{}{
		"reason": reason,
	}

	body, err := json.Marshal(revokeBody)
	if err != nil {
		return fmt.Errorf("failed to marshal revoke request: %w", err)
	}

	// DigiCert uses certificate_id in the URL path for revocation
	revokeURL := fmt.Sprintf("%s/certificate/%s/revoke", c.config.BaseURL, request.Serial)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, revokeURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %w", err)
	}
	req.Header.Set("X-DC-DEVKEY", c.config.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("DigiCert revoke request failed: %w", err)
	}
	defer resp.Body.Close()

	// DigiCert returns 204 No Content on successful revocation
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("DigiCert revoke returned status %d: %s", resp.StatusCode, string(respBody))
	}

	c.logger.Info("DigiCert certificate revoked", "serial", request.Serial, "reason", reason)
	return nil
}

// GetOrderStatus checks the status of a DigiCert certificate order
// using bounded internal polling (asyncpoll.Poll). One call blocks
// for up to PollMaxWait (default 10m) doing exponential backoff;
// returns Done with the cert, Failed with the rejection reason, or
// StillPending if the deadline expires (caller can re-invoke).
//
// Audit fix #5: previously this method made one HTTP call per
// scheduler tick. Under load that pile-drives the upstream rate
// limit. asyncpoll wraps the one-shot logic with backoff + jitter.
func (c *Connector) GetOrderStatus(ctx context.Context, orderID string) (*issuer.OrderStatus, error) {
	c.logger.Debug("checking DigiCert order status", "order_id", orderID)

	// Closure-scoped accumulators — Poll passes back only the Result;
	// the cert / pending message land here for the wrapper to return.
	var done *issuer.OrderStatus
	var lastPendingMsg string

	cfg := asyncpoll.Config{MaxWait: c.config.pollMaxWait()}

	res, err := asyncpoll.Poll(ctx, cfg, func(ctx context.Context) (asyncpoll.Result, error) {
		status, result, pollErr := c.pollOrderOnce(ctx, orderID)
		if status != nil {
			switch result {
			case asyncpoll.Done:
				done = status
			case asyncpoll.StillPending:
				if status.Message != nil {
					lastPendingMsg = *status.Message
				}
			}
		}
		return result, pollErr
	})

	now := time.Now()
	switch res {
	case asyncpoll.Done:
		return done, nil
	case asyncpoll.Failed:
		// Permanent failure — surface the upstream's error to the
		// caller so handler middleware / scheduler can mark the job
		// failed with the actual reason.
		return nil, err
	default: // StillPending — MaxWait or ctx cancel
		msg := lastPendingMsg
		if msg == "" {
			msg = fmt.Sprintf("order %s still pending after PollMaxWait", orderID)
		}
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "pending",
			Message:   &msg,
			UpdatedAt: now,
		}, nil
	}
}

// pollOrderOnce makes one HTTP GET against the DigiCert order-status
// endpoint and translates the response into an asyncpoll.Result plus
// (when applicable) a populated OrderStatus. Used by GetOrderStatus
// as the per-iteration closure for asyncpoll.Poll.
func (c *Connector) pollOrderOnce(ctx context.Context, orderID string) (*issuer.OrderStatus, asyncpoll.Result, error) {
	statusURL := fmt.Sprintf("%s/order/certificate/%s", c.config.BaseURL, orderID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
	if err != nil {
		return nil, asyncpoll.Failed, fmt.Errorf("failed to create status request: %w", err)
	}
	req.Header.Set("X-DC-DEVKEY", c.config.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Transient network error — keep polling. Caller's MaxWait
		// will eventually fire if it persists.
		return nil, asyncpoll.StillPending, fmt.Errorf("DigiCert status request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, asyncpoll.StillPending, fmt.Errorf("failed to read status response: %w", err)
	}

	// Status-code triage:
	//   2xx          → fall through to body parse below.
	//   429          → StillPending (rate limited; retry with backoff).
	//   5xx          → StillPending (upstream unhealthy; transient).
	//   other 4xx    → Failed (permanent client error: 400 bad
	//                  request, 401 auth, 403 forbidden, 404 order
	//                  doesn't exist). No amount of polling fixes
	//                  these.
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("DigiCert order status returned %d: %s", resp.StatusCode, string(respBody))
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return nil, asyncpoll.StillPending, err
		}
		return nil, asyncpoll.Failed, err
	}

	var statusResp orderStatusResponse
	if err := json.Unmarshal(respBody, &statusResp); err != nil {
		// Parse errors are permanent — the upstream's response shape
		// changed or the body is corrupted. Retrying produces the
		// same parse error.
		return nil, asyncpoll.Failed, fmt.Errorf("failed to parse status response: %w", err)
	}

	now := time.Now()
	switch statusResp.Status {
	case "issued":
		if statusResp.Certificate.ID == 0 {
			return nil, asyncpoll.Failed, fmt.Errorf("order is issued but certificate_id is missing")
		}
		certPEM, chainPEM, serial, notBefore, notAfter, err := c.downloadCertificate(ctx, statusResp.Certificate.ID)
		if err != nil {
			return nil, asyncpoll.Failed, fmt.Errorf("failed to download certificate: %w", err)
		}
		c.logger.Info("DigiCert order completed", "order_id", orderID, "serial", serial)
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "completed",
			CertPEM:   &certPEM,
			ChainPEM:  &chainPEM,
			Serial:    &serial,
			NotBefore: &notBefore,
			NotAfter:  &notAfter,
			UpdatedAt: now,
		}, asyncpoll.Done, nil

	case "pending", "processing":
		msg := fmt.Sprintf("order %s is %s", orderID, statusResp.Status)
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "pending",
			Message:   &msg,
			UpdatedAt: now,
		}, asyncpoll.StillPending, nil

	case "rejected", "denied":
		// Completed-with-negative-answer. NOT a transient failure
		// (the order won't un-reject itself), but also not a
		// caller-facing Go error — wrap in OrderStatus{Status:"failed"}
		// so the scheduler sees a definitive completion.
		msg := fmt.Sprintf("order %s was %s", orderID, statusResp.Status)
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "failed",
			Message:   &msg,
			UpdatedAt: now,
		}, asyncpoll.Done, nil

	default:
		msg := fmt.Sprintf("unknown order status: %s", statusResp.Status)
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "pending",
			Message:   &msg,
			UpdatedAt: now,
		}, asyncpoll.StillPending, nil
	}
}

// downloadCertificate downloads the PEM bundle for a DigiCert certificate.
func (c *Connector) downloadCertificate(ctx context.Context, certificateID int) (certPEM string, chainPEM string, serial string, notBefore time.Time, notAfter time.Time, err error) {
	downloadURL := fmt.Sprintf("%s/certificate/%d/download/format/pem_all", c.config.BaseURL, certificateID)
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if reqErr != nil {
		err = fmt.Errorf("failed to create download request: %w", reqErr)
		return
	}
	req.Header.Set("X-DC-DEVKEY", c.config.APIKey)

	resp, doErr := c.httpClient.Do(req)
	if doErr != nil {
		err = fmt.Errorf("DigiCert download request failed: %w", doErr)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		err = fmt.Errorf("DigiCert download returned status %d: %s", resp.StatusCode, string(body))
		return
	}

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		err = fmt.Errorf("failed to read download response: %w", readErr)
		return
	}

	// Parse the PEM bundle: first cert is the leaf, rest are intermediates
	certPEM, chainPEM, serial, notBefore, notAfter, err = parsePEMBundle(string(body))
	return
}

// parsePEMBundle splits a PEM bundle into leaf cert and chain, extracting metadata.
func parsePEMBundle(bundle string) (certPEM string, chainPEM string, serial string, notBefore time.Time, notAfter time.Time, err error) {
	var certs []string
	remaining := bundle

	for {
		var block *pem.Block
		block, rest := pem.Decode([]byte(remaining))
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, string(pem.EncodeToMemory(block)))
		}
		remaining = string(rest)
	}

	if len(certs) == 0 {
		err = fmt.Errorf("no certificates found in PEM bundle")
		return
	}

	certPEM = certs[0]
	if len(certs) > 1 {
		chainPEM = strings.Join(certs[1:], "")
	}

	// Parse leaf cert for metadata
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		err = fmt.Errorf("failed to decode leaf certificate PEM")
		return
	}

	cert, parseErr := x509.ParseCertificate(block.Bytes)
	if parseErr != nil {
		err = fmt.Errorf("failed to parse leaf certificate: %w", parseErr)
		return
	}

	serial = cert.SerialNumber.String()
	notBefore = cert.NotBefore
	notAfter = cert.NotAfter
	return
}

// GenerateCRL is not supported because DigiCert manages CRL distribution.
func (c *Connector) GenerateCRL(ctx context.Context, revokedCerts []issuer.RevokedCertEntry) ([]byte, error) {
	return nil, fmt.Errorf("DigiCert manages CRL distribution; use DigiCert's CRL endpoints")
}

// SignOCSPResponse is not supported because DigiCert manages OCSP.
func (c *Connector) SignOCSPResponse(ctx context.Context, req issuer.OCSPSignRequest) ([]byte, error) {
	return nil, fmt.Errorf("DigiCert manages OCSP; use DigiCert's OCSP responder")
}

// GetCACertPEM is not directly supported. DigiCert intermediate certificates
// come with each certificate issuance as part of the PEM bundle.
func (c *Connector) GetCACertPEM(ctx context.Context) (string, error) {
	return "", fmt.Errorf("DigiCert intermediate certificates are included with each issued certificate")
}

// GetRenewalInfo returns nil, nil as DigiCert does not support ACME Renewal Information (ARI).
func (c *Connector) GetRenewalInfo(ctx context.Context, certPEM string) (*issuer.RenewalInfoResult, error) {
	return nil, nil
}

// Ensure Connector implements the issuer.Connector interface.
var _ issuer.Connector = (*Connector)(nil)
