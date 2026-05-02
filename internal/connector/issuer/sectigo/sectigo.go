// Package sectigo implements the issuer.Connector interface for Sectigo Certificate Manager (SCM).
//
// Sectigo Certificate Manager is an enterprise certificate authority offering DV, OV, and EV
// certificates. Like DigiCert, Sectigo uses an asynchronous order model: submit an enrollment,
// receive an sslId, then poll for completion. OV/EV certificates require organization validation
// which may take hours or days; DV certificates may be issued immediately.
//
// This connector maps to certctl's existing job state machine:
//   - IssueCertificate submits the enrollment; if status is "Issued", returns cert immediately.
//     If status is "Applied" or "Pending", returns OrderID with empty CertPEM — the job system
//     polls via GetOrderStatus.
//   - GetOrderStatus polls the order; when status becomes "Issued", downloads and parses the
//     PEM bundle via the collect endpoint.
//
// Authentication: Three custom headers on every request — customerUri, login, password.
//
// Sectigo SCM REST API used:
//
//	POST /ssl/v1/enroll                - Submit certificate enrollment
//	GET  /ssl/v1/{sslId}              - Check enrollment status
//	GET  /ssl/v1/collect/{sslId}/pem  - Download PEM bundle when issued
//	POST /ssl/v1/revoke/{sslId}       - Revoke certificate
//	GET  /ssl/v1/types                - List available cert types (used for health check)
package sectigo

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
	"github.com/shankar0123/certctl/internal/secret"
)

// Config represents the Sectigo Certificate Manager issuer connector configuration.
type Config struct {
	// CustomerURI is the Sectigo customer URI (organization identifier).
	// Required. Set via CERTCTL_SECTIGO_CUSTOMER_URI environment variable.
	CustomerURI string `json:"customer_uri"`

	// Login is the Sectigo API account login.
	// Required. Set via CERTCTL_SECTIGO_LOGIN environment variable.
	//
	// Type: *secret.Ref (audit fix #6 Phase 2). Login can be tied to
	// a privileged service-account identity, so it's protected from
	// accidental logging the same way Password is.
	Login *secret.Ref `json:"login"`

	// Password is the Sectigo API account password or API key.
	// Required. Set via CERTCTL_SECTIGO_PASSWORD environment variable.
	// Same *secret.Ref protections as Login.
	Password *secret.Ref `json:"password"`

	// OrgID is the Sectigo organization ID for certificate enrollments.
	// Required. Set via CERTCTL_SECTIGO_ORG_ID environment variable.
	OrgID int `json:"org_id"`

	// CertType is the Sectigo certificate type ID (from GET /ssl/v1/types).
	// Required for enrollment. Set via CERTCTL_SECTIGO_CERT_TYPE environment variable.
	CertType int `json:"cert_type"`

	// Term is the certificate validity in days (e.g., 365, 730).
	// Default: 365. Set via CERTCTL_SECTIGO_TERM environment variable.
	Term int `json:"term"`

	// BaseURL is the Sectigo SCM API base URL.
	// Default: "https://cert-manager.com/api".
	// Set via CERTCTL_SECTIGO_BASE_URL environment variable.
	BaseURL string `json:"base_url"`

	// PollMaxWaitSeconds caps how long GetOrderStatus blocks doing
	// internal exponential-backoff polling before returning
	// StillPending. Default 600 (10 minutes). Sectigo's
	// collectNotReady sentinel maps to StillPending so recently-
	// issued certs that aren't yet retrievable get the backoff
	// schedule rather than tight-loop polling.
	//
	// Set via CERTCTL_SECTIGO_POLL_MAX_WAIT_SECONDS. Audit fix #5.
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

// Connector implements the issuer.Connector interface for Sectigo Certificate Manager.
type Connector struct {
	config     *Config
	logger     *slog.Logger
	httpClient *http.Client
}

// New creates a new Sectigo SCM connector with the given configuration and logger.
func New(config *Config, logger *slog.Logger) *Connector {
	if config != nil {
		if config.Term == 0 {
			config.Term = 365
		}
		if config.BaseURL == "" {
			config.BaseURL = "https://cert-manager.com/api"
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

// enrollRequest is the JSON body for Sectigo certificate enrollment.
type enrollRequest struct {
	OrgID             int    `json:"orgId"`
	CSR               string `json:"csr"`
	CertType          int    `json:"certType"`
	Term              int    `json:"term"`
	SubjAltNames      string `json:"subjAltNames,omitempty"`
	Comments          string `json:"comments,omitempty"`
	ExternalRequester string `json:"externalRequester,omitempty"`
}

// enrollResponse is the JSON response from a certificate enrollment.
type enrollResponse struct {
	SSLId   int    `json:"sslId"`
	RenewId string `json:"renewId,omitempty"`
}

// statusResponse is the JSON response from an enrollment status check.
type statusResponse struct {
	SSLId        int    `json:"sslId"`
	Status       string `json:"status"`
	CommonName   string `json:"commonName,omitempty"`
	SerialNumber string `json:"serialNumber,omitempty"`
}

// setAuthHeaders sets the three Sectigo authentication headers on a request.
//
// Login and Password are pulled from *secret.Ref via Use, which zero-fills
// the per-call buffer after the header string is set; the Ref's underlying
// bytes remain encrypted at rest. The Use return value is intentionally
// ignored — Set never errors and the only failure modes inside Use are
// nil-Ref / empty-Ref which the upstream IsEmpty validation has already
// excluded for production paths. Audit fix #6 Phase 2.
func (c *Connector) setAuthHeaders(req *http.Request) {
	req.Header.Set("customerUri", c.config.CustomerURI)
	if c.config.Login != nil {
		_ = c.config.Login.Use(func(buf []byte) error {
			req.Header.Set("login", string(buf))
			return nil
		})
	}
	if c.config.Password != nil {
		_ = c.config.Password.Use(func(buf []byte) error {
			req.Header.Set("password", string(buf))
			return nil
		})
	}
	req.Header.Set("Content-Type", "application/json")
}

// ValidateConfig checks that the Sectigo configuration is valid and API access works.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid Sectigo config: %w", err)
	}

	if cfg.CustomerURI == "" {
		return fmt.Errorf("Sectigo customer_uri is required")
	}

	if cfg.Login.IsEmpty() {
		return fmt.Errorf("Sectigo login is required")
	}

	if cfg.Password.IsEmpty() {
		return fmt.Errorf("Sectigo password is required")
	}

	if cfg.OrgID == 0 {
		return fmt.Errorf("Sectigo org_id is required")
	}

	if cfg.Term == 0 {
		cfg.Term = 365
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://cert-manager.com/api"
	}

	// Test API access via GET /ssl/v1/types (health check)
	typesURL := cfg.BaseURL + "/ssl/v1/types"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, typesURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create API test request: %w", err)
	}
	req.Header.Set("customerUri", cfg.CustomerURI)
	if cfg.Login != nil {
		_ = cfg.Login.Use(func(buf []byte) error {
			req.Header.Set("login", string(buf))
			return nil
		})
	}
	if cfg.Password != nil {
		_ = cfg.Password.Use(func(buf []byte) error {
			req.Header.Set("password", string(buf))
			return nil
		})
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Sectigo API not reachable at %s: %w", cfg.BaseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("Sectigo API credentials are invalid (status %d)", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Sectigo API returned status %d", resp.StatusCode)
	}

	c.config = &cfg
	c.logger.Info("Sectigo Certificate Manager configuration validated",
		"base_url", cfg.BaseURL,
		"org_id", cfg.OrgID)

	return nil
}

// IssueCertificate submits a certificate enrollment to Sectigo SCM.
// If the certificate is issued immediately (DV certs), returns the cert.
// If pending (OV/EV certs), returns OrderID with empty CertPEM for polling.
func (c *Connector) IssueCertificate(ctx context.Context, request issuer.IssuanceRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing Sectigo enrollment request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs),
		"cert_type", c.config.CertType)

	enrollReq := enrollRequest{
		OrgID:    c.config.OrgID,
		CSR:      request.CSRPEM,
		CertType: c.config.CertType,
		Term:     c.config.Term,
		Comments: "Issued by certctl",
	}

	if len(request.SANs) > 0 {
		enrollReq.SubjAltNames = strings.Join(request.SANs, ",")
	}

	body, err := json.Marshal(enrollReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal enrollment request: %w", err)
	}

	enrollURL := c.config.BaseURL + "/ssl/v1/enroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, enrollURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create enrollment request: %w", err)
	}
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Sectigo enrollment request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read enrollment response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("Sectigo enrollment returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var enrollResp enrollResponse
	if err := json.Unmarshal(respBody, &enrollResp); err != nil {
		return nil, fmt.Errorf("failed to parse enrollment response: %w", err)
	}

	orderID := fmt.Sprintf("%d", enrollResp.SSLId)

	c.logger.Info("Sectigo enrollment submitted", "ssl_id", orderID)

	// Check status immediately to see if cert was issued right away
	status, err := c.checkStatus(ctx, enrollResp.SSLId)
	if err != nil {
		// Status check failed but enrollment succeeded — return as pending
		c.logger.Warn("Sectigo status check after enrollment failed, treating as pending",
			"ssl_id", orderID, "error", err)
		return &issuer.IssuanceResult{
			OrderID: orderID,
		}, nil
	}

	if status.Status == "Issued" {
		certPEM, chainPEM, serial, notBefore, notAfter, collectErr := c.collectCertificate(ctx, enrollResp.SSLId)
		if collectErr != nil {
			// Cert is issued but collect failed — might not be generated yet
			c.logger.Warn("Sectigo certificate issued but collect failed, treating as pending",
				"ssl_id", orderID, "error", collectErr)
			return &issuer.IssuanceResult{
				OrderID: orderID,
			}, nil
		}

		c.logger.Info("Sectigo certificate issued immediately",
			"ssl_id", orderID,
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
	c.logger.Info("Sectigo enrollment pending validation",
		"ssl_id", orderID,
		"status", status.Status)

	return &issuer.IssuanceResult{
		OrderID: orderID,
	}, nil
}

// RenewCertificate renews a certificate by submitting a new enrollment.
// Sectigo supports POST /ssl/renewById/{sslId} but for simplicity we submit
// a new enrollment (same pattern as DigiCert).
func (c *Connector) RenewCertificate(ctx context.Context, request issuer.RenewalRequest) (*issuer.IssuanceResult, error) {
	c.logger.Info("processing Sectigo renewal request",
		"common_name", request.CommonName,
		"san_count", len(request.SANs))

	return c.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: request.CommonName,
		SANs:       request.SANs,
		CSRPEM:     request.CSRPEM,
		EKUs:       request.EKUs,
	})
}

// RevokeCertificate revokes a certificate at Sectigo SCM.
func (c *Connector) RevokeCertificate(ctx context.Context, request issuer.RevocationRequest) error {
	c.logger.Info("processing Sectigo revocation request", "serial", request.Serial)

	reason := "Unspecified"
	if request.Reason != nil {
		reason = mapRevocationReason(*request.Reason)
	}

	revokeBody := map[string]interface{}{
		"reason": reason,
	}

	body, err := json.Marshal(revokeBody)
	if err != nil {
		return fmt.Errorf("failed to marshal revoke request: %w", err)
	}

	// Sectigo uses sslId in the URL path for revocation
	revokeURL := fmt.Sprintf("%s/ssl/v1/revoke/%s", c.config.BaseURL, request.Serial)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, revokeURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %w", err)
	}
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Sectigo revoke request failed: %w", err)
	}
	defer resp.Body.Close()

	// Sectigo returns 204 No Content on successful revocation
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Sectigo revoke returned status %d: %s", resp.StatusCode, string(respBody))
	}

	c.logger.Info("Sectigo certificate revoked", "serial", request.Serial, "reason", reason)
	return nil
}

// GetOrderStatus checks the status of a Sectigo certificate enrollment
// using bounded internal polling (asyncpoll.Poll). One call blocks for
// up to PollMaxWait (default 10m) doing exponential backoff with
// jitter; returns Done with the cert, Failed with the rejection
// reason, or StillPending if the deadline expires (caller can
// re-invoke).
//
// Audit fix #5 Phase 2: previously each scheduler tick made one HTTP
// call against an unready order. Sectigo's collectNotReady sentinel
// (cert approved but not yet generated) now maps to StillPending and
// rides the backoff schedule rather than tight-loop polling.
func (c *Connector) GetOrderStatus(ctx context.Context, orderID string) (*issuer.OrderStatus, error) {
	c.logger.Debug("checking Sectigo enrollment status", "ssl_id", orderID)

	// Parse sslId from string once at entry — invalid ID is a
	// permanent error, no point polling.
	var sslId int
	if _, err := fmt.Sscanf(orderID, "%d", &sslId); err != nil {
		return nil, fmt.Errorf("invalid Sectigo ssl_id: %s", orderID)
	}

	var done *issuer.OrderStatus
	var lastPendingMsg string
	cfg := asyncpoll.Config{MaxWait: c.config.pollMaxWait()}

	res, err := asyncpoll.Poll(ctx, cfg, func(ctx context.Context) (asyncpoll.Result, error) {
		status, result, pollErr := c.pollEnrollmentOnce(ctx, sslId, orderID)
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
		return nil, err
	default:
		msg := lastPendingMsg
		if msg == "" {
			msg = fmt.Sprintf("enrollment %s still pending after PollMaxWait", orderID)
		}
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "pending",
			Message:   &msg,
			UpdatedAt: now,
		}, nil
	}
}

// pollEnrollmentOnce makes one HTTP GET against the Sectigo SCM
// status endpoint and translates the response into an asyncpoll.Result
// plus (when applicable) a populated OrderStatus.
//
// collectNotReady is the load-bearing Sectigo sentinel: even when
// the SCM status endpoint reports "Issued", the cert may not yet be
// retrievable from the collect endpoint. We treat this as
// StillPending so the backoff schedule applies.
func (c *Connector) pollEnrollmentOnce(ctx context.Context, sslId int, orderID string) (*issuer.OrderStatus, asyncpoll.Result, error) {
	status, err := c.checkStatus(ctx, sslId)
	if err != nil {
		// Triage by examining the wrapped status code: 4xx (not 429)
		// is permanent (404 = enrollment doesn't exist, 400 = bad
		// request, 401/403 = auth). Parse failures are also
		// permanent — the upstream's response shape is broken.
		// 5xx / 429 / network errors are transient and ride the
		// backoff schedule.
		if isPermanentStatusError(err) {
			return nil, asyncpoll.Failed, err
		}
		return nil, asyncpoll.StillPending, err
	}

	now := time.Now()
	switch status.Status {
	case "Issued":
		certPEM, chainPEM, serial, notBefore, notAfter, collectErr := c.collectCertificate(ctx, sslId)
		if collectErr != nil {
			if isCollectNotReady(collectErr) {
				msg := fmt.Sprintf("enrollment %s is issued but certificate not yet generated", orderID)
				return &issuer.OrderStatus{
					OrderID:   orderID,
					Status:    "pending",
					Message:   &msg,
					UpdatedAt: now,
				}, asyncpoll.StillPending, nil
			}
			return nil, asyncpoll.Failed, fmt.Errorf("failed to collect certificate: %w", collectErr)
		}
		c.logger.Info("Sectigo enrollment completed", "ssl_id", orderID, "serial", serial)
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

	case "Applied", "Pending":
		msg := fmt.Sprintf("enrollment %s is %s", orderID, status.Status)
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "pending",
			Message:   &msg,
			UpdatedAt: now,
		}, asyncpoll.StillPending, nil

	case "Rejected":
		msg := fmt.Sprintf("enrollment %s was rejected", orderID)
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "failed",
			Message:   &msg,
			UpdatedAt: now,
		}, asyncpoll.Done, nil

	case "Revoked", "Expired", "Not Enrolled":
		msg := fmt.Sprintf("enrollment %s has status: %s", orderID, status.Status)
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "failed",
			Message:   &msg,
			UpdatedAt: now,
		}, asyncpoll.Done, nil

	default:
		msg := fmt.Sprintf("unknown enrollment status: %s", status.Status)
		return &issuer.OrderStatus{
			OrderID:   orderID,
			Status:    "pending",
			Message:   &msg,
			UpdatedAt: now,
		}, asyncpoll.StillPending, nil
	}
}

// isPermanentStatusError reports whether an error returned from
// checkStatus represents a permanent client-side failure (4xx other
// than 429, or a body-parse failure). Used by pollEnrollmentOnce to
// distinguish "stop polling" from "transient; keep polling".
//
// Heuristic-based on the error wrap shape: checkStatus formats HTTP
// status errors as "Sectigo status returned %d:" so we can grep for
// known permanent codes. Parse-failure errors contain "parse status
// response".
func isPermanentStatusError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, code := range []string{"returned 400", "returned 401", "returned 403", "returned 404"} {
		if strings.Contains(msg, code) {
			return true
		}
	}
	return strings.Contains(msg, "parse status response")
}

// checkStatus retrieves the enrollment status from Sectigo.
func (c *Connector) checkStatus(ctx context.Context, sslId int) (*statusResponse, error) {
	statusURL := fmt.Sprintf("%s/ssl/v1/%d", c.config.BaseURL, sslId)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create status request: %w", err)
	}
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Sectigo status request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read status response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Sectigo status returned %d: %s", resp.StatusCode, string(respBody))
	}

	var statusResp statusResponse
	if err := json.Unmarshal(respBody, &statusResp); err != nil {
		return nil, fmt.Errorf("failed to parse status response: %w", err)
	}

	return &statusResp, nil
}

// collectCertificate downloads the PEM bundle for a Sectigo certificate.
func (c *Connector) collectCertificate(ctx context.Context, sslId int) (certPEM string, chainPEM string, serial string, notBefore time.Time, notAfter time.Time, err error) {
	collectURL := fmt.Sprintf("%s/ssl/v1/collect/%d/pem", c.config.BaseURL, sslId)
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, collectURL, nil)
	if reqErr != nil {
		err = fmt.Errorf("failed to create collect request: %w", reqErr)
		return
	}
	c.setAuthHeaders(req)

	resp, doErr := c.httpClient.Do(req)
	if doErr != nil {
		err = fmt.Errorf("Sectigo collect request failed: %w", doErr)
		return
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		err = fmt.Errorf("failed to read collect response: %w", readErr)
		return
	}

	// Sectigo returns 400 with code -183 when cert is approved but not yet generated
	if resp.StatusCode == http.StatusBadRequest {
		err = &collectNotReadyError{statusCode: resp.StatusCode, body: string(body)}
		return
	}

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("Sectigo collect returned status %d: %s", resp.StatusCode, string(body))
		return
	}

	// Parse the PEM bundle: first cert is the leaf, rest are intermediates
	certPEM, chainPEM, serial, notBefore, notAfter, err = parsePEMBundle(string(body))
	return
}

// collectNotReadyError indicates the certificate is not yet generated.
type collectNotReadyError struct {
	statusCode int
	body       string
}

func (e *collectNotReadyError) Error() string {
	return fmt.Sprintf("certificate not yet available (status %d): %s", e.statusCode, e.body)
}

// isCollectNotReady checks if an error indicates the cert is not yet generated.
func isCollectNotReady(err error) bool {
	_, ok := err.(*collectNotReadyError)
	return ok
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

// mapRevocationReason maps RFC 5280 / certctl reason strings to Sectigo reason strings.
func mapRevocationReason(reason string) string {
	switch strings.ToLower(reason) {
	case "keycompromise", "key_compromise":
		return "Compromised"
	case "cessationofoperation", "cessation_of_operation":
		return "Cessation of Operation"
	case "affiliationchanged", "affiliation_changed":
		return "Affiliation Changed"
	case "superseded":
		return "Superseded"
	default:
		return "Unspecified"
	}
}

// GenerateCRL is not supported because Sectigo manages CRL distribution.
func (c *Connector) GenerateCRL(ctx context.Context, revokedCerts []issuer.RevokedCertEntry) ([]byte, error) {
	return nil, fmt.Errorf("Sectigo manages CRL distribution; use Sectigo's CRL endpoints")
}

// SignOCSPResponse is not supported because Sectigo manages OCSP.
func (c *Connector) SignOCSPResponse(ctx context.Context, req issuer.OCSPSignRequest) ([]byte, error) {
	return nil, fmt.Errorf("Sectigo manages OCSP; use Sectigo's OCSP responder")
}

// GetCACertPEM is not directly supported. Sectigo intermediate certificates
// come with each certificate issuance as part of the PEM bundle.
func (c *Connector) GetCACertPEM(ctx context.Context) (string, error) {
	return "", fmt.Errorf("Sectigo intermediate certificates are included with each issued certificate")
}

// GetRenewalInfo returns nil, nil as Sectigo does not support ACME Renewal Information (ARI).
func (c *Connector) GetRenewalInfo(ctx context.Context, certPEM string) (*issuer.RenewalInfoResult, error) {
	return nil, nil
}

// Ensure Connector implements the issuer.Connector interface.
var _ issuer.Connector = (*Connector)(nil)
