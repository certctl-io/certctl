package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/pkcs7"
	"github.com/certctl-io/certctl/internal/validation"
	"github.com/google/uuid"
)

// SCEP RFC 8894 + Intune master bundle Phase 11.5 — SCEP probe.
//
// Probes an SCEP server URL for capability + posture metadata
// (RFC 8894 §3.5.1 GetCACaps + GetCACert). Used for pre-migration
// assessment + compliance posture audits. Deliberately does NOT POST a
// CSR — capability-only.
//
// SSRF defense: the HTTP client uses validation.SafeHTTPDialContext so
// dial-time DNS resolution is checked against the reserved-IP filter
// (defends against DNS rebinding); the URL is also validated up-front
// via validation.ValidateSafeURL for an early diagnostic.
//
// The probe accumulates persistent history in scep_probe_results
// (migration 000021) when SetSCEPProbeRepo wired a repo at startup;
// otherwise the probe runs and returns its result without persisting.

// scepProbeTimeout caps a single probe at 30s. The probe issues at
// most 2-3 GETs against the target, each with default Go HTTP-client
// behavior (single connection, no retries) — 30s is generous for
// reachable servers and bounds the wait for unreachable / hung ones.
const scepProbeTimeout = 30 * time.Second

// scepProbeUserAgent identifies certctl in the target server's logs so
// operators running the probe see a clear source attribution.
const scepProbeUserAgent = "certctl-network-scan/scep-probe"

// ProbeSCEP probes the given URL as an SCEP server and returns a
// structured posture snapshot. The result is also persisted via
// SetSCEPProbeRepo (when configured) so the GUI can render recent
// probe history.
//
// Validation order:
//
//  1. validation.ValidateSafeURL — catches obvious SSRF targets
//     (loopback / link-local / cloud-metadata literals) before any
//     network call. Cheap early diagnostic.
//  2. The HTTP transport's DialContext (SafeHTTPDialContext) re-
//     resolves the target host at dial time and re-checks reserved
//     IPs. Defends against DNS-rebinding (the URL passes step 1 but
//     resolves to a reserved IP at dial time).
//  3. The probe issues GET ?operation=GetCACaps and GET ?operation=GetCACert.
//     GetCACert can return either a single DER cert OR a PKCS#7
//     SignedData certs-only envelope (RFC 8894 §3.5.1). The probe
//     handles both.
func (s *NetworkScanService) ProbeSCEP(ctx context.Context, rawURL string) (*domain.SCEPProbeResult, error) {
	id := s.scepProbeID()
	now := s.nowFnOrDefault()
	started := now()
	result := &domain.SCEPProbeResult{
		ID:        id,
		TargetURL: rawURL,
		ProbedAt:  started,
	}

	// Step 1: cheap up-front URL validation (SSRF early diagnostic).
	// Defaults to validation.ValidateSafeURL; tests inject a permissive
	// validator via service-level field so they can hit httptest
	// loopback servers (which the production validator correctly
	// rejects). Mirrors the webhook notifier's `newForTest` pattern.
	validateURL := s.scepValidateURL
	if validateURL == nil {
		validateURL = validation.ValidateSafeURL
	}
	if err := validateURL(rawURL); err != nil {
		result.Reachable = false
		result.Error = "url validation: " + err.Error()
		result.ProbeDurationMs = time.Since(started).Milliseconds()
		s.persistProbeResult(ctx, result)
		return result, fmt.Errorf("scep probe: validate url: %w", err)
	}

	// Normalize the base URL — strip any trailing query string so we
	// can append ?operation=... unambiguously.
	parsed, err := url.Parse(rawURL)
	if err != nil {
		result.Reachable = false
		result.Error = "url parse: " + err.Error()
		result.ProbeDurationMs = time.Since(started).Milliseconds()
		s.persistProbeResult(ctx, result)
		return result, fmt.Errorf("scep probe: parse url: %w", err)
	}
	parsed.RawQuery = ""
	baseURL := parsed.String()

	client := s.scepProbeClient()

	// Step 2: GetCACaps — newline-separated capability list.
	caps, capsErr := s.scepGetCACaps(ctx, client, baseURL)
	if capsErr != nil {
		result.Reachable = false
		result.Error = "GetCACaps: " + capsErr.Error()
		result.ProbeDurationMs = time.Since(started).Milliseconds()
		s.persistProbeResult(ctx, result)
		return result, capsErr
	}
	result.Reachable = true
	result.AdvertisedCaps = caps
	for _, c := range caps {
		switch strings.TrimSpace(c) {
		case "SCEPStandard":
			result.SupportsRFC8894 = true
		case "AES":
			result.SupportsAES = true
		case "POSTPKIOperation":
			result.SupportsPOSTOperation = true
		case "Renewal":
			result.SupportsRenewal = true
		case "SHA-256":
			result.SupportsSHA256 = true
		case "SHA-512":
			result.SupportsSHA512 = true
		}
	}

	// Step 3: GetCACert — DER cert OR PKCS#7 SignedData certs-only envelope.
	certs, certErr := s.scepGetCACert(ctx, client, baseURL)
	if certErr != nil {
		// Non-fatal: server reached + caps parsed, but CA cert fetch
		// failed. Operator gets caps + the error explaining the CA
		// cert state.
		result.Error = "GetCACert: " + certErr.Error()
	} else if len(certs) > 0 {
		result.CACertChainLength = len(certs)
		leaf := certs[0]
		result.CACertSubject = leaf.Subject.String()
		result.CACertIssuer = leaf.Issuer.String()
		result.CACertNotBefore = leaf.NotBefore
		result.CACertNotAfter = leaf.NotAfter
		nowVal := now()
		result.CACertExpired = nowVal.After(leaf.NotAfter)
		if !result.CACertExpired {
			result.CACertDaysToExpiry = int(leaf.NotAfter.Sub(nowVal).Hours() / 24)
		}
		result.CACertAlgorithm = describeCertAlgorithm(leaf)
	}

	result.ProbeDurationMs = time.Since(started).Milliseconds()
	s.persistProbeResult(ctx, result)
	return result, nil
}

// scepGetCACaps fetches GET ?operation=GetCACaps and parses the
// newline-separated capability list. Lines are trimmed of CRLF; empty
// lines are skipped. Per RFC 8894 §3.5.2 the response Content-Type is
// text/plain with one capability per line.
func (s *NetworkScanService) scepGetCACaps(ctx context.Context, client *http.Client, baseURL string) ([]string, error) {
	url := baseURL + "?operation=GetCACaps"
	body, err := s.scepHTTPGet(ctx, client, url)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// scepGetCACert fetches GET ?operation=GetCACert and parses the
// returned cert(s). RFC 8894 §3.5.1: the response is either:
//
//   - A single DER-encoded X.509 cert (Content-Type
//     application/x-x509-ca-cert) when the CA has a single cert.
//   - A PKCS#7 SignedData certs-only envelope (Content-Type
//     application/x-x509-ca-ra-cert) when the CA returns multiple
//     certs (CA + RA, or CA chain).
//
// We attempt the PKCS#7 parse first, fall back to single-cert DER
// parse if that fails. Returns the cert chain in order (CA leaf first).
func (s *NetworkScanService) scepGetCACert(ctx context.Context, client *http.Client, baseURL string) ([]*x509.Certificate, error) {
	url := baseURL + "?operation=GetCACert"
	body, err := s.scepHTTPGet(ctx, client, url)
	if err != nil {
		return nil, err
	}

	// Try PKCS#7 SignedData first — the multi-cert form. ParseSignedData
	// already decodes each embedded cert into *x509.Certificate, so we
	// just take the slice as-is.
	if signed, p7Err := pkcs7.ParseSignedData(body); p7Err == nil && len(signed.Certificates) > 0 {
		return signed.Certificates, nil
	}

	// Fall back to single DER cert (or a PEM-wrapped cert from a
	// non-conforming server — try both).
	if c, err := x509.ParseCertificate(body); err == nil {
		return []*x509.Certificate{c}, nil
	}
	if block, _ := pem.Decode(body); block != nil {
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			return []*x509.Certificate{c}, nil
		}
	}
	return nil, errors.New("could not parse GetCACert response as DER, PEM, or PKCS#7 SignedData")
}

// scepHTTPGet issues a single GET with the probe's user agent + the
// SSRF-defended HTTP client. Reads the body up to 1MB to defend against
// a huge-response DoS from a misbehaving target.
//
// Defense in depth (CodeQL #23 / CWE-918 SSRF):
//
//   - The HTTP client's transport is built with validation.SafeHTTPDialContext
//     (see scepProbeClient below). Every dial — including any dial along a
//     redirect chain — re-resolves the host and rejects connections to
//     reserved IP ranges (loopback, RFC 1918, link-local, multicast,
//     CGNAT, IPv6 ULAs, etc.). This is the authoritative SSRF + DNS-
//     rebinding guard; even if an attacker bypassed the upstream URL
//     validator, the dial would still fail.
//
//   - In addition to the dial-time guard, this function re-runs
//     validation.ValidateSafeURL on the URL right before the request
//     is built. The validator is already invoked at ProbeSCEP entry,
//     but re-running it here:
//     (a) Closes CodeQL go/request-forgery — the analyzer's taint
//     tracker now sees the sanitizer in the same function as the
//     sink (client.Do).
//     (b) Catches any future call site that wires a URL into
//     scepHTTPGet without going through ProbeSCEP. If anyone adds
//     such a path the validator catches the regression at the
//     sink — fail-closed by default.
//     (c) Is cheap (a single parse + reserved-IP lookup; the URL is
//     already parsed once upstream so the OS DNS cache likely
//     still has the answer).
//
//   - When the service is configured with a permissive validator
//     (scepValidateURL — set by tests targeting httptest loopback
//     servers), the same permissive validator applies here. Production
//     callers leave scepValidateURL nil so validation.ValidateSafeURL
//     is the active gate.
func (s *NetworkScanService) scepHTTPGet(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	validateURL := s.scepValidateURL
	if validateURL == nil {
		validateURL = validation.ValidateSafeURL
	}
	if err := validateURL(rawURL); err != nil {
		return nil, fmt.Errorf("validate url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", scepProbeUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}

// scepProbeClient returns the lazily-built SSRF-defended HTTP client.
// Built once per service lifetime; the transport reuses connections.
func (s *NetworkScanService) scepProbeClient() *http.Client {
	if s.scepHTTPClient != nil {
		return s.scepHTTPClient
	}
	transport := &http.Transport{
		DialContext:           validation.SafeHTTPDialContext(scepProbeTimeout),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	s.scepHTTPClient = &http.Client{
		Timeout:   scepProbeTimeout,
		Transport: transport,
	}
	return s.scepHTTPClient
}

// scepProbeID returns a fresh ID for a probe row. Defaults to
// "spr-<uuid>"; tests can inject a deterministic generator via
// (NetworkScanService).scepIDFn.
func (s *NetworkScanService) scepProbeID() string {
	if s.scepIDFn != nil {
		return s.scepIDFn()
	}
	return "spr-" + uuid.New().String()
}

// nowFnOrDefault returns the configured clock (for test injection) or
// time.Now if unset. Used so the probe's two NotAfter comparisons
// (CACertExpired + ProbedAt) share a single observation point.
func (s *NetworkScanService) nowFnOrDefault() func() time.Time {
	if s.nowFn != nil {
		return s.nowFn
	}
	return time.Now
}

// persistProbeResult writes the probe outcome to scep_probe_results
// when a repo was wired. Failure to persist is logged but doesn't
// fail the caller — the probe's primary contract is "run + return"
// not "run + persist". Operators get the result regardless.
func (s *NetworkScanService) persistProbeResult(ctx context.Context, result *domain.SCEPProbeResult) {
	if s.scepProbeRepo == nil {
		return
	}
	if err := s.scepProbeRepo.Insert(ctx, result); err != nil && s.logger != nil {
		s.logger.Warn("scep probe result persist failed (probe still returned to caller)",
			"target_url", result.TargetURL,
			"id", result.ID,
			"error", err)
	}
}

// ListRecentSCEPProbes returns the most recent N probe rows. Thin
// wrapper around the repository so the handler depends on the service
// surface, not the repo directly. Returns empty slice (not nil) when
// no repo is wired so JSON marshaling stays clean.
func (s *NetworkScanService) ListRecentSCEPProbes(ctx context.Context, limit int) ([]*domain.SCEPProbeResult, error) {
	if s.scepProbeRepo == nil {
		return []*domain.SCEPProbeResult{}, nil
	}
	return s.scepProbeRepo.ListRecent(ctx, limit)
}

// describeCertAlgorithm returns a short, operator-friendly description
// of the cert's public key algorithm + size. Examples:
//   - "RSA-2048" / "RSA-3072" / "RSA-4096"
//   - "ECDSA-P256" / "ECDSA-P384" / "ECDSA-P521"
//   - "Ed25519"
//   - "" for unrecognized algorithms.
func describeCertAlgorithm(c *x509.Certificate) string {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		// Curve is embedded in ecdsa.PublicKey; check the interface
		// itself for nil before calling Params() via promotion (QF1008
		// — staticcheck wants the promoted-method form, not the
		// chained selector). Still need the nil check because
		// calling Params() on a nil embedded interface would panic.
		if pub.Curve != nil {
			if params := pub.Params(); params != nil {
				return "ECDSA-" + params.Name
			}
		}
		return "ECDSA"
	}
	switch c.PublicKeyAlgorithm {
	case x509.Ed25519:
		return "Ed25519"
	case x509.DSA:
		return "DSA"
	}
	return ""
}
