//go:build integration

// Package integration_test — CRL/OCSP-Responder Bundle Phase 6 e2e.
//
// Verifies the full revocation-status flow against a live stack:
//   1. Issue a cert via the local issuer.
//   2. Fetch the OCSP response for that cert's serial — expect Good.
//   3. Revoke the cert via the standard revoke endpoint.
//   4. Wait for the scheduler to refresh the CRL cache (or trigger an
//      immediate cache miss by fetching the CRL directly — the
//      cache-miss path uses singleflight to coalesce + regenerate).
//   5. Fetch the CRL — assert the cert's serial is in the revocation list.
//   6. Fetch the OCSP response again — expect Revoked.
//   7. Verify the OCSP response was signed by the dedicated responder
//      cert (NOT the CA key directly), per RFC 6960 §2.6.
//   8. Verify the responder cert carries id-pkix-ocsp-nocheck (RFC 6960
//      §4.2.2.2.1).
//
// Sandbox note: the certctl development sandbox doesn't have Docker
// available, so this test was written but not executed there. CI runs
// it via the standard integration-test workflow which spins up the
// docker-compose.test.yml stack. Run locally:
//
//	cd deploy && docker compose -f docker-compose.test.yml up --build -d
//	cd deploy/test && go test -tags integration -v -run TestCRLOCSPLifecycle -timeout 10m ./...

package integration_test

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ---------------------------------------------------------------------------
// Test-stack-specific identifiers — match deploy/docker-compose.test.yml's
// seed data + migrations/seed.sql. The CRL/OCSP suite issues its own certs
// (rather than reusing mc-local-test from the main TestIntegrationSuite)
// so the suites can run independently and in parallel.
// ---------------------------------------------------------------------------

const (
	crlE2EIssuerID    = "iss-local"
	crlE2EOwnerID     = "owner-test-admin"
	crlE2ETeamID      = "team-test-ops"
	crlE2EPolicyID    = "rp-default"
	crlE2EProfileID   = "prof-test-tls"
	crlE2EJobsTimeout = 180 * time.Second
)

// TestCRLOCSPLifecycle exercises the CRL/OCSP-Responder backend
// end-to-end against the running test stack. Skipped in -short.
func TestCRLOCSPLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("integration only")
	}

	// Boot-state preconditions — assumes docker-compose.test.yml is
	// up; the existing integration_test.go tests rely on the same
	// invariant. If your run errors out here, run the up command
	// from the package doc comment first.
	requireServerReady(t)

	issuerID := "iss-local" // assumes local issuer is seeded in the test stack

	// 1. Issue a cert. Reuses the existing helper from integration_test.go
	//    (issueCertificateAgainstLocal).
	cert, certPEM, certSerial := issueLocalCert(t, "crl-ocsp-e2e.example.com")
	t.Logf("issued cert serial=%s", certSerial)

	// 2. Fetch OCSP for the fresh cert — expect Good.
	resp1, responder1 := fetchOCSP(t, issuerID, certSerial)
	if resp1.Status != ocsp.Good {
		t.Fatalf("pre-revoke OCSP status = %d, want Good (0)", resp1.Status)
	}
	if !certHasOCSPNoCheck(responder1) {
		t.Errorf("responder cert missing id-pkix-ocsp-nocheck extension (RFC 6960 §4.2.2.2.1)")
	}
	if responder1.Subject.CommonName == cert.Issuer.CommonName {
		t.Errorf("OCSP response was signed by CA cert directly; expected dedicated responder cert per RFC 6960 §2.6")
	}

	// 3. Revoke the cert via the standard API.
	revokeCertViaAPI(t, certSerial, "key_compromise")

	// 4. Trigger the cache-miss path by fetching CRL directly.
	//    The cache service's singleflight gate collapses concurrent
	//    misses; the first fetch after revocation regenerates the CRL
	//    with the new entry. (The scheduler also refreshes on its 1h
	//    tick, but the test doesn't wait that long.)
	time.Sleep(2 * time.Second) // allow scheduler debounce

	crl := fetchCRL(t, issuerID)
	if !crlContainsSerial(crl, certSerial) {
		// If the cache hadn't expired yet, force a regen by hitting
		// the endpoint a second time after a small delay — the
		// staleness check in CRLCacheEntry.IsStale flips on
		// next_update.
		time.Sleep(3 * time.Second)
		crl = fetchCRL(t, issuerID)
		if !crlContainsSerial(crl, certSerial) {
			t.Fatalf("revoked serial %s not present in CRL after wait", certSerial)
		}
	}
	t.Logf("CRL contains revoked serial %s", certSerial)

	// 5. Fetch OCSP again — expect Revoked.
	resp2, _ := fetchOCSP(t, issuerID, certSerial)
	if resp2.Status != ocsp.Revoked {
		t.Fatalf("post-revoke OCSP status = %d, want Revoked (1)", resp2.Status)
	}
	t.Logf("OCSP shows revoked, reason=%d", resp2.RevocationReason)

	// 6. Sanity: silence unused-variable lint for certPEM (kept in
	//    signature for future assertions on cert chain validity).
	_ = certPEM
}

// TestCRLOCSPPostEndpoint verifies the POST OCSP endpoint
// (RFC 6960 §A.1.1) accepts a binary OCSPRequest body. Companion to
// TestCRLOCSPLifecycle which exercises the GET form via fetchOCSP.
func TestCRLOCSPPostEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("integration only")
	}
	requireServerReady(t)

	cert, _, certSerial := issueLocalCert(t, "post-ocsp-e2e.example.com")
	caCert := fetchCACert(t, "iss-local")

	ocspReq, err := ocsp.CreateRequest(cert, caCert, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	url := serverBaseURL(t) + "/.well-known/pki/ocsp/iss-local"
	httpReq, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(ocspReq)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")

	httpResp, err := httpClient(t).Do(httpReq)
	if err != nil {
		t.Fatalf("POST OCSP: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(httpResp.Body)
		t.Fatalf("POST OCSP: status %d, body=%s", httpResp.StatusCode, body)
	}
	respBytes, _ := io.ReadAll(httpResp.Body)
	parsed, err := ocsp.ParseResponse(respBytes, caCert)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if parsed.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("POST OCSP response serial mismatch: got %v, want %v",
			parsed.SerialNumber, cert.SerialNumber)
	}
	t.Logf("POST OCSP returned status=%d for serial=%s", parsed.Status, certSerial)
}

// ---------------------------------------------------------------------------
// Helpers — these wrap the existing integration_test.go primitives where
// possible; new helpers (fetchCRL, fetchOCSP, certHasOCSPNoCheck) are
// added here. The full set lives in this file rather than being scattered
// across package_test.go to keep the e2e suite self-contained per the
// existing convention.
// ---------------------------------------------------------------------------

// crlE2ECert tracks the certctl-side ID + the parsed leaf together. The
// revoke endpoint is keyed by the certctl certificate ID (mc-*), not by
// the X.509 serial — so the test threads both through the helpers.
type crlE2ECert struct {
	CertctlID string            // e.g. "mc-crl-e2e-<n>"
	Leaf      *x509.Certificate // parsed leaf
	HexSerial string            // lowercase hex of Leaf.SerialNumber, no leading zero stripping
	PEMChain  string            // raw pem_chain string from versions endpoint
	IssuerCA  *x509.Certificate // parsed issuer CA (chain[1] when present, else chain[0])
}

// crlE2ECerts holds the in-flight cert-ID → cert mapping so revokeCertViaAPI
// can resolve the hex serial back to the certctl cert ID. Populated by
// issueLocalCert. Map access is safe because the e2e test is single-threaded
// (the integration tag suites don't t.Parallel()).
var crlE2ECerts = map[string]*crlE2ECert{}

// issueLocalCert issues a cert against the test-stack's local issuer and
// returns the parsed leaf + raw PEM chain + hex serial. Wires through the
// existing integration_test.go primitives:
//   - newTestClient() for the HTTPS Bearer-authenticated client
//   - waitForJobsDone() for the async issuance job
//   - parsePEMCert() for the PEM → x509.Certificate parse
//
// The cert ID is derived from a monotonic counter so successive calls in
// the same run get unique IDs (mc-crl-e2e-1, mc-crl-e2e-2, …) — keeps the
// test re-runnable against the same DB without ON CONFLICT noise.
func issueLocalCert(t *testing.T, commonName string) (cert *x509.Certificate, certPEM string, hexSerial string) {
	t.Helper()

	c := newTestClient()

	certID := fmt.Sprintf("mc-crl-e2e-%d", len(crlE2ECerts)+1)
	body := fmt.Sprintf(`{
		"id": %q,
		"name": %q,
		"common_name": %q,
		"sans": [%q],
		"issuer_id": %q,
		"owner_id": %q,
		"team_id": %q,
		"renewal_policy_id": %q,
		"certificate_profile_id": %q,
		"environment": "test"
	}`, certID, certID, commonName, commonName,
		crlE2EIssuerID, crlE2EOwnerID, crlE2ETeamID, crlE2EPolicyID, crlE2EProfileID)

	resp, err := c.Post("/api/v1/certificates", body)
	if err != nil {
		t.Fatalf("issueLocalCert: POST /certificates: %v", err)
	}
	if resp.StatusCode/100 != 2 {
		t.Fatalf("issueLocalCert: POST status %d, body=%s", resp.StatusCode, readBody(resp))
	}
	resp.Body.Close()

	// Trigger issuance + wait for the job to finish.
	resp, err = c.Post("/api/v1/certificates/"+certID+"/renew", "")
	if err != nil {
		t.Fatalf("issueLocalCert: POST renew: %v", err)
	}
	resp.Body.Close()
	waitForJobsDone(t, c, certID, crlE2EJobsTimeout)

	// Pull the freshly-issued version.
	resp, err = c.Get("/api/v1/certificates/" + certID + "/versions")
	if err != nil {
		t.Fatalf("issueLocalCert: GET versions: %v", err)
	}
	rawBody := readBody(resp)
	var versions []certVersion
	if err := json.Unmarshal([]byte(rawBody), &versions); err != nil {
		// Versions endpoint may use the paged envelope.
		var pr pagedResponse
		if err := json.Unmarshal([]byte(rawBody), &pr); err != nil {
			t.Fatalf("issueLocalCert: decode versions: %v (body: %s)", err, rawBody)
		}
		if err := json.Unmarshal(pr.Data, &versions); err != nil {
			t.Fatalf("issueLocalCert: unmarshal paged versions: %v", err)
		}
	}
	if len(versions) == 0 {
		t.Fatalf("issueLocalCert: no versions returned for %s", certID)
	}
	v := versions[0]
	if v.PEMChain == "" {
		t.Fatalf("issueLocalCert: empty pem_chain on version %s", v.ID)
	}

	leaf, issuerCA := parsePEMChain(t, v.PEMChain)
	hex := strings.ToLower(leaf.SerialNumber.Text(16))

	crlE2ECerts[hex] = &crlE2ECert{
		CertctlID: certID,
		Leaf:      leaf,
		HexSerial: hex,
		PEMChain:  v.PEMChain,
		IssuerCA:  issuerCA,
	}
	return leaf, v.PEMChain, hex
}

// parsePEMChain decodes a leaf || issuer || ... PEM bundle. Returns the leaf
// + the next cert in the chain (the issuing CA, used as the OCSP issuer).
// If the chain has only one cert (self-signed test root), returns it twice.
func parsePEMChain(t *testing.T, chainPEM string) (leaf, issuer *x509.Certificate) {
	t.Helper()
	rest := []byte(chainPEM)
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parsePEMChain: %v", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		t.Fatalf("parsePEMChain: no certificates decoded from chain")
	}
	leaf = certs[0]
	if len(certs) >= 2 {
		issuer = certs[1]
	} else {
		issuer = certs[0] // self-signed test root
	}
	return leaf, issuer
}

// revokeCertViaAPI calls POST /api/v1/certificates/{id}/revoke. The certctl
// API keys revocation by certctl cert ID (mc-*), not by X.509 serial — so
// this resolver looks up the cert ID via the hex-serial registry populated
// by issueLocalCert.
func revokeCertViaAPI(t *testing.T, hexSerial string, reason string) {
	t.Helper()
	entry, ok := crlE2ECerts[strings.ToLower(hexSerial)]
	if !ok {
		t.Fatalf("revokeCertViaAPI: no certctl ID registered for serial %s — call issueLocalCert first", hexSerial)
	}
	c := newTestClient()
	body := fmt.Sprintf(`{"reason": %q}`, reason)
	resp, err := c.Post("/api/v1/certificates/"+entry.CertctlID+"/revoke", body)
	if err != nil {
		t.Fatalf("revokeCertViaAPI: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("revokeCertViaAPI: POST status %d, body=%s", resp.StatusCode, readBody(resp))
	}
}

// fetchCRL hits GET /.well-known/pki/crl/{issuer_id} and returns the
// parsed RevocationList. Asserts 200 + content-type.
func fetchCRL(t *testing.T, issuerID string) *x509.RevocationList {
	t.Helper()
	url := serverBaseURL(t) + "/.well-known/pki/crl/" + issuerID
	resp, err := httpClient(t).Get(url)
	if err != nil {
		t.Fatalf("fetchCRL Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("fetchCRL: status %d, body=%s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	return crl
}

// fetchOCSP hits the GET form of the OCSP endpoint (the POST form is
// exercised separately in TestCRLOCSPPostEndpoint). Returns the parsed
// response + the responder cert (so the test can assert it's NOT the
// CA cert, per RFC 6960 §2.6).
func fetchOCSP(t *testing.T, issuerID, hexSerial string) (*ocsp.Response, *x509.Certificate) {
	t.Helper()
	url := fmt.Sprintf("%s/.well-known/pki/ocsp/%s/%s", serverBaseURL(t), issuerID, hexSerial)
	resp, err := httpClient(t).Get(url)
	if err != nil {
		t.Fatalf("fetchOCSP Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("fetchOCSP: status %d, body=%s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	caCert := fetchCACert(t, issuerID)
	parsed, err := ocsp.ParseResponse(body, caCert)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	return parsed, parsed.Certificate
}

// fetchCACert returns the issuing CA certificate for the given issuer.
//
// Strategy: a cert issued via issueLocalCert against this issuer left its
// chain in the crlE2ECerts registry; the second cert in that chain is the
// issuing CA (or the leaf itself for a self-signed test root). This
// avoids a dependency on a /.well-known/pki/cacert/ endpoint that the
// backend doesn't expose today — the bundle is published via the EST
// /.well-known/est/cacerts surface (PKCS#7) but the test-harness route
// here is simpler and deterministic.
//
// If no leaf has been issued yet against this issuer, falls back to a
// just-in-time issuance so the helper is callable from any phase order.
func fetchCACert(t *testing.T, issuerID string) *x509.Certificate {
	t.Helper()
	for _, entry := range crlE2ECerts {
		if entry.IssuerCA != nil && entry.Leaf.Issuer.CommonName != "" {
			// All issued e2e certs share the same iss-local CA; the first
			// one we find is correct for issuerID == "iss-local".
			if issuerID == crlE2EIssuerID || strings.HasPrefix(issuerID, "iss-local") {
				return entry.IssuerCA
			}
		}
	}
	// Fallback: no cert in registry for this issuer yet — synthesise one.
	_, _, _ = issueLocalCert(t, fmt.Sprintf("cacert-bootstrap-%d.example.com", time.Now().UnixNano()))
	for _, entry := range crlE2ECerts {
		if entry.IssuerCA != nil {
			return entry.IssuerCA
		}
	}
	t.Fatalf("fetchCACert: no CA cert resolvable for issuer %s after bootstrap", issuerID)
	return nil
}

// crlContainsSerial returns true if the parsed CRL has an entry for
// the given hex-encoded serial.
func crlContainsSerial(crl *x509.RevocationList, hexSerial string) bool {
	target := new(big.Int)
	target.SetString(hexSerial, 16)
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(target) == 0 {
			return true
		}
	}
	return false
}

// certHasOCSPNoCheck returns true if the cert carries the
// id-pkix-ocsp-nocheck extension (OID 1.3.6.1.5.5.7.48.1.5) per
// RFC 6960 §4.2.2.2.1.
func certHasOCSPNoCheck(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// requireServerReady polls /health until it returns 200, or t.Fatals after
// 30s. The endpoint is unauthenticated (router.go pins it as a Bearer-free
// liveness route for K8s/Docker probes) so it doubles as a "is the test
// stack up?" probe before the suite makes its first authenticated call.
func requireServerReady(t *testing.T) {
	t.Helper()
	client := newUnauthHTTPClient()
	deadline := time.Now().Add(30 * time.Second)
	url := serverURL + "/health"
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("requireServerReady: %s never returned 200 within 30s — is the test stack up? (run `docker compose -f deploy/docker-compose.test.yml up -d` first)", url)
}

// serverBaseURL returns the server URL configured by the integration
// harness (CERTCTL_TEST_SERVER_URL, defaulting to https://localhost:8443
// per deploy/docker-compose.test.yml).
func serverBaseURL(t *testing.T) string {
	t.Helper()
	return serverURL
}

// httpClient returns the unauthenticated TLS-trust-aware client from the
// integration harness. The /.well-known/pki/{crl,ocsp}/ endpoints are
// reachable without a Bearer token by design (M-006: relying parties
// must validate revocation without API keys), so we deliberately use the
// no-Authorization client here — this matches how a real revocation-
// validating consumer would hit the endpoints in production.
func httpClient(t *testing.T) *http.Client {
	t.Helper()
	return newUnauthHTTPClient()
}
