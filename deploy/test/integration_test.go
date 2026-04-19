//go:build integration

// Package integration_test provides end-to-end integration tests for the certctl platform.
//
// These tests run against a live Docker Compose environment (certctl server, agent,
// PostgreSQL, Pebble ACME server, step-ca). The test assumes all containers are
// already running and healthy before execution.
//
// Run:
//
//	cd deploy && docker compose -f docker-compose.test.yml up --build -d
//	cd deploy/test && go test -tags integration -v -timeout 10m ./...
package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// ---------------------------------------------------------------------------
// Configuration — all overridable via environment variables
// ---------------------------------------------------------------------------

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var (
	serverURL = envOr("CERTCTL_TEST_SERVER_URL", "http://localhost:8443")
	apiKey    = envOr("CERTCTL_TEST_API_KEY", "test-key-2026")
	dbURL     = envOr("CERTCTL_TEST_DB_URL", "postgres://certctl:testpass@localhost:5432/certctl?sslmode=disable")
	nginxTLS  = envOr("CERTCTL_TEST_NGINX_TLS", "localhost:8444")
)

// ---------------------------------------------------------------------------
// Shared state between phases (populated by earlier phases, consumed by later)
// ---------------------------------------------------------------------------

var (
	localCertCreated  bool
	acmeCertCreated   bool
	stepcaCertCreated bool
	smimeCertCreated  bool
)

// ---------------------------------------------------------------------------
// HTTP test client
// ---------------------------------------------------------------------------

type testClient struct {
	http    *http.Client
	baseURL string
	apiKey  string
}

func newTestClient() *testClient {
	return &testClient{
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: serverURL,
		apiKey:  apiKey,
	}
}

func (c *testClient) do(method, path string, body io.Reader) (*http.Response, error) {
	url := c.baseURL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

func (c *testClient) Get(path string) (*http.Response, error) {
	return c.do("GET", path, nil)
}

func (c *testClient) Post(path string, body string) (*http.Response, error) {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	return c.do("POST", path, r)
}

func (c *testClient) PostRaw(path string, contentType string, body []byte) (*http.Response, error) {
	url := c.baseURL + path
	req, err := http.NewRequest("POST", url, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", contentType)
	return c.http.Do(req)
}

// decodeJSON reads the response body and unmarshals JSON into v.
func decodeJSON(resp *http.Response, v interface{}) error {
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("json unmarshal: %w (body: %s)", err, string(data))
	}
	return nil
}

// readBody reads and returns the response body as a string.
func readBody(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// ---------------------------------------------------------------------------
// JSON response types (lightweight — avoids importing internal packages)
// ---------------------------------------------------------------------------

// pagedResponse mirrors the API's list response envelope.
type pagedResponse struct {
	Data    json.RawMessage `json:"data"`
	Total   int             `json:"total"`
	Page    int             `json:"page"`
	PerPage int             `json:"per_page"`
}

// certResponse is a minimal certificate record for JSON decoding.
type certResponse struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	CommonName           string `json:"common_name"`
	Status               string `json:"status"`
	IssuerID             string `json:"issuer_id"`
	CertificateProfileID string `json:"certificate_profile_id"`
}

// certVersion represents a certificate version with PEM data.
type certVersion struct {
	ID            string `json:"id"`
	CertificateID string `json:"certificate_id"`
	SerialNumber  string `json:"serial_number"`
	PEMChain      string `json:"pem_chain"`
	CSRPEM        string `json:"csr_pem"`
}

// jobResponse is a minimal job record for JSON decoding.
type jobResponse struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	CertificateID string `json:"certificate_id"`
	Status        string `json:"status"`
	LastError     string `json:"last_error"`
}

// agentResponse is a minimal agent record.
type agentResponse struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// metricsResponse for JSON metrics endpoint.
type metricsResponse struct {
	Gauge   map[string]interface{} `json:"gauge"`
	Counter map[string]interface{} `json:"counter"`
	Uptime  float64                `json:"uptime_seconds"`
}

// M-006: The non-standard JSON CRL endpoint (`GET /api/v1/crl`) was removed.
// RFC 5280 §5 defines only the DER wire format, which is now served
// unauthenticated at `/.well-known/pki/crl/{issuer_id}` per RFC 8615.
// The `crlResponse` Go struct that used to decode the JSON envelope is gone;
// Phase 7 parses the DER bytes directly via `x509.ParseRevocationList`.

// ---------------------------------------------------------------------------
// PostgreSQL test helper
// ---------------------------------------------------------------------------

type testDB struct {
	db *sql.DB
}

func newTestDB(t *testing.T) *testDB {
	t.Helper()
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	db.SetMaxOpenConns(2)
	if err := db.Ping(); err != nil {
		t.Fatalf("ping test DB: %v", err)
	}
	return &testDB{db: db}
}

func (d *testDB) Exec(t *testing.T, query string, args ...interface{}) {
	t.Helper()
	if _, err := d.db.Exec(query, args...); err != nil {
		t.Fatalf("db exec: %v\nquery: %s", err, query)
	}
}

func (d *testDB) Close() {
	d.db.Close()
}

// ---------------------------------------------------------------------------
// Polling / wait helper
// ---------------------------------------------------------------------------

// waitFor polls checkFn until it returns true or the timeout expires.
func waitFor(t *testing.T, description string, timeout, interval time.Duration, checkFn func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ok, err := checkFn()
		if err != nil {
			t.Logf("waitFor(%s): check error: %v", description, err)
		}
		if ok {
			return
		}
		time.Sleep(interval)
	}
	t.Fatalf("waitFor(%s): timed out after %v", description, timeout)
}

// waitForJobsDone waits for all jobs for a certificate to reach terminal state.
func waitForJobsDone(t *testing.T, c *testClient, certID string, timeout time.Duration) {
	t.Helper()
	waitFor(t, "jobs done for "+certID, timeout, 5*time.Second, func() (bool, error) {
		resp, err := c.Get("/api/v1/jobs")
		if err != nil {
			return false, err
		}
		var pr pagedResponse
		if err := decodeJSON(resp, &pr); err != nil {
			return false, err
		}
		var jobs []jobResponse
		if err := json.Unmarshal(pr.Data, &jobs); err != nil {
			return false, err
		}

		var total, completed, failed int
		for _, j := range jobs {
			if j.CertificateID != certID {
				continue
			}
			total++
			switch j.Status {
			case "Completed":
				completed++
			case "Failed", "Cancelled":
				failed++
			}
		}

		// No jobs yet — keep waiting
		if total == 0 {
			return false, nil
		}

		// Still have active jobs
		active := total - completed - failed
		if active > 0 {
			return false, nil
		}

		// All terminal — at least one completed?
		if completed > 0 {
			return true, nil
		}

		// All failed
		t.Logf("all %d jobs for %s are in terminal state but none completed", total, certID)
		return false, fmt.Errorf("all jobs failed for %s", certID)
	})
}

// ---------------------------------------------------------------------------
// x509 helpers
// ---------------------------------------------------------------------------

// parsePEMCert parses the first certificate from a PEM string.
func parsePEMCert(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse x509 certificate: %v", err)
	}
	return cert
}

// getTLSCert connects to the given address with the specified SNI and returns the peer cert.
func getTLSCert(t *testing.T, addr, sni string) *x509.Certificate {
	t.Helper()
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp", addr,
		&tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		},
	)
	if err != nil {
		t.Fatalf("TLS dial %s (SNI=%s): %v", addr, sni, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("TLS handshake returned no peer certificates")
	}
	return certs[0]
}

// reloadNGINX sends a reload signal to the NGINX container so it picks up new certs.
func reloadNGINX(t *testing.T) {
	t.Helper()
	cmd := exec.Command("docker", "exec", "certctl-test-nginx", "nginx", "-s", "reload")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("nginx reload: %v (output: %s)", err, string(out))
	}
	time.Sleep(3 * time.Second)
}

// generateCSR creates an ECDSA P-256 key pair and a CSR for the given common name.
func generateCSR(t *testing.T, cn string) (keyPEM, csrDER []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return nil, der // keyPEM not needed for EST test
}

// ---------------------------------------------------------------------------
// Main test suite — phases run sequentially
// ---------------------------------------------------------------------------

func TestIntegrationSuite(t *testing.T) {
	c := newTestClient()
	db := newTestDB(t)
	defer db.Close()

	// -----------------------------------------------------------------------
	// Phase 1: Health Check
	// -----------------------------------------------------------------------
	t.Run("Phase01_HealthCheck", func(t *testing.T) {
		resp, err := c.Get("/health")
		if err != nil {
			t.Fatalf("GET /health: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /health: status %d, want 200", resp.StatusCode)
		}
	})

	// -----------------------------------------------------------------------
	// Phase 2: Agent Heartbeat
	// -----------------------------------------------------------------------
	t.Run("Phase02_AgentHeartbeat", func(t *testing.T) {
		var agent agentResponse
		ok := false
		for i := 0; i < 15; i++ {
			resp, err := c.Get("/api/v1/agents/agent-test-01")
			if err != nil {
				t.Logf("attempt %d: GET agent: %v", i, err)
				time.Sleep(3 * time.Second)
				continue
			}
			if err := decodeJSON(resp, &agent); err != nil {
				t.Logf("attempt %d: decode agent: %v", i, err)
				time.Sleep(3 * time.Second)
				continue
			}
			if strings.EqualFold(agent.Status, "online") {
				ok = true
				break
			}
			time.Sleep(3 * time.Second)
		}
		if !ok {
			t.Skip("agent not yet online (may be slow to heartbeat)")
		}
	})

	// -----------------------------------------------------------------------
	// Phase 3: Verify Pre-Seeded Data
	// -----------------------------------------------------------------------
	t.Run("Phase03_VerifySeeds", func(t *testing.T) {
		// Agents >= 2
		t.Run("Agents", func(t *testing.T) {
			resp, err := c.Get("/api/v1/agents")
			if err != nil {
				t.Fatalf("GET /api/v1/agents: %v", err)
			}
			var pr pagedResponse
			if err := decodeJSON(resp, &pr); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if pr.Total < 2 {
				t.Fatalf("agents: got %d, want >= 2", pr.Total)
			}
		})

		// Issuers >= 3
		t.Run("Issuers", func(t *testing.T) {
			resp, err := c.Get("/api/v1/issuers")
			if err != nil {
				t.Fatalf("GET /api/v1/issuers: %v", err)
			}
			var pr pagedResponse
			if err := decodeJSON(resp, &pr); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if pr.Total < 3 {
				t.Fatalf("issuers: got %d, want >= 3", pr.Total)
			}
		})

		// Targets >= 1
		t.Run("Targets", func(t *testing.T) {
			resp, err := c.Get("/api/v1/targets")
			if err != nil {
				t.Fatalf("GET /api/v1/targets: %v", err)
			}
			var pr pagedResponse
			if err := decodeJSON(resp, &pr); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if pr.Total < 1 {
				t.Fatalf("targets: got %d, want >= 1", pr.Total)
			}
		})

		// Profiles >= 2
		t.Run("Profiles", func(t *testing.T) {
			resp, err := c.Get("/api/v1/profiles")
			if err != nil {
				t.Fatalf("GET /api/v1/profiles: %v", err)
			}
			var pr pagedResponse
			if err := decodeJSON(resp, &pr); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if pr.Total < 2 {
				t.Fatalf("profiles: got %d, want >= 2", pr.Total)
			}
		})
	})

	// -----------------------------------------------------------------------
	// Phase 4: Local CA Issuance
	// -----------------------------------------------------------------------
	t.Run("Phase04_LocalCA_Issuance", func(t *testing.T) {
		// Create certificate record
		resp, err := c.Post("/api/v1/certificates", `{
			"id": "mc-local-test",
			"name": "local-test-cert",
			"common_name": "local.certctl.test",
			"sans": ["local.certctl.test"],
			"issuer_id": "iss-local",
			"owner_id": "owner-test-admin",
			"team_id": "team-test-ops",
			"renewal_policy_id": "rp-default",
			"certificate_profile_id": "prof-test-tls",
			"environment": "development"
		}`)
		if err != nil {
			t.Fatalf("POST certificate: %v", err)
		}
		var cert certResponse
		if err := decodeJSON(resp, &cert); err != nil {
			t.Fatalf("decode cert response: %v", err)
		}
		if cert.ID != "mc-local-test" {
			t.Fatalf("cert ID: got %q, want mc-local-test", cert.ID)
		}
		localCertCreated = true

		// Link certificate to NGINX target
		db.Exec(t, "INSERT INTO certificate_target_mappings (certificate_id, target_id) VALUES ('mc-local-test', 'target-test-nginx') ON CONFLICT DO NOTHING")

		// Trigger issuance
		resp, err = c.Post("/api/v1/certificates/mc-local-test/renew", "")
		if err != nil {
			t.Fatalf("trigger issuance: %v", err)
		}
		body := readBody(resp)
		if !strings.Contains(body, "renewal_triggered") && !strings.Contains(body, "status") {
			t.Fatalf("trigger response unexpected: %s", body)
		}

		// Verify a job was created
		time.Sleep(2 * time.Second)
		resp, err = c.Get("/api/v1/jobs")
		if err != nil {
			t.Fatalf("GET jobs: %v", err)
		}
		var pr pagedResponse
		if err := decodeJSON(resp, &pr); err != nil {
			t.Fatalf("decode jobs: %v", err)
		}
		var jobs []jobResponse
		if err := json.Unmarshal(pr.Data, &jobs); err != nil {
			t.Fatalf("unmarshal jobs: %v", err)
		}
		jobCount := 0
		for _, j := range jobs {
			if j.CertificateID == "mc-local-test" {
				jobCount++
			}
		}
		if jobCount == 0 {
			t.Fatal("no jobs created for mc-local-test")
		}

		// Wait for jobs to complete
		waitForJobsDone(t, c, "mc-local-test", 180*time.Second)

		// Reload NGINX and verify TLS
		reloadNGINX(t)

		t.Run("VerifyNGINXTLS", func(t *testing.T) {
			cert := getTLSCert(t, nginxTLS, "local.certctl.test")

			// Check subject or SAN matches
			matched := cert.Subject.CommonName == "local.certctl.test"
			if !matched {
				for _, dns := range cert.DNSNames {
					if dns == "local.certctl.test" {
						matched = true
						break
					}
				}
			}
			if !matched {
				t.Errorf("NGINX cert does not match local.certctl.test: CN=%s, DNSNames=%v",
					cert.Subject.CommonName, cert.DNSNames)
			}
		})

		// Verify cert status in API
		t.Run("CertStatusActive", func(t *testing.T) {
			resp, err := c.Get("/api/v1/certificates/mc-local-test")
			if err != nil {
				t.Fatalf("GET cert: %v", err)
			}
			var cr certResponse
			if err := decodeJSON(resp, &cr); err != nil {
				t.Fatalf("decode cert: %v", err)
			}
			if cr.Status != "Active" {
				t.Logf("cert status: %s (expected Active, may need more time)", cr.Status)
			}
		})
	})

	// -----------------------------------------------------------------------
	// Phase 5: ACME (Pebble) Issuance
	// -----------------------------------------------------------------------
	t.Run("Phase05_ACME_Issuance", func(t *testing.T) {
		resp, err := c.Post("/api/v1/certificates", `{
			"id": "mc-acme-test",
			"name": "acme-test-cert",
			"common_name": "acme.certctl.test",
			"sans": ["acme.certctl.test"],
			"issuer_id": "iss-acme-staging",
			"owner_id": "owner-test-admin",
			"team_id": "team-test-ops",
			"renewal_policy_id": "rp-default",
			"certificate_profile_id": "prof-test-tls",
			"environment": "staging"
		}`)
		if err != nil {
			t.Fatalf("POST certificate: %v", err)
		}
		var cert certResponse
		if err := decodeJSON(resp, &cert); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if cert.ID != "mc-acme-test" {
			t.Fatalf("cert ID: got %q, want mc-acme-test", cert.ID)
		}
		acmeCertCreated = true

		// Link to target + trigger
		db.Exec(t, "INSERT INTO certificate_target_mappings (certificate_id, target_id) VALUES ('mc-acme-test', 'target-test-nginx') ON CONFLICT DO NOTHING")

		resp, err = c.Post("/api/v1/certificates/mc-acme-test/renew", "")
		if err != nil {
			t.Fatalf("trigger: %v", err)
		}
		body := readBody(resp)
		if !strings.Contains(body, "renewal_triggered") && !strings.Contains(body, "status") {
			t.Fatalf("unexpected trigger response: %s", body)
		}

		// Wait for completion
		waitForJobsDone(t, c, "mc-acme-test", 180*time.Second)

		// Reload NGINX and verify TLS
		reloadNGINX(t)
		tlsCert := getTLSCert(t, nginxTLS, "acme.certctl.test")

		matched := false
		for _, dns := range tlsCert.DNSNames {
			if dns == "acme.certctl.test" {
				matched = true
				break
			}
		}
		if !matched && tlsCert.Subject.CommonName == "acme.certctl.test" {
			matched = true
		}
		if !matched {
			t.Errorf("NGINX cert does not match acme.certctl.test: CN=%s, DNSNames=%v",
				tlsCert.Subject.CommonName, tlsCert.DNSNames)
		}
	})

	// -----------------------------------------------------------------------
	// Phase 6: step-ca Issuance
	// -----------------------------------------------------------------------
	t.Run("Phase06_StepCA_Issuance", func(t *testing.T) {
		resp, err := c.Post("/api/v1/certificates", `{
			"id": "mc-stepca-test",
			"name": "stepca-test-cert",
			"common_name": "stepca.certctl.test",
			"sans": ["stepca.certctl.test"],
			"issuer_id": "iss-stepca",
			"owner_id": "owner-test-admin",
			"team_id": "team-test-ops",
			"renewal_policy_id": "rp-default",
			"certificate_profile_id": "prof-test-tls",
			"environment": "staging"
		}`)
		if err != nil {
			t.Fatalf("POST certificate: %v", err)
		}
		var cert certResponse
		if err := decodeJSON(resp, &cert); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if cert.ID != "mc-stepca-test" {
			t.Fatalf("cert ID: got %q, want mc-stepca-test", cert.ID)
		}
		stepcaCertCreated = true

		db.Exec(t, "INSERT INTO certificate_target_mappings (certificate_id, target_id) VALUES ('mc-stepca-test', 'target-test-nginx') ON CONFLICT DO NOTHING")

		resp, err = c.Post("/api/v1/certificates/mc-stepca-test/renew", "")
		if err != nil {
			t.Fatalf("trigger: %v", err)
		}
		body := readBody(resp)
		if !strings.Contains(body, "renewal_triggered") && !strings.Contains(body, "status") {
			t.Fatalf("unexpected trigger response: %s", body)
		}

		waitForJobsDone(t, c, "mc-stepca-test", 120*time.Second)
	})

	// -----------------------------------------------------------------------
	// Phase 7: Revocation
	// -----------------------------------------------------------------------
	t.Run("Phase07_Revocation", func(t *testing.T) {
		if !localCertCreated {
			t.Skip("depends on Phase04 (Local CA cert not created)")
		}

		// Revoke mc-local-test
		resp, err := c.Post("/api/v1/certificates/mc-local-test/revoke", `{"reason": "superseded"}`)
		if err != nil {
			t.Fatalf("revoke: %v", err)
		}
		body := readBody(resp)
		if !strings.Contains(strings.ToLower(body), "revoked") && !strings.Contains(body, "status") {
			t.Fatalf("revocation response unexpected: %s", body)
		}

		// Check DER CRL served unauthenticated under /.well-known/pki/ per
		// RFC 5280 §5 + RFC 8615 (M-006). Use a plain http.Get — no Bearer
		// token — to prove the endpoint is reachable by relying parties that
		// have no certctl API credentials.
		t.Run("CRL_DER_Unauthenticated", func(t *testing.T) {
			resp, err := http.Get(serverURL + "/.well-known/pki/crl/iss-local")
			if err != nil {
				t.Fatalf("GET DER CRL: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("unexpected status: got %d, want 200 (body=%s)", resp.StatusCode, string(body))
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/pkix-crl" {
				t.Errorf("Content-Type: got %q, want %q", ct, "application/pkix-crl")
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read CRL body: %v", err)
			}
			if len(body) == 0 {
				t.Fatal("CRL body empty")
			}

			// Parse the DER bytes as an X.509 CRL (RFC 5280) and verify the
			// just-revoked certificate is listed.
			crl, err := x509.ParseRevocationList(body)
			if err != nil {
				t.Fatalf("parse DER CRL: %v", err)
			}
			if len(crl.RevokedCertificateEntries) < 1 {
				t.Fatalf("CRL entries: got %d, want >= 1", len(crl.RevokedCertificateEntries))
			}
		})

		// Verify cert status is Revoked
		t.Run("StatusRevoked", func(t *testing.T) {
			resp, err := c.Get("/api/v1/certificates/mc-local-test")
			if err != nil {
				t.Fatalf("GET cert: %v", err)
			}
			var cr certResponse
			if err := decodeJSON(resp, &cr); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if cr.Status != "Revoked" {
				t.Errorf("cert status: got %q, want Revoked", cr.Status)
			}
		})
	})

	// -----------------------------------------------------------------------
	// Phase 8: Certificate Discovery
	// -----------------------------------------------------------------------
	t.Run("Phase08_Discovery", func(t *testing.T) {
		resp, err := c.Get("/api/v1/discovered-certificates")
		if err != nil {
			t.Fatalf("GET discovered-certificates: %v", err)
		}
		var pr pagedResponse
		if err := decodeJSON(resp, &pr); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if pr.Total < 1 {
			t.Skip("no discovered certificates yet (agent scan may not have run)")
		}
		t.Logf("discovered %d certificate(s)", pr.Total)

		// Check discovery summary
		resp, err = c.Get("/api/v1/discovery-summary")
		if err != nil {
			t.Fatalf("GET discovery-summary: %v", err)
		}
		body := readBody(resp)
		t.Logf("discovery summary: %s", body)
	})

	// -----------------------------------------------------------------------
	// Phase 9: Renewal (re-issue step-ca or ACME cert)
	// -----------------------------------------------------------------------
	t.Run("Phase09_Renewal", func(t *testing.T) {
		// Find an Active cert to renew (mc-local-test was revoked)
		var renewalCert string
		for _, candidate := range []string{"mc-stepca-test", "mc-acme-test"} {
			resp, err := c.Get("/api/v1/certificates/" + candidate)
			if err != nil {
				continue
			}
			var cr certResponse
			if err := decodeJSON(resp, &cr); err != nil {
				continue
			}
			if cr.Status == "Active" {
				renewalCert = candidate
				break
			}
		}
		if renewalCert == "" {
			t.Skip("no certificate in Active state for renewal test")
		}

		t.Logf("using %s for renewal test", renewalCert)

		// Trigger renewal
		resp, err := c.Post("/api/v1/certificates/"+renewalCert+"/renew", "")
		if err != nil {
			t.Fatalf("trigger renewal: %v", err)
		}
		body := readBody(resp)
		if !strings.Contains(body, "renewal_triggered") && !strings.Contains(body, "status") {
			t.Skipf("renewal trigger returned: %s", body)
		}

		// Wait for completion
		waitForJobsDone(t, c, renewalCert, 180*time.Second)

		// Verify version history shows >= 2 versions
		resp, err = c.Get("/api/v1/certificates/" + renewalCert + "/versions")
		if err != nil {
			t.Fatalf("GET versions: %v", err)
		}
		// Versions endpoint may return array or paged response
		body = readBody(resp)

		// Try as array first
		var versions []certVersion
		if err := json.Unmarshal([]byte(body), &versions); err != nil {
			// Try as paged response
			var pr pagedResponse
			if err := json.Unmarshal([]byte(body), &pr); err != nil {
				t.Fatalf("decode versions: %v", err)
			}
			if err := json.Unmarshal(pr.Data, &versions); err != nil {
				t.Fatalf("unmarshal versions data: %v", err)
			}
		}
		if len(versions) < 2 {
			t.Logf("expected >= 2 versions, got %d", len(versions))
		}
	})

	// -----------------------------------------------------------------------
	// Phase 10: EST Enrollment (RFC 7030)
	// -----------------------------------------------------------------------
	t.Run("Phase10_EST_Enrollment", func(t *testing.T) {
		// Test cacerts
		t.Run("CACerts", func(t *testing.T) {
			resp, err := c.Get("/.well-known/est/cacerts")
			if err != nil {
				t.Fatalf("GET cacerts: %v", err)
			}
			body := readBody(resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("cacerts status: %d, body: %s", resp.StatusCode, body)
			}
			// Should be valid base64 (PKCS#7)
			if _, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body)); err != nil {
				t.Fatalf("cacerts is not valid base64: %v", err)
			}
		})

		// Test csrattrs
		t.Run("CSRAttrs", func(t *testing.T) {
			resp, err := c.Get("/.well-known/est/csrattrs")
			if err != nil {
				t.Fatalf("GET csrattrs: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
				t.Fatalf("csrattrs status: %d, want 200 or 204", resp.StatusCode)
			}
		})

		// Test simpleenroll
		t.Run("SimpleEnroll", func(t *testing.T) {
			_, csrDER := generateCSR(t, "est-device.certctl.test")
			csrB64 := base64.StdEncoding.EncodeToString(csrDER)

			resp, err := c.PostRaw("/.well-known/est/simpleenroll", "application/pkcs10", []byte(csrB64))
			if err != nil {
				t.Fatalf("POST simpleenroll: %v", err)
			}
			body := readBody(resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("simpleenroll status: %d, body: %s", resp.StatusCode, body)
			}
			// Response should be valid base64 (PKCS#7 with issued cert)
			if _, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body)); err != nil {
				t.Fatalf("simpleenroll response is not valid base64: %v", err)
			}
		})

		// Test simplereenroll
		t.Run("SimpleReEnroll", func(t *testing.T) {
			_, csrDER := generateCSR(t, "est-device.certctl.test")
			csrB64 := base64.StdEncoding.EncodeToString(csrDER)

			resp, err := c.PostRaw("/.well-known/est/simplereenroll", "application/pkcs10", []byte(csrB64))
			if err != nil {
				t.Fatalf("POST simplereenroll: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("simplereenroll status: %d, want 200", resp.StatusCode)
			}
		})
	})

	// -----------------------------------------------------------------------
	// Phase 11: S/MIME Certificate Issuance
	// -----------------------------------------------------------------------
	t.Run("Phase11_SMIME_Issuance", func(t *testing.T) {
		// Create S/MIME cert record
		resp, err := c.Post("/api/v1/certificates", `{
			"id": "mc-smime-test",
			"name": "smime-test-cert",
			"common_name": "testuser@certctl.test",
			"sans": ["testuser@certctl.test"],
			"issuer_id": "iss-local",
			"owner_id": "owner-test-admin",
			"team_id": "team-test-ops",
			"renewal_policy_id": "rp-default",
			"certificate_profile_id": "prof-test-smime",
			"environment": "staging"
		}`)
		if err != nil {
			t.Fatalf("POST certificate: %v", err)
		}
		var cert certResponse
		if err := decodeJSON(resp, &cert); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if cert.ID != "mc-smime-test" {
			t.Fatalf("cert ID: got %q, want mc-smime-test", cert.ID)
		}
		smimeCertCreated = true

		// Link to target (needed for agent work routing)
		db.Exec(t, "INSERT INTO certificate_target_mappings (certificate_id, target_id) VALUES ('mc-smime-test', 'target-test-nginx') ON CONFLICT DO NOTHING")

		// Trigger issuance
		resp, err = c.Post("/api/v1/certificates/mc-smime-test/renew", "")
		if err != nil {
			t.Fatalf("trigger: %v", err)
		}
		body := readBody(resp)
		if !strings.Contains(body, "renewal_triggered") && !strings.Contains(body, "status") {
			t.Fatalf("trigger response: %s", body)
		}

		// Wait for issuance
		waitForJobsDone(t, c, "mc-smime-test", 120*time.Second)

		// Fetch the issued cert and verify with crypto/x509
		resp, err = c.Get("/api/v1/certificates/mc-smime-test/versions")
		if err != nil {
			t.Fatalf("GET versions: %v", err)
		}
		versionsBody := readBody(resp)

		var versions []certVersion
		if err := json.Unmarshal([]byte(versionsBody), &versions); err != nil {
			var pr pagedResponse
			if err2 := json.Unmarshal([]byte(versionsBody), &pr); err2 != nil {
				t.Fatalf("decode versions: %v / %v", err, err2)
			}
			if err := json.Unmarshal(pr.Data, &versions); err != nil {
				t.Fatalf("unmarshal versions data: %v", err)
			}
		}

		if len(versions) == 0 {
			t.Fatal("no certificate versions found for mc-smime-test")
		}

		lastVersion := versions[len(versions)-1]
		pemData := lastVersion.PEMChain
		if pemData == "" {
			t.Skip("no PEM data in certificate version")
		}

		x509Cert := parsePEMCert(t, pemData)

		// Verify emailProtection EKU
		t.Run("EKU_EmailProtection", func(t *testing.T) {
			hasEmailProtection := false
			for _, eku := range x509Cert.ExtKeyUsage {
				if eku == x509.ExtKeyUsageEmailProtection {
					hasEmailProtection = true
					break
				}
			}
			if !hasEmailProtection {
				t.Errorf("S/MIME cert missing emailProtection EKU, got: %v", x509Cert.ExtKeyUsage)
			}
		})

		// Verify Digital Signature KeyUsage
		t.Run("KeyUsage_DigitalSignature", func(t *testing.T) {
			if x509Cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
				t.Errorf("S/MIME cert missing DigitalSignature KeyUsage, got: %v", x509Cert.KeyUsage)
			}
		})

		// Verify Content Commitment (Non-Repudiation) KeyUsage
		t.Run("KeyUsage_ContentCommitment", func(t *testing.T) {
			if x509Cert.KeyUsage&x509.KeyUsageContentCommitment == 0 {
				t.Logf("S/MIME cert missing ContentCommitment KeyUsage (non-fatal), got: %v", x509Cert.KeyUsage)
			}
		})

		// Verify email SAN
		t.Run("EmailSAN", func(t *testing.T) {
			hasEmail := false
			for _, email := range x509Cert.EmailAddresses {
				if email == "testuser@certctl.test" {
					hasEmail = true
					break
				}
			}
			if !hasEmail {
				t.Errorf("S/MIME cert missing email SAN testuser@certctl.test, got emails: %v, DNS: %v",
					x509Cert.EmailAddresses, x509Cert.DNSNames)
			}
		})
	})

	// -----------------------------------------------------------------------
	// Phase 12: API Spot Checks
	// -----------------------------------------------------------------------
	t.Run("Phase12_APISpotChecks", func(t *testing.T) {
		// Health (repeat — ensures still up after all operations)
		t.Run("Health", func(t *testing.T) {
			resp, err := c.Get("/health")
			if err != nil {
				t.Fatalf("GET /health: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("health status: %d", resp.StatusCode)
			}
		})

		// JSON Metrics
		t.Run("MetricsJSON", func(t *testing.T) {
			resp, err := c.Get("/api/v1/metrics")
			if err != nil {
				t.Fatalf("GET metrics: %v", err)
			}
			var m metricsResponse
			if err := decodeJSON(resp, &m); err != nil {
				t.Fatalf("decode metrics: %v", err)
			}
			if m.Gauge == nil {
				t.Error("metrics: gauge map is nil")
			}
		})

		// Stats Summary
		t.Run("StatsSummary", func(t *testing.T) {
			resp, err := c.Get("/api/v1/stats/summary")
			if err != nil {
				t.Fatalf("GET stats/summary: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("stats status: %d", resp.StatusCode)
			}
			// Just verify it parses as valid JSON
			var raw json.RawMessage
			if err := decodeJSON(resp, &raw); err != nil {
				t.Fatalf("decode stats: %v", err)
			}
		})

		// Audit Trail
		t.Run("AuditTrail", func(t *testing.T) {
			resp, err := c.Get("/api/v1/audit")
			if err != nil {
				t.Fatalf("GET audit: %v", err)
			}
			var pr pagedResponse
			if err := decodeJSON(resp, &pr); err != nil {
				t.Fatalf("decode audit: %v", err)
			}
			if pr.Total < 1 {
				t.Error("audit trail is empty")
			}
			t.Logf("audit trail: %d events", pr.Total)
		})

		// Jobs summary
		t.Run("JobsTotal", func(t *testing.T) {
			resp, err := c.Get("/api/v1/jobs")
			if err != nil {
				t.Fatalf("GET jobs: %v", err)
			}
			var pr pagedResponse
			if err := decodeJSON(resp, &pr); err != nil {
				t.Fatalf("decode jobs: %v", err)
			}
			t.Logf("total jobs: %d", pr.Total)
		})

		// Prometheus metrics
		t.Run("Prometheus", func(t *testing.T) {
			resp, err := c.Get("/api/v1/metrics/prometheus")
			if err != nil {
				t.Fatalf("GET prometheus: %v", err)
			}
			body := readBody(resp)
			if !strings.Contains(body, "certctl_certificate_total") {
				t.Error("prometheus metrics missing certctl_certificate_total")
			}
		})
	})

	// -----------------------------------------------------------------------
	// Phase 13: I-005 Phase 1 Red — Notification Retry + Dead Letter Queue (E2E)
	//
	// Pins the full retry-loop contract end-to-end. Phase 2 Green must turn
	// every subtest Green with a single coherent change set (migration 000016
	// live, scheduler notificationRetryLoop wired as the 11th loop bumping
	// the total from 10 → 11, service RetryFailedNotifications + MarkAsDead +
	// RequeueNotification implemented, handler POST
	// /api/v1/notifications/{id}/requeue routed, list handler parsing the
	// status query param).
	//
	// Subtests:
	//
	//   1. MarkAsDead_OnMaxAttempts — a notification seeded at retry_count=4
	//      (one failure shy of the max_attempts=5 gate) with next_retry_at in
	//      the past is promoted to status='dead' on the first retry-loop
	//      tick. The pre-increment arithmetic `retry_count + 1 = 5 =
	//      max_attempts` triggers MarkAsDead instead of scheduling another
	//      retry.
	//
	//   2. Requeue_FlipsDeadToPending — POST
	//      /api/v1/notifications/{id}/requeue on a dead row flips status back
	//      to 'pending', resets retry_count to 0, and clears next_retry_at
	//      so the existing ProcessPendingNotifications loop (not the retry
	//      sweep) picks it up on its next tick.
	//
	//   3. ListFilter_StatusDead — GET /api/v1/notifications?status=dead
	//      returns only rows in status='dead' so the UI's Dead Letter tab
	//      (web/src/pages/NotificationsPage.test.tsx subtest #1) can isolate
	//      them without client-side filtering.
	//
	// Red behavior at HEAD (what Phase 2 Green must flip):
	//
	//   * Schema: the INSERTs reference retry_count, next_retry_at,
	//     last_error. Migration 000016 is already written (file (a) of
	//     Phase 1 Red) but until it is applied the INSERTs fail with
	//     "column does not exist" — schema-level Red halt.
	//
	//   * Subtest 1: no retry loop exists at HEAD. The seeded row stays at
	//     status='failed' retry_count=4 forever. The 4-minute waitFor
	//     therefore times out.
	//
	//   * Subtest 2: /notifications/{id}/requeue is not routed at HEAD
	//     (internal/api/handler/notifications.go registers only list / get /
	//     mark-read). The POST returns 404.
	//
	//   * Subtest 3: the list handler does not parse the status query param
	//     at HEAD. The response includes rows of every status, so the
	//     "leaked non-dead row" assertion fires.
	// -----------------------------------------------------------------------
	t.Run("Phase13_NotificationRetryDLQ", func(t *testing.T) {
		// Unreachable endpoint so every webhook delivery attempt fails
		// deterministically — port 1 is never bound. Pinning retry_count=4
		// + a guaranteed-failing channel is what turns the seeded row into
		// 'dead' on the very next scheduler tick (one delivery attempt,
		// retry_count 4→5, crosses max_attempts=5 → MarkAsDead).
		const blackHole = "http://127.0.0.1:1/i005-red-black-hole"

		// ---------------------------------------------------------------
		// Subtest 1: failed → dead transition after one retry-loop tick
		// ---------------------------------------------------------------
		t.Run("MarkAsDead_OnMaxAttempts", func(t *testing.T) {
			id := fmt.Sprintf("notif-i005-dead-%d", time.Now().UnixNano())

			// retry_count=4 + next attempt = 5 = max_attempts → MarkAsDead.
			// next_retry_at is backdated so the row is immediately eligible
			// for the retry sweep rather than having to wait for its own
			// backoff to elapse.
			past := time.Now().Add(-30 * time.Second).UTC()
			db.Exec(t, `
				INSERT INTO notification_events
				  (id, type, channel, recipient, message, status,
				   retry_count, next_retry_at, last_error)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			`,
				id, "ExpirationWarning", "Webhook", blackHole,
				"I-005 integration: DLQ promotion on max_attempts",
				"failed", 4, past, "transient webhook 500",
			)

			// Give the retry sweep up to 4m to tick at least once (default
			// 2m interval + seed/sweep/notifier slop). On success the row
			// carries status='dead' and retry_count has advanced to 5.
			waitFor(t, "notification transitions to dead", 4*time.Minute, 5*time.Second,
				func() (bool, error) {
					var status string
					var retry int
					err := db.db.QueryRow(
						"SELECT status, retry_count FROM notification_events WHERE id = $1",
						id,
					).Scan(&status, &retry)
					if err != nil {
						return false, err
					}
					return strings.EqualFold(status, "dead") && retry >= 5, nil
				})

			// The dead-letter tab is only useful if operators can see why
			// the row died. MarkAsDead must preserve the most recent
			// failure string in last_error rather than nil'ing it.
			var lastErr sql.NullString
			if err := db.db.QueryRow(
				"SELECT last_error FROM notification_events WHERE id = $1", id,
			).Scan(&lastErr); err != nil {
				t.Fatalf("read last_error: %v", err)
			}
			if !lastErr.Valid || lastErr.String == "" {
				t.Errorf("dead notification %s has empty last_error — "+
					"retry loop must preserve the most recent failure", id)
			}
		})

		// ---------------------------------------------------------------
		// Subtest 2: dead → pending via manual Requeue endpoint
		// ---------------------------------------------------------------
		t.Run("Requeue_FlipsDeadToPending", func(t *testing.T) {
			id := fmt.Sprintf("notif-i005-requeue-%d", time.Now().UnixNano())

			// Seed directly at status='dead' rather than waiting for a
			// scheduler tick — this subtest isolates the requeue handler,
			// not the retry loop (subtest 1 already pins that).
			past := time.Now().Add(-10 * time.Minute).UTC()
			db.Exec(t, `
				INSERT INTO notification_events
				  (id, type, channel, recipient, message, status,
				   retry_count, next_retry_at, last_error)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			`,
				id, "ExpirationWarning", "Webhook", blackHole,
				"I-005 integration: manual requeue",
				"dead", 5, past, "max attempts reached",
			)

			resp, err := c.Post("/api/v1/notifications/"+id+"/requeue", "")
			if err != nil {
				t.Fatalf("POST requeue: %v", err)
			}
			body := readBody(resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("requeue status %d, want 200 (body: %s)",
					resp.StatusCode, body)
			}
			// Phase 2 Green handler responds with {"status":"requeued"}
			// to mirror MarkAsRead's {"status":"marked_as_read"} envelope.
			if !strings.Contains(body, "requeued") {
				t.Errorf("requeue body missing 'requeued' marker: %s", body)
			}

			// DB must reflect the full flip: pending status, reset counter,
			// cleared next_retry_at. Clearing next_retry_at is what moves
			// the row out of the retry-sweep partial index and back under
			// ProcessPendingNotifications.
			var status string
			var retry int
			var nextRetry sql.NullTime
			if err := db.db.QueryRow(`
				SELECT status, retry_count, next_retry_at
				  FROM notification_events WHERE id = $1
			`, id).Scan(&status, &retry, &nextRetry); err != nil {
				t.Fatalf("read requeued row: %v", err)
			}
			if !strings.EqualFold(status, "pending") {
				t.Errorf("after requeue: status=%q, want 'pending'", status)
			}
			if retry != 0 {
				t.Errorf("after requeue: retry_count=%d, want 0", retry)
			}
			if nextRetry.Valid {
				t.Errorf("after requeue: next_retry_at=%v, want NULL",
					nextRetry.Time)
			}
		})

		// ---------------------------------------------------------------
		// Subtest 3: GET /notifications?status=dead isolates DLQ rows
		// ---------------------------------------------------------------
		t.Run("ListFilter_StatusDead", func(t *testing.T) {
			suffix := fmt.Sprintf("%d", time.Now().UnixNano())
			deadID := "notif-i005-filter-dead-" + suffix
			pendingID := "notif-i005-filter-pending-" + suffix

			// One row at each end of the lifecycle so we can prove the
			// filter both matches and excludes.
			db.Exec(t, `
				INSERT INTO notification_events
				  (id, type, channel, recipient, message, status, retry_count)
				VALUES ($1, 'ExpirationWarning', 'Webhook', $2,
				        'I-005 filter test: dead row', 'dead', 5)
			`, deadID, blackHole)
			db.Exec(t, `
				INSERT INTO notification_events
				  (id, type, channel, recipient, message, status, retry_count)
				VALUES ($1, 'ExpirationWarning', 'Webhook', $2,
				        'I-005 filter test: pending row', 'pending', 0)
			`, pendingID, blackHole)

			// per_page large enough to rule out pagination artifacts as
			// the reason a seeded row might be missing from the response.
			resp, err := c.Get("/api/v1/notifications?status=dead&per_page=500")
			if err != nil {
				t.Fatalf("GET notifications?status=dead: %v", err)
			}
			var pr pagedResponse
			if err := decodeJSON(resp, &pr); err != nil {
				t.Fatalf("decode: %v", err)
			}

			type row struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			}
			var rows []row
			if err := json.Unmarshal(pr.Data, &rows); err != nil {
				t.Fatalf("unmarshal rows: %v", err)
			}

			var sawDead, sawPending bool
			for _, r := range rows {
				if r.ID == deadID {
					sawDead = true
				}
				if r.ID == pendingID {
					sawPending = true
				}
				if !strings.EqualFold(r.Status, "dead") {
					t.Errorf("status=dead filter leaked non-dead row: "+
						"id=%s status=%s", r.ID, r.Status)
				}
			}
			if !sawDead {
				t.Errorf("status=dead filter missed seeded dead row %s", deadID)
			}
			if sawPending {
				t.Errorf("status=dead filter leaked seeded pending row %s",
					pendingID)
			}
		})
	})
}
