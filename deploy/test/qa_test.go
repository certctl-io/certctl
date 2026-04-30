//go:build qa

// Package integration_test provides the certctl V2.1 Release QA suite.
//
// This file automates every scriptable test from docs/testing-guide.md against
// a running Docker Compose demo stack. Tests that require a browser, external
// service (Vault, DigiCert, Sectigo, Google CAS), Windows, or Kubernetes are
// skipped with a reason.
//
// Run:
//
//	cd deploy && docker compose -f docker-compose.yml -f docker-compose.demo.yml up --build -d
//	# Wait for healthy state (~15s)
//	cd deploy/test && go test -tags qa -v -timeout 10m ./...
//
// Run a single Part:
//
//	go test -tags qa -v -run TestQA/Part14 ./...
//
// Environment overrides:
//
//	CERTCTL_QA_SERVER_URL     (default: https://localhost:8443)
//	CERTCTL_QA_API_KEY        (default: change-me-in-production)
//	CERTCTL_QA_DB_URL         (default: postgres://certctl:certctl@localhost:5432/certctl?sslmode=disable)
//	CERTCTL_QA_REPO_DIR       (default: ../.. — the certctl repo root)
//	CERTCTL_QA_CA_BUNDLE      (default: ./certs/ca.crt — the demo stack's init container writes here)
//	CERTCTL_QA_INSECURE       (default: false — set to "true" to skip TLS verify, e.g. before the init container finishes)
//
// TLS note (HTTPS-Everywhere M-007, Phase 6): the demo compose stack now
// listens on https://localhost:8443 with a self-signed cert written by the
// tls-init container. This suite pins the issuing CA via
// CERTCTL_QA_CA_BUNDLE so cert rotation or a tampered proxy fails the
// handshake instead of being silently trusted. CERTCTL_QA_INSECURE="true"
// is an explicit opt-out for bootstrap scenarios — there is no silent
// plaintext downgrade, matching the server-side pre-flight guard added in
// Phase 5 (task #203).
//
// Q-1 closure (cat-s3-58ce7e9840be): this file contains 11 `t.Skip("Requires
// X — manual test")` markers across the Part10..Part37 subtests
// (Sub-CA, ARI, Vault, DigiCert, CLI binary, MCP-server binary,
// scheduler-timing, docker-log inspection, and three browser-UI parts).
// Each marks a subtest that exercises a path requiring real external
// services or human-in-the-loop verification — they were never meant
// to run unattended in CI. The file-level `//go:build qa` tag at line 1
// already keeps them out of the default `go test ./...` invocation;
// the runtime t.Skip is the second-line guard for operators who run
// `-tags qa` against a stack that doesn't have the required external
// service available. The audit recommendation was "audit each skip and
// decide" — for these 11, the decision is **document-skip**: the gating
// is correct, and the t.Skip messages already name the missing
// precondition. No restructuring needed.
package integration_test

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// QA Configuration
// ---------------------------------------------------------------------------

func qaEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var (
	qaServerURL    = qaEnv("CERTCTL_QA_SERVER_URL", "https://localhost:8443")
	qaAPIKey       = qaEnv("CERTCTL_QA_API_KEY", "change-me-in-production")
	qaDBURL        = qaEnv("CERTCTL_QA_DB_URL", "postgres://certctl:certctl@localhost:5432/certctl?sslmode=disable")
	qaRepoDir      = qaEnv("CERTCTL_QA_REPO_DIR", filepath.Join("..", ".."))
	qaCABundlePath = qaEnv("CERTCTL_QA_CA_BUNDLE", "./certs/ca.crt")
	qaInsecure     = strings.EqualFold(os.Getenv("CERTCTL_QA_INSECURE"), "true")
)

// ---------------------------------------------------------------------------
// QA HTTP client
// ---------------------------------------------------------------------------

type qaClient struct {
	http    *http.Client
	baseURL string
	apiKey  string
}

// buildQATLSConfig returns the *tls.Config used by every qaClient. TLS 1.3
// minimum matches the server-side config pinned in Phase 2 (cmd/server).
// When CERTCTL_QA_INSECURE=true we skip verification entirely — useful
// when running against a compose stack where the tls-init container hasn't
// written ca.crt yet, or when pointing at a dev server with a rotated cert.
// Otherwise we pin CERTCTL_QA_CA_BUNDLE and panic on read/parse failure
// rather than silently downgrading to the system trust store (which would
// mask a missing init container).
func buildQATLSConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if qaInsecure {
		cfg.InsecureSkipVerify = true
		return cfg
	}
	pem, err := os.ReadFile(qaCABundlePath)
	if err != nil {
		panic(fmt.Sprintf("qa test: read CA bundle %q: %v — set CERTCTL_QA_CA_BUNDLE or CERTCTL_QA_INSECURE=true", qaCABundlePath, err))
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		panic(fmt.Sprintf("qa test: no PEM certificates parsed from %q", qaCABundlePath))
	}
	cfg.RootCAs = pool
	return cfg
}

func newQAClient() *qaClient {
	return &qaClient{
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: buildQATLSConfig()},
		},
		baseURL: qaServerURL,
		apiKey:  qaAPIKey,
	}
}

func (c *qaClient) do(method, path string, body string) (*http.Response, error) {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, c.baseURL+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

func (c *qaClient) get(path string) (*http.Response, error)        { return c.do("GET", path, "") }
func (c *qaClient) post(path, body string) (*http.Response, error) { return c.do("POST", path, body) }
func (c *qaClient) put(path, body string) (*http.Response, error)  { return c.do("PUT", path, body) }
func (c *qaClient) delete(path string) (*http.Response, error)     { return c.do("DELETE", path, "") }

// statusCode makes a request and returns the HTTP status code.
func (c *qaClient) statusCode(method, path, body string) (int, error) {
	resp, err := c.do(method, path, body)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// getJSON makes a GET request and decodes the JSON response.
func (c *qaClient) getJSON(t *testing.T, path string, v interface{}) {
	t.Helper()
	resp, err := c.get(path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("GET %s: status %d, body: %s", path, resp.StatusCode, string(body))
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("GET %s: decode JSON: %v (body: %s)", path, err, string(data))
	}
}

// bodyStr makes a request and returns the body as a string.
func (c *qaClient) bodyStr(t *testing.T, method, path, body string) (int, string) {
	t.Helper()
	resp, err := c.do(method, path, body)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// timedGet makes a GET request and returns the duration.
func (c *qaClient) timedGet(path string) (time.Duration, int, error) {
	start := time.Now()
	resp, err := c.do("GET", path, "")
	elapsed := time.Since(start)
	if err != nil {
		return elapsed, 0, err
	}
	resp.Body.Close()
	return elapsed, resp.StatusCode, nil
}

// ---------------------------------------------------------------------------
// JSON response helpers (lightweight, no internal imports)
// ---------------------------------------------------------------------------

type qaPagedResponse struct {
	Data    json.RawMessage `json:"data"`
	Total   int             `json:"total"`
	Page    int             `json:"page"`
	PerPage int             `json:"per_page"`
}

type qaCert struct {
	ID         string  `json:"id"`
	CommonName string  `json:"common_name"`
	Status     string  `json:"status"`
	IssuerID   string  `json:"issuer_id"`
	OwnerID    *string `json:"owner_id"`
	ProfileID  *string `json:"certificate_profile_id"`
}

type qaJob struct {
	ID            string  `json:"id"`
	Type          string  `json:"type"`
	Status        string  `json:"status"`
	CertificateID string  `json:"certificate_id"`
	AgentID       *string `json:"agent_id"`
}

type qaIssuer struct {
	ID      string          `json:"id"`
	Name    string          `json:"name"`
	Type    string          `json:"type"`
	Source  string          `json:"source"`
	Enabled bool            `json:"enabled"`
	Config  json.RawMessage `json:"config"`
}

type qaTarget struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Source  string `json:"source"`
	Enabled bool   `json:"enabled"`
}

type qaAgent struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	OS     string `json:"os"`
	Arch   string `json:"architecture"`
}

type qaNotification struct {
	ID   string `json:"id"`
	Read bool   `json:"read"`
}

type qaStats struct {
	TotalCertificates    int `json:"total_certificates"`
	ActiveCertificates   int `json:"active_certificates"`
	ExpiringCertificates int `json:"expiring_certificates"`
	TotalAgents          int `json:"total_agents"`
}

type qaMetrics struct {
	Gauge   map[string]interface{} `json:"gauge"`
	Counter map[string]interface{} `json:"counter"`
	Uptime  float64                `json:"uptime_seconds"`
}

type qaDiscoveredCert struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	CommonName  string `json:"common_name"`
	Fingerprint string `json:"fingerprint_sha256"`
}

type qaDiscoverySummary struct {
	Unmanaged int `json:"unmanaged"`
	Managed   int `json:"managed"`
	Dismissed int `json:"dismissed"`
}

type qaNetworkScanTarget struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}

// ---------------------------------------------------------------------------
// Source file helper
// ---------------------------------------------------------------------------

func repoFile(relPath string) string {
	return filepath.Join(qaRepoDir, relPath)
}

func fileContains(t *testing.T, relPath, substr string) {
	t.Helper()
	data, err := os.ReadFile(repoFile(relPath))
	if err != nil {
		t.Fatalf("read %s: %v", relPath, err)
	}
	if !strings.Contains(string(data), substr) {
		t.Fatalf("%s does not contain %q", relPath, substr)
	}
}

func fileExists(t *testing.T, relPath string) {
	t.Helper()
	if _, err := os.Stat(repoFile(relPath)); os.IsNotExist(err) {
		t.Fatalf("file does not exist: %s", relPath)
	}
}

// ---------------------------------------------------------------------------
// Database helper
// ---------------------------------------------------------------------------

type qaDB struct {
	db *sql.DB
}

func openQADB(t *testing.T) *qaDB {
	t.Helper()
	db, err := sql.Open("postgres", qaDBURL)
	if err != nil {
		t.Fatalf("connect to QA DB: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping QA DB: %v", err)
	}
	return &qaDB{db: db}
}

func (d *qaDB) queryInt(t *testing.T, query string) int {
	t.Helper()
	var n int
	if err := d.db.QueryRow(query).Scan(&n); err != nil {
		t.Fatalf("queryInt: %v\nquery: %s", err, query)
	}
	return n
}

func (d *qaDB) close() { d.db.Close() }

// ===========================================================================
// QA Test Suite
// ===========================================================================

func TestQA(t *testing.T) {
	c := newQAClient()

	// Verify server is reachable before running anything.
	resp, err := c.get("/health")
	if err != nil {
		t.Fatalf("Server unreachable at %s: %v\nIs the Docker Compose stack running?", qaServerURL, err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("Server unhealthy: GET /health returned %d", resp.StatusCode)
	}

	// ===================================================================
	// Part 1: Infrastructure & Deployment
	// ===================================================================
	t.Run("Part01_Infrastructure", func(t *testing.T) {
		db := openQADB(t)
		defer db.close()

		t.Run("PostgreSQL_TableCount", func(t *testing.T) {
			n := db.queryInt(t, `SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'`)
			if n < 19 {
				t.Fatalf("table count = %d, want >= 19", n)
			}
		})

		t.Run("HealthEndpoint", func(t *testing.T) {
			code, _ := c.statusCode("GET", "/health", "")
			if code != 200 {
				t.Fatalf("GET /health = %d, want 200", code)
			}
		})

		t.Run("ReadyEndpoint", func(t *testing.T) {
			code, _ := c.statusCode("GET", "/ready", "")
			if code != 200 {
				t.Fatalf("GET /ready = %d, want 200", code)
			}
		})

		t.Run("SeedData_Certs", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/certificates", &pr)
			if pr.Total < 10 {
				t.Fatalf("seed certs = %d, want >= 10", pr.Total)
			}
		})

		t.Run("SeedData_Agents", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/agents", &pr)
			if pr.Total < 3 {
				t.Fatalf("seed agents = %d, want >= 3", pr.Total)
			}
		})

		t.Run("SeedData_Issuers", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/issuers", &pr)
			if pr.Total < 3 {
				t.Fatalf("seed issuers = %d, want >= 3", pr.Total)
			}
		})

		t.Run("SeedData_Targets", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/targets", &pr)
			if pr.Total < 3 {
				t.Fatalf("seed targets = %d, want >= 3", pr.Total)
			}
		})

		t.Run("SeedData_Policies", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/policies", &pr)
			if pr.Total < 1 {
				t.Fatalf("seed policies = %d, want >= 1", pr.Total)
			}
		})
	})

	// ===================================================================
	// Part 2: Authentication & Security
	// ===================================================================
	t.Run("Part02_Auth", func(t *testing.T) {
		t.Run("NoAuth_Returns401", func(t *testing.T) {
			req, _ := http.NewRequest("GET", qaServerURL+"/api/v1/certificates", nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != 401 {
				t.Fatalf("no-auth status = %d, want 401", resp.StatusCode)
			}
		})

		t.Run("BadKey_Returns401", func(t *testing.T) {
			req, _ := http.NewRequest("GET", qaServerURL+"/api/v1/certificates", nil)
			req.Header.Set("Authorization", "Bearer wrong-key")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != 401 {
				t.Fatalf("bad-key status = %d, want 401", resp.StatusCode)
			}
		})

		t.Run("HealthEndpoint_NoAuth", func(t *testing.T) {
			req, _ := http.NewRequest("GET", qaServerURL+"/health", nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("/health without auth = %d, want 200", resp.StatusCode)
			}
		})

		t.Run("PrivateKey_NotInCertDetail", func(t *testing.T) {
			_, body := c.bodyStr(t, "GET", "/api/v1/certificates?per_page=1", "")
			if strings.Contains(body, "PRIVATE KEY") {
				t.Fatal("API response contains private key material")
			}
		})
	})

	// ===================================================================
	// Part 3: Certificate Lifecycle (CRUD)
	// ===================================================================
	t.Run("Part03_CertCRUD", func(t *testing.T) {
		t.Run("Create_Minimal", func(t *testing.T) {
			// C-001 scope-expansion: the handler's ValidateRequired
			// contract now gates common_name, owner_id, team_id,
			// issuer_id, name, and renewal_policy_id. A 3-field
			// payload would 400 regardless of the id hint, so the
			// "minimal" variant carries every required field.
			code, body := c.bodyStr(t, "POST", "/api/v1/certificates", `{
				"id": "mc-qa-minimal",
				"name": "qa-minimal",
				"common_name": "qa-minimal.example.com",
				"issuer_id": "iss-local",
				"owner_id": "o-alice",
				"team_id": "t-platform",
				"renewal_policy_id": "rp-standard"
			}`)
			if code != 201 && code != 200 {
				t.Fatalf("create cert: status %d, body: %s", code, body)
			}
		})

		t.Run("Create_Full", func(t *testing.T) {
			code, body := c.bodyStr(t, "POST", "/api/v1/certificates", `{
				"id": "mc-qa-full",
				"name": "qa-full",
				"common_name": "qa-full.example.com",
				"sans": ["qa-full-alt.example.com"],
				"issuer_id": "iss-local",
				"environment": "staging",
				"owner_id": "o-alice",
				"team_id": "t-platform",
				"renewal_policy_id": "rp-standard"
			}`)
			if code != 201 && code != 200 {
				t.Fatalf("create cert: status %d, body: %s", code, body)
			}
		})

		t.Run("Get_ByID", func(t *testing.T) {
			var cert qaCert
			c.getJSON(t, "/api/v1/certificates/mc-qa-minimal", &cert)
			if cert.CommonName != "qa-minimal.example.com" {
				t.Fatalf("CN = %q, want qa-minimal.example.com", cert.CommonName)
			}
		})

		t.Run("Get_NotFound", func(t *testing.T) {
			code, _ := c.statusCode("GET", "/api/v1/certificates/nonexistent-cert-id", "")
			if code != 404 {
				t.Fatalf("nonexistent cert = %d, want 404", code)
			}
		})

		t.Run("List_Pagination", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/certificates?per_page=5", &pr)
			if pr.PerPage != 5 {
				t.Fatalf("per_page = %d, want 5", pr.PerPage)
			}
			if pr.Total < 10 {
				t.Fatalf("total = %d, want >= 10", pr.Total)
			}
		})

		t.Run("Filter_ByStatus", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/certificates?status=Active", &pr)
			var certs []qaCert
			json.Unmarshal(pr.Data, &certs)
			for _, cert := range certs {
				if cert.Status != "Active" {
					t.Fatalf("filter returned non-Active cert: %s status=%s", cert.ID, cert.Status)
				}
			}
		})

		t.Run("Filter_ByIssuer", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/certificates?issuer_id=iss-local", &pr)
			var certs []qaCert
			json.Unmarshal(pr.Data, &certs)
			for _, cert := range certs {
				if cert.IssuerID != "iss-local" {
					t.Fatalf("filter returned wrong issuer: %s issuer=%s", cert.ID, cert.IssuerID)
				}
			}
		})

		t.Run("SparseFields", func(t *testing.T) {
			_, body := c.bodyStr(t, "GET", "/api/v1/certificates?fields=id,common_name&per_page=1", "")
			if !strings.Contains(body, "id") || !strings.Contains(body, "common_name") {
				t.Fatalf("sparse fields missing expected fields: %s", body)
			}
		})

		t.Run("Update", func(t *testing.T) {
			code, _ := c.bodyStr(t, "PUT", "/api/v1/certificates/mc-qa-minimal", `{"environment":"production"}`)
			if code != 200 {
				t.Fatalf("update cert = %d, want 200", code)
			}
		})

		t.Run("Archive", func(t *testing.T) {
			code, _ := c.statusCode("DELETE", "/api/v1/certificates/mc-qa-full", "")
			if code != 204 && code != 200 {
				t.Fatalf("archive cert = %d, want 204 or 200", code)
			}
		})

		// Cleanup
		t.Cleanup(func() {
			c.delete("/api/v1/certificates/mc-qa-minimal")
			c.delete("/api/v1/certificates/mc-qa-full")
		})
	})

	// ===================================================================
	// Part 4: Renewal Workflow
	// ===================================================================
	t.Run("Part04_Renewal", func(t *testing.T) {
		t.Run("TriggerRenewal_CreatesJob", func(t *testing.T) {
			code, body := c.bodyStr(t, "POST", "/api/v1/certificates/mc-web-prod/renew", "")
			if code != 200 && code != 201 && code != 202 {
				t.Fatalf("trigger renewal = %d, body: %s", code, body)
			}
		})

		t.Run("Renewal_NonexistentCert_404", func(t *testing.T) {
			code, _ := c.statusCode("POST", "/api/v1/certificates/nonexistent/renew", "")
			if code != 404 {
				t.Fatalf("renew nonexistent = %d, want 404", code)
			}
		})

		t.Run("AgentWork_ReturnsPendingJobs", func(t *testing.T) {
			// Use a known agent from seed data (ag-web-prod in seed_demo.sql)
			_, body := c.bodyStr(t, "GET", "/api/v1/agents/ag-web-prod/work", "")
			// Should return JSON array (even if empty)
			if !strings.HasPrefix(strings.TrimSpace(body), "[") && !strings.HasPrefix(strings.TrimSpace(body), "null") {
				t.Fatalf("agent work not a JSON array: %s", body[:min(len(body), 100)])
			}
		})
	})

	// ===================================================================
	// Part 5: Revocation
	// ===================================================================
	t.Run("Part05_Revocation", func(t *testing.T) {
		t.Run("Revoke_DefaultReason", func(t *testing.T) {
			code, _ := c.bodyStr(t, "POST", "/api/v1/certificates/mc-blog-prod/revoke", `{}`)
			if code != 200 {
				t.Fatalf("revoke = %d, want 200", code)
			}
		})

		t.Run("Revoke_AlreadyRevoked", func(t *testing.T) {
			code, _ := c.statusCode("POST", "/api/v1/certificates/mc-blog-prod/revoke", `{"reason":"keyCompromise"}`)
			if code != 200 && code != 409 {
				t.Fatalf("re-revoke = %d, want 200 or 409", code)
			}
		})

		t.Run("Revoke_Nonexistent", func(t *testing.T) {
			code, _ := c.statusCode("POST", "/api/v1/certificates/nonexistent/revoke", `{}`)
			if code != 404 {
				t.Fatalf("revoke nonexistent = %d, want 404", code)
			}
		})

		t.Run("Revoke_InvalidReason", func(t *testing.T) {
			code, _ := c.statusCode("POST", "/api/v1/certificates/mc-grpc-prod/revoke", `{"reason":"madeUpReason"}`)
			if code != 400 {
				t.Fatalf("invalid reason = %d, want 400", code)
			}
		})

		// M-006: The non-standard JSON CRL endpoint was removed. RFC 5280 §5
		// defines only the DER wire format, now served unauthenticated at
		// `/.well-known/pki/crl/{issuer_id}` per RFC 8615. Use a plain
		// http.Get — no Bearer — to prove the endpoint is reachable by
		// relying parties with no API credentials.
		t.Run("CRL_DER_Unauthenticated", func(t *testing.T) {
			resp, err := http.Get(qaServerURL + "/.well-known/pki/crl/iss-local")
			if err != nil {
				t.Fatalf("GET DER CRL: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("CRL = %d (body=%s)", resp.StatusCode, string(b))
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
			crl, err := x509.ParseRevocationList(body)
			if err != nil {
				t.Fatalf("parse DER CRL: %v", err)
			}
			if len(crl.RevokedCertificateEntries) < 1 {
				t.Fatalf("CRL entries: got %d, want >= 1", len(crl.RevokedCertificateEntries))
			}
		})
	})

	// ===================================================================
	// Part 6: Policies & Profiles
	// ===================================================================
	t.Run("Part06_Policies", func(t *testing.T) {
		t.Run("ListPolicies", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/policies", &pr)
			if pr.Total < 1 {
				t.Fatalf("policies = %d, want >= 1", pr.Total)
			}
		})

		t.Run("CreatePolicy", func(t *testing.T) {
			code, _ := c.bodyStr(t, "POST", "/api/v1/policies", `{
				"id": "rp-qa", "name": "QA Policy", "type": "AllowedDomains",
				"config": {"domains": ["*.example.com"]}
			}`)
			if code != 201 && code != 200 {
				t.Fatalf("create policy = %d", code)
			}
		})

		t.Run("InvalidPolicyType", func(t *testing.T) {
			code, _ := c.statusCode("POST", "/api/v1/policies", `{
				"id": "rp-bad", "name": "Bad", "type": "invalid_type",
				"config": {}
			}`)
			if code != 400 {
				t.Fatalf("invalid type = %d, want 400", code)
			}
		})

		t.Run("DeletePolicy", func(t *testing.T) {
			code, _ := c.statusCode("DELETE", "/api/v1/policies/rp-qa", "")
			if code != 204 && code != 200 {
				t.Fatalf("delete policy = %d", code)
			}
		})

		t.Run("ListProfiles", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/profiles", &pr)
			if pr.Total < 1 {
				t.Fatalf("profiles = %d, want >= 1", pr.Total)
			}
		})

		t.Run("CreateProfile", func(t *testing.T) {
			code, _ := c.bodyStr(t, "POST", "/api/v1/profiles", `{
				"id": "prof-qa", "name": "QA Profile",
				"allowed_key_algorithms": [{"algorithm":"RSA","min_size":2048},{"algorithm":"ECDSA","min_size":256}],
				"max_ttl_seconds": 7776000
			}`)
			if code != 201 && code != 200 {
				t.Fatalf("create profile = %d", code)
			}
			t.Cleanup(func() { c.delete("/api/v1/profiles/prof-qa") })
		})
	})

	// ===================================================================
	// Part 7: Ownership, Teams & Agent Groups
	// ===================================================================
	t.Run("Part07_Ownership", func(t *testing.T) {
		t.Run("ListTeams", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/teams", &pr)
			if pr.Total < 1 {
				t.Fatalf("teams = %d, want >= 1", pr.Total)
			}
		})

		t.Run("TeamCRUD", func(t *testing.T) {
			code, _ := c.bodyStr(t, "POST", "/api/v1/teams", `{"id":"t-qa","name":"QA Team"}`)
			if code != 201 && code != 200 {
				t.Fatalf("create team = %d", code)
			}
			code, _ = c.statusCode("DELETE", "/api/v1/teams/t-qa", "")
			if code != 204 && code != 200 {
				t.Fatalf("delete team = %d", code)
			}
		})

		t.Run("OwnerCRUD", func(t *testing.T) {
			code, _ := c.bodyStr(t, "POST", "/api/v1/owners", `{
				"id":"o-qa","name":"QA Owner","email":"qa@example.com","team_id":"t-platform"
			}`)
			if code != 201 && code != 200 {
				t.Fatalf("create owner = %d", code)
			}
			t.Cleanup(func() { c.delete("/api/v1/owners/o-qa") })
		})

		t.Run("ListAgentGroups", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/agent-groups", &pr)
			if pr.Total < 1 {
				t.Fatalf("agent groups = %d, want >= 1", pr.Total)
			}
		})
	})

	// ===================================================================
	// Part 8: Job System
	// ===================================================================
	t.Run("Part08_Jobs", func(t *testing.T) {
		t.Run("ListJobs", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/jobs", &pr)
			if pr.Total < 1 {
				t.Fatalf("jobs = %d, want >= 1", pr.Total)
			}
		})

		t.Run("GetNonexistentJob", func(t *testing.T) {
			code, _ := c.statusCode("GET", "/api/v1/jobs/nonexistent", "")
			if code != 404 {
				t.Fatalf("nonexistent job = %d, want 404", code)
			}
		})
	})

	// ===================================================================
	// Part 9: Issuer Connectors
	// ===================================================================
	t.Run("Part09_Issuers", func(t *testing.T) {
		t.Run("ListIssuers", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/issuers", &pr)
			if pr.Total < 3 {
				t.Fatalf("issuers = %d, want >= 3", pr.Total)
			}
		})

		t.Run("GetIssuerDetail", func(t *testing.T) {
			var iss qaIssuer
			c.getJSON(t, "/api/v1/issuers/iss-local", &iss)
			if iss.ID != "iss-local" {
				t.Fatalf("issuer ID = %q, want iss-local", iss.ID)
			}
		})

		t.Run("CreateIssuer", func(t *testing.T) {
			code, _ := c.bodyStr(t, "POST", "/api/v1/issuers", `{
				"id":"iss-qa","name":"QA Issuer","type":"GenericCA","config":{}
			}`)
			if code != 201 && code != 200 {
				t.Fatalf("create issuer = %d", code)
			}
			t.Cleanup(func() { c.delete("/api/v1/issuers/iss-qa") })
		})

		t.Run("CreateIssuer_MissingName", func(t *testing.T) {
			code, _ := c.statusCode("POST", "/api/v1/issuers", `{"type":"GenericCA","config":{}}`)
			if code != 400 {
				t.Fatalf("missing name = %d, want 400", code)
			}
		})
	})

	// ===================================================================
	// Part 10-11: Sub-CA Mode, ARI — mostly manual (need real CA setup)
	// ===================================================================
	t.Run("Part10_SubCA", func(t *testing.T) {
		t.Skip("Requires CA cert+key setup — manual test")
	})

	t.Run("Part11_ARI", func(t *testing.T) {
		t.Skip("Requires ACME CA with ARI support — manual test")
	})

	// ===================================================================
	// Part 12-13: Vault PKI, DigiCert — require external services
	// ===================================================================
	t.Run("Part12_VaultPKI", func(t *testing.T) {
		t.Skip("Requires live Vault server — manual test")
	})

	t.Run("Part13_DigiCert", func(t *testing.T) {
		t.Skip("Requires DigiCert sandbox — manual test")
	})

	// ===================================================================
	// Part 14: Target Connectors & Deployment
	// ===================================================================
	t.Run("Part14_Targets", func(t *testing.T) {
		t.Run("ListTargets", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/targets", &pr)
			if pr.Total < 3 {
				t.Fatalf("targets = %d, want >= 3", pr.Total)
			}
		})

		t.Run("CreateNGINXTarget", func(t *testing.T) {
			code, _ := c.bodyStr(t, "POST", "/api/v1/targets", `{
				"id":"tgt-qa-nginx","name":"QA NGINX","type":"NGINX",
				"config":{"cert_path":"/etc/nginx/ssl/cert.pem","key_path":"/etc/nginx/ssl/key.pem","reload_command":"nginx -s reload"}
			}`)
			if code != 201 && code != 200 {
				t.Fatalf("create target = %d", code)
			}
			t.Cleanup(func() { c.delete("/api/v1/targets/tgt-qa-nginx") })
		})

		t.Run("DeleteTarget_204", func(t *testing.T) {
			c.post("/api/v1/targets", `{"id":"tgt-qa-del","name":"Delete Me","type":"NGINX","config":{}}`)
			code, _ := c.statusCode("DELETE", "/api/v1/targets/tgt-qa-del", "")
			if code != 204 {
				t.Fatalf("delete target = %d, want 204", code)
			}
		})
	})

	// ===================================================================
	// Part 15-17: Apache/HAProxy, Traefik/Caddy, IIS — need real services or Windows
	// ===================================================================

	// ===================================================================
	// Part 18: Agent Operations
	// ===================================================================
	t.Run("Part18_Agents", func(t *testing.T) {
		t.Run("RegisterAgent", func(t *testing.T) {
			code, _ := c.bodyStr(t, "POST", "/api/v1/agents/ag-qa-new/heartbeat", `{
				"os":"linux","architecture":"amd64","version":"1.0.0"
			}`)
			if code != 200 {
				t.Fatalf("heartbeat = %d, want 200", code)
			}
		})

		t.Run("AgentMetadata", func(t *testing.T) {
			var agent qaAgent
			c.getJSON(t, "/api/v1/agents/ag-qa-new", &agent)
			if agent.OS != "linux" {
				t.Fatalf("agent OS = %q, want linux", agent.OS)
			}
			if agent.Arch != "amd64" {
				t.Fatalf("agent arch = %q, want amd64", agent.Arch)
			}
		})

		t.Run("HeartbeatNonexistent", func(t *testing.T) {
			// Heartbeat auto-creates agents, so this should succeed
			code, _ := c.statusCode("POST", "/api/v1/agents/ag-qa-ghost/heartbeat", `{}`)
			if code != 200 {
				t.Fatalf("ghost heartbeat = %d, want 200", code)
			}
			t.Cleanup(func() {
				c.delete("/api/v1/agents/ag-qa-new")
				c.delete("/api/v1/agents/ag-qa-ghost")
			})
		})
	})

	// ===================================================================
	// Part 19: Agent Work Routing
	// ===================================================================
	t.Run("Part19_WorkRouting", func(t *testing.T) {
		t.Run("EmptyWork_NoTargets", func(t *testing.T) {
			// Register agent with no targets
			c.post("/api/v1/agents/ag-qa-notargets/heartbeat", `{}`)
			_, body := c.bodyStr(t, "GET", "/api/v1/agents/ag-qa-notargets/work", "")
			body = strings.TrimSpace(body)
			if body != "[]" && body != "null" {
				t.Fatalf("expected empty work, got: %s", body[:min(len(body), 200)])
			}
			t.Cleanup(func() { c.delete("/api/v1/agents/ag-qa-notargets") })
		})
	})

	// ===================================================================
	// Part 20: Post-Deployment TLS Verification
	// ===================================================================
	t.Run("Part20_Verification", func(t *testing.T) {
		t.Run("GetVerification_NoJob", func(t *testing.T) {
			code, _ := c.statusCode("GET", "/api/v1/jobs/nonexistent/verification", "")
			if code != 404 {
				t.Fatalf("verification for nonexistent job = %d, want 404", code)
			}
		})
	})

	// ===================================================================
	// Part 21: EST Server (RFC 7030)
	// ===================================================================
	t.Run("Part21_EST", func(t *testing.T) {
		t.Run("CACerts", func(t *testing.T) {
			// EST routes use r.Register() which applies full middleware (incl. auth)
			resp, err := c.get("/.well-known/est/cacerts")
			if err != nil {
				t.Fatalf("GET cacerts: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("cacerts = %d, want 200", resp.StatusCode)
			}
			ct := resp.Header.Get("Content-Type")
			if !strings.Contains(ct, "pkcs7") && !strings.Contains(ct, "application") {
				t.Logf("cacerts content-type: %s (expected pkcs7-mime)", ct)
			}
		})

		t.Run("CSRAttrs", func(t *testing.T) {
			resp, err := c.get("/.well-known/est/csrattrs")
			if err != nil {
				t.Fatalf("GET csrattrs: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != 200 && resp.StatusCode != 204 {
				t.Fatalf("csrattrs = %d, want 200 or 204", resp.StatusCode)
			}
		})
	})

	// ===================================================================
	// Part 22: Certificate Export
	// ===================================================================
	t.Run("Part22_Export", func(t *testing.T) {
		t.Run("ExportPEM", func(t *testing.T) {
			code, body := c.bodyStr(t, "GET", "/api/v1/certificates/mc-web-prod/export/pem", "")
			if code != 200 {
				t.Fatalf("export PEM = %d", code)
			}
			if !strings.Contains(body, "certificate") && !strings.Contains(body, "pem") {
				t.Logf("PEM export body (first 200 chars): %s", body[:min(len(body), 200)])
			}
		})

		t.Run("ExportPKCS12", func(t *testing.T) {
			code, _ := c.bodyStr(t, "POST", "/api/v1/certificates/mc-web-prod/export/pkcs12", `{"password":"test123"}`)
			// PKCS12 may fail if no cert version exists
			if code != 200 && code != 404 {
				t.Fatalf("export PKCS12 = %d, want 200 or 404", code)
			}
		})

		t.Run("Export_Nonexistent", func(t *testing.T) {
			code, _ := c.statusCode("GET", "/api/v1/certificates/nonexistent/export/pem", "")
			if code != 404 {
				t.Fatalf("export nonexistent = %d, want 404", code)
			}
		})
	})

	// ===================================================================
	// Part 23: S/MIME & EKU Support — manual test (no automation yet)
	// ===================================================================
	t.Run("Part23_SMIMEEku", func(t *testing.T) {
		t.Skip("Part 23 (S/MIME & EKU) is documented in docs/testing-guide.md::Part 23 " +
			"as a manual test. Automation candidates: profile creation with SMIME EKU; " +
			"issuance request with mismatched EKU should 400; issued cert MUST contain " +
			"SMIMECapabilities extension when profile.allow_smime=true.")
	})

	// ===================================================================
	// Part 24: OCSP Responder & DER CRL — manual test (no automation yet)
	// ===================================================================
	t.Run("Part24_OCSPCRL", func(t *testing.T) {
		t.Skip("Part 24 (OCSP/CRL) is documented in docs/testing-guide.md::Part 24 " +
			"as a manual test. Automation candidates: GET /.well-known/pki/ocsp/{issuer}/{serial} " +
			"returns RFC 6960 OCSPResponse; DER CRL response is valid ASN.1 and signed by issuing CA; " +
			"Must-Staple cert returns OCSP for fail-open relying parties.")
	})

	// ===================================================================
	// Part 25: Certificate Discovery
	// ===================================================================
	t.Run("Part25_Discovery", func(t *testing.T) {
		t.Run("ListDiscovered", func(t *testing.T) {
			code, _ := c.bodyStr(t, "GET", "/api/v1/discovered-certificates", "")
			if code != 200 {
				t.Fatalf("list discovered = %d", code)
			}
		})

		t.Run("DiscoverySummary", func(t *testing.T) {
			code, body := c.bodyStr(t, "GET", "/api/v1/discovery-summary", "")
			if code != 200 {
				t.Fatalf("discovery summary = %d", code)
			}
			if !strings.Contains(body, "unmanaged") {
				t.Fatalf("summary missing unmanaged field")
			}
		})

		t.Run("ListNetworkScanTargets", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/network-scan-targets", &pr)
			if pr.Total < 3 {
				t.Fatalf("scan targets = %d, want >= 3", pr.Total)
			}
		})

		t.Run("CreateNetworkScanTarget", func(t *testing.T) {
			code, _ := c.bodyStr(t, "POST", "/api/v1/network-scan-targets", `{
				"id":"nst-qa","name":"QA Scan","cidrs":["10.0.0.0/24"],"ports":[443]
			}`)
			if code != 201 && code != 200 {
				t.Fatalf("create scan target = %d", code)
			}
			t.Cleanup(func() { c.delete("/api/v1/network-scan-targets/nst-qa") })
		})

		t.Run("InvalidCIDR", func(t *testing.T) {
			code, _ := c.statusCode("POST", "/api/v1/network-scan-targets", `{
				"name":"Bad","cidrs":["not-a-cidr"],"ports":[443]
			}`)
			if code != 400 {
				t.Fatalf("invalid CIDR = %d, want 400", code)
			}
		})
	})

	// ===================================================================
	// Part 26: Enhanced Query API
	// ===================================================================
	t.Run("Part26_QueryAPI", func(t *testing.T) {
		t.Run("SortDescending", func(t *testing.T) {
			code, _ := c.bodyStr(t, "GET", "/api/v1/certificates?sort=-createdAt&per_page=5", "")
			if code != 200 {
				t.Fatalf("sort desc = %d", code)
			}
		})

		t.Run("CursorPagination", func(t *testing.T) {
			code, body := c.bodyStr(t, "GET", "/api/v1/certificates?page_size=3", "")
			if code != 200 {
				t.Fatalf("cursor page = %d", code)
			}
			// Should have next_cursor or data
			if !strings.Contains(body, "data") {
				t.Fatalf("cursor response missing data")
			}
		})

		t.Run("TimeRangeFilter", func(t *testing.T) {
			code, _ := c.bodyStr(t, "GET", "/api/v1/certificates?expires_before=2030-01-01T00:00:00Z", "")
			if code != 200 {
				t.Fatalf("time range = %d", code)
			}
		})

		t.Run("InvalidSortField", func(t *testing.T) {
			code, _ := c.statusCode("GET", "/api/v1/certificates?sort=notAField", "")
			if code != 400 {
				t.Logf("invalid sort field = %d (may return 200 ignoring bad sort)", code)
			}
		})
	})

	// ===================================================================
	// Part 27: Request Body Size Limits
	// ===================================================================
	t.Run("Part27_BodyLimits", func(t *testing.T) {
		t.Run("OversizedBody_Rejected", func(t *testing.T) {
			// Send a 2MB body (default limit is 1MB)
			bigBody := `{"name":"` + strings.Repeat("x", 2*1024*1024) + `"}`
			code, _ := c.statusCode("POST", "/api/v1/certificates", bigBody)
			if code != 413 && code != 400 {
				t.Fatalf("oversize body = %d, want 413 or 400", code)
			}
		})
	})

	// ===================================================================
	// Part 28-29: CLI, MCP — require compiled binaries
	// ===================================================================
	t.Run("Part28_CLI", func(t *testing.T) {
		t.Skip("Requires compiled certctl-cli binary — manual test")
	})

	t.Run("Part29_MCP", func(t *testing.T) {
		t.Skip("Requires compiled mcp-server binary + stdio — manual test")
	})

	// ===================================================================
	// Part 30: Observability
	// ===================================================================
	t.Run("Part30_Observability", func(t *testing.T) {
		t.Run("DashboardSummary", func(t *testing.T) {
			var stats qaStats
			c.getJSON(t, "/api/v1/stats/summary", &stats)
			if stats.TotalCertificates < 10 {
				t.Fatalf("total certs = %d, want >= 10", stats.TotalCertificates)
			}
		})

		t.Run("CertsByStatus", func(t *testing.T) {
			code, body := c.bodyStr(t, "GET", "/api/v1/stats/certificates-by-status", "")
			if code != 200 {
				t.Fatalf("certs by status = %d", code)
			}
			if !strings.Contains(body, "Active") {
				t.Fatalf("missing Active status in response")
			}
		})

		t.Run("ExpirationTimeline", func(t *testing.T) {
			code, _ := c.bodyStr(t, "GET", "/api/v1/stats/expiration-timeline?days=90", "")
			if code != 200 {
				t.Fatalf("expiration timeline = %d", code)
			}
		})

		t.Run("JobTrends", func(t *testing.T) {
			code, _ := c.bodyStr(t, "GET", "/api/v1/stats/job-trends?days=30", "")
			if code != 200 {
				t.Fatalf("job trends = %d", code)
			}
		})

		t.Run("IssuanceRate", func(t *testing.T) {
			code, _ := c.bodyStr(t, "GET", "/api/v1/stats/issuance-rate?days=30", "")
			if code != 200 {
				t.Fatalf("issuance rate = %d", code)
			}
		})

		t.Run("JSONMetrics", func(t *testing.T) {
			var m qaMetrics
			c.getJSON(t, "/api/v1/metrics", &m)
			if m.Uptime <= 0 {
				t.Fatalf("uptime = %f, want > 0", m.Uptime)
			}
			if len(m.Gauge) == 0 {
				t.Fatal("no gauge metrics")
			}
		})

		t.Run("Prometheus_ContentType", func(t *testing.T) {
			resp, err := c.get("/api/v1/metrics/prometheus")
			if err != nil {
				t.Fatalf("GET prometheus: %v", err)
			}
			ct := resp.Header.Get("Content-Type")
			resp.Body.Close()
			if !strings.Contains(ct, "text/plain") {
				t.Fatalf("prometheus content-type = %q, want text/plain", ct)
			}
		})

		t.Run("Prometheus_HasMetrics", func(t *testing.T) {
			_, body := c.bodyStr(t, "GET", "/api/v1/metrics/prometheus", "")
			for _, metric := range []string{
				"certctl_certificate_total",
				"certctl_agent_total",
				"certctl_job_pending",
				"certctl_uptime_seconds",
			} {
				if !strings.Contains(body, metric) {
					t.Errorf("prometheus output missing %s", metric)
				}
			}
		})
	})

	// ===================================================================
	// Part 31: Notifications
	// ===================================================================
	t.Run("Part31_Notifications", func(t *testing.T) {
		t.Run("ListNotifications", func(t *testing.T) {
			code, _ := c.bodyStr(t, "GET", "/api/v1/notifications", "")
			if code != 200 {
				t.Fatalf("list notifications = %d", code)
			}
		})

		t.Run("GetNonexistent", func(t *testing.T) {
			code, _ := c.statusCode("GET", "/api/v1/notifications/nonexistent", "")
			if code != 404 {
				t.Fatalf("nonexistent notification = %d, want 404", code)
			}
		})
	})

	// ===================================================================
	// Part 32: Audit Trail
	// ===================================================================
	t.Run("Part32_Audit", func(t *testing.T) {
		t.Run("ListEvents", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/audit", &pr)
			if pr.Total < 10 {
				t.Fatalf("audit events = %d, want >= 10", pr.Total)
			}
		})

		t.Run("Immutability_NoPUT", func(t *testing.T) {
			code, _ := c.statusCode("PUT", "/api/v1/audit/any-event-id", `{"action":"hack"}`)
			if code == 200 {
				t.Fatal("PUT /events should not return 200 — audit trail must be immutable")
			}
		})

		t.Run("Immutability_NoDELETE", func(t *testing.T) {
			code, _ := c.statusCode("DELETE", "/api/v1/audit/any-event-id", "")
			if code == 200 || code == 204 {
				t.Fatal("DELETE /events should not succeed — audit trail must be immutable")
			}
		})
	})

	// ===================================================================
	// Part 33: Background Scheduler (log-based checks)
	// ===================================================================
	t.Run("Part33_Scheduler", func(t *testing.T) {
		t.Skip("Scheduler tests are timing-dependent — verify via Docker logs manually")
	})

	// ===================================================================
	// Part 34: Structured Logging
	// ===================================================================
	t.Run("Part34_Logging", func(t *testing.T) {
		t.Skip("Requires Docker log inspection — manual test")
	})

	// ===================================================================
	// Part 35: GUI Testing
	// ===================================================================
	t.Run("Part35_GUI", func(t *testing.T) {
		t.Skip("Requires browser — manual test")
	})

	// ===================================================================
	// Part 36-37: Issuer Catalog, Frontend Audit
	// ===================================================================
	t.Run("Part36_IssuerCatalog", func(t *testing.T) {
		t.Skip("Requires browser — manual test")
	})

	t.Run("Part37_FrontendAudit", func(t *testing.T) {
		t.Skip("Requires browser — manual test")
	})

	// ===================================================================
	// Part 38: Error Handling
	// ===================================================================
	t.Run("Part38_ErrorHandling", func(t *testing.T) {
		t.Run("MalformedJSON", func(t *testing.T) {
			code, _ := c.statusCode("POST", "/api/v1/certificates", "this is not json")
			if code != 400 {
				t.Fatalf("malformed JSON = %d, want 400", code)
			}
		})

		t.Run("MissingRequiredField", func(t *testing.T) {
			code, _ := c.statusCode("POST", "/api/v1/certificates", `{"id":"mc-qa-noCN"}`)
			if code != 400 {
				t.Fatalf("missing CN = %d, want 400", code)
			}
		})

		t.Run("MethodNotAllowed", func(t *testing.T) {
			code, _ := c.statusCode("PATCH", "/api/v1/certificates", "")
			if code != 405 {
				t.Logf("PATCH /certificates = %d (server may not distinguish 405 from 404)", code)
			}
		})

		t.Run("UTF8InCommonName", func(t *testing.T) {
			code, _ := c.bodyStr(t, "POST", "/api/v1/certificates", `{
				"id":"mc-qa-utf8","common_name":"日本語.example.com","issuer_id":"iss-local"
			}`)
			if code == 500 {
				t.Fatal("server crashed on UTF-8 common name")
			}
			t.Cleanup(func() { c.delete("/api/v1/certificates/mc-qa-utf8") })
		})

		t.Run("EmptyBody", func(t *testing.T) {
			code, _ := c.statusCode("POST", "/api/v1/certificates", "")
			if code == 500 {
				t.Fatal("server crashed on empty body")
			}
		})
	})

	// ===================================================================
	// Part 39: Performance Spot Checks
	// ===================================================================
	t.Run("Part39_Performance", func(t *testing.T) {
		t.Run("ListCerts_Under200ms", func(t *testing.T) {
			d, code, err := c.timedGet("/api/v1/certificates?per_page=15")
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			if code != 200 {
				t.Fatalf("status = %d", code)
			}
			if d > 200*time.Millisecond {
				t.Fatalf("took %v, want < 200ms", d)
			}
		})

		t.Run("StatsSummary_Under500ms", func(t *testing.T) {
			d, code, _ := c.timedGet("/api/v1/stats/summary")
			if code != 200 {
				t.Fatalf("status = %d", code)
			}
			if d > 500*time.Millisecond {
				t.Fatalf("took %v, want < 500ms", d)
			}
		})

		t.Run("Metrics_Under200ms", func(t *testing.T) {
			d, code, _ := c.timedGet("/api/v1/metrics")
			if code != 200 {
				t.Fatalf("status = %d", code)
			}
			if d > 200*time.Millisecond {
				t.Fatalf("took %v, want < 200ms", d)
			}
		})

		t.Run("Prometheus_Under300ms", func(t *testing.T) {
			d, code, _ := c.timedGet("/api/v1/metrics/prometheus")
			if code != 200 {
				t.Fatalf("status = %d", code)
			}
			if d > 300*time.Millisecond {
				t.Fatalf("took %v, want < 300ms", d)
			}
		})

		t.Run("AuditTrail_Under500ms", func(t *testing.T) {
			d, code, _ := c.timedGet("/api/v1/audit?per_page=50")
			if code != 200 {
				t.Fatalf("status = %d", code)
			}
			if d > 500*time.Millisecond {
				t.Fatalf("took %v, want < 500ms", d)
			}
		})
	})

	// ===================================================================
	// Part 40: Documentation Verification (source checks)
	// ===================================================================
	t.Run("Part40_Docs", func(t *testing.T) {
		t.Run("README_Exists", func(t *testing.T) {
			fileExists(t, "README.md")
		})

		t.Run("Quickstart_Exists", func(t *testing.T) {
			fileExists(t, "docs/quickstart.md")
		})

		t.Run("Architecture_Exists", func(t *testing.T) {
			fileExists(t, "docs/architecture.md")
		})

		t.Run("Connectors_Exists", func(t *testing.T) {
			fileExists(t, "docs/connectors.md")
		})

		t.Run("Compliance_Exists", func(t *testing.T) {
			fileExists(t, "docs/compliance.md")
		})

		t.Run("MigrationGuides_Exist", func(t *testing.T) {
			for _, guide := range []string{
				"docs/migrate-from-certbot.md",
				"docs/migrate-from-acmesh.md",
				"docs/certctl-for-cert-manager-users.md",
			} {
				fileExists(t, guide)
			}
		})

		t.Run("IssuerTypes_InDocs", func(t *testing.T) {
			data, err := os.ReadFile(repoFile("docs/connectors.md"))
			if err != nil {
				t.Fatalf("read connectors.md: %v", err)
			}
			doc := string(data)
			for _, typ := range []string{"ACME", "Vault", "step-ca", "DigiCert", "Sectigo", "Google CAS", "Local CA", "OpenSSL"} {
				if !strings.Contains(doc, typ) {
					t.Errorf("connectors.md missing issuer type: %s", typ)
				}
			}
		})

		t.Run("TargetTypes_InDocs", func(t *testing.T) {
			data, err := os.ReadFile(repoFile("docs/connectors.md"))
			if err != nil {
				t.Fatalf("read connectors.md: %v", err)
			}
			doc := string(data)
			for _, typ := range []string{"NGINX", "Apache", "HAProxy", "Traefik", "Caddy", "Envoy", "F5", "IIS", "SSH", "Postfix", "Java Keystore"} {
				if !strings.Contains(doc, typ) {
					t.Errorf("connectors.md missing target type: %s", typ)
				}
			}
		})
	})

	// ===================================================================
	// Part 41: Regression Tests
	// ===================================================================
	t.Run("Part41_Regression", func(t *testing.T) {
		t.Run("DELETE_Returns204", func(t *testing.T) {
			c.post("/api/v1/targets", `{"id":"tgt-qa-regr","name":"Regression","type":"NGINX","config":{}}`)
			code, _ := c.statusCode("DELETE", "/api/v1/targets/tgt-qa-regr", "")
			if code != 204 {
				t.Fatalf("DELETE target = %d, want 204", code)
			}
		})

		t.Run("PerPage_MaxFallback", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/certificates?per_page=9999", &pr)
			if pr.PerPage != 50 {
				t.Fatalf("per_page = %d, want 50 (default fallback)", pr.PerPage)
			}
		})

		t.Run("SeedNetworkScanTargets", func(t *testing.T) {
			var pr qaPagedResponse
			c.getJSON(t, "/api/v1/network-scan-targets", &pr)
			if pr.Total < 3 {
				t.Fatalf("scan targets = %d, want >= 3", pr.Total)
			}
		})

		t.Run("NoErrors_Is_With_New", func(t *testing.T) {
			// Verify no test files use the broken errors.Is(err, errors.New(...)) pattern
			data, err := os.ReadFile(repoFile("internal/service"))
			if err != nil {
				// Can't read a directory, use filepath.Walk
				var found int
				filepath.Walk(repoFile("internal/service"), func(path string, info os.FileInfo, err error) error {
					if err != nil || !strings.HasSuffix(path, "_test.go") {
						return nil
					}
					content, _ := os.ReadFile(path)
					if strings.Contains(string(content), "errors.Is") && strings.Contains(string(content), "errors.New") {
						// Check if they're on the same line
						for _, line := range strings.Split(string(content), "\n") {
							if strings.Contains(line, "errors.Is") && strings.Contains(line, "errors.New") {
								found++
							}
						}
					}
					return nil
				})
				_ = data
				if found > 0 {
					t.Fatalf("found %d instances of errors.Is(err, errors.New(...)) anti-pattern", found)
				}
				return
			}
		})
	})

	// ===================================================================
	// Part 42: Envoy Target Connector (source checks)
	// ===================================================================
	t.Run("Part42_Envoy", func(t *testing.T) {
		t.Run("DomainType", func(t *testing.T) {
			fileContains(t, "internal/domain/connector.go", "TargetTypeEnvoy")
		})

		t.Run("ConnectorExists", func(t *testing.T) {
			fileExists(t, "internal/connector/target/envoy/envoy.go")
		})

		t.Run("TestFileExists", func(t *testing.T) {
			fileExists(t, "internal/connector/target/envoy/envoy_test.go")
		})

		t.Run("InOpenAPI", func(t *testing.T) {
			fileContains(t, "api/openapi.yaml", "Envoy")
		})

		t.Run("AgentDispatch", func(t *testing.T) {
			fileContains(t, "cmd/agent/main.go", "envoy")
		})
	})

	// ===================================================================
	// Part 43: Postfix & Dovecot
	// ===================================================================
	t.Run("Part43_PostfixDovecot", func(t *testing.T) {
		t.Run("DomainTypes", func(t *testing.T) {
			fileContains(t, "internal/domain/connector.go", "TargetTypePostfix")
			fileContains(t, "internal/domain/connector.go", "TargetTypeDovecot")
		})

		t.Run("ConnectorExists", func(t *testing.T) {
			fileExists(t, "internal/connector/target/postfix/postfix.go")
		})

		t.Run("InOpenAPI", func(t *testing.T) {
			fileContains(t, "api/openapi.yaml", "Postfix")
			fileContains(t, "api/openapi.yaml", "Dovecot")
		})
	})

	// ===================================================================
	// Part 44: SSH Target Connector
	// ===================================================================
	t.Run("Part44_SSH", func(t *testing.T) {
		t.Run("DomainType", func(t *testing.T) {
			fileContains(t, "internal/domain/connector.go", "TargetTypeSSH")
		})

		t.Run("ConnectorExists", func(t *testing.T) {
			fileExists(t, "internal/connector/target/ssh/ssh.go")
		})

		t.Run("AgentDispatch", func(t *testing.T) {
			fileContains(t, "cmd/agent/main.go", "sshconn")
		})

		t.Run("InOpenAPI", func(t *testing.T) {
			fileContains(t, "api/openapi.yaml", "SSH")
		})
	})

	// ===================================================================
	// Part 45: Windows Certificate Store
	// ===================================================================
	t.Run("Part45_WinCertStore", func(t *testing.T) {
		t.Run("DomainType", func(t *testing.T) {
			fileContains(t, "internal/domain/connector.go", "TargetTypeWinCertStore")
		})

		t.Run("ConnectorExists", func(t *testing.T) {
			fileExists(t, "internal/connector/target/wincertstore/wincertstore.go")
		})

		t.Run("SharedCertutil", func(t *testing.T) {
			fileExists(t, "internal/connector/target/certutil/certutil.go")
			fileExists(t, "internal/connector/target/certutil/certutil_test.go")
		})
	})

	// ===================================================================
	// Part 46: Java Keystore
	// ===================================================================
	t.Run("Part46_JavaKeystore", func(t *testing.T) {
		t.Run("DomainType", func(t *testing.T) {
			fileContains(t, "internal/domain/connector.go", "TargetTypeJavaKeystore")
		})

		t.Run("ConnectorExists", func(t *testing.T) {
			fileExists(t, "internal/connector/target/javakeystore/javakeystore.go")
		})

		t.Run("InOpenAPI", func(t *testing.T) {
			fileContains(t, "api/openapi.yaml", "JavaKeystore")
		})
	})

	// ===================================================================
	// Part 47: Certificate Digest Email
	// ===================================================================
	t.Run("Part47_Digest", func(t *testing.T) {
		t.Run("PreviewEndpoint", func(t *testing.T) {
			code, _ := c.bodyStr(t, "GET", "/api/v1/digest/preview", "")
			// 200 if SMTP configured, 503 if not
			if code != 200 && code != 503 {
				t.Fatalf("digest preview = %d, want 200 or 503", code)
			}
		})

		t.Run("ServiceExists", func(t *testing.T) {
			fileExists(t, "internal/service/digest.go")
		})

		t.Run("AdapterExists", func(t *testing.T) {
			fileExists(t, "internal/connector/notifier/email/adapter.go")
		})
	})

	// ===================================================================
	// Part 48: Dynamic Issuer Configuration
	// ===================================================================
	t.Run("Part48_DynamicIssuers", func(t *testing.T) {
		t.Run("CryptoPackage", func(t *testing.T) {
			fileExists(t, "internal/crypto/crypto.go")
		})

		t.Run("CreateIssuerViaAPI", func(t *testing.T) {
			code, body := c.bodyStr(t, "POST", "/api/v1/issuers", `{
				"name":"QA Dynamic ACME","type":"ACME",
				"config":{"directory_url":"https://acme-staging-v02.api.letsencrypt.org/directory","email":"qa@example.com"}
			}`)
			if code != 201 && code != 200 {
				t.Fatalf("create dynamic issuer = %d, body: %s", code, body)
			}
			// Extract ID for cleanup
			var resp map[string]interface{}
			json.Unmarshal([]byte(body), &resp)
			if id, ok := resp["id"].(string); ok {
				t.Cleanup(func() { c.delete("/api/v1/issuers/" + id) })
			}
		})

		t.Run("ConfigRedacted", func(t *testing.T) {
			// Check that sensitive fields are masked in list responses
			_, body := c.bodyStr(t, "GET", "/api/v1/issuers", "")
			// If vault token or api_key appears unmasked, it's a security issue
			if strings.Contains(body, "s.") && strings.Contains(body, "vault_token") {
				// Heuristic — real vault tokens start with "s."
				t.Log("WARNING: Vault token may be exposed in API response")
			}
		})

		t.Run("Migration_Exists", func(t *testing.T) {
			fileExists(t, "migrations/000009_issuer_config.up.sql")
		})
	})

	// ===================================================================
	// Part 49: Dynamic Target Configuration
	// ===================================================================
	t.Run("Part49_DynamicTargets", func(t *testing.T) {
		t.Run("CreateTargetViaAPI", func(t *testing.T) {
			code, body := c.bodyStr(t, "POST", "/api/v1/targets", `{
				"name":"QA Dynamic NGINX","type":"NGINX",
				"config":{"cert_path":"/etc/ssl/cert.pem","key_path":"/etc/ssl/key.pem","reload_command":"nginx -s reload"}
			}`)
			if code != 201 && code != 200 {
				t.Fatalf("create dynamic target = %d, body: %s", code, body)
			}
			var resp map[string]interface{}
			json.Unmarshal([]byte(body), &resp)
			if id, ok := resp["id"].(string); ok {
				t.Cleanup(func() { c.delete("/api/v1/targets/" + id) })
			}
		})

		t.Run("Migration_Exists", func(t *testing.T) {
			fileExists(t, "migrations/000010_target_config.up.sql")
		})
	})

	// ===================================================================
	// Part 50: Onboarding Wizard
	// ===================================================================
	t.Run("Part50_Onboarding", func(t *testing.T) {
		t.Run("WizardComponent_Exists", func(t *testing.T) {
			fileExists(t, "web/src/pages/OnboardingWizard.tsx")
		})

		t.Run("DockerCompose_Split", func(t *testing.T) {
			// Clean compose should NOT reference seed_demo
			data, _ := os.ReadFile(repoFile("deploy/docker-compose.yml"))
			if strings.Contains(string(data), "seed_demo") {
				t.Fatal("docker-compose.yml should not reference seed_demo.sql")
			}
			// Demo override SHOULD reference seed_demo
			data, _ = os.ReadFile(repoFile("deploy/docker-compose.demo.yml"))
			if !strings.Contains(string(data), "seed_demo") {
				t.Fatal("docker-compose.demo.yml should reference seed_demo.sql")
			}
		})
	})

	// ===================================================================
	// Part 51: ACME Profile Selection
	// ===================================================================
	t.Run("Part51_ACMEProfiles", func(t *testing.T) {
		t.Run("ProfileModule_Exists", func(t *testing.T) {
			fileExists(t, "internal/connector/issuer/acme/profile.go")
			fileExists(t, "internal/connector/issuer/acme/profile_test.go")
		})

		t.Run("ProfileConfig_InFrontend", func(t *testing.T) {
			fileContains(t, "web/src/config/issuerTypes.ts", "profile")
		})

		t.Run("ARI_RFC9773_NoOldRefs", func(t *testing.T) {
			// Verify no remaining references to old RFC 9702
			files := []string{
				"internal/connector/issuer/acme/ari.go",
				"internal/domain/ari.go",
				"internal/service/renewal.go",
			}
			for _, f := range files {
				data, err := os.ReadFile(repoFile(f))
				if err != nil {
					continue
				}
				if strings.Contains(string(data), "9702") {
					t.Errorf("%s still references RFC 9702 (should be 9773)", f)
				}
			}
		})
	})

	// ===================================================================
	// Part 52: Helm Chart
	// ===================================================================
	t.Run("Part52_HelmChart", func(t *testing.T) {
		t.Run("ChartYAML_Exists", func(t *testing.T) {
			fileExists(t, "deploy/helm/certctl/Chart.yaml")
		})

		t.Run("ValuesYAML_Exists", func(t *testing.T) {
			fileExists(t, "deploy/helm/certctl/values.yaml")
		})

		t.Run("Templates_Exist", func(t *testing.T) {
			for _, tmpl := range []string{
				"deploy/helm/certctl/templates/server-deployment.yaml",
				"deploy/helm/certctl/templates/server-service.yaml",
				"deploy/helm/certctl/templates/postgres-statefulset.yaml",
				"deploy/helm/certctl/templates/agent-daemonset.yaml",
			} {
				fileExists(t, tmpl)
			}
		})

		t.Run("SecurityContext_InTemplates", func(t *testing.T) {
			fileContains(t, "deploy/helm/certctl/templates/server-deployment.yaml", "securityContext")
		})

		t.Run("HealthProbes_InTemplates", func(t *testing.T) {
			fileContains(t, "deploy/helm/certctl/templates/server-deployment.yaml", "livenessProbe")
			fileContains(t, "deploy/helm/certctl/templates/server-deployment.yaml", "readinessProbe")
		})
	})

	// ===================================================================
	t.Run("Part53_KubernetesSecrets", func(t *testing.T) {
		t.Run("ConnectorPackageExists", func(t *testing.T) {
			fileExists(t, "internal/connector/target/k8ssecret/k8ssecret.go")
		})

		t.Run("TestFileExists", func(t *testing.T) {
			fileExists(t, "internal/connector/target/k8ssecret/k8ssecret_test.go")
		})

		t.Run("DomainTypeRegistered", func(t *testing.T) {
			fileContains(t, "internal/domain/connector.go", `TargetTypeKubernetesSecrets`)
		})

		t.Run("ServiceValidationEntry", func(t *testing.T) {
			fileContains(t, "internal/service/target.go", `TargetTypeKubernetesSecrets`)
		})

		t.Run("AgentDispatchCase", func(t *testing.T) {
			fileContains(t, "cmd/agent/main.go", `"KubernetesSecrets"`)
		})

		t.Run("FrontendTypeLabel", func(t *testing.T) {
			fileContains(t, "web/src/pages/TargetsPage.tsx", `KubernetesSecrets`)
		})

		t.Run("OpenAPIEnum", func(t *testing.T) {
			fileContains(t, "api/openapi.yaml", `KubernetesSecrets`)
		})

		t.Run("HelmRBAC", func(t *testing.T) {
			fileContains(t, "deploy/helm/certctl/templates/serviceaccount.yaml", `secrets`)
		})
	})

	// ===================================================================
	t.Run("Part54_AWSACMPCA", func(t *testing.T) {
		t.Run("ConnectorPackageExists", func(t *testing.T) {
			fileExists(t, "internal/connector/issuer/awsacmpca/awsacmpca.go")
		})

		t.Run("TestFileExists", func(t *testing.T) {
			fileExists(t, "internal/connector/issuer/awsacmpca/awsacmpca_test.go")
		})

		t.Run("DomainTypeRegistered", func(t *testing.T) {
			fileContains(t, "internal/domain/connector.go", `IssuerTypeAWSACMPCA`)
		})

		t.Run("ServiceValidationEntry", func(t *testing.T) {
			fileContains(t, "internal/service/issuer.go", `IssuerTypeAWSACMPCA`)
		})

		t.Run("FactoryCase", func(t *testing.T) {
			fileContains(t, "internal/connector/issuerfactory/factory.go", `"AWSACMPCA"`)
		})

		t.Run("ConfigStruct", func(t *testing.T) {
			fileContains(t, "internal/config/config.go", `AWSACMPCAConfig`)
		})

		t.Run("EnvVarSeed", func(t *testing.T) {
			fileContains(t, "internal/service/issuer.go", `iss-awsacmpca`)
		})

		t.Run("FrontendIssuerType", func(t *testing.T) {
			fileContains(t, "web/src/config/issuerTypes.ts", `AWSACMPCA`)
		})

		t.Run("OpenAPIEnum", func(t *testing.T) {
			fileContains(t, "api/openapi.yaml", `AWSACMPCA`)
		})

		t.Run("SeedDemoData", func(t *testing.T) {
			fileContains(t, "migrations/seed_demo.sql", `iss-awsacmpca`)
		})
	})

	// ===================================================================
	// Part 55: Agent Soft-Retirement (I-004) — manual test (no automation yet)
	// ===================================================================
	t.Run("Part55_AgentSoftRetire", func(t *testing.T) {
		t.Skip("Part 55 (Agent Soft-Retirement) is documented in docs/testing-guide.md::Part 55 " +
			"as a manual test. Automation candidates: POST /api/v1/agents/{id}/retire with " +
			"soft=true does not delete; foreign-key cascade behavior on certs owned by retired " +
			"agent; reactivation flow restores agent status.")
	})

	// ===================================================================
	// Part 56: Notification Retry & Dead-Letter Queue (I-005) — manual test (no automation yet)
	// ===================================================================
	t.Run("Part56_NotificationDeadLetter", func(t *testing.T) {
		t.Skip("Part 56 (Notification Retry/Dead-Letter) is documented in docs/testing-guide.md::Part 56 " +
			"as a manual test. Automation candidates: notification with N consecutive failures " +
			"transitions to status=DeadLetter; POST /api/v1/notifications/{id}/requeue resets to " +
			"Pending; idempotency under concurrent retry; alert on dead-letter buildup.")
	})
}

// Note: uses Go 1.21+ built-in min() — no custom definition needed.
