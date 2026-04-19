package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClient_ListCertificates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/certificates" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{
					"id":          "mc-1",
					"common_name": "example.com",
					"status":      "Active",
					"expires_at":  "2025-12-31T00:00:00Z",
					"issuer_id":   "iss-local",
				},
			},
			"total": 1,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "table")
	err := client.ListCertificates([]string{})
	if err != nil {
		t.Fatalf("ListCertificates failed: %v", err)
	}
}

func TestClient_GetCertificate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/certificates/mc-1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          "mc-1",
			"common_name": "example.com",
			"status":      "Active",
			"expires_at":  "2025-12-31T00:00:00Z",
			"issuer_id":   "iss-local",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "json")
	err := client.GetCertificate("mc-1")
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
}

func TestClient_RenewCertificate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/certificates/mc-1/renew" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"job_id": "job-123",
			"status": "Pending",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "table")
	err := client.RenewCertificate("mc-1")
	if err != nil {
		t.Fatalf("RenewCertificate failed: %v", err)
	}
}

func TestClient_RevokeCertificate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/certificates/mc-1/revoke" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "revoked",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "table")
	err := client.RevokeCertificate("mc-1", "cessationOfOperation")
	if err != nil {
		t.Fatalf("RevokeCertificate failed: %v", err)
	}
}

func TestClient_BulkRevokeCertificates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/certificates/bulk-revoke" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Verify request body contains expected fields
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if body["reason"] != "keyCompromise" {
			t.Errorf("expected reason keyCompromise, got %v", body["reason"])
		}
		if body["profile_id"] != "prof-tls" {
			t.Errorf("expected profile_id prof-tls, got %v", body["profile_id"])
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total_matched": 3,
			"total_revoked": 2,
			"total_skipped": 1,
			"total_failed":  0,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "table")
	err := client.BulkRevokeCertificates([]string{
		"--reason", "keyCompromise",
		"--profile-id", "prof-tls",
	})
	if err != nil {
		t.Fatalf("BulkRevokeCertificates failed: %v", err)
	}
}

func TestClient_ListAgents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/agents" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{
					"id":           "ag-1",
					"hostname":     "agent1.example.com",
					"status":       "Online",
					"os":           "linux",
					"architecture": "amd64",
					"ip_address":   "192.168.1.1",
				},
			},
			"total": 1,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "table")
	err := client.ListAgents([]string{})
	if err != nil {
		t.Fatalf("ListAgents failed: %v", err)
	}
}

func TestClient_GetAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/agents/ag-1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":           "ag-1",
			"hostname":     "agent1.example.com",
			"status":       "Online",
			"os":           "linux",
			"architecture": "amd64",
			"ip_address":   "192.168.1.1",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "json")
	err := client.GetAgent("ag-1")
	if err != nil {
		t.Fatalf("GetAgent failed: %v", err)
	}
}

func TestClient_ListJobs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/jobs" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{
					"id":             "job-1",
					"type":           "Renewal",
					"certificate_id": "mc-1",
					"status":         "Completed",
					"attempts":       1,
					"max_attempts":   3,
				},
			},
			"total": 1,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "table")
	err := client.ListJobs([]string{})
	if err != nil {
		t.Fatalf("ListJobs failed: %v", err)
	}
}

func TestClient_GetJob(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/jobs/job-1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":             "job-1",
			"type":           "Renewal",
			"certificate_id": "mc-1",
			"status":         "Completed",
			"attempts":       1,
			"max_attempts":   3,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "json")
	err := client.GetJob("job-1")
	if err != nil {
		t.Fatalf("GetJob failed: %v", err)
	}
}

func TestClient_CancelJob(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/jobs/job-1/cancel" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "table")
	err := client.CancelJob("job-1")
	if err != nil {
		t.Fatalf("CancelJob failed: %v", err)
	}
}

func TestClient_GetStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/v1/health" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":    "healthy",
				"timestamp": time.Now().Format(time.RFC3339),
			})
		} else if r.URL.Path == "/api/v1/stats/summary" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"total_certificates": 10,
					"total_agents":       5,
				},
			})
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "table")
	err := client.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
}

func TestParsePEMCertificates(t *testing.T) {
	// Generate a self-signed test certificate
	cert := generateTestCert()

	// Encode it to PEM
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	// Parse it back
	certs, err := parsePEMCertificates(pemData)
	if err != nil {
		t.Fatalf("parsePEMCertificates failed: %v", err)
	}

	if len(certs) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(certs))
	}

	if certs[0].Subject.CommonName != "test.example.com" {
		t.Fatalf("expected CommonName 'test.example.com', got %s", certs[0].Subject.CommonName)
	}
}

func TestParsePEMCertificates_Multiple(t *testing.T) {
	// Generate two test certificates
	cert1 := generateTestCert()
	cert2 := generateTestCert()

	// Encode both to PEM
	block1 := &pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw}
	block2 := &pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw}

	pemData := append(pem.EncodeToMemory(block1), pem.EncodeToMemory(block2)...)

	// Parse them back
	certs, err := parsePEMCertificates(pemData)
	if err != nil {
		t.Fatalf("parsePEMCertificates failed: %v", err)
	}

	if len(certs) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(certs))
	}
}

func TestParsePEMCertificates_NoCertificates(t *testing.T) {
	pemData := []byte("no certificates here")

	_, err := parsePEMCertificates(pemData)
	if err == nil {
		t.Fatal("expected error for empty PEM data")
	}
}

func TestClient_AuthHeader(t *testing.T) {
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"data": []interface{}{}})
	}))
	defer server.Close()

	client := NewClient(server.URL, "testkey123", "json")
	client.do("GET", "/api/v1/certificates", nil, nil)

	if authHeader != "Bearer testkey123" {
		t.Fatalf("expected 'Bearer testkey123', got '%s'", authHeader)
	}
}

// TestClient_ImportCertificates_MissingRequiredFlags verifies the CLI
// import command rejects invocations missing any of the four required
// flags (--owner-id, --team-id, --renewal-policy-id, --issuer-id)
// before any network call is attempted. This is the C-001 scope-expansion
// closure for the CLI layer: the handler now requires all six cert
// fields, so the importer must collect ownership / team / policy /
// issuer up front rather than hard-coding iss-local and letting the
// server 400 on every POST.
func TestClient_ImportCertificates_MissingRequiredFlags(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cases := []struct {
		name    string
		args    []string
		missing string
	}{
		{
			name:    "missing owner-id",
			args:    []string{"--team-id", "t-platform", "--renewal-policy-id", "rp-default", "--issuer-id", "iss-local", "certs.pem"},
			missing: "--owner-id",
		},
		{
			name:    "missing team-id",
			args:    []string{"--owner-id", "o-alice", "--renewal-policy-id", "rp-default", "--issuer-id", "iss-local", "certs.pem"},
			missing: "--team-id",
		},
		{
			name:    "missing renewal-policy-id",
			args:    []string{"--owner-id", "o-alice", "--team-id", "t-platform", "--issuer-id", "iss-local", "certs.pem"},
			missing: "--renewal-policy-id",
		},
		{
			name:    "missing issuer-id",
			args:    []string{"--owner-id", "o-alice", "--team-id", "t-platform", "--renewal-policy-id", "rp-default", "certs.pem"},
			missing: "--issuer-id",
		},
		{
			name:    "no flags at all",
			args:    []string{"certs.pem"},
			missing: "--owner-id",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := NewClient(server.URL, "", "table")
			err := client.ImportCertificates(tc.args)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			msg := err.Error()
			if !containsStr(msg, tc.missing) {
				t.Fatalf("expected error to name %q, got: %v", tc.missing, err)
			}
			if !containsStr(msg, "required") {
				t.Fatalf("expected error message to mention 'required', got: %v", err)
			}
		})
	}

	if requestCount != 0 {
		t.Fatalf("expected zero HTTP requests before flag validation, got %d", requestCount)
	}
}

// TestClient_ImportCertificates_MissingPositionalArgs verifies the
// import command errors out when flags are present but no PEM file
// paths follow them.
func TestClient_ImportCertificates_MissingPositionalArgs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected HTTP request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "table")
	err := client.ImportCertificates([]string{
		"--owner-id", "o-alice",
		"--team-id", "t-platform",
		"--renewal-policy-id", "rp-default",
		"--issuer-id", "iss-local",
	})
	if err == nil {
		t.Fatal("expected error when no PEM file paths are supplied")
	}
	if !containsStr(err.Error(), "PEM file") {
		t.Fatalf("expected error to mention 'PEM file', got: %v", err)
	}
}

// TestClient_ImportCertificates_SixFieldPayload verifies the happy
// path: given all four required flags plus a PEM file, the importer
// POSTs a request containing all six required fields plus the
// name-template–resolved name. The httptest handler decodes the
// request body and asserts every required field is populated with
// the values supplied via flags.
func TestClient_ImportCertificates_SixFieldPayload(t *testing.T) {
	// Generate a test cert and write it to a temp PEM file.
	cert := generateTestCert()
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	pemPath := filepath.Join(t.TempDir(), "test.pem")
	if err := os.WriteFile(pemPath, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		t.Fatalf("write temp PEM: %v", err)
	}

	var gotBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/certificates" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"mc-imported"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "table")
	err := client.ImportCertificates([]string{
		"--owner-id", "o-alice",
		"--team-id", "t-platform",
		"--renewal-policy-id", "rp-default",
		"--issuer-id", "iss-local",
		"--name-template", "imported-{cn}",
		pemPath,
	})
	if err != nil {
		t.Fatalf("ImportCertificates failed: %v", err)
	}

	// Verify every required field from the six-field contract is present.
	required := []struct {
		field string
		want  interface{}
	}{
		{"name", "imported-test.example.com"},
		{"common_name", "test.example.com"},
		{"issuer_id", "iss-local"},
		{"owner_id", "o-alice"},
		{"team_id", "t-platform"},
		{"renewal_policy_id", "rp-default"},
	}
	for _, r := range required {
		got, ok := gotBody[r.field]
		if !ok {
			t.Errorf("payload missing required field %q (body: %+v)", r.field, gotBody)
			continue
		}
		if got != r.want {
			t.Errorf("field %q = %v, want %v", r.field, got, r.want)
		}
	}
}

// containsStr is a tiny substring helper so the test file doesn't
// need a `strings` import dependency aside from what's already there.
func containsStr(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// Helper function to generate a test certificate
func generateTestCert() *x509.Certificate {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com", "*.test.example.com"},
	}

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	cert, _ := x509.ParseCertificate(certBytes)

	return cert
}
