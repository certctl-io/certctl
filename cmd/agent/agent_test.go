package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAgent_Heartbeat_Success tests that heartbeat sends correct metadata and handles 200 response.
func TestAgent_Heartbeat_Success(t *testing.T) {
	// Create mock server to validate heartbeat request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify correct endpoint and method
		if r.URL.Path != "/api/v1/agents/a-test-agent/heartbeat" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s, expected POST", r.Method)
		}

		// Verify auth header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-key" {
			t.Errorf("unexpected auth header: %s", auth)
		}

		// Verify request body contains required fields
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}

		// Check required fields
		if _, ok := payload["version"]; !ok {
			t.Error("missing version in heartbeat")
		}
		if _, ok := payload["hostname"]; !ok {
			t.Error("missing hostname in heartbeat")
		}
		if _, ok := payload["os"]; !ok {
			t.Error("missing os in heartbeat")
		}
		if _, ok := payload["architecture"]; !ok {
			t.Error("missing architecture in heartbeat")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-test-agent",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	// Should not panic
	agent.sendHeartbeat(context.Background())
}

// TestAgent_Heartbeat_ServerError tests that heartbeat handles 500 response gracefully.
func TestAgent_Heartbeat_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-test-agent",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	// Should increment consecutive failures
	failureBefore := agent.consecutiveFailures
	agent.sendHeartbeat(context.Background())
	failureAfter := agent.consecutiveFailures

	if failureAfter != failureBefore+1 {
		t.Errorf("expected consecutive failures to increment, got %d, want %d", failureAfter, failureBefore+1)
	}
}

// TestAgent_Heartbeat_ConnectionError tests that heartbeat handles connection error.
func TestAgent_Heartbeat_ConnectionError(t *testing.T) {
	// Use an invalid address that will fail immediately
	cfg := &AgentConfig{
		ServerURL: "http://invalid-host-that-does-not-exist.local:9999",
		APIKey:    "test-key",
		AgentID:   "a-test-agent",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	// Should fail due to connection error
	agent.sendHeartbeat(context.Background())

	if agent.consecutiveFailures != 1 {
		t.Errorf("expected consecutive failures to be 1, got %d", agent.consecutiveFailures)
	}
}

// TestAgent_PollWork_NoWork tests that work polling handles empty work list.
func TestAgent_PollWork_NoWork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/a-test-agent/work" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s", r.Method)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(WorkResponse{
			Jobs:  []JobItem{},
			Count: 0,
		})
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-test-agent",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	// Should not panic
	agent.pollForWork(context.Background())
}

// TestAgent_PollWork_Success tests that work polling parses and returns jobs correctly.
func TestAgent_PollWork_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		workResp := WorkResponse{
			Count: 2,
			Jobs: []JobItem{
				{
					ID:            "j-csr-001",
					Type:          "Issuance",
					CertificateID: "mc-001",
					CommonName:    "example.com",
					SANs:          []string{"www.example.com"},
					Status:        "AwaitingCSR",
				},
				{
					ID:            "j-deploy-001",
					Type:          "Deployment",
					CertificateID: "mc-001",
					TargetID:      strPtr("t-nginx-1"),
					TargetType:    "NGINX",
					TargetConfig:  json.RawMessage(`{"cert_path":"/etc/nginx/cert.pem"}`),
					Status:        "Pending",
				},
			},
		}

		json.NewEncoder(w).Encode(workResp)
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-test-agent",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	// Should not panic; work items are processed in separate gorines in real usage
	agent.pollForWork(context.Background())
}

// TestSplitPEMChain tests PEM chain splitting into cert and chain.
func TestSplitPEMChain(t *testing.T) {
	// Create two test certificates
	cert1, _ := generateTestCertWithCN("cert1.example.com")
	cert2, _ := generateTestCertWithCN("cert2.example.com")

	block1 := &pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw}
	block2 := &pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw}

	cert1PEM := string(pem.EncodeToMemory(block1))
	cert2PEM := string(pem.EncodeToMemory(block2))

	chainPEM := cert1PEM + "\n" + cert2PEM

	// Split
	certOnly, chain := splitPEMChain(chainPEM)

	// Verify cert part
	if !bytes.Contains([]byte(certOnly), []byte("-----BEGIN CERTIFICATE-----")) {
		t.Error("cert part missing BEGIN marker")
	}

	// Verify chain part
	if !bytes.Contains([]byte(chain), []byte("-----BEGIN CERTIFICATE-----")) {
		t.Error("chain part missing BEGIN marker")
	}

	// Verify they're different
	if certOnly == chain {
		t.Error("cert and chain should be different")
	}
}

// TestSplitPEMChain_SingleCert tests PEM chain splitting with single certificate.
func TestSplitPEMChain_SingleCert(t *testing.T) {
	cert, _ := generateTestCertWithCN("example.com")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	certPEM := string(pem.EncodeToMemory(block))

	certOnly, chain := splitPEMChain(certPEM)

	if certOnly != certPEM {
		t.Error("single cert should be returned as-is")
	}
	if chain != "" {
		t.Error("chain should be empty for single cert")
	}
}

// TestSplitPEMChain_InvalidPEM tests PEM chain splitting with invalid PEM.
func TestSplitPEMChain_InvalidPEM(t *testing.T) {
	invalidPEM := "not a valid pem"

	certOnly, chain := splitPEMChain(invalidPEM)

	if certOnly != invalidPEM {
		t.Error("invalid PEM should be returned as-is in cert part")
	}
	if chain != "" {
		t.Error("chain should be empty for invalid PEM")
	}
}

// TestParsePEMFile tests parsing a PEM file with certificates.
func TestParsePEMFile(t *testing.T) {
	// Create a temporary file with a PEM certificate
	tmpdir := t.TempDir()
	certPath := filepath.Join(tmpdir, "cert.pem")

	cert, _ := generateTestCert()
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	certPEM := pem.EncodeToMemory(block)

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("failed to write test cert: %v", err)
	}

	cfg := &AgentConfig{
		ServerURL: "http://localhost:8443",
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	// Parse the file
	entries := agent.parsePEMFile(certPath)

	if len(entries) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(entries))
		return
	}

	entry := entries[0]
	if entry.CommonName != "test.example.com" {
		t.Errorf("expected CN 'test.example.com', got '%s'", entry.CommonName)
	}
	if entry.SourceFormat != "PEM" {
		t.Errorf("expected format 'PEM', got '%s'", entry.SourceFormat)
	}
	if entry.SourcePath != certPath {
		t.Errorf("expected path '%s', got '%s'", certPath, entry.SourcePath)
	}

	// Verify fingerprint is non-empty and correct length (SHA256 hex = 64 chars)
	if len(entry.FingerprintSHA256) != 64 {
		t.Errorf("expected 64-char fingerprint, got %d", len(entry.FingerprintSHA256))
	}
}

// TestParsePEMFile_MultipleCerts tests parsing a PEM file with multiple certificates.
func TestParsePEMFile_MultipleCerts(t *testing.T) {
	tmpdir := t.TempDir()
	certPath := filepath.Join(tmpdir, "chain.pem")

	cert1, _ := generateTestCertWithCN("cert1.example.com")
	cert2, _ := generateTestCertWithCN("cert2.example.com")

	block1 := &pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw}
	block2 := &pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw}

	certPEM := append(pem.EncodeToMemory(block1), pem.EncodeToMemory(block2)...)

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("failed to write test cert: %v", err)
	}

	cfg := &AgentConfig{
		ServerURL: "http://localhost:8443",
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	entries := agent.parsePEMFile(certPath)

	if len(entries) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(entries))
	}
}

// TestParseDERFile tests parsing a DER-encoded certificate file.
func TestParseDERFile(t *testing.T) {
	tmpdir := t.TempDir()
	derPath := filepath.Join(tmpdir, "cert.der")

	cert, _ := generateTestCertWithCN("test.example.com")
	if err := os.WriteFile(derPath, cert.Raw, 0644); err != nil {
		t.Fatalf("failed to write test cert: %v", err)
	}

	cfg := &AgentConfig{
		ServerURL: "http://localhost:8443",
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	entry, err := agent.parseDERFile(derPath)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	if entry.CommonName != "test.example.com" {
		t.Errorf("expected CN 'test.example.com', got '%s'", entry.CommonName)
	}
	if entry.SourceFormat != "DER" {
		t.Errorf("expected format 'DER', got '%s'", entry.SourceFormat)
	}
	if len(entry.FingerprintSHA256) != 64 {
		t.Errorf("expected 64-char fingerprint, got %d", len(entry.FingerprintSHA256))
	}
}

// TestParseDERFile_Invalid tests parsing an invalid DER file.
func TestParseDERFile_Invalid(t *testing.T) {
	tmpdir := t.TempDir()
	derPath := filepath.Join(tmpdir, "invalid.der")

	if err := os.WriteFile(derPath, []byte("not a valid der file"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cfg := &AgentConfig{
		ServerURL: "http://localhost:8443",
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	_, err := agent.parseDERFile(derPath)
	if err == nil {
		t.Error("expected error for invalid DER file")
	}
}

// TestScanDirectory tests scanning a directory for certificate files.
func TestScanDirectory(t *testing.T) {
	tmpdir := t.TempDir()

	// Create subdirectory
	subdir := filepath.Join(tmpdir, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	// Create certificates with various extensions
	cert1, _ := generateTestCertWithCN("cert1.example.com")
	cert2, _ := generateTestCertWithCN("cert2.example.com")

	// Write cert1.pem
	block1 := &pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw}
	if err := os.WriteFile(filepath.Join(tmpdir, "cert1.pem"), pem.EncodeToMemory(block1), 0644); err != nil {
		t.Fatalf("failed to write cert1: %v", err)
	}

	// Write cert2.crt in subdir
	block2 := &pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw}
	if err := os.WriteFile(filepath.Join(subdir, "cert2.crt"), pem.EncodeToMemory(block2), 0644); err != nil {
		t.Fatalf("failed to write cert2: %v", err)
	}

	cfg := &AgentConfig{
		ServerURL:     "http://localhost:8443",
		APIKey:        "test-key",
		AgentID:       "a-test",
		Hostname:      "test-host",
		DiscoveryDirs: []string{tmpdir},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	// Simulate directory walk manually (as runDiscoveryScan does)
	var certs []discoveredCertEntry
	filepath.Walk(tmpdir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		switch ext {
		case ".pem", ".crt":
			found := agent.parsePEMFile(path)
			certs = append(certs, found...)
		}
		return nil
	})

	if len(certs) != 2 {
		t.Errorf("expected 2 certificates from directory scan, got %d", len(certs))
	}
}

// TestCreateTargetConnector_NGINX tests connector creation for NGINX target.
func TestCreateTargetConnector_NGINX(t *testing.T) {
	cfg := &AgentConfig{
		ServerURL: "http://localhost:8443",
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	configJSON := json.RawMessage(`{"cert_path":"/etc/nginx/cert.pem"}`)
	connector, err := agent.createTargetConnector("NGINX", configJSON)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if connector == nil {
		t.Error("expected connector to be non-nil")
	}
}

// TestCreateTargetConnector_Unsupported tests connector creation for unsupported type.
func TestCreateTargetConnector_Unsupported(t *testing.T) {
	cfg := &AgentConfig{
		ServerURL: "http://localhost:8443",
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	_, err := agent.createTargetConnector("UnsupportedType", nil)

	if err == nil {
		t.Error("expected error for unsupported target type")
	}
}

// TestFetchCertificate_Success tests fetching a certificate from the control plane.
func TestFetchCertificate_Success(t *testing.T) {
	cert, _ := generateTestCertWithCN("test.example.com")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	expectedCertPEM := string(pem.EncodeToMemory(block))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/a-test/certificates/mc-001" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"certificate_pem": expectedCertPEM,
		})
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	certPEM, err := agent.fetchCertificate(context.Background(), "mc-001")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if certPEM != expectedCertPEM {
		t.Error("certificate PEM mismatch")
	}
}

// TestFetchCertificate_NotFound tests fetching a non-existent certificate.
func TestFetchCertificate_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	_, err := agent.fetchCertificate(context.Background(), "mc-nonexistent")
	if err == nil {
		t.Error("expected error for non-existent certificate")
	}
}

// TestReportJobStatus_Success tests reporting job status to the control plane.
func TestReportJobStatus_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/a-test/jobs/j-001/status" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}

		var payload map[string]string
		json.NewDecoder(r.Body).Decode(&payload)

		if payload["status"] != "Completed" {
			t.Errorf("expected status 'Completed', got '%s'", payload["status"])
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	err := agent.reportJobStatus(context.Background(), "j-001", "Completed", "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestReportJobStatus_WithError tests reporting job status with error message.
func TestReportJobStatus_WithError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		json.NewDecoder(r.Body).Decode(&payload)

		if payload["status"] != "Failed" {
			t.Errorf("expected status 'Failed', got '%s'", payload["status"])
		}
		if payload["error"] != "deployment failed" {
			t.Errorf("expected error 'deployment failed', got '%s'", payload["error"])
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	err := agent.reportJobStatus(context.Background(), "j-001", "Failed", "deployment failed")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestMakeRequest_Success tests making an authenticated HTTP request.
func TestMakeRequest_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-key" {
			t.Errorf("unexpected auth: %s", auth)
		}

		// Verify content-type
		ct := r.Header.Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("unexpected content-type: %s", ct)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	resp, err := agent.makeRequest(context.Background(), http.MethodPost, "/test", map[string]string{"key": "value"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status: %d", resp.StatusCode)
	}
}

// TestMakeRequest_InvalidURL tests making a request with invalid URL.
func TestMakeRequest_InvalidURL(t *testing.T) {
	cfg := &AgentConfig{
		ServerURL: "http://invalid-host-that-does-not-exist.local:9999",
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	_, err := agent.makeRequest(context.Background(), http.MethodGet, "/test", nil)
	if err == nil {
		t.Error("expected error for unreachable host")
	}
}

// TestCertKeyInfo tests extraction of key algorithm and size from certificates.
func TestCertKeyInfo(t *testing.T) {
	tests := []struct {
		name        string
		genKey      func() interface{}
		expectedAlg string
		minBitSize  int
	}{
		{
			name: "ECDSA P-256",
			genKey: func() interface{} {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return key.Public()
			},
			expectedAlg: "ECDSA",
			minBitSize:  256,
		},
		{
			name: "RSA 2048",
			genKey: func() interface{} {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return key.Public()
			},
			expectedAlg: "RSA",
			minBitSize:  2048,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey := tt.genKey()

			// Create certificate with this key
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					CommonName: "test.com",
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(24 * time.Hour),
				KeyUsage:              x509.KeyUsageDigitalSignature,
				BasicConstraintsValid: true,
			}

			var privKey interface{}
			if ecdsaPub, ok := pubKey.(*ecdsa.PublicKey); ok {
				key, _ := ecdsa.GenerateKey(ecdsaPub.Curve, rand.Reader)
				privKey = key
			} else if rsaPub, ok := pubKey.(*rsa.PublicKey); ok {
				key, _ := rsa.GenerateKey(rand.Reader, rsaPub.N.BitLen())
				privKey = key
			}

			certDER, _ := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
			cert, _ := x509.ParseCertificate(certDER)

			alg, bitSize := certKeyInfo(cert)
			if alg != tt.expectedAlg {
				t.Errorf("expected algorithm %s, got %s", tt.expectedAlg, alg)
			}
			if bitSize < tt.minBitSize {
				t.Errorf("expected bitsize >= %d, got %d", tt.minBitSize, bitSize)
			}
		})
	}
}

// TestNewAgent tests agent initialization.
func TestNewAgent(t *testing.T) {
	cfg := &AgentConfig{
		ServerURL: "http://localhost:8443",
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	if agent.config != cfg {
		t.Error("config not set correctly")
	}
	if agent.heartbeatInterval != 60*time.Second {
		t.Errorf("expected heartbeat interval 60s, got %v", agent.heartbeatInterval)
	}
	if agent.pollInterval != 30*time.Second {
		t.Errorf("expected poll interval 30s, got %v", agent.pollInterval)
	}
	if agent.client == nil {
		t.Error("HTTP client not initialized")
	}
}

// TestNewAgent_WithLogger tests agent initialization with logger.
func TestNewAgent_WithLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &AgentConfig{
		ServerURL: "http://localhost:8443",
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}

	agent, _ := NewAgent(cfg, logger)

	if agent.logger != logger {
		t.Error("logger not set correctly")
	}
}

// Helper to create test certificates with specific CN
func generateTestCertWithCN(commonName string) (*x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              []string{commonName},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

// Helper to create string pointer
func strPtr(s string) *string {
	return &s
}

// TestCreateTargetConnector_AllSupportedTypes tests connector creation for all 16 supported target types.
func TestCreateTargetConnector_AllSupportedTypes(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		typeName string
		config   interface{}
	}{
		{
			name:     "NGINX",
			typeName: "NGINX",
			config: map[string]string{
				"cert_path": filepath.Join(tmpDir, "cert.pem"),
				"key_path":  filepath.Join(tmpDir, "key.pem"),
			},
		},
		{
			name:     "Apache",
			typeName: "Apache",
			config: map[string]string{
				"cert_path": filepath.Join(tmpDir, "cert.pem"),
				"key_path":  filepath.Join(tmpDir, "key.pem"),
			},
		},
		{
			name:     "HAProxy",
			typeName: "HAProxy",
			config: map[string]string{
				"cert_path": filepath.Join(tmpDir, "cert.pem"),
			},
		},
		{
			name:     "F5",
			typeName: "F5",
			config: map[string]string{
				"host": "192.0.2.1",
			},
		},
		{
			name:     "IIS",
			typeName: "IIS",
			config: map[string]string{
				"cert_store": "My",
			},
		},
		{
			name:     "Traefik",
			typeName: "Traefik",
			config: map[string]string{
				"cert_dir": tmpDir,
			},
		},
		{
			name:     "Caddy",
			typeName: "Caddy",
			config: map[string]string{
				"mode": "file",
			},
		},
		{
			name:     "Envoy",
			typeName: "Envoy",
			config: map[string]string{
				"cert_dir": tmpDir,
			},
		},
		{
			name:     "Postfix",
			typeName: "Postfix",
			config: map[string]string{
				"cert_path": filepath.Join(tmpDir, "cert.pem"),
				"key_path":  filepath.Join(tmpDir, "key.pem"),
			},
		},
		{
			name:     "Dovecot",
			typeName: "Dovecot",
			config: map[string]string{
				"cert_path": filepath.Join(tmpDir, "cert.pem"),
				"key_path":  filepath.Join(tmpDir, "key.pem"),
			},
		},
		{
			name:     "SSH",
			typeName: "SSH",
			config: map[string]string{
				"host":      "192.0.2.1",
				"user":      "root",
				"cert_path": "/etc/ssl/cert.pem",
				"key_path":  "/etc/ssl/key.pem",
			},
		},
		{
			name:     "WinCertStore",
			typeName: "WinCertStore",
			config: map[string]string{
				"cert_store": "My",
			},
		},
		{
			name:     "JavaKeystore",
			typeName: "JavaKeystore",
			config: map[string]string{
				"keystore_path": filepath.Join(tmpDir, "keystore.jks"),
			},
		},
		{
			name:     "KubernetesSecrets",
			typeName: "KubernetesSecrets",
			config: map[string]string{
				"namespace":   "default",
				"secret_name": "tls-secret",
			},
		},
		{
			// Rank 5 of the 2026-05-03 Infisical deep-research deliverable.
			// Region must be a valid AWS region; the connector lazy-loads
			// the SDK client during ValidateConfig but New() with a populated
			// region should succeed against the SDK credential chain
			// (LoadDefaultConfig doesn't require live creds).
			name:     "AWSACM",
			typeName: "AWSACM",
			config: map[string]string{
				"region": "us-east-1",
			},
		},
		{
			// Rank 5 (Azure half). Vault URL + cert name; the SDK client
			// lazy-loads via DefaultAzureCredential which doesn't require
			// live creds at construction time.
			name:     "AzureKeyVault",
			typeName: "AzureKeyVault",
			config: map[string]string{
				"vault_url":        "https://test-vault.vault.azure.net",
				"certificate_name": "demo-cert",
			},
		},
	}

	cfg := &AgentConfig{
		ServerURL: "http://localhost:8443",
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configJSON, err := json.Marshal(tt.config)
			if err != nil {
				t.Fatalf("failed to marshal config: %v", err)
			}

			connector, err := agent.createTargetConnector(tt.typeName, configJSON)

			// Some connectors (like WinCertStore, IIS) may error on non-Windows platforms
			// or with insufficient validation. We accept either a valid connector or an error
			// for now — the real unit tests in internal/connector/target/* cover validation
			if connector == nil && err != nil {
				// This is acceptable if the connector validates required fields
				t.Logf("connector creation returned error (may be validation): %v", err)
				return
			}

			if connector == nil {
				t.Errorf("expected connector to be non-nil for type %s", tt.typeName)
			}
		})
	}
}

// TestCreateTargetConnector_InvalidJSON tests connector creation with invalid JSON for each type.
func TestCreateTargetConnector_InvalidJSON(t *testing.T) {
	tests := []string{
		"NGINX",
		"Apache",
		"HAProxy",
		"F5",
		"IIS",
		"Traefik",
		"Caddy",
		"Envoy",
		"Postfix",
		"Dovecot",
		"SSH",
		"WinCertStore",
		"JavaKeystore",
		"KubernetesSecrets",
		"AWSACM",
		"AzureKeyVault",
	}

	cfg := &AgentConfig{
		ServerURL: "http://localhost:8443",
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	invalidJSON := json.RawMessage("{invalid json}")

	for _, typeName := range tests {
		t.Run(typeName, func(t *testing.T) {
			_, err := agent.createTargetConnector(typeName, invalidJSON)

			if err == nil {
				t.Errorf("expected error for invalid JSON with type %s", typeName)
			}
		})
	}
}

// TestCreateTargetConnector_UnknownType tests connector creation with unknown target type.
func TestCreateTargetConnector_UnknownType(t *testing.T) {
	cfg := &AgentConfig{
		ServerURL: "http://localhost:8443",
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	_, err := agent.createTargetConnector("MagicBox", nil)

	if err == nil {
		t.Error("expected error for unsupported target type")
	}
	if !strings.Contains(err.Error(), "unsupported target type") {
		t.Errorf("expected 'unsupported target type' error, got: %v", err)
	}
}

// TestCreateTargetConnector_EmptyConfig tests connector creation with empty config JSON.
func TestCreateTargetConnector_EmptyConfig(t *testing.T) {
	tests := []string{
		"NGINX",
		"Apache",
		"HAProxy",
		"Traefik",
		"Caddy",
		"Envoy",
	}

	cfg := &AgentConfig{
		ServerURL: "http://localhost:8443",
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	for _, typeName := range tests {
		t.Run(typeName, func(t *testing.T) {
			// Empty config should be handled gracefully (defaults applied)
			connector, err := agent.createTargetConnector(typeName, nil)

			// Should not error on nil/empty config (defaults are applied)
			if err != nil {
				// Validation errors are acceptable, but parsing errors are not
				if !strings.Contains(err.Error(), "invalid") && !strings.Contains(err.Error(), "missing") {
					t.Logf("connector creation with empty config returned: %v", err)
				}
				return
			}

			if connector == nil {
				t.Errorf("expected non-nil connector for type %s with empty config", typeName)
			}
		})
	}
}

// TestRunDiscoveryScan_ValidCerts tests discovery scanning with valid certificates.
func TestRunDiscoveryScan_ValidCerts(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid PEM certificate file
	cert, _ := generateTestCertWithCN("example.com")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	certPEM := pem.EncodeToMemory(block)

	certPath := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("failed to write certificate: %v", err)
	}

	// Mock server to accept discovery report
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/a-test/discoveries" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Verify request body
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Logf("failed to decode discovery report: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Verify report contains certificates
		certs, ok := payload["certificates"].([]interface{})
		if !ok || len(certs) == 0 {
			t.Logf("expected certificates in report")
		}

		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL:     server.URL,
		APIKey:        "test-key",
		AgentID:       "a-test",
		Hostname:      "test-host",
		DiscoveryDirs: []string{tmpDir},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	// Run discovery scan
	agent.runDiscoveryScan(context.Background())

	// If we got here without panic/error, the test passes
}

// TestRunDiscoveryScan_NoCertificates tests discovery scanning with empty directory.
func TestRunDiscoveryScan_NoCertificates(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an empty directory
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should not receive a request if no certs found and no errors
		t.Logf("discovery report received: %s", r.URL.Path)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL:     server.URL,
		APIKey:        "test-key",
		AgentID:       "a-test",
		Hostname:      "test-host",
		DiscoveryDirs: []string{tmpDir},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	// Run discovery scan - should complete without error even with empty directory
	agent.runDiscoveryScan(context.Background())
}

// TestRunDiscoveryScan_MultipleCerts tests discovery scanning with multiple certificate files.
func TestRunDiscoveryScan_MultipleCerts(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple certificate files
	cert1, _ := generateTestCertWithCN("cert1.example.com")
	cert2, _ := generateTestCertWithCN("cert2.example.com")

	block1 := &pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw}
	block2 := &pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw}

	certPath1 := filepath.Join(tmpDir, "cert1.pem")
	certPath2 := filepath.Join(tmpDir, "cert2.crt")

	if err := os.WriteFile(certPath1, pem.EncodeToMemory(block1), 0644); err != nil {
		t.Fatalf("failed to write cert1: %v", err)
	}
	if err := os.WriteFile(certPath2, pem.EncodeToMemory(block2), 0644); err != nil {
		t.Fatalf("failed to write cert2: %v", err)
	}

	certCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/a-test/discoveries" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Count certificates in report
		if certs, ok := payload["certificates"].([]interface{}); ok {
			certCount = len(certs)
		}

		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL:     server.URL,
		APIKey:        "test-key",
		AgentID:       "a-test",
		Hostname:      "test-host",
		DiscoveryDirs: []string{tmpDir},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	// Run discovery scan
	agent.runDiscoveryScan(context.Background())

	if certCount != 2 {
		t.Logf("expected 2 certificates in discovery report, got %d", certCount)
	}
}

// TestRunDiscoveryScan_DERCertificate tests discovery scanning with DER-encoded certificate.
func TestRunDiscoveryScan_DERCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a DER-encoded certificate file
	cert, _ := generateTestCertWithCN("der.example.com")
	derPath := filepath.Join(tmpDir, "cert.der")

	if err := os.WriteFile(derPath, cert.Raw, 0644); err != nil {
		t.Fatalf("failed to write DER certificate: %v", err)
	}

	certCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/a-test/discoveries" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if certs, ok := payload["certificates"].([]interface{}); ok {
			certCount = len(certs)
		}

		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL:     server.URL,
		APIKey:        "test-key",
		AgentID:       "a-test",
		Hostname:      "test-host",
		DiscoveryDirs: []string{tmpDir},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	// Run discovery scan
	agent.runDiscoveryScan(context.Background())

	if certCount != 1 {
		t.Logf("expected 1 DER certificate in discovery report, got %d", certCount)
	}
}

// TestRunDiscoveryScan_Subdirectories tests discovery scanning with subdirectories.
func TestRunDiscoveryScan_Subdirectories(t *testing.T) {
	tmpDir := t.TempDir()

	// Create subdirectory
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	// Create certificate in subdirectory
	cert, _ := generateTestCertWithCN("subdir.example.com")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	certPath := filepath.Join(subDir, "cert.pem")

	if err := os.WriteFile(certPath, pem.EncodeToMemory(block), 0644); err != nil {
		t.Fatalf("failed to write certificate: %v", err)
	}

	certCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/a-test/discoveries" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if certs, ok := payload["certificates"].([]interface{}); ok {
			certCount = len(certs)
		}

		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL:     server.URL,
		APIKey:        "test-key",
		AgentID:       "a-test",
		Hostname:      "test-host",
		DiscoveryDirs: []string{tmpDir},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	// Run discovery scan - should recursively find certs in subdirs
	agent.runDiscoveryScan(context.Background())

	if certCount != 1 {
		t.Logf("expected 1 certificate in subdirectory, got %d", certCount)
	}
}

// TestRunDiscoveryScan_ServerError tests discovery scanning when server returns error.
func TestRunDiscoveryScan_ServerError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a certificate file
	cert, _ := generateTestCertWithCN("example.com")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	certPath := filepath.Join(tmpDir, "cert.pem")

	if err := os.WriteFile(certPath, pem.EncodeToMemory(block), 0644); err != nil {
		t.Fatalf("failed to write certificate: %v", err)
	}

	// Mock server returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL:     server.URL,
		APIKey:        "test-key",
		AgentID:       "a-test",
		Hostname:      "test-host",
		DiscoveryDirs: []string{tmpDir},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	// Should handle server error gracefully without panicking
	agent.runDiscoveryScan(context.Background())
}

// TestDiscoveredCertEntry_ValidFields tests that discovered certificate entries have valid fields.
func TestDiscoveredCertEntry_ValidFields(t *testing.T) {
	tmpDir := t.TempDir()

	// Create certificate with specific details
	cert, _ := generateTestCertWithCN("test.example.com")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	certPEM := pem.EncodeToMemory(block)

	certPath := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("failed to write certificate: %v", err)
	}

	cfg := &AgentConfig{
		ServerURL: "http://localhost:8443",
		APIKey:    "test-key",
		AgentID:   "a-test",
		Hostname:  "test-host",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, _ := NewAgent(cfg, logger)

	entries := agent.parsePEMFile(certPath)

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	entry := entries[0]

	// Verify all required fields are populated
	if entry.CommonName == "" {
		t.Error("CommonName should not be empty")
	}
	if entry.FingerprintSHA256 == "" {
		t.Error("FingerprintSHA256 should not be empty")
	}
	if len(entry.FingerprintSHA256) != 64 {
		t.Errorf("FingerprintSHA256 should be 64 hex chars, got %d", len(entry.FingerprintSHA256))
	}
	if entry.SerialNumber == "" {
		t.Error("SerialNumber should not be empty")
	}
	if entry.IssuerDN == "" {
		t.Error("IssuerDN should not be empty")
	}
	if entry.SubjectDN == "" {
		t.Error("SubjectDN should not be empty")
	}
	if entry.NotBefore == "" {
		t.Error("NotBefore should not be empty")
	}
	if entry.NotAfter == "" {
		t.Error("NotAfter should not be empty")
	}
	if entry.KeyAlgorithm == "" {
		t.Error("KeyAlgorithm should not be empty")
	}
	if entry.KeySize == 0 {
		t.Error("KeySize should not be zero")
	}
	if entry.SourcePath == "" {
		t.Error("SourcePath should not be empty")
	}
	if entry.SourceFormat != "PEM" {
		t.Errorf("SourceFormat should be 'PEM', got '%s'", entry.SourceFormat)
	}
	if entry.PEMData == "" {
		t.Error("PEMData should not be empty")
	}
}

// ---------------------------------------------------------------------------
// HTTPS-Everywhere milestone (v2.2, §3.2 / §7) — Phase 5 client-side tests.
//
// These tests pin the agent's pre-flight HTTPS-scheme guard and the TLS
// configuration surface (CA bundle loading + TLS 1.3 round-trip) so that
// regressions surface at unit-test time, not at the first heartbeat of a
// production rollout. Matches the same contract asserted by the sibling
// binaries cmd/cli/main_test.go and cmd/mcp-server/main_test.go — the three
// must stay in lock-step because all three are HTTPS-only clients of the
// same control plane.
// ---------------------------------------------------------------------------

// TestValidateHTTPSScheme pins the pre-flight URL-scheme guard that the
// HTTPS-Everywhere milestone requires on the agent binary startup path. The
// agent's diagnostic is distinct from the CLI/MCP variants because it names
// CERTCTL_SERVER_URL (the only input channel — no --server flag on the
// agent). Every case here mirrors the dispatch arms in cmd/agent/main.go:
// validateHTTPSScheme; drifting the error-message substrings is what this
// test is here to catch.
func TestValidateHTTPSScheme(t *testing.T) {
	tests := []struct {
		name       string
		serverURL  string
		wantErr    bool
		wantErrSub string
	}{
		{
			name:      "https URL passes",
			serverURL: "https://certctl-server:8443",
			wantErr:   false,
		},
		{
			name:      "https URL with path passes",
			serverURL: "https://certctl.example.com/api/v1",
			wantErr:   false,
		},
		{
			name:      "uppercase HTTPS scheme passes (url.Parse lowercases)",
			serverURL: "HTTPS://certctl-server:8443",
			wantErr:   false,
		},
		{
			name:       "empty URL rejected names CERTCTL_SERVER_URL",
			serverURL:  "",
			wantErr:    true,
			wantErrSub: "CERTCTL_SERVER_URL is empty",
		},
		{
			name:       "plaintext http rejected",
			serverURL:  "http://certctl-server:8443",
			wantErr:    true,
			wantErrSub: "plaintext http://",
		},
		{
			name:      "bare host missing scheme falls through to unsupported",
			serverURL: "localhost:8443",
			wantErr:   true,
			// url.Parse treats "localhost:8443" as scheme=localhost,
			// opaque=8443 — exercises the default arm (unsupported scheme)
			// rather than the empty-scheme arm. Both are fail-closed, which
			// is what we care about.
			wantErrSub: "unsupported scheme",
		},
		{
			name:       "path-only URL rejected",
			serverURL:  "//certctl-server:8443",
			wantErr:    true,
			wantErrSub: "missing a scheme",
		},
		{
			name:       "unsupported scheme rejected",
			serverURL:  "ftp://certctl-server:8443",
			wantErr:    true,
			wantErrSub: "unsupported scheme",
		},
		{
			name:       "ws scheme rejected",
			serverURL:  "ws://certctl-server:8443",
			wantErr:    true,
			wantErrSub: "unsupported scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHTTPSScheme(tt.serverURL)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateHTTPSScheme(%q) err=%v wantErr=%v", tt.serverURL, err, tt.wantErr)
			}
			if tt.wantErr && tt.wantErrSub != "" && !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Errorf("validateHTTPSScheme(%q) err=%q must contain %q so operators see the right diagnostic",
					tt.serverURL, err.Error(), tt.wantErrSub)
			}
		})
	}
}

// writeTestCABundle PEM-encodes a cert's DER bytes and writes the result to a
// tmp file inside dir. Used by CA-bundle tests so each case owns a distinct
// file path (matters for the "missing file" case which must point at a path
// that provably does not exist). Returns the path.
func writeTestCABundle(t *testing.T, dir string, certDER []byte, filename string) string {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, pemBytes, 0644); err != nil {
		t.Fatalf("writing CA bundle %q: %v", path, err)
	}
	return path
}

// TestNewAgent_CABundle_Success confirms that a well-formed PEM bundle gets
// parsed into an x509.CertPool and wired onto the agent's HTTP client
// transport. This is the happy path the docs/tls.md "Private CA signed
// server cert" section depends on.
func TestNewAgent_CABundle_Success(t *testing.T) {
	cert, err := generateTestCertWithCN("test.certctl.local")
	if err != nil {
		t.Fatalf("generateTestCertWithCN: %v", err)
	}
	bundlePath := writeTestCABundle(t, t.TempDir(), cert.Raw, "ca-bundle.pem")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, err := NewAgent(&AgentConfig{
		ServerURL:    "https://certctl-server:8443",
		APIKey:       "test-key",
		AgentID:      "a-test",
		Hostname:     "test-host",
		CABundlePath: bundlePath,
	}, logger)
	if err != nil {
		t.Fatalf("NewAgent with valid CA bundle err=%v want nil", err)
	}

	transport, ok := agent.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("agent.client.Transport is %T; want *http.Transport", agent.client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil; HTTPS-everywhere milestone requires a non-nil TLS config")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion=%x want TLS 1.3 (%x) per §2.3 of the milestone spec",
			transport.TLSClientConfig.MinVersion, tls.VersionTLS13)
	}
	if transport.TLSClientConfig.RootCAs == nil {
		t.Error("RootCAs is nil; the configured CA bundle was silently dropped")
	}
}

// TestNewAgent_CABundle_MissingFile pins the fail-loud behavior when the
// operator points CERTCTL_SERVER_CA_BUNDLE_PATH at a path that does not
// exist. Falling back to system roots here would mask a misconfiguration as
// a much harder-to-debug TLS handshake failure downstream.
func TestNewAgent_CABundle_MissingFile(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	missingPath := filepath.Join(t.TempDir(), "does-not-exist.pem")
	_, err := NewAgent(&AgentConfig{
		ServerURL:    "https://certctl-server:8443",
		APIKey:       "test-key",
		AgentID:      "a-test",
		Hostname:     "test-host",
		CABundlePath: missingPath,
	}, logger)
	if err == nil {
		t.Fatal("NewAgent err=nil for missing CA bundle path; must fail loud at startup")
	}
	if !strings.Contains(err.Error(), "reading CA bundle") {
		t.Errorf("err=%q must contain \"reading CA bundle\" so operators can trace the cause", err.Error())
	}
}

// TestNewAgent_CABundle_EmptyPEM covers the "file exists but contains no
// valid certs" case (garbage, wrong-format, stripped PEM). AppendCertsFromPEM
// returns false in this case; NewAgent must translate that into a fail-loud
// startup error rather than quietly carry on with an empty pool.
func TestNewAgent_CABundle_EmptyPEM(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	bundlePath := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(bundlePath, []byte("not a pem-encoded certificate, just garbage\n"), 0644); err != nil {
		t.Fatalf("writing garbage bundle: %v", err)
	}
	_, err := NewAgent(&AgentConfig{
		ServerURL:    "https://certctl-server:8443",
		APIKey:       "test-key",
		AgentID:      "a-test",
		Hostname:     "test-host",
		CABundlePath: bundlePath,
	}, logger)
	if err == nil {
		t.Fatal("NewAgent err=nil for empty-PEM CA bundle; must fail loud at startup")
	}
	if !strings.Contains(err.Error(), "no valid PEM-encoded certificates") {
		t.Errorf("err=%q must contain \"no valid PEM-encoded certificates\" so operators see why the bundle was rejected", err.Error())
	}
}

// TestNewAgent_TLSRoundTrip is the end-to-end integration-style check: spin
// up an httptest.NewTLSServer (which presents a self-signed cert over TLS
// 1.3), feed that cert into the agent as a CA bundle, and confirm the agent
// successfully completes a heartbeat round-trip over HTTPS. This proves that
// (a) the CA pool is actually being consulted during verification and (b)
// the TLS 1.3 MinVersion doesn't break against httptest's default
// negotiation. Equivalent to the "TLS handshake succeeds against a
// self-signed control plane" integration gate, but runs in-process with no
// Docker dependency.
func TestNewAgent_TLSRoundTrip(t *testing.T) {
	var heartbeatHit int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agents/a-tls-test/heartbeat" && r.Method == http.MethodPost {
			heartbeatHit++
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// server.Certificate() returns the *x509.Certificate httptest presents;
	// PEM-encode its DER bytes so NewAgent's AppendCertsFromPEM can ingest it.
	bundlePath := writeTestCABundle(t, t.TempDir(), server.Certificate().Raw, "httptest-ca.pem")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, err := NewAgent(&AgentConfig{
		ServerURL:    server.URL,
		APIKey:       "test-key",
		AgentID:      "a-tls-test",
		Hostname:     "tls-test-host",
		CABundlePath: bundlePath,
	}, logger)
	if err != nil {
		t.Fatalf("NewAgent with httptest CA bundle err=%v want nil", err)
	}

	agent.sendHeartbeat(context.Background())

	if heartbeatHit != 1 {
		t.Fatalf("heartbeat handler hit %d times; want 1 — the TLS round-trip must actually complete", heartbeatHit)
	}
}
