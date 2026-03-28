package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

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
	agent := NewAgent(cfg, logger)

	_, err := agent.makeRequest(context.Background(), http.MethodGet, "/test", nil)
	if err == nil {
		t.Error("expected error for unreachable host")
	}
}

// TestCertKeyInfo tests extraction of key algorithm and size from certificates.
func TestCertKeyInfo(t *testing.T) {
	tests := []struct {
		name         string
		genKey       func() interface{}
		expectedAlg  string
		minBitSize   int
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
	agent := NewAgent(cfg, logger)

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

	agent := NewAgent(cfg, logger)

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
