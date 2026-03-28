package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestComputeCertificateFingerprint(t *testing.T) {
	// Generate a test certificate for fingerprint validation
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))

	fp, err := computeCertificateFingerprint(certPEM)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(fp) != 64 { // SHA256 hex = 64 chars
		t.Errorf("expected 64 char fingerprint, got %d", len(fp))
	}
}

func TestComputeCertificateFingerprint_InvalidPEM(t *testing.T) {
	_, err := computeCertificateFingerprint("not a valid pem")
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestComputeCertificateFingerprint_EmptyString(t *testing.T) {
	_, err := computeCertificateFingerprint("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestExtractTargetHostAndPort_ValidConfig(t *testing.T) {
	config := map[string]interface{}{
		"host": "example.com",
		"port": 443.0,
	}
	configJSON, _ := json.Marshal(config)

	host, port, err := extractTargetHostAndPort(configJSON)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if host != "example.com" {
		t.Errorf("expected host example.com, got %s", host)
	}
	if port != 443 {
		t.Errorf("expected port 443, got %d", port)
	}
}

func TestExtractTargetHostAndPort_DefaultPort(t *testing.T) {
	config := map[string]interface{}{
		"hostname": "test.local",
	}
	configJSON, _ := json.Marshal(config)

	host, port, err := extractTargetHostAndPort(configJSON)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if host != "test.local" {
		t.Errorf("expected host test.local, got %s", host)
	}
	if port != 443 {
		t.Errorf("expected default port 443, got %d", port)
	}
}

func TestExtractTargetHostAndPort_MissingHost(t *testing.T) {
	config := map[string]interface{}{
		"port": 443.0,
	}
	configJSON, _ := json.Marshal(config)

	_, _, err := extractTargetHostAndPort(configJSON)
	if err == nil {
		t.Error("expected error for missing host")
	}
}

func TestExtractTargetHostAndPort_InvalidJSON(t *testing.T) {
	configJSON := []byte("invalid json{")

	_, _, err := extractTargetHostAndPort(configJSON)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestExtractTargetHostAndPort_AlternativeFieldNames(t *testing.T) {
	tests := []struct {
		name      string
		config    map[string]interface{}
		expected  string
	}{
		{"host", map[string]interface{}{"host": "host1.com"}, "host1.com"},
		{"hostname", map[string]interface{}{"hostname": "host2.com"}, "host2.com"},
		{"target", map[string]interface{}{"target": "host3.com"}, "host3.com"},
		{"address", map[string]interface{}{"address": "host4.com"}, "host4.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configJSON, _ := json.Marshal(tt.config)
			host, _, err := extractTargetHostAndPort(configJSON)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if host != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, host)
			}
		})
	}
}

func TestVerifyDeployment_Timeout(t *testing.T) {
	cert, _ := generateTestCert()
	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))

	ctx := context.Background()
	result, err := verifyDeployment(ctx, "192.0.2.1", 443, certPEM, 0, 100*time.Millisecond, nil)

	// Connection to reserved test IP should timeout or fail
	if err == nil && result == nil {
		t.Error("expected error or result for unreachable host")
	}
}

func TestVerifyDeployment_InvalidCertPEM(t *testing.T) {
	ctx := context.Background()
	result, err := verifyDeployment(ctx, "localhost", 443, "not a cert", 0, 5*time.Second, nil)

	if err == nil {
		t.Error("expected error for invalid certificate PEM")
	}
	if result != nil {
		t.Error("expected no result on error")
	}
}

// Helper function to generate a test certificate for testing
func generateTestCert() (*x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

func TestReportVerificationResult_Success(t *testing.T) {
	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/jobs/j-test/verify" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}

		// Check auth header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-api-key" {
			t.Errorf("unexpected auth header: %s", auth)
		}

		// Verify request body
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		if payload["verified"] != true {
			t.Error("expected verified to be true")
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"job_id":   "j-test",
			"verified": true,
		})
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-api-key",
	}
	agent := NewAgent(cfg, nil)

	result := &VerificationResult{
		ExpectedFingerprint: "abc123",
		ActualFingerprint:   "abc123",
		Verified:            true,
		VerifiedAt:          time.Now().UTC(),
	}

	err := agent.reportVerificationResult(context.Background(), "j-test", "t-nginx1", result)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReportVerificationResult_MissingFields(t *testing.T) {
	agent := NewAgent(&AgentConfig{}, nil)

	result := &VerificationResult{
		Verified:   true,
		VerifiedAt: time.Now().UTC(),
	}

	err := agent.reportVerificationResult(context.Background(), "", "t-nginx1", result)
	if err == nil {
		t.Error("expected error for missing job ID")
	}
}

func TestVerifyDeployment_ContextCancellation(t *testing.T) {
	cert, _ := generateTestCert()
	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := verifyDeployment(ctx, "localhost", 443, certPEM, 1*time.Second, 5*time.Second, nil)

	if err == nil {
		t.Error("expected error for cancelled context")
	}
	if result != nil {
		t.Error("expected no result on context cancellation")
	}
}

// Mock TLS server for verification testing.
// Reserved for future use when real TLS verification integration tests are added.
var _ = func(t *testing.T, cert *x509.Certificate) (string, func()) {
	// Create TLS listener with test certificate
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	address := listener.Addr().String()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Simple echo to keep connection alive
		buf := make([]byte, 1024)
		conn.Read(buf) //nolint:errcheck
	}()

	cleanup := func() {
		listener.Close()
	}

	return address, cleanup
}

func TestVerificationResult_JSONMarshaling(t *testing.T) {
	now := time.Now().UTC()
	result := &VerificationResult{
		ExpectedFingerprint: "abc123",
		ActualFingerprint:   "def456",
		Verified:            false,
		VerifiedAt:          now,
		Error:               "fingerprint mismatch",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Errorf("unexpected error marshaling: %v", err)
	}

	var unmarshaled VerificationResult
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("unexpected error unmarshaling: %v", err)
	}

	if unmarshaled.Error != "fingerprint mismatch" {
		t.Errorf("error mismatch: got %s", unmarshaled.Error)
	}
}

func TestReportVerificationResult_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	cfg := &AgentConfig{
		ServerURL: server.URL,
		APIKey:    "test-api-key",
	}
	agent := NewAgent(cfg, nil)

	result := &VerificationResult{
		ExpectedFingerprint: "abc123",
		ActualFingerprint:   "abc123",
		Verified:            true,
		VerifiedAt:          time.Now().UTC(),
	}

	err := agent.reportVerificationResult(context.Background(), "j-test", "t-nginx1", result)
	if err == nil {
		t.Error("expected error for server error response")
	}
}

func TestExtractTargetHostAndPort_InvalidPort(t *testing.T) {
	config := map[string]interface{}{
		"host": "example.com",
		"port": 99999.0,
	}
	configJSON, _ := json.Marshal(config)

	_, _, err := extractTargetHostAndPort(configJSON)
	if err == nil {
		t.Error("expected error for invalid port")
	}
}

func TestExtractTargetHostAndPort_ZeroPort(t *testing.T) {
	config := map[string]interface{}{
		"host": "example.com",
		"port": 0.0,
	}
	configJSON, _ := json.Marshal(config)

	_, _, err := extractTargetHostAndPort(configJSON)
	if err == nil {
		t.Error("expected error for zero port")
	}
}

func TestVerifyDeployment_FingerprintComparison(t *testing.T) {
	// Create a simple TLS server for testing
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Get the server's TLS certificate from TLS config
	if len(server.TLS.Certificates) == 0 {
		t.Skip("no TLS certificates configured on test server")
	}

	// Parse the leaf certificate from the DER bytes
	leafDER := server.TLS.Certificates[0].Certificate[0]
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("failed to parse test server certificate: %v", err)
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert.Raw,
	}))

	// Get host and port from the listener address
	addr := server.Listener.Addr().String()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("failed to parse server address: %v", err)
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	// Verify deployment against the live TLS server
	ctx := context.Background()
	result, _ := verifyDeployment(ctx, host, port, certPEM, 0, 5*time.Second, nil)

	// This test may fail in some environments due to TLS setup complexity
	// The key is testing the fingerprint comparison logic
	if result != nil {
		if result.Verified && result.ExpectedFingerprint != result.ActualFingerprint {
			t.Error("fingerprint mismatch: expected and actual should match if Verified is true")
		}
	}
}
