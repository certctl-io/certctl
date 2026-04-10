package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestValidateConfig_MissingDirectoryURL(t *testing.T) {
	c := New(nil, testLogger())
	cfg, _ := json.Marshal(map[string]string{"email": "test@example.com"})
	err := c.ValidateConfig(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "directory_url is required") {
		t.Fatalf("expected directory_url error, got: %v", err)
	}
}

func TestValidateConfig_MissingEmail(t *testing.T) {
	c := New(nil, testLogger())
	cfg, _ := json.Marshal(map[string]string{"directory_url": "https://example.com/directory"})
	err := c.ValidateConfig(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "email is required") {
		t.Fatalf("expected email error, got: %v", err)
	}
}

func TestValidateConfig_InvalidChallengeType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"newNonce":"","newAccount":"","newOrder":""}`)
	}))
	defer srv.Close()

	c := New(nil, testLogger())
	cfg, _ := json.Marshal(map[string]string{
		"directory_url":  srv.URL,
		"email":          "test@example.com",
		"challenge_type": "invalid-challenge",
	})
	err := c.ValidateConfig(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "invalid challenge_type") {
		t.Fatalf("expected invalid challenge_type error, got: %v", err)
	}
}

func TestValidateConfig_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"newNonce":"","newAccount":"","newOrder":""}`)
	}))
	defer srv.Close()

	c := New(nil, testLogger())
	cfg, _ := json.Marshal(map[string]string{
		"directory_url": srv.URL,
		"email":         "test@example.com",
	})
	err := c.ValidateConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestValidateConfig_EABFieldsPreserved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"newNonce":"","newAccount":"","newOrder":""}`)
	}))
	defer srv.Close()

	c := New(nil, testLogger())
	cfg, _ := json.Marshal(map[string]string{
		"directory_url": srv.URL,
		"email":         "test@example.com",
		"eab_kid":       "kid-12345",
		"eab_hmac":      base64.RawURLEncoding.EncodeToString([]byte("test-hmac-key")),
	})
	err := c.ValidateConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if c.config.EABKid != "kid-12345" {
		t.Fatalf("expected EABKid to be preserved, got: %s", c.config.EABKid)
	}
	if c.config.EABHmac == "" {
		t.Fatal("expected EABHmac to be preserved")
	}
}

func TestEnsureClient_EABDecodeError(t *testing.T) {
	c := New(&Config{
		DirectoryURL: "https://acme.example.com/directory",
		Email:        "test@example.com",
		EABKid:       "kid-12345",
		EABHmac:      "!!!not-valid-base64url!!!",
	}, testLogger())

	err := c.ensureClient(context.Background())
	if err == nil || !strings.Contains(err.Error(), "decode EAB HMAC") {
		t.Fatalf("expected EAB decode error, got: %v", err)
	}
}

func TestEnsureClient_EABBindingSet(t *testing.T) {
	// We can't fully mock the ACME protocol (JWS nonce exchange), but we can
	// verify that valid EAB credentials are decoded and attached to the account
	// without panicking. The ensureClient call will fail at the network level
	// (no real ACME server), but it must NOT fail at EAB decoding.
	hmacKey := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-secret-key"))
	c := New(&Config{
		DirectoryURL: "https://127.0.0.1:1/directory", // unreachable — that's fine
		Email:        "test@example.com",
		EABKid:       "kid-zerossl-12345",
		EABHmac:      hmacKey,
	}, testLogger())

	err := c.ensureClient(context.Background())
	// Expected: network error (unreachable server), NOT an EAB decode error
	if err != nil && strings.Contains(err.Error(), "decode EAB HMAC") {
		t.Fatalf("EAB decode should not fail with valid base64url key, got: %v", err)
	}
	// We expect some error (network unreachable) — that's correct
	if err == nil {
		t.Log("ensureClient succeeded (unexpected but not a failure for this test)")
	}
}

// --- ZeroSSL auto-EAB tests ---

func TestIsZeroSSL(t *testing.T) {
	tests := []struct {
		url    string
		expect bool
	}{
		{"https://acme.zerossl.com/v2/DV90", true},
		{"https://ACME.ZEROSSL.COM/v2/DV90", true},
		{"https://acme-v02.api.letsencrypt.org/directory", false},
		{"https://acme.example.com/directory", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isZeroSSL(tt.url); got != tt.expect {
			t.Errorf("isZeroSSL(%q) = %v, want %v", tt.url, got, tt.expect)
		}
	}
}

func TestFetchZeroSSLEAB_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("expected form content-type, got %s", ct)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if email := r.FormValue("email"); email != "test@example.com" {
			t.Errorf("expected email test@example.com, got %s", email)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success":true,"eab_kid":"kid_abc123","eab_hmac_key":"dGVzdC1obWFjLWtleQ"}`)
	}))
	defer srv.Close()

	// Override the endpoint for testing
	origEndpoint := zeroSSLEABEndpoint
	defer func() { zeroSSLEABEndpoint = origEndpoint }()
	zeroSSLEABEndpoint = srv.URL

	kid, hmac, err := fetchZeroSSLEAB(context.Background(), "test@example.com")
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if kid != "kid_abc123" {
		t.Errorf("expected kid_abc123, got %s", kid)
	}
	if hmac != "dGVzdC1obWFjLWtleQ" {
		t.Errorf("expected dGVzdC1obWFjLWtleQ, got %s", hmac)
	}
}

func TestFetchZeroSSLEAB_EmptyEmail(t *testing.T) {
	_, _, err := fetchZeroSSLEAB(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "email is required") {
		t.Fatalf("expected email required error, got: %v", err)
	}
}

func TestFetchZeroSSLEAB_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"success":false,"error":"invalid email"}`)
	}))
	defer srv.Close()

	origEndpoint := zeroSSLEABEndpoint
	defer func() { zeroSSLEABEndpoint = origEndpoint }()
	zeroSSLEABEndpoint = srv.URL

	_, _, err := fetchZeroSSLEAB(context.Background(), "bad@example.com")
	if err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("expected API error, got: %v", err)
	}
}

func TestFetchZeroSSLEAB_MissingCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success":false,"error":"rate limited"}`)
	}))
	defer srv.Close()

	origEndpoint := zeroSSLEABEndpoint
	defer func() { zeroSSLEABEndpoint = origEndpoint }()
	zeroSSLEABEndpoint = srv.URL

	_, _, err := fetchZeroSSLEAB(context.Background(), "test@example.com")
	if err == nil || !strings.Contains(err.Error(), "EAB generation failed") {
		t.Fatalf("expected EAB generation failed error, got: %v", err)
	}
}

func TestEnsureClient_ZeroSSLAutoEAB(t *testing.T) {
	// Mock ZeroSSL EAB endpoint
	eabSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success":true,"eab_kid":"auto-kid-123","eab_hmac_key":"dGVzdC1obWFjLWtleQ"}`)
	}))
	defer eabSrv.Close()

	origEndpoint := zeroSSLEABEndpoint
	defer func() { zeroSSLEABEndpoint = origEndpoint }()
	zeroSSLEABEndpoint = eabSrv.URL

	// Use an unreachable ACME directory — we only care that auto-EAB fetch happens
	c := New(&Config{
		DirectoryURL: "https://acme.zerossl.com/v2/DV90",
		Email:        "test@example.com",
		// EABKid and EABHmac intentionally empty — should auto-fetch
	}, testLogger())

	err := c.ensureClient(context.Background())
	// Will fail at ACME protocol level (unreachable ZeroSSL directory), but
	// EAB credentials should have been auto-fetched and set on config
	if c.config.EABKid != "auto-kid-123" {
		t.Errorf("expected auto-fetched EABKid, got: %s (err: %v)", c.config.EABKid, err)
	}
	if c.config.EABHmac != "dGVzdC1obWFjLWtleQ" {
		t.Errorf("expected auto-fetched EABHmac, got: %s", c.config.EABHmac)
	}
}

// --- parseCSRPEM tests ---

func TestParseCSRPEM_ValidPEM(t *testing.T) {
	// Generate a real ECDSA P-256 CSR using crypto/x509
	key, err := generateTestKey()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject:   generateTestName("test.example.com"),
		DNSNames:  []string{"test.example.com", "www.test.example.com"},
		PublicKey: &key.PublicKey,
	}

	csrDER, err := x509.CreateCertificateRequest(nil, &csrTemplate, key)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}

	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}))

	// Test parseCSRPEM
	result, err := parseCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("parseCSRPEM failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("expected non-empty DER bytes")
	}

	// Verify it's valid DER by parsing it
	parsed, err := x509.ParseCertificateRequest(result)
	if err != nil {
		t.Fatalf("failed to parse result as valid CSR: %v", err)
	}

	if !strings.Contains(parsed.Subject.String(), "test.example.com") {
		t.Errorf("expected CN in parsed CSR, got: %s", parsed.Subject.String())
	}
}

func TestParseCSRPEM_InvalidPEM(t *testing.T) {
	tests := []struct {
		name    string
		pem     string
		wantErr bool
	}{
		{"empty string", "", true},
		{"not PEM format", "not-a-pem", true},
		{"valid PEM but wrong type", "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----", true},
		{"invalid base64", "-----BEGIN CERTIFICATE REQUEST-----\n!!!not-valid-base64!!!\n-----END CERTIFICATE REQUEST-----", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCSRPEM(tt.pem)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCSRPEM() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// --- parseDERChain tests ---

func TestParseDERChain_ValidChain(t *testing.T) {
	// Generate a root and leaf certificate for testing
	rootKey, err := generateTestKey()
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}

	leafKey, err := generateTestKey()
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}

	// Root cert (self-signed)
	rootTemplate := x509.Certificate{
		Subject:               generateTestName("Root CA"),
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootDER, err := x509.CreateCertificate(nil, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}

	// Leaf cert (signed by root)
	leafTemplate := x509.Certificate{
		Subject:      generateTestName("test.example.com"),
		SerialNumber: big.NewInt(100),
		DNSNames:     []string{"test.example.com", "www.test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		PublicKey:    &leafKey.PublicKey,
	}

	leafDER, err := x509.CreateCertificate(nil, &leafTemplate, &rootTemplate, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}

	// Parse the chain
	certPEM, chainPEM, serial, notBefore, notAfter, err := parseDERChain([][]byte{leafDER, rootDER})
	if err != nil {
		t.Fatalf("parseDERChain failed: %v", err)
	}

	// Verify leaf cert PEM
	if !strings.Contains(certPEM, "BEGIN CERTIFICATE") {
		t.Errorf("certPEM should contain PEM header, got: %s", certPEM)
	}

	// Verify chain PEM contains root
	if !strings.Contains(chainPEM, "BEGIN CERTIFICATE") {
		t.Errorf("chainPEM should contain root cert PEM, got: %s", chainPEM)
	}

	// Verify serial is correctly extracted
	if serial != "100" {
		t.Errorf("expected serial '100', got: %s", serial)
	}

	// Verify timestamps are set
	if notBefore.IsZero() {
		t.Error("notBefore should not be zero")
	}
	if notAfter.IsZero() {
		t.Error("notAfter should not be zero")
	}

	// Verify we can parse the returned PEM
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("failed to decode returned certPEM")
	}

	parsedLeaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse returned certPEM: %v", err)
	}

	if parsedLeaf.SerialNumber.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("parsed leaf serial mismatch: got %v, expected 100", parsedLeaf.SerialNumber)
	}
}

func TestParseDERChain_SingleCert(t *testing.T) {
	// Generate a single certificate
	key, err := generateTestKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		Subject:      generateTestName("test.example.com"),
		SerialNumber: big.NewInt(42),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		PublicKey:    &key.PublicKey,
	}

	certDER, err := x509.CreateCertificate(nil, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	certPEM, chainPEM, serial, notBefore, notAfter, err := parseDERChain([][]byte{certDER})
	if err != nil {
		t.Fatalf("parseDERChain failed: %v", err)
	}

	if !strings.Contains(certPEM, "BEGIN CERTIFICATE") {
		t.Error("certPEM should contain PEM header")
	}

	if chainPEM != "" {
		t.Errorf("chainPEM should be empty for single cert, got: %s", chainPEM)
	}

	if serial != "42" {
		t.Errorf("expected serial '42', got: %s", serial)
	}

	if notBefore.IsZero() || notAfter.IsZero() {
		t.Error("timestamps should be set")
	}
}

func TestParseDERChain_EmptyChain(t *testing.T) {
	_, _, _, _, _, err := parseDERChain([][]byte{})
	if err == nil {
		t.Fatal("expected error for empty chain")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected 'empty' in error message, got: %v", err)
	}
}

func TestParseDERChain_InvalidDER(t *testing.T) {
	// Invalid DER bytes
	invalidDER := []byte{0xFF, 0xFF, 0xFF}
	_, _, _, _, _, err := parseDERChain([][]byte{invalidDER})
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}
}

// --- IssueCertificate / RenewCertificate error path tests ---
// Note: Full IssueCertificate/RenewCertificate testing requires an ACME server.
// We test the CSR parsing logic which is the first step.

func TestIssueCertificateCSRParsing(t *testing.T) {
	tests := []struct {
		name    string
		csrPEM  string
		wantErr bool
	}{
		{"invalid PEM", "not-a-valid-csr-pem", true},
		{"empty PEM", "", true},
		{"wrong PEM type", "-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCSRPEM(tt.csrPEM)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCSRPEM() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// --- RevokeCertificate behavior test ---
// ACME revocation is not fully supported in V1 — it requires certificate DER, not just the serial.
// Full testing would require an ACME server; we verify the basic interface behavior.
// Skipped here because it requires network access for ACME client initialization.

// --- GenerateCRL and SignOCSPResponse error path tests ---

func TestGenerateCRL_NotSupported(t *testing.T) {
	c := New(&Config{
		DirectoryURL: "https://example.com/acme/directory",
		Email:        "test@example.com",
	}, testLogger())

	_, err := c.GenerateCRL(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for CRL generation")
	}
	if !strings.Contains(err.Error(), "not support") {
		t.Errorf("expected 'not support' in error, got: %v", err)
	}
}

func TestSignOCSPResponse_NotSupported(t *testing.T) {
	c := New(&Config{
		DirectoryURL: "https://example.com/acme/directory",
		Email:        "test@example.com",
	}, testLogger())

	req := issuer.OCSPSignRequest{
		CertSerial: big.NewInt(123),
	}

	_, err := c.SignOCSPResponse(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for OCSP signing")
	}
	if !strings.Contains(err.Error(), "not support") {
		t.Errorf("expected 'not support' in error, got: %v", err)
	}
}

func TestGetCACertPEM_NotSupported(t *testing.T) {
	c := New(&Config{
		DirectoryURL: "https://example.com/acme/directory",
		Email:        "test@example.com",
	}, testLogger())

	_, err := c.GetCACertPEM(context.Background())
	if err == nil {
		t.Fatal("expected error for GetCACertPEM")
	}
	if !strings.Contains(err.Error(), "not") {
		t.Errorf("expected error message, got: %v", err)
	}
}

// --- httpClient behavior tests ---

func TestHttpClient_DefaultTimeout(t *testing.T) {
	c := New(&Config{
		DirectoryURL: "https://example.com/acme/directory",
		Email:        "test@example.com",
		Insecure:     false,
	}, testLogger())

	client := c.httpClient()
	if client == nil {
		t.Fatal("httpClient should not be nil")
	}
	if client.Timeout == 0 {
		t.Error("httpClient should have a non-zero timeout")
	}
}

func TestHttpClient_InsecureSkipVerify(t *testing.T) {
	c := New(&Config{
		DirectoryURL: "https://example.com/acme/directory",
		Email:        "test@example.com",
		Insecure:     true,
	}, testLogger())

	client := c.httpClient()
	if client == nil {
		t.Fatal("httpClient should not be nil")
	}

	// Verify that the transport has InsecureSkipVerify enabled
	if client.Transport == nil {
		t.Error("client transport should be set for insecure mode")
	} else {
		transport := client.Transport.(*http.Transport)
		if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
			t.Error("TLS config should have InsecureSkipVerify=true")
		}
	}
}

// --- buildIdentifiers tests ---

func TestBuildIdentifiers_CommonNameOnly(t *testing.T) {
	identifiers := buildIdentifiers("example.com", nil)
	if len(identifiers) != 1 {
		t.Fatalf("expected 1 identifier, got %d", len(identifiers))
	}
	if identifiers[0].Value != "example.com" {
		t.Errorf("expected 'example.com', got %s", identifiers[0].Value)
	}
}

func TestBuildIdentifiers_CommonNameAndSANs(t *testing.T) {
	identifiers := buildIdentifiers("example.com", []string{"www.example.com", "api.example.com"})
	if len(identifiers) != 3 {
		t.Fatalf("expected 3 identifiers, got %d", len(identifiers))
	}

	expected := map[string]bool{
		"example.com":     true,
		"www.example.com": true,
		"api.example.com": true,
	}

	for _, id := range identifiers {
		if !expected[id.Value] {
			t.Errorf("unexpected identifier: %s", id.Value)
		}
		if id.Type != "dns" {
			t.Errorf("expected type 'dns', got %s", id.Type)
		}
	}
}

func TestBuildIdentifiers_DeduplicatesCommonName(t *testing.T) {
	// If CommonName is also in SANs, it should only appear once
	identifiers := buildIdentifiers("example.com", []string{"example.com", "www.example.com"})
	if len(identifiers) != 2 {
		t.Fatalf("expected 2 identifiers (deduplicated), got %d", len(identifiers))
	}
}

func TestBuildIdentifiers_EmptyCommonName(t *testing.T) {
	identifiers := buildIdentifiers("", []string{"www.example.com"})
	if len(identifiers) != 1 {
		t.Fatalf("expected 1 identifier, got %d", len(identifiers))
	}
	if identifiers[0].Value != "www.example.com" {
		t.Errorf("expected 'www.example.com', got %s", identifiers[0].Value)
	}
}

// --- New constructor tests ---

func TestNew_WithNilConfig(t *testing.T) {
	c := New(nil, testLogger())
	if c == nil {
		t.Fatal("New should return a non-nil Connector")
	}
	if c.config != nil {
		t.Error("config should be nil when initialized with nil")
	}
	if len(c.challengeTokens) != 0 {
		t.Error("challengeTokens should be initialized as empty map")
	}
}

func TestNew_WithHTTPPort0DefaultsTo80(t *testing.T) {
	cfg := &Config{
		DirectoryURL:  "https://example.com/acme",
		Email:         "test@example.com",
		HTTPPort:      0, // Should default to 80
		ChallengeType: "http-01",
	}
	c := New(cfg, testLogger())
	if c.config.HTTPPort != 80 {
		t.Errorf("expected HTTPPort to default to 80, got %d", c.config.HTTPPort)
	}
}

func TestNew_WithChallengeTypeDefaultsToHTTP01(t *testing.T) {
	cfg := &Config{
		DirectoryURL: "https://example.com/acme",
		Email:        "test@example.com",
		HTTPPort:     8080,
		// ChallengeType intentionally empty
	}
	c := New(cfg, testLogger())
	if c.config.ChallengeType != "http-01" {
		t.Errorf("expected ChallengeType to default to http-01, got %s", c.config.ChallengeType)
	}
}

func TestNew_WithDNSPropagationWaitDefaultsTo30(t *testing.T) {
	cfg := &Config{
		DirectoryURL:  "https://example.com/acme",
		Email:         "test@example.com",
		ChallengeType: "dns-01",
		// DNSPropagationWait intentionally 0
	}
	c := New(cfg, testLogger())
	if c.config.DNSPropagationWait != 30 {
		t.Errorf("expected DNSPropagationWait to default to 30, got %d", c.config.DNSPropagationWait)
	}
}

func TestNew_InitializesDNSSolverForDNS01(t *testing.T) {
	cfg := &Config{
		DirectoryURL:     "https://example.com/acme",
		Email:            "test@example.com",
		ChallengeType:    "dns-01",
		DNSPresentScript: "/bin/sh", // Use a real script that exists
	}
	c := New(cfg, testLogger())
	// DNS solver should be initialized for dns-01
	if c.dnsSolver == nil && cfg.DNSPresentScript != "" {
		// Note: it only initializes if the script path is not empty
		t.Error("dnsSolver should be initialized for dns-01 with present script")
	}
}

func TestNew_InitializesDNSSolverForDNSPersist01(t *testing.T) {
	cfg := &Config{
		DirectoryURL:     "https://example.com/acme",
		Email:            "test@example.com",
		ChallengeType:    "dns-persist-01",
		DNSPresentScript: "/bin/sh", // Use a real script path
	}
	c := New(cfg, testLogger())
	if c.dnsSolver == nil && cfg.DNSPresentScript != "" {
		t.Error("dnsSolver should be initialized for dns-persist-01 with present script")
	}
}

func TestNew_NooDNSSolverForHTTP01(t *testing.T) {
	cfg := &Config{
		DirectoryURL:     "https://example.com/acme",
		Email:            "test@example.com",
		ChallengeType:    "http-01",
		DNSPresentScript: "/nonexistent/path", // Intentionally not initialized
	}
	c := New(cfg, testLogger())
	if c.dnsSolver != nil {
		t.Error("dnsSolver should not be initialized for http-01")
	}
}

// --- ValidateConfig additional coverage tests ---

func TestValidateConfig_DNSPresentScriptRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"newNonce":"","newAccount":"","newOrder":""}`)
	}))
	defer srv.Close()

	c := New(nil, testLogger())
	cfg, _ := json.Marshal(map[string]string{
		"directory_url":  srv.URL,
		"email":          "test@example.com",
		"challenge_type": "dns-01",
		// Missing dns_present_script
	})

	err := c.ValidateConfig(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error when dns_present_script is missing for dns-01")
	}
	if !strings.Contains(err.Error(), "dns_present_script") {
		t.Errorf("expected 'dns_present_script' in error, got: %v", err)
	}
}

func TestValidateConfig_DNSPersistIssuerDomainRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"newNonce":"","newAccount":"","newOrder":""}`)
	}))
	defer srv.Close()

	c := New(nil, testLogger())
	cfg, _ := json.Marshal(map[string]string{
		"directory_url":     srv.URL,
		"email":             "test@example.com",
		"challenge_type":    "dns-persist-01",
		"dns_present_script": "/tmp/script.sh",
		// Missing dns_persist_issuer_domain
	})

	err := c.ValidateConfig(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error when dns_persist_issuer_domain is missing for dns-persist-01")
	}
	if !strings.Contains(err.Error(), "dns_persist_issuer_domain") {
		t.Errorf("expected 'dns_persist_issuer_domain' in error, got: %v", err)
	}
}

func TestValidateConfig_InvalidJSON(t *testing.T) {
	c := New(nil, testLogger())
	err := c.ValidateConfig(context.Background(), []byte("{invalid json}"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("expected 'invalid' in error, got: %v", err)
	}
}

// Note: Profile validation tests are in profile_test.go

func TestValidateConfig_ACMEDirectoryUnreachable(t *testing.T) {
	c := New(nil, testLogger())
	cfg, _ := json.Marshal(map[string]string{
		"directory_url": "https://127.0.0.1:1/directory", // Unreachable
		"email":         "test@example.com",
	})

	err := c.ValidateConfig(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for unreachable ACME directory")
	}
}

func TestValidateConfig_HTTPStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := New(nil, testLogger())
	cfg, _ := json.Marshal(map[string]string{
		"directory_url": srv.URL,
		"email":         "test@example.com",
	})

	err := c.ValidateConfig(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for non-2xx status")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("expected '404' in error, got: %v", err)
	}
}

func TestValidateConfig_DNS01WithPresentScript(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"newNonce":"","newAccount":"","newOrder":""}`)
	}))
	defer srv.Close()

	c := New(nil, testLogger())
	cfg, _ := json.Marshal(map[string]string{
		"directory_url":     srv.URL,
		"email":             "test@example.com",
		"challenge_type":    "dns-01",
		"dns_present_script": "/bin/sh",
		"dns_cleanup_script": "/bin/sh",
	})

	err := c.ValidateConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected DNS-01 with present script to succeed, got: %v", err)
	}

	// Verify config was updated
	if c.config.ChallengeType != "dns-01" {
		t.Errorf("expected ChallengeType=dns-01, got %s", c.config.ChallengeType)
	}
}

func TestValidateConfig_DNSPersist01WithAllFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"newNonce":"","newAccount":"","newOrder":""}`)
	}))
	defer srv.Close()

	c := New(nil, testLogger())
	cfg, _ := json.Marshal(map[string]string{
		"directory_url":           srv.URL,
		"email":                   "test@example.com",
		"challenge_type":          "dns-persist-01",
		"dns_present_script":      "/bin/sh",
		"dns_persist_issuer_domain": "letsencrypt.org",
	})

	err := c.ValidateConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected DNS-PERSIST-01 to succeed, got: %v", err)
	}

	if c.config.DNSPersistIssuerDomain != "letsencrypt.org" {
		t.Errorf("expected issuer domain to be set, got %s", c.config.DNSPersistIssuerDomain)
	}
}

// --- Additional comprehensive tests ---

func TestParseDERChain_MultipleChainCerts(t *testing.T) {
	// Generate a complete chain: leaf -> intermediate -> root
	rootKey, _ := generateTestKey()
	intermediateKey, _ := generateTestKey()
	leafKey, _ := generateTestKey()

	// Root certificate (self-signed)
	rootTemplate := x509.Certificate{
		Subject:               generateTestName("Root CA"),
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, _ := x509.CreateCertificate(nil, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)

	// Intermediate certificate (signed by root)
	intermediateTemplate := x509.Certificate{
		Subject:               generateTestName("Intermediate CA"),
		SerialNumber:          big.NewInt(2),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKey:             &intermediateKey.PublicKey,
	}
	intermediateDER, _ := x509.CreateCertificate(nil, &intermediateTemplate, &rootTemplate, &intermediateKey.PublicKey, rootKey)

	// Leaf certificate (signed by intermediate)
	leafTemplate := x509.Certificate{
		Subject:      generateTestName("leaf.example.com"),
		SerialNumber: big.NewInt(100),
		DNSNames:     []string{"leaf.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		PublicKey:    &leafKey.PublicKey,
	}
	leafDER, _ := x509.CreateCertificate(nil, &leafTemplate, &intermediateTemplate, &leafKey.PublicKey, intermediateKey)

	certPEM, chainPEM, serial, _, _, err := parseDERChain([][]byte{leafDER, intermediateDER, rootDER})
	if err != nil {
		t.Fatalf("parseDERChain failed: %v", err)
	}

	// Verify serial from leaf
	if serial != "100" {
		t.Errorf("expected serial '100', got: %s", serial)
	}

	// Verify chainPEM contains both intermediate and root
	chainCount := strings.Count(chainPEM, "BEGIN CERTIFICATE")
	if chainCount != 2 {
		t.Errorf("expected 2 certs in chain, found %d", chainCount)
	}

	// Verify certPEM contains only the leaf
	if !strings.Contains(certPEM, "BEGIN CERTIFICATE") {
		t.Error("certPEM should contain certificate header")
	}
}

func TestParseCSRPEM_WithTrailingWhitespace(t *testing.T) {
	key, _ := generateTestKey()
	csrTemplate := x509.CertificateRequest{
		Subject:   generateTestName("test.example.com"),
		PublicKey: &key.PublicKey,
	}
	csrDER, _ := x509.CreateCertificateRequest(nil, &csrTemplate, key)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}))

	// Add trailing whitespace and newlines
	csrWithWhitespace := csrPEM + "\n\n  \n"

	result, err := parseCSRPEM(csrWithWhitespace)
	if err != nil {
		t.Fatalf("parseCSRPEM should handle trailing whitespace, got: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("expected non-empty result")
	}
}

func TestParseCSRPEM_MultipleCSRsInPEM(t *testing.T) {
	key, _ := generateTestKey()
	csrTemplate := x509.CertificateRequest{
		Subject:   generateTestName("test.example.com"),
		PublicKey: &key.PublicKey,
	}
	csrDER, _ := x509.CreateCertificateRequest(nil, &csrTemplate, key)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}))

	// pem.Decode only returns the first PEM block, so this tests that behavior
	multiCSRPEM := csrPEM + "\n" + csrPEM

	result, err := parseCSRPEM(multiCSRPEM)
	if err != nil {
		t.Fatalf("parseCSRPEM should handle multiple PEMs by decoding the first, got: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("expected non-empty result")
	}
}

// --- Helper functions for tests ---

func generateTestKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func generateTestName(cn string) pkix.Name {
	return pkix.Name{
		CommonName:   cn,
		Organization: []string{"Test Org"},
		Country:      []string{"US"},
	}
}
