package acme

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
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
