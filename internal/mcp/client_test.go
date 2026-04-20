package mcp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	c, err := NewClient("https://localhost:8443", "test-key", "", false)
	if err != nil {
		t.Fatalf("NewClient err=%v want nil", err)
	}
	if c.baseURL != "https://localhost:8443" {
		t.Errorf("expected baseURL https://localhost:8443, got %s", c.baseURL)
	}
	if c.apiKey != "test-key" {
		t.Errorf("expected apiKey test-key, got %s", c.apiKey)
	}
	if c.httpClient == nil {
		t.Fatal("expected httpClient to be non-nil")
	}
}

func TestClient_Get(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("expected Bearer test-key auth, got %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("expected Accept application/json, got %s", r.Header.Get("Accept"))
		}
		if r.URL.Query().Get("status") != "Active" {
			t.Errorf("expected status=Active query param, got %s", r.URL.Query().Get("status"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data":  []interface{}{},
			"total": 0,
		})
	}))
	defer server.Close()

	c, _ := NewClient(server.URL, "test-key", "", false)
	data, err := c.Get("/api/v1/certificates", map[string][]string{"status": {"Active"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data == nil {
		t.Fatal("expected non-nil response data")
	}
}

func TestClient_Get_NoAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("expected no auth header, got %s", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()

	c, _ := NewClient(server.URL, "", "", false)
	_, err := c.Get("/api/v1/certificates", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClient_Post(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		body, _ := io.ReadAll(r.Body)
		var parsed map[string]interface{}
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("failed to parse request body: %v", err)
		}
		if parsed["name"] != "test-cert" {
			t.Errorf("expected name=test-cert, got %v", parsed["name"])
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": "mc-test"})
	}))
	defer server.Close()

	c, _ := NewClient(server.URL, "test-key", "", false)
	data, err := c.Post("/api/v1/certificates", map[string]string{"name": "test-cert"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result["id"] != "mc-test" {
		t.Errorf("expected id=mc-test, got %s", result["id"])
	}
}

func TestClient_Put(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"mc-test","name":"updated"}`))
	}))
	defer server.Close()

	c, _ := NewClient(server.URL, "test-key", "", false)
	data, err := c.Put("/api/v1/certificates/mc-test", map[string]string{"name": "updated"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data == nil {
		t.Fatal("expected non-nil response data")
	}
}

func TestClient_Delete_204(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	c, _ := NewClient(server.URL, "test-key", "", false)
	data, err := c.Delete("/api/v1/certificates/mc-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result["status"] != "deleted" {
		t.Errorf("expected status=deleted for 204, got %s", result["status"])
	}
}

func TestClient_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not found"}`))
	}))
	defer server.Close()

	c, _ := NewClient(server.URL, "test-key", "", false)
	_, err := c.Get("/api/v1/certificates/nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	expected := "API error (HTTP 404)"
	if !containsStr(err.Error(), expected) {
		t.Errorf("expected error containing %q, got %q", expected, err.Error())
	}
}

func TestClient_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer server.Close()

	c, _ := NewClient(server.URL, "test-key", "", false)
	_, err := c.Post("/api/v1/certificates", map[string]string{"name": "test"})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	expected := "API error (HTTP 500)"
	if !containsStr(err.Error(), expected) {
		t.Errorf("expected error containing %q, got %q", expected, err.Error())
	}
}

func TestClient_GetRaw(t *testing.T) {
	derData := []byte{0x30, 0x82, 0x01, 0x00} // fake DER bytes
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(http.StatusOK)
		w.Write(derData)
	}))
	defer server.Close()

	c, _ := NewClient(server.URL, "test-key", "", false)
	data, contentType, err := c.GetRaw("/.well-known/pki/crl/iss-local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if contentType != "application/pkix-crl" {
		t.Errorf("expected content-type application/pkix-crl, got %s", contentType)
	}
	if len(data) != len(derData) {
		t.Errorf("expected %d bytes, got %d", len(derData), len(data))
	}
}

func TestClient_GetRaw_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("issuer not found"))
	}))
	defer server.Close()

	c, _ := NewClient(server.URL, "test-key", "", false)
	_, _, err := c.GetRaw("/.well-known/pki/crl/nonexistent")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestClient_ConnectionRefused(t *testing.T) {
	c, _ := NewClient("https://localhost:1", "test-key", "", false)
	_, err := c.Get("/api/v1/certificates", nil)
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestClient_PostNilBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "" {
			t.Errorf("expected no Content-Type for nil body, got %s", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status":"accepted"}`))
	}))
	defer server.Close()

	c, _ := NewClient(server.URL, "test-key", "", false)
	data, err := c.Post("/api/v1/certificates/mc-test/renew", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestClient_QueryParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "2" {
			t.Errorf("expected page=2, got %s", r.URL.Query().Get("page"))
		}
		if r.URL.Query().Get("per_page") != "10" {
			t.Errorf("expected per_page=10, got %s", r.URL.Query().Get("per_page"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":[],"total":0}`))
	}))
	defer server.Close()

	c, _ := NewClient(server.URL, "test-key", "", false)
	q := paginationQuery(2, 10)
	_, err := c.Get("/api/v1/certificates", q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// containsStr is a simple helper to avoid importing strings in tests.
func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// generateTestCert produces a short-lived self-signed RSA-2048 certificate for
// tests that need a PEM-encodable cert. Mirrors the helper used in
// internal/cli/client_test.go so the two packages pin the same HTTPS-Everywhere
// TLS-wiring contract against matching test fixtures.
func generateTestCert() *x509.Certificate {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.certctl.local",
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.certctl.local"},
	}

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	cert, _ := x509.ParseCertificate(certBytes)
	return cert
}

// -----------------------------------------------------------------------------
// HTTPS-Everywhere milestone (v2.2, §3.2 + §7 Phase 5):
// The MCP server binary talks HTTPS-only to the certctl control plane. These
// tests pin the three contracts every client binary (agent, CLI, MCP) must
// satisfy in lock-step:
//   (a) CA bundle load success — PEM loads, RootCAs + MinVersion=TLS1.3 wired
//       through the injected *http.Transport so the httpClient actually uses
//       them on the wire, not just in the struct.
//   (b) CA bundle load failure — missing file and malformed/empty PEM each fail
//       loud with a pinned substring so operators get a useful diagnostic.
//   (c) End-to-end TLS round-trip — an httptest.NewTLSServer whose own cert is
//       written out as the CA bundle validates that every TLS-config knob
//       actually flows into the dialer.
// The substrings below must stay in sync with internal/mcp/client.go:NewClient;
// drifting them in isolation is exactly what this suite is here to catch.
// -----------------------------------------------------------------------------

// writeCABundle PEM-encodes a DER cert and writes it to a temp file under the
// test's own TempDir. Returns the absolute path for piping into NewClient.
func writeCABundle(t *testing.T, dir string, certDER []byte, filename string) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("writing CA bundle to %q: %v", path, err)
	}
	return path
}

// TestNewClient_CABundle_Success pins the happy path: a valid PEM CA bundle
// loads, populates RootCAs on the client's TLS config, and leaves
// MinVersion=TLS1.3 intact. Regression guard for any future edit that
// accidentally swaps the transport or detaches *tls.Config from *http.Transport.
func TestNewClient_CABundle_Success(t *testing.T) {
	cert := generateTestCert()
	tmp := t.TempDir()
	bundlePath := writeCABundle(t, tmp, cert.Raw, "ca.pem")

	client, err := NewClient("https://certctl-server:8443", "test-key", bundlePath, false)
	if err != nil {
		t.Fatalf("NewClient with valid CA bundle err=%v want nil", err)
	}
	if client == nil {
		t.Fatal("NewClient returned nil client on happy path")
	}

	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("httpClient.Transport type=%T want *http.Transport (TLS config injection broke)", client.httpClient.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("transport.TLSClientConfig is nil; TLS config must be set on every client")
	}
	if transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("transport.TLSClientConfig.RootCAs is nil; CA bundle path was ignored")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion=%d want tls.VersionTLS13 (%d); HTTPS-Everywhere requires TLS1.3 floor",
			transport.TLSClientConfig.MinVersion, tls.VersionTLS13)
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify=true with insecure=false arg; flag wiring crossed")
	}
}

// TestNewClient_CABundle_MissingFile pins the fail-loud path for a nonexistent
// bundle path. The error surface must include "reading CA bundle" so operators
// see the right diagnostic instead of a downstream TLS-handshake-error.
func TestNewClient_CABundle_MissingFile(t *testing.T) {
	_, err := NewClient("https://certctl-server:8443", "test-key", "/nonexistent/path/ca.pem", false)
	if err == nil {
		t.Fatal("NewClient with missing CA bundle err=nil; must fail loud so operators see the right diagnostic")
	}
	if !containsStr(err.Error(), "reading CA bundle") {
		t.Errorf("err=%q must contain %q so operators can locate the misconfigured path", err.Error(), "reading CA bundle")
	}
}

// TestNewClient_CABundle_EmptyPEM pins the fail-loud path for a file whose
// contents are not valid PEM. AppendCertsFromPEM returning false is the signal
// we need to surface — otherwise the client would silently ship with an empty
// cert pool and every TLS handshake would fail downstream.
func TestNewClient_CABundle_EmptyPEM(t *testing.T) {
	tmp := t.TempDir()
	garbagePath := filepath.Join(tmp, "garbage.pem")
	if err := os.WriteFile(garbagePath, []byte("not a pem certificate, just bytes"), 0o600); err != nil {
		t.Fatalf("writing garbage file: %v", err)
	}

	_, err := NewClient("https://certctl-server:8443", "test-key", garbagePath, false)
	if err == nil {
		t.Fatal("NewClient with malformed PEM err=nil; must fail loud, not silently skip")
	}
	if !containsStr(err.Error(), "no valid PEM-encoded certificates") {
		t.Errorf("err=%q must contain %q so operators know the file parsed but held no certs",
			err.Error(), "no valid PEM-encoded certificates")
	}
}

// TestNewClient_TLSRoundTrip validates that the TLS config knobs we set on
// NewClient actually reach the wire. An httptest.NewTLSServer signs its own
// self-signed leaf; we PEM-encode that server cert, write it as the CA bundle,
// and issue a real HTTPS GET via c.Get. A successful round-trip proves RootCAs
// + MinVersion are flowing through *http.Transport into the dialer, not just
// surviving into the client struct.
func TestNewClient_TLSRoundTrip(t *testing.T) {
	var handlerHit int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/certificates" {
			handlerHit++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data":  []interface{}{},
				"total": 0,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	serverCert := server.Certificate()
	if serverCert == nil {
		t.Fatal("httptest.NewTLSServer.Certificate() returned nil; cannot build CA bundle")
	}

	tmp := t.TempDir()
	bundlePath := writeCABundle(t, tmp, serverCert.Raw, "server-ca.pem")

	client, err := NewClient(server.URL, "test-key", bundlePath, false)
	if err != nil {
		t.Fatalf("NewClient(TLS server) err=%v want nil", err)
	}
	data, err := client.Get("/api/v1/certificates", nil)
	if err != nil {
		t.Fatalf("Get over HTTPS err=%v; TLS config must reach the wire", err)
	}
	if data == nil {
		t.Fatal("Get over HTTPS returned nil data; want non-empty JSON body")
	}
	if handlerHit != 1 {
		t.Errorf("handlerHit=%d want 1; request did not reach the TLS server", handlerHit)
	}
}

// TestNewClient_InsecureSkipVerify pins the dev-only escape hatch: an untrusted
// TLS server (cert NOT in the client's root pool) must be reachable when
// insecure=true. This is the only path in the control plane that disables
// certificate verification; it's documented in docs/tls.md and gated by the
// CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY env var so it never slips into
// production silently.
func TestNewClient_InsecureSkipVerify(t *testing.T) {
	var handlerHit int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerHit++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data":  []interface{}{},
			"total": 0,
		})
	}))
	defer server.Close()

	// No CA bundle → system roots, which will NOT trust the self-signed
	// httptest cert. insecure=true is the only thing keeping this call from
	// failing with an x509-unknown-authority error.
	client, err := NewClient(server.URL, "test-key", "", true)
	if err != nil {
		t.Fatalf("NewClient(insecure=true) err=%v want nil", err)
	}

	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("httpClient.Transport type=%T want *http.Transport", client.httpClient.Transport)
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("insecure=true arg did not set TLSClientConfig.InsecureSkipVerify; flag wiring broken")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion=%d want tls.VersionTLS13 even with insecure=true (TLS1.3 floor is not optional)",
			transport.TLSClientConfig.MinVersion)
	}

	data, err := client.Get("/api/v1/certificates", nil)
	if err != nil {
		t.Fatalf("Get(insecure=true) err=%v; escape hatch must still complete the round-trip", err)
	}
	if data == nil {
		t.Fatal("Get(insecure=true) returned nil data; want non-empty JSON body")
	}
	if handlerHit != 1 {
		t.Errorf("handlerHit=%d want 1; insecure round-trip did not reach the server", handlerHit)
	}
}
