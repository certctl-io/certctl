package ejbca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/connector/issuer"
	"github.com/certctl-io/certctl/internal/connector/issuer/ejbca"
	"github.com/certctl-io/certctl/internal/secret"
)

// mustNewForValidateConfig returns an EJBCA connector wired in OAuth2 mode
// with a placeholder token. ValidateConfig parses raw JSON independently of
// the connector's auth wiring, so this dummy connector is sufficient for
// ValidateConfig-only tests. The pre-existing tests called New(nil, ...) for
// this; with the new (*Connector, error) signature that requires a non-nil
// config, the OAuth2 placeholder is the cheapest substitute.
func mustNewForValidateConfig(t *testing.T, logger *slog.Logger) *ejbca.Connector {
	t.Helper()
	c, err := ejbca.New(&ejbca.Config{
		APIUrl:   "https://placeholder",
		AuthMode: "oauth2",
		Token:    secret.NewRefFromString("placeholder"),
		CAName:   "placeholder",
	}, logger)
	if err != nil {
		t.Fatalf("ejbca.New (OAuth2 dummy): %v", err)
	}
	return c
}

func TestEJBCAConnector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("ValidateConfig_Success_mTLS", func(t *testing.T) {
		// Use a placeholder connector for ValidateConfig — the JSON
		// shape is what's being validated, not the connector's mTLS
		// wiring. (Production New() with these fake paths would fail
		// at tls.LoadX509KeyPair, which is the correct behavior tested
		// separately by TestNew_MTLSCertLoadFailure.)
		config := ejbca.Config{
			APIUrl:         "https://ejbca.example.com:8443/ejbca/ejbca-rest-api/v1",
			AuthMode:       "mtls",
			ClientCertPath: "/etc/ssl/certs/client.crt",
			ClientKeyPath:  "/etc/ssl/private/client.key",
			CAName:         "Management CA",
		}

		connector := mustNewForValidateConfig(t, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	t.Run("ValidateConfig_Success_OAuth2", func(t *testing.T) {
		config := ejbca.Config{
			APIUrl:   "https://ejbca.example.com:8443/ejbca/ejbca-rest-api/v1",
			AuthMode: "oauth2",
			Token:    secret.NewRefFromString("test-oauth2-token"),
			CAName:   "Management CA",
		}

		connector, err := ejbca.New(&config, logger)
		if err != nil {
			t.Fatalf("ejbca.New (OAuth2): %v", err)
		}
		rawConfig, _ := json.Marshal(config)
		err = connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingAPIUrl", func(t *testing.T) {
		config := ejbca.Config{
			AuthMode: "mtls",
			CAName:   "Management CA",
		}

		connector := mustNewForValidateConfig(t, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing api_url")
		}
		if !strings.Contains(err.Error(), "api_url is required") {
			t.Errorf("Expected api_url required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingCAName", func(t *testing.T) {
		config := ejbca.Config{
			APIUrl:   "https://ejbca.example.com:8443/ejbca/ejbca-rest-api/v1",
			AuthMode: "mtls",
		}

		connector := mustNewForValidateConfig(t, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing ca_name")
		}
		if !strings.Contains(err.Error(), "ca_name is required") {
			t.Errorf("Expected ca_name required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_mTLS_MissingCertPath", func(t *testing.T) {
		config := ejbca.Config{
			APIUrl:        "https://ejbca.example.com:8443/ejbca/ejbca-rest-api/v1",
			AuthMode:      "mtls",
			ClientKeyPath: "/etc/ssl/private/client.key",
			CAName:        "Management CA",
		}

		connector := mustNewForValidateConfig(t, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing client_cert_path with auth_mode=mtls")
		}
		if !strings.Contains(err.Error(), "client_cert_path is required") {
			t.Errorf("Expected client_cert_path required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_OAuth2_MissingToken", func(t *testing.T) {
		config := ejbca.Config{
			APIUrl:   "https://ejbca.example.com:8443/ejbca/ejbca-rest-api/v1",
			AuthMode: "oauth2",
			CAName:   "Management CA",
		}

		connector := mustNewForValidateConfig(t, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing token with auth_mode=oauth2")
		}
		if !strings.Contains(err.Error(), "token is required") {
			t.Errorf("Expected token required error, got: %v", err)
		}
	})

	t.Run("ValidateConfig_InvalidAuthMode", func(t *testing.T) {
		config := ejbca.Config{
			APIUrl:   "https://ejbca.example.com:8443/ejbca/ejbca-rest-api/v1",
			AuthMode: "invalid",
			CAName:   "Management CA",
		}

		connector := mustNewForValidateConfig(t, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for invalid auth_mode")
		}
		if !strings.Contains(err.Error(), "auth_mode must be") {
			t.Errorf("Expected auth_mode validation error, got: %v", err)
		}
	})

	t.Run("IssueCertificate_Synchronous", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)
		testChainPEM, _ := generateTestCert(t)

		// Extract DER from PEM for encoding
		certBlock, _ := pem.Decode([]byte(testCertPEM))
		chainBlock, _ := pem.Decode([]byte(testChainPEM))

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/certificate/pkcs10enroll") && r.Method == http.MethodPost {
				// Parse the CSR from request
				var enrollReq map[string]interface{}
				json.NewDecoder(r.Body).Decode(&enrollReq)

				// Verify CSR is base64-encoded
				if csrB64, ok := enrollReq["certificate_request"].(string); ok {
					// Decode to verify it's valid base64
					if _, err := base64.StdEncoding.DecodeString(csrB64); err != nil {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
				}

				w.WriteHeader(http.StatusOK)
				w.Header().Set("Content-Type", "application/json")

				respData := map[string]interface{}{
					"certificate":       base64.StdEncoding.EncodeToString(certBlock.Bytes),
					"certificate_chain": []string{base64.StdEncoding.EncodeToString(chainBlock.Bytes)},
					"serial_number":     "123456",
				}
				json.NewEncoder(w).Encode(respData)
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := &ejbca.Config{
			APIUrl:   srv.URL,
			AuthMode: "oauth2",
			Token:    secret.NewRefFromString("test-token"),
			CAName:   "Management CA",
		}
		connector := ejbca.NewWithHTTPClient(config, logger, srv.Client())

		_, csrPEM := generateTestCSR(t, "test.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "test.example.com",
			SANs:       []string{"test.example.com"},
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("IssueCertificate failed: %v", err)
		}

		if result.CertPEM == "" {
			t.Error("CertPEM should not be empty")
		}
		if result.OrderID == "" {
			t.Error("OrderID should not be empty")
		}
		if !strings.Contains(result.OrderID, "::") {
			t.Errorf("OrderID should contain issuer_dn::serial separator, got: %s", result.OrderID)
		}
		t.Logf("EJBCA issued cert: serial=%s, orderID=%s", result.Serial, result.OrderID)
	})

	t.Run("IssueCertificate_WithProfiles", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)
		certBlock, _ := pem.Decode([]byte(testCertPEM))

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/certificate/pkcs10enroll") && r.Method == http.MethodPost {
				// Verify profiles are in request
				var enrollReq map[string]interface{}
				json.NewDecoder(r.Body).Decode(&enrollReq)

				if certProfile, ok := enrollReq["certificate_profile_name"].(string); !ok || certProfile != "ENDUSER" {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(`{"error":"invalid certificate_profile_name"}`))
					return
				}
				if eeProfile, ok := enrollReq["end_entity_profile_name"].(string); !ok || eeProfile != "ENDUSER" {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(`{"error":"invalid end_entity_profile_name"}`))
					return
				}

				w.WriteHeader(http.StatusOK)
				w.Header().Set("Content-Type", "application/json")
				respData := map[string]interface{}{
					"certificate":       base64.StdEncoding.EncodeToString(certBlock.Bytes),
					"certificate_chain": []string{},
					"serial_number":     "789012",
				}
				json.NewEncoder(w).Encode(respData)
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := &ejbca.Config{
			APIUrl:      srv.URL,
			AuthMode:    "oauth2",
			Token:       secret.NewRefFromString("test-token"),
			CAName:      "Management CA",
			CertProfile: "ENDUSER",
			EEProfile:   "ENDUSER",
		}
		connector := ejbca.NewWithHTTPClient(config, logger, srv.Client())

		_, csrPEM := generateTestCSR(t, "app.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "app.example.com",
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("IssueCertificate with profiles failed: %v", err)
		}

		if result.CertPEM == "" {
			t.Error("CertPEM should not be empty")
		}
	})

	t.Run("IssueCertificate_Error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid CSR"}`))
		}))
		defer srv.Close()

		config := &ejbca.Config{
			APIUrl:   srv.URL,
			AuthMode: "oauth2",
			Token:    secret.NewRefFromString("test-token"),
			CAName:   "Management CA",
		}
		connector := ejbca.NewWithHTTPClient(config, logger, srv.Client())

		req := issuer.IssuanceRequest{
			CommonName: "test.example.com",
			CSRPEM:     "invalid-csr",
		}

		_, err := connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error for invalid CSR")
		}
	})

	t.Run("GetOrderStatus_Issued", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)
		certBlock, _ := pem.Decode([]byte(testCertPEM))

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/certificate/") && r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				w.Header().Set("Content-Type", "application/json")
				respData := map[string]interface{}{
					"certificate":       base64.StdEncoding.EncodeToString(certBlock.Bytes),
					"certificate_chain": []string{},
					"serial_number":     "123456",
				}
				json.NewEncoder(w).Encode(respData)
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := &ejbca.Config{
			APIUrl:   srv.URL,
			AuthMode: "oauth2",
			Token:    secret.NewRefFromString("test-token"),
			CAName:   "Management CA",
		}
		connector := ejbca.NewWithHTTPClient(config, logger, srv.Client())

		orderID := "CN=Test CA::123456"
		status, err := connector.GetOrderStatus(ctx, orderID)
		if err != nil {
			t.Fatalf("GetOrderStatus failed: %v", err)
		}

		if status.Status != "completed" {
			t.Errorf("Expected status 'completed', got '%s'", status.Status)
		}
		if status.CertPEM == nil || *status.CertPEM == "" {
			t.Error("CertPEM should not be empty for issued order")
		}
	})

	t.Run("RenewCertificate_Success", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)
		certBlock, _ := pem.Decode([]byte(testCertPEM))

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/certificate/pkcs10enroll") && r.Method == http.MethodPost {
				w.WriteHeader(http.StatusOK)
				w.Header().Set("Content-Type", "application/json")
				respData := map[string]interface{}{
					"certificate":       base64.StdEncoding.EncodeToString(certBlock.Bytes),
					"certificate_chain": []string{},
					"serial_number":     "654321",
				}
				json.NewEncoder(w).Encode(respData)
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := &ejbca.Config{
			APIUrl:   srv.URL,
			AuthMode: "oauth2",
			Token:    secret.NewRefFromString("test-token"),
			CAName:   "Management CA",
		}
		connector := ejbca.NewWithHTTPClient(config, logger, srv.Client())

		_, csrPEM := generateTestCSR(t, "renew.example.com")
		renewReq := issuer.RenewalRequest{
			CommonName: "renew.example.com",
			CSRPEM:     csrPEM,
		}

		result, err := connector.RenewCertificate(ctx, renewReq)
		if err != nil {
			t.Fatalf("RenewCertificate failed: %v", err)
		}

		if result.CertPEM == "" {
			t.Error("CertPEM should not be empty")
		}
		if result.OrderID == "" {
			t.Error("OrderID should not be empty")
		}
	})

	t.Run("RevokeCertificate_Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/revoke") && r.Method == http.MethodPut {
				// Verify reason is in request
				var revokeReq map[string]interface{}
				json.NewDecoder(r.Body).Decode(&revokeReq)

				if _, ok := revokeReq["reason"]; !ok {
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				w.WriteHeader(http.StatusNoContent)
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := &ejbca.Config{
			APIUrl:   srv.URL,
			AuthMode: "oauth2",
			Token:    secret.NewRefFromString("test-token"),
			CAName:   "Management CA",
		}
		connector := ejbca.NewWithHTTPClient(config, logger, srv.Client())

		reason := "keyCompromise"
		revokeReq := issuer.RevocationRequest{
			Serial: "123456",
			Reason: &reason,
		}

		err := connector.RevokeCertificate(ctx, revokeReq)
		if err != nil {
			t.Fatalf("RevokeCertificate failed: %v", err)
		}
	})

	t.Run("RevokeCertificate_ReasonMapping", func(t *testing.T) {
		reasons := []struct {
			name     string
			code     int
			mappedTo string
		}{
			{"keyCompromise", 1, "keyCompromise"},
			{"caCompromise", 2, "caCompromise"},
			{"superseded", 4, "superseded"},
			{"cessationOfOperation", 5, "cessationOfOperation"},
		}

		for _, tc := range reasons {
			t.Run(tc.name, func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.Contains(r.URL.Path, "/revoke") && r.Method == http.MethodPut {
						var revokeReq map[string]interface{}
						json.NewDecoder(r.Body).Decode(&revokeReq)

						// Verify the reason code matches
						if reason, ok := revokeReq["reason"].(float64); ok {
							if int(reason) != tc.code {
								w.WriteHeader(http.StatusBadRequest)
								w.Write([]byte(fmt.Sprintf(`{"error":"expected reason %d, got %d"}`, tc.code, int(reason))))
								return
							}
						}

						w.WriteHeader(http.StatusNoContent)
						return
					}
					http.NotFound(w, r)
				}))
				defer srv.Close()

				config := &ejbca.Config{
					APIUrl:   srv.URL,
					AuthMode: "oauth2",
					Token:    secret.NewRefFromString("test-token"),
					CAName:   "Management CA",
				}
				connector := ejbca.NewWithHTTPClient(config, logger, srv.Client())

				revokeReq := issuer.RevocationRequest{
					Serial: "test-serial",
					Reason: &tc.name,
				}

				err := connector.RevokeCertificate(ctx, revokeReq)
				if err != nil {
					t.Fatalf("RevokeCertificate with reason %s failed: %v", tc.name, err)
				}
			})
		}
	})

	t.Run("GetRenewalInfo_ReturnsNil", func(t *testing.T) {
		config := &ejbca.Config{
			APIUrl:   "https://ejbca.example.com:8443/ejbca/ejbca-rest-api/v1",
			AuthMode: "oauth2",
			Token:    secret.NewRefFromString("test-token"),
			CAName:   "Management CA",
		}
		connector, err := ejbca.New(config, logger)
		if err != nil {
			t.Fatalf("ejbca.New: %v", err)
		}

		result, err := connector.GetRenewalInfo(ctx, "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
		if err != nil {
			t.Fatalf("GetRenewalInfo should not return error, got: %v", err)
		}
		if result != nil {
			t.Fatal("GetRenewalInfo should return nil for EJBCA")
		}
	})

	t.Run("GenerateCRL_Unsupported", func(t *testing.T) {
		config := &ejbca.Config{
			APIUrl:   "https://ejbca.example.com:8443/ejbca/ejbca-rest-api/v1",
			AuthMode: "oauth2",
			Token:    secret.NewRefFromString("test-token"),
			CAName:   "Management CA",
		}
		connector, err := ejbca.New(config, logger)
		if err != nil {
			t.Fatalf("ejbca.New: %v", err)
		}

		_, err = connector.GenerateCRL(ctx, []issuer.RevokedCertEntry{})
		if err == nil {
			t.Fatal("Expected error for unsupported GenerateCRL")
		}
		if !strings.Contains(err.Error(), "CRL distribution") {
			t.Errorf("Expected CRL distribution error, got: %v", err)
		}
	})

	t.Run("SignOCSPResponse_Unsupported", func(t *testing.T) {
		config := &ejbca.Config{
			APIUrl:   "https://ejbca.example.com:8443/ejbca/ejbca-rest-api/v1",
			AuthMode: "oauth2",
			Token:    secret.NewRefFromString("test-token"),
			CAName:   "Management CA",
		}
		connector, err := ejbca.New(config, logger)
		if err != nil {
			t.Fatalf("ejbca.New: %v", err)
		}

		_, err = connector.SignOCSPResponse(ctx, issuer.OCSPSignRequest{})
		if err == nil {
			t.Fatal("Expected error for unsupported SignOCSPResponse")
		}
		if !strings.Contains(err.Error(), "OCSP") {
			t.Errorf("Expected OCSP error, got: %v", err)
		}
	})
}

// TestNew_MTLSWiresClientCert closes the audit's #2 D11 blocker by exercising
// the production New() path (NOT NewWithHTTPClient). Pre-fix, New() built an
// http.Client with only Timeout set; mTLS mode advertised support but never
// loaded the cert. Tests passed via NewWithHTTPClient mock injection — a path
// the production constructor never took. This test calls New() with real
// cert/key files and asserts:
//
//  1. Error is nil (cert load succeeded).
//  2. The connector's HTTP client has a non-nil Transport.
//  3. Transport.TLSClientConfig.Certificates carries the loaded cert.
//
// As an end-to-end proof, the test then makes a request against an
// httptest.NewTLSServer with ClientAuth: tls.RequireAndVerifyClientCert
// and asserts the request succeeds — proving the cert was actually
// presented on the wire (not just stashed in a struct field).
func TestNew_MTLSWiresClientCert(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// 1. Generate a CA cert + a client cert signed by the CA. Use ECDSA-P256
	//    to match the codebase's preferred algorithm.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key gen: %v", err)
	}
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "EJBCA-Test-CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("client key gen: %v", err)
	}
	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ejbca-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}

	// 2. Write cert + key to temp files (Go stdlib's tls.LoadX509KeyPair
	//    requires file paths).
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	if err := os.WriteFile(certPath, clientCertPEM, 0o600); err != nil {
		t.Fatalf("write client cert: %v", err)
	}
	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})
	if err := os.WriteFile(keyPath, clientKeyPEM, 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}

	// 3. Call production New() (NOT NewWithHTTPClient) with the cert paths.
	cfg := &ejbca.Config{
		APIUrl:         "https://placeholder",
		AuthMode:       "mtls",
		ClientCertPath: certPath,
		ClientKeyPath:  keyPath,
		CAName:         "Management CA",
	}
	conn, err := ejbca.New(cfg, logger)
	if err != nil {
		t.Fatalf("ejbca.New: %v", err)
	}
	if conn == nil {
		t.Fatal("New returned nil connector")
	}

	// 4. Assert via the exported HTTPClient accessor that the transport
	//    is wired and carries the loaded cert. (Connector exposes
	//    HTTPClient only in test builds via the helper below.)
	httpClient := ejbca.HTTPClientForTest(conn)
	if httpClient == nil {
		t.Fatal("connector httpClient is nil")
	}
	tr, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", httpClient.Transport)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("Transport.TLSClientConfig is nil — mTLS not wired")
	}
	if len(tr.TLSClientConfig.Certificates) == 0 {
		t.Fatal("Transport.TLSClientConfig.Certificates is empty — cert not loaded")
	}

	// 5. End-to-end proof: spin up an httptest TLS server that requires
	//    a client cert signed by our CA. Hit it with the connector's
	//    client and assert the request succeeds (cert was presented).
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client cert", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
	}
	srv.StartTLS()
	defer srv.Close()

	// The httptest server's cert isn't trusted by our client; for the
	// purpose of this test we replace the RootCAs to trust it. We
	// intentionally keep the Certificates (client cert) intact — the
	// test is about whether the client cert is presented, not about
	// the server cert chain.
	srvCertDER := srv.Certificate().Raw
	srvCert, err := x509.ParseCertificate(srvCertDER)
	if err != nil {
		t.Fatalf("parse srv cert: %v", err)
	}
	srvPool := x509.NewCertPool()
	srvPool.AddCert(srvCert)
	tr.TLSClientConfig.RootCAs = srvPool

	resp, err := httpClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("HTTPS request to mTLS server failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d (cert was probably not presented)", resp.StatusCode)
	}
}

// TestNew_MTLSCertLoadFailure asserts that a missing-cert path returns an
// error wrapping fs.ErrNotExist. This is the negative path: misconfigured
// operators must get an immediate failure at issuer construction, not a
// cryptic 401 at first issuance.
func TestNew_MTLSCertLoadFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &ejbca.Config{
		APIUrl:         "https://placeholder",
		AuthMode:       "mtls",
		ClientCertPath: "/nonexistent/path/to/cert.pem",
		ClientKeyPath:  "/nonexistent/path/to/key.pem",
		CAName:         "Management CA",
	}
	_, err := ejbca.New(cfg, logger)
	if err == nil {
		t.Fatal("expected error from missing cert path")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected error to wrap fs.ErrNotExist, got: %v", err)
	}
}

// TestNew_OAuth2NoTransportTuning asserts that the OAuth2 path does NOT
// accidentally apply mTLS-style transport customization. This catches the
// reverse class of bug: someone modifying New() in a way that leaks mTLS
// transport into the OAuth2 path.
func TestNew_OAuth2NoTransportTuning(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &ejbca.Config{
		APIUrl:   "https://placeholder",
		AuthMode: "oauth2",
		Token:    secret.NewRefFromString("test-token"),
		CAName:   "Management CA",
	}
	conn, err := ejbca.New(cfg, logger)
	if err != nil {
		t.Fatalf("ejbca.New (OAuth2): %v", err)
	}
	httpClient := ejbca.HTTPClientForTest(conn)
	if httpClient == nil {
		t.Fatal("connector httpClient is nil")
	}
	if httpClient.Transport != nil {
		t.Fatalf("expected Transport to be nil for OAuth2 mode, got: %T", httpClient.Transport)
	}
}

// TestNew_InvalidAuthMode asserts that any auth_mode other than "mtls" or
// "oauth2" returns (nil, error) immediately rather than falling through to
// the default (mtls) which would then fail at cert load.
func TestNew_InvalidAuthMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &ejbca.Config{
		APIUrl:   "https://placeholder",
		AuthMode: "invalid",
		Token:    secret.NewRefFromString("test-token"),
		CAName:   "Management CA",
	}
	_, err := ejbca.New(cfg, logger)
	if err == nil {
		t.Fatal("expected error from invalid auth_mode")
	}
	if !strings.Contains(err.Error(), "invalid auth_mode") {
		t.Errorf("expected 'invalid auth_mode' error, got: %v", err)
	}
}

// generateTestCert creates a self-signed test certificate and returns the PEM string.
func generateTestCert(t *testing.T) (certPEM string, keyPEM string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("Test Certificate %s", serial.String()[:8]),
		},
		DNSNames:              []string{"test.example.com"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))

	return certPEM, keyPEM
}

// generateTestCSR creates a test CSR for the given common name.
func generateTestCSR(t *testing.T, commonName string) (*x509.CertificateRequest, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:           []string{commonName},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}))

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	return csr, csrPEM
}
