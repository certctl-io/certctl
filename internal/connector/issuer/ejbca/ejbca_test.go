package ejbca_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/ejbca"
)

func TestEJBCAConnector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("ValidateConfig_Success_mTLS", func(t *testing.T) {
		config := ejbca.Config{
			APIUrl:         "https://ejbca.example.com:8443/ejbca/ejbca-rest-api/v1",
			AuthMode:       "mtls",
			ClientCertPath: "/etc/ssl/certs/client.crt",
			ClientKeyPath:  "/etc/ssl/private/client.key",
			CAName:         "Management CA",
		}

		connector := ejbca.New(&config, logger)
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
			Token:    "test-oauth2-token",
			CAName:   "Management CA",
		}

		connector := ejbca.New(&config, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingAPIUrl", func(t *testing.T) {
		config := ejbca.Config{
			AuthMode: "mtls",
			CAName:   "Management CA",
		}

		connector := ejbca.New(nil, logger)
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

		connector := ejbca.New(nil, logger)
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

		connector := ejbca.New(nil, logger)
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

		connector := ejbca.New(nil, logger)
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

		connector := ejbca.New(nil, logger)
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
			Token:    "test-token",
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
			Token:       "test-token",
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
			Token:    "test-token",
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
			Token:    "test-token",
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
			Token:    "test-token",
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
			Token:    "test-token",
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
					Token:    "test-token",
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
			Token:    "test-token",
			CAName:   "Management CA",
		}
		connector := ejbca.New(config, logger)

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
			Token:    "test-token",
			CAName:   "Management CA",
		}
		connector := ejbca.New(config, logger)

		_, err := connector.GenerateCRL(ctx, []issuer.RevokedCertEntry{})
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
			Token:    "test-token",
			CAName:   "Management CA",
		}
		connector := ejbca.New(config, logger)

		_, err := connector.SignOCSPResponse(ctx, issuer.OCSPSignRequest{})
		if err == nil {
			t.Fatal("Expected error for unsupported SignOCSPResponse")
		}
		if !strings.Contains(err.Error(), "OCSP") {
			t.Errorf("Expected OCSP error, got: %v", err)
		}
	})
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
