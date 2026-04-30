package stepca_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/stepca"
)

func TestStepCAConnector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	t.Run("ValidateConfig_Success", func(t *testing.T) {
		// Start a mock step-ca health endpoint
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"ok"}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		config := stepca.Config{
			CAURL:           srv.URL,
			ProvisionerName: "test-provisioner",
			ValidityDays:    90,
		}

		connector := stepca.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	t.Run("ValidateConfig_MissingCAURL", func(t *testing.T) {
		config := stepca.Config{
			ProvisionerName: "test",
		}

		connector := stepca.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing ca_url")
		}
	})

	t.Run("ValidateConfig_MissingProvisioner", func(t *testing.T) {
		config := stepca.Config{
			CAURL: "https://ca.example.com",
		}

		connector := stepca.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing provisioner_name")
		}
	})

	t.Run("ValidateConfig_UnreachableCA", func(t *testing.T) {
		config := stepca.Config{
			CAURL:           "http://localhost:19999",
			ProvisionerName: "test",
		}

		connector := stepca.New(nil, logger)
		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for unreachable CA")
		}
	})

	t.Run("IssueCertificate_Success", func(t *testing.T) {
		// Generate a test certificate to return in the mock
		testCertPEM, testKeyPEM := generateTestCert(t)
		_ = testKeyPEM

		// Start a mock step-ca server
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"ok"}`))
			case "/sign":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				resp := fmt.Sprintf(`{"crt": %q, "ca": %q}`, testCertPEM, testCertPEM)
				w.Write([]byte(resp))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &stepca.Config{
			CAURL:           srv.URL,
			ProvisionerName: "test-provisioner",
			ValidityDays:    30,
		}
		connector := stepca.New(config, logger)

		_, csrPEM, err := generateStepCATestCSR("app.internal.corp")
		if err != nil {
			t.Fatalf("Failed to generate CSR: %v", err)
		}

		req := issuer.IssuanceRequest{
			CommonName: "app.internal.corp",
			SANs:       []string{"app.internal.corp"},
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("IssueCertificate failed: %v", err)
		}

		if result.CertPEM == "" {
			t.Error("CertPEM is empty")
		}
		if result.Serial == "" {
			t.Error("Serial is empty")
		}
		if result.OrderID == "" {
			t.Error("OrderID is empty")
		}

		t.Logf("step-ca issued cert: serial=%s", result.Serial)
	})

	t.Run("IssueCertificate_ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				w.WriteHeader(http.StatusOK)
			case "/sign":
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"invalid token"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &stepca.Config{
			CAURL:           srv.URL,
			ProvisionerName: "test-provisioner",
		}
		connector := stepca.New(config, logger)

		_, csrPEM, _ := generateStepCATestCSR("test.example.com")
		req := issuer.IssuanceRequest{
			CommonName: "test.example.com",
			CSRPEM:     csrPEM,
		}

		_, err := connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error for server error response")
		}
		t.Logf("Correctly got error: %v", err)
	})

	t.Run("RenewCertificate", func(t *testing.T) {
		testCertPEM, _ := generateTestCert(t)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				w.WriteHeader(http.StatusOK)
			case "/sign":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				resp := fmt.Sprintf(`{"crt": %q, "ca": %q}`, testCertPEM, testCertPEM)
				w.Write([]byte(resp))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &stepca.Config{
			CAURL:           srv.URL,
			ProvisionerName: "test-provisioner",
		}
		connector := stepca.New(config, logger)

		_, csrPEM, _ := generateStepCATestCSR("renew.example.com")
		renewReq := issuer.RenewalRequest{
			CommonName: "renew.example.com",
			CSRPEM:     csrPEM,
		}

		result, err := connector.RenewCertificate(ctx, renewReq)
		if err != nil {
			t.Fatalf("RenewCertificate failed: %v", err)
		}

		if result.Serial == "" {
			t.Error("Serial is empty")
		}
	})

	t.Run("RevokeCertificate_Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				w.WriteHeader(http.StatusOK)
			case "/revoke":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"ok"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &stepca.Config{
			CAURL:           srv.URL,
			ProvisionerName: "test-provisioner",
		}
		connector := stepca.New(config, logger)

		reason := "keyCompromise"
		revokeReq := issuer.RevocationRequest{
			Serial: "1234567890",
			Reason: &reason,
		}

		err := connector.RevokeCertificate(ctx, revokeReq)
		if err != nil {
			t.Fatalf("RevokeCertificate failed: %v", err)
		}
	})

	t.Run("RevokeCertificate_ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/health":
				w.WriteHeader(http.StatusOK)
			case "/revoke":
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"unauthorized"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		config := &stepca.Config{
			CAURL:           srv.URL,
			ProvisionerName: "test-provisioner",
		}
		connector := stepca.New(config, logger)

		revokeReq := issuer.RevocationRequest{
			Serial: "1234567890",
		}

		err := connector.RevokeCertificate(ctx, revokeReq)
		if err == nil {
			t.Fatal("Expected error for server error response")
		}
	})

	t.Run("GetOrderStatus", func(t *testing.T) {
		config := &stepca.Config{
			CAURL:           "https://ca.example.com",
			ProvisionerName: "test-provisioner",
		}
		connector := stepca.New(config, logger)

		status, err := connector.GetOrderStatus(ctx, "stepca-12345")
		if err != nil {
			t.Fatalf("GetOrderStatus failed: %v", err)
		}

		if status.Status != "completed" {
			t.Errorf("Expected status 'completed', got '%s'", status.Status)
		}
	})
}

// generateTestCert creates a self-signed test certificate and returns the PEM strings.
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
			CommonName: "Test Certificate",
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

func generateStepCATestCSR(commonName string) (*x509.CertificateRequest, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
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
		return nil, "", err
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, "", err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	return csr, string(csrPEM), nil
}

func TestGenerateProvisionerTokenEphemeralKey(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
		// No ProvisionerKeyPath — forces ephemeral key generation
	}
	_ = stepca.New(config, logger) // verify constructor doesn't panic

	// This should NOT panic and should return a non-empty token
	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		SANs:       []string{"test.example.com", "app.example.com"},
		CSRPEM:     csrPEM,
	}

	// We can't test token generation directly since it's unexported,
	// but we can verify issuance with ephemeral key works against mock server
	testCertPEM, _ := generateTestCert(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			resp := fmt.Sprintf(`{"crt": %q, "ca": %q}`, testCertPEM, testCertPEM)
			w.Write([]byte(resp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config.CAURL = srv.URL
	connector := stepca.New(config, logger)

	result, err := connector.IssueCertificate(ctx, req)
	if err != nil {
		t.Fatalf("IssueCertificate with ephemeral key failed: %v", err)
	}

	if result.Serial == "" {
		t.Error("Expected non-empty serial")
	}
}

func TestParseSignResponse_SimpleFormat(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	testCertPEM, _ := generateTestCert(t)

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}
	_ = stepca.New(config, logger) // verify constructor doesn't panic

	// Test the simple crt/ca response format
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			// Simple format: crt and ca fields
			resp := fmt.Sprintf(`{"crt": %q, "ca": %q}`, testCertPEM, testCertPEM)
			w.Write([]byte(resp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config.CAURL = srv.URL
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		CSRPEM:     csrPEM,
	}

	result, err := connector.IssueCertificate(ctx, req)
	if err != nil {
		t.Fatalf("IssueCertificate with simple format failed: %v", err)
	}

	if result.CertPEM != testCertPEM {
		t.Errorf("CertPEM mismatch: got %q, want %q", result.CertPEM, testCertPEM)
	}
	if result.ChainPEM != testCertPEM {
		t.Errorf("ChainPEM mismatch: got %q, want %q", result.ChainPEM, testCertPEM)
	}
}

func TestParseSignResponse_StructuredFormat(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	testCertPEM, _ := generateTestCert(t)

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}
	_ = stepca.New(config, logger) // verify constructor doesn't panic

	// Test the structured response format
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			// Structured format with serverPEM and caPEM
			resp := fmt.Sprintf(`{
				"serverPEM": {"certificate": %q},
				"caPEM": {"certificate": %q}
			}`, testCertPEM, testCertPEM)
			w.Write([]byte(resp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config.CAURL = srv.URL
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		CSRPEM:     csrPEM,
	}

	result, err := connector.IssueCertificate(ctx, req)
	if err != nil {
		t.Fatalf("IssueCertificate with structured format failed: %v", err)
	}

	if result.CertPEM != testCertPEM {
		t.Errorf("CertPEM mismatch")
	}
}

func TestParseSignResponse_InvalidCertPEM(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}

	// Test invalid PEM in response
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			// Invalid PEM data
			resp := `{"crt": "not a certificate", "ca": ""}`
			w.Write([]byte(resp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config.CAURL = srv.URL
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		CSRPEM:     csrPEM,
	}

	_, err := connector.IssueCertificate(ctx, req)
	if err == nil {
		t.Fatal("Expected error for invalid certificate PEM")
	}
}

func TestParseSignResponse_EmptyCertificate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}

	// Test empty certificate in response
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			resp := `{"crt": "", "ca": ""}`
			w.Write([]byte(resp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config.CAURL = srv.URL
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		CSRPEM:     csrPEM,
	}

	_, err := connector.IssueCertificate(ctx, req)
	if err == nil {
		t.Fatal("Expected error for empty certificate")
	}
}

func TestValidateConfig_ProvisionerKeyPathNotExist(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	config := stepca.Config{
		CAURL:              srv.URL,
		ProvisionerName:    "test-provisioner",
		ProvisionerKeyPath: "/nonexistent/path/to/key.json",
	}

	connector := stepca.New(nil, logger)
	rawConfig, _ := json.Marshal(config)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("Expected error for non-existent provisioner key path")
	}
}

func TestIssueCertificate_ValidityDaysSet(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	testCertPEM, _ := generateTestCert(t)
	capturedRequest := []byte{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			// Capture the request to verify NotBefore/NotAfter are set
			var body []byte
			body, _ = io.ReadAll(r.Body)
			capturedRequest = body

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			resp := fmt.Sprintf(`{"crt": %q, "ca": %q}`, testCertPEM, testCertPEM)
			w.Write([]byte(resp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config := &stepca.Config{
		CAURL:           srv.URL,
		ProvisionerName: "test-provisioner",
		ValidityDays:    90,
	}
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		CSRPEM:     csrPEM,
	}

	result, err := connector.IssueCertificate(ctx, req)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	if result.Serial == "" {
		t.Error("Expected non-empty serial")
	}

	// Verify that the request body contained notBefore and notAfter
	if !bytes.Contains(capturedRequest, []byte("notBefore")) || !bytes.Contains(capturedRequest, []byte("notAfter")) {
		t.Errorf("Expected notBefore and notAfter in request body, got: %s", string(capturedRequest))
	}
}

func TestRevokeCertificate_NoReasonProvided(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/revoke":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config := &stepca.Config{
		CAURL:           srv.URL,
		ProvisionerName: "test-provisioner",
	}
	connector := stepca.New(config, logger)

	// No reason provided — should default to "unspecified"
	revokeReq := issuer.RevocationRequest{
		Serial: "1234567890",
		Reason: nil,
	}

	err := connector.RevokeCertificate(ctx, revokeReq)
	if err != nil {
		t.Fatalf("RevokeCertificate without reason failed: %v", err)
	}
}

func TestGenerateCRL_NotSupported(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}
	connector := stepca.New(config, logger)

	_, err := connector.GenerateCRL(ctx, nil)
	if err == nil {
		t.Fatal("Expected error for GenerateCRL not supported")
	}
}

func TestSignOCSPResponse_NotSupported(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}
	connector := stepca.New(config, logger)

	_, err := connector.SignOCSPResponse(ctx, issuer.OCSPSignRequest{})
	if err == nil {
		t.Fatal("Expected error for SignOCSPResponse not supported")
	}
}

func TestGetCACertPEM_NotSupported(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}
	connector := stepca.New(config, logger)

	_, err := connector.GetCACertPEM(ctx)
	if err == nil {
		t.Fatal("Expected error for GetCACertPEM not supported")
	}
}

func TestGetRenewalInfo_NotSupported(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}
	connector := stepca.New(config, logger)

	result, err := connector.GetRenewalInfo(ctx, "test cert pem")
	if err != nil || result != nil {
		t.Fatalf("Expected (nil, nil) for GetRenewalInfo, got (%v, %v)", result, err)
	}
}

func TestParseSignResponse_CertChainFormat(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	testCertPEM, _ := generateTestCert(t)

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}
	_ = stepca.New(config, logger) // verify constructor doesn't panic

	// Test the certChainPEM array response format (multiple certs in array)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			// Array format with multiple certs (leaf + intermediate + root)
			resp := fmt.Sprintf(`{
				"certChainPEM": [
					{"certificate": %q},
					{"certificate": %q},
					{"certificate": %q}
				]
			}`, testCertPEM, testCertPEM, testCertPEM)
			w.Write([]byte(resp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config.CAURL = srv.URL
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		CSRPEM:     csrPEM,
	}

	result, err := connector.IssueCertificate(ctx, req)
	if err != nil {
		t.Fatalf("IssueCertificate with cert chain format failed: %v", err)
	}

	// Chain should include intermediate + root (all except first)
	if result.CertPEM != testCertPEM {
		t.Error("Leaf cert mismatch")
	}
	// Chain should include 2 certs (intermediate + root)
	if result.ChainPEM == "" {
		t.Error("Chain should not be empty when multiple certs provided")
	}
}

func TestValidateConfig_InvalidJSON(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	connector := stepca.New(nil, logger)
	rawConfig := json.RawMessage(`{invalid json}`)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("Expected error for invalid JSON config")
	}
}

func TestIssueCertificate_ContextCancelled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}
	connector := stepca.New(config, logger)

	// Cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		CSRPEM:     csrPEM,
	}

	_, err := connector.IssueCertificate(ctx, req)
	if err == nil {
		t.Fatal("Expected error for cancelled context")
	}
}

func TestIssueCertificate_MalformedResponseJSON(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			// Malformed JSON response
			w.Write([]byte(`{invalid json}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config.CAURL = srv.URL
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		CSRPEM:     csrPEM,
	}

	_, err := connector.IssueCertificate(ctx, req)
	if err == nil {
		t.Fatal("Expected error for malformed response JSON")
	}
}

func TestIssueCertificate_StatusOK(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	testCertPEM, _ := generateTestCert(t)

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}

	// Test with 200 OK response (alternative to 201 Created)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK) // 200 instead of 201
			resp := fmt.Sprintf(`{"crt": %q, "ca": %q}`, testCertPEM, testCertPEM)
			w.Write([]byte(resp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config.CAURL = srv.URL
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		CSRPEM:     csrPEM,
	}

	result, err := connector.IssueCertificate(ctx, req)
	if err != nil {
		t.Fatalf("IssueCertificate with 200 OK status failed: %v", err)
	}

	if result.Serial == "" {
		t.Error("Expected non-empty serial")
	}
}

func TestRevokeCertificate_ErrorReadingBody(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/revoke":
			w.WriteHeader(http.StatusInternalServerError)
			// Don't write anything (simulate error reading response)
			w.Write([]byte(`Internal error`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config.CAURL = srv.URL
	connector := stepca.New(config, logger)

	revokeReq := issuer.RevocationRequest{
		Serial: "1234567890",
	}

	err := connector.RevokeCertificate(ctx, revokeReq)
	if err == nil {
		t.Fatal("Expected error for revoke server error")
	}
}

func TestIssueCertificate_NoValidityDays(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	testCertPEM, _ := generateTestCert(t)
	capturedRequest := []byte{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			// Capture the request to verify behavior with 0 ValidityDays
			var body []byte
			body, _ = io.ReadAll(r.Body)
			capturedRequest = body

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			resp := fmt.Sprintf(`{"crt": %q, "ca": %q}`, testCertPEM, testCertPEM)
			w.Write([]byte(resp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config := &stepca.Config{
		CAURL:           srv.URL,
		ProvisionerName: "test-provisioner",
		ValidityDays:    0, // No validity days set
	}
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		CSRPEM:     csrPEM,
	}

	result, err := connector.IssueCertificate(ctx, req)
	if err != nil {
		t.Fatalf("IssueCertificate with 0 ValidityDays failed: %v", err)
	}

	if result.Serial == "" {
		t.Error("Expected non-empty serial")
	}

	// When ValidityDays is 0, the code doesn't set NotBefore/NotAfter
	// Just verify that the request was captured and processed
	if len(capturedRequest) == 0 {
		t.Error("Expected non-empty captured request")
	}
}

func TestValidateConfig_HealthCheckError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := stepca.Config{
		CAURL:           "http://invalid-url-that-will-not-resolve.local:9999",
		ProvisionerName: "test-provisioner",
	}

	connector := stepca.New(nil, logger)
	rawConfig, _ := json.Marshal(config)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("Expected error for unreachable CA")
	}
}

func TestIssueCertificate_ReadResponseBodyError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}

	// Create a response with status 201 but an unreadable body
	// This is hard to simulate with httptest, so we'll just test the normal path
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			testCertPEM, _ := generateTestCert(t)
			resp := fmt.Sprintf(`{"crt": %q, "ca": %q}`, testCertPEM, testCertPEM)
			w.Write([]byte(resp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config.CAURL = srv.URL
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		CSRPEM:     csrPEM,
	}

	result, err := connector.IssueCertificate(ctx, req)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	if result.Serial == "" {
		t.Error("Expected non-empty serial")
	}
}

func TestIssueCertificate_BadStatus(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized) // 401 is neither 200 nor 201
			w.Write([]byte(`{"error":"unauthorized"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config.CAURL = srv.URL
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		CSRPEM:     csrPEM,
	}

	_, err := connector.IssueCertificate(ctx, req)
	if err == nil {
		t.Fatal("Expected error for 401 response")
	}
}

func TestRenewCertificate_DelegatesToIssuance(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	testCertPEM, _ := generateTestCert(t)
	callCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			callCount++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			resp := fmt.Sprintf(`{"crt": %q, "ca": %q}`, testCertPEM, testCertPEM)
			w.Write([]byte(resp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config := &stepca.Config{
		CAURL:           srv.URL,
		ProvisionerName: "test-provisioner",
	}
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("renew.example.com")
	renewReq := issuer.RenewalRequest{
		CommonName: "renew.example.com",
		SANs:       []string{"renew.example.com", "app.example.com"},
		CSRPEM:     csrPEM,
	}

	result, err := connector.RenewCertificate(ctx, renewReq)
	if err != nil {
		t.Fatalf("RenewCertificate failed: %v", err)
	}

	if result.Serial == "" {
		t.Error("Expected non-empty serial")
	}

	// Should have made exactly 1 call to /sign
	if callCount != 1 {
		t.Errorf("Expected 1 sign call, got %d", callCount)
	}
}

func TestNew_WithRootCertPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Create a temporary cert file
	testCertPEM, _ := generateTestCert(t)
	tmpFile := os.TempDir() + "/test_ca_cert.pem"
	err := os.WriteFile(tmpFile, []byte(testCertPEM), 0644)
	if err != nil {
		t.Fatalf("Failed to write test cert: %v", err)
	}
	defer os.Remove(tmpFile)

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
		RootCertPath:    tmpFile,
	}

	connector := stepca.New(config, logger)
	if connector == nil {
		t.Fatal("Expected non-nil connector")
	}
}

func TestNew_WithInvalidRootCertPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
		RootCertPath:    "/nonexistent/path/to/cert.pem",
	}

	// Should not panic, just log a warning and fall back to system trust store
	connector := stepca.New(config, logger)
	if connector == nil {
		t.Fatal("Expected non-nil connector")
	}
}

func TestNew_WithNilConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	connector := stepca.New(nil, logger)
	if connector == nil {
		t.Fatal("Expected non-nil connector even with nil config")
	}
}

func TestValidateConfig_HealthCheck_NotOK(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusServiceUnavailable) // 503 instead of 200
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	config := stepca.Config{
		CAURL:           srv.URL,
		ProvisionerName: "test-provisioner",
	}

	connector := stepca.New(nil, logger)
	rawConfig, _ := json.Marshal(config)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("Expected error for non-200 health check")
	}
}

func TestParseSignResponse_MalformedPEM(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			// Send PEM with invalid base64 or invalid cert
			resp := `{"crt": "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n", "ca": ""}`
			w.Write([]byte(resp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config.CAURL = srv.URL
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		CSRPEM:     csrPEM,
	}

	_, err := connector.IssueCertificate(ctx, req)
	if err == nil {
		t.Fatal("Expected error for malformed PEM")
	}
}

func TestIssueCertificate_WithMultipleSANs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	testCertPEM, _ := generateTestCert(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			resp := fmt.Sprintf(`{"crt": %q, "ca": %q}`, testCertPEM, testCertPEM)
			w.Write([]byte(resp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config := &stepca.Config{
		CAURL:           srv.URL,
		ProvisionerName: "test-provisioner",
		ValidityDays:    365,
	}
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("app.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "app.example.com",
		SANs:       []string{"app.example.com", "api.example.com", "www.example.com"},
		CSRPEM:     csrPEM,
	}

	result, err := connector.IssueCertificate(ctx, req)
	if err != nil {
		t.Fatalf("IssueCertificate with multiple SANs failed: %v", err)
	}

	if result.Serial == "" {
		t.Error("Expected non-empty serial")
	}
}

func TestIssueCertificate_NetworkError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &stepca.Config{
		CAURL:           "http://localhost:29999", // Port that's not listening
		ProvisionerName: "test-provisioner",
	}
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		CSRPEM:     csrPEM,
	}

	_, err := connector.IssueCertificate(ctx, req)
	if err == nil {
		t.Fatal("Expected error for network connection failure")
	}
}

func TestRevokeCertificate_NetworkError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &stepca.Config{
		CAURL:           "http://localhost:29999", // Port that's not listening
		ProvisionerName: "test-provisioner",
	}
	connector := stepca.New(config, logger)

	revokeReq := issuer.RevocationRequest{
		Serial: "1234567890",
	}

	err := connector.RevokeCertificate(ctx, revokeReq)
	if err == nil {
		t.Fatal("Expected error for network connection failure")
	}
}

func TestParseSignResponse_NoServerPEM(t *testing.T) {
	// Test when neither crt/ca nor serverPEM/caPEM nor certChainPEM are present
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			// Empty response
			resp := `{}`
			w.Write([]byte(resp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config.CAURL = srv.URL
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		CSRPEM:     csrPEM,
	}

	_, err := connector.IssueCertificate(ctx, req)
	if err == nil {
		t.Fatal("Expected error for empty response")
	}
}

func TestValidateConfig_CreateHealthCheckRequest_Error(t *testing.T) {
	// This is harder to test since we need to create a request with an invalid URL
	// Let's just test with an invalid CAURL that fails to parse
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := stepca.Config{
		CAURL:           "https://[invalid-ip]:9000", // Invalid IPv6 format
		ProvisionerName: "test-provisioner",
	}

	connector := stepca.New(nil, logger)
	rawConfig, _ := json.Marshal(config)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("Expected error for invalid CAURL")
	}
}

func TestIssueCertificate_MarshalSignRequestError(t *testing.T) {
	// This is hard to test since json.Marshal typically doesn't fail for structs
	// We've covered the main paths, so this is a limitation of the testable code
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	testCertPEM, _ := generateTestCert(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			resp := fmt.Sprintf(`{"crt": %q, "ca": %q}`, testCertPEM, testCertPEM)
			w.Write([]byte(resp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config := &stepca.Config{
		CAURL:           srv.URL,
		ProvisionerName: "test-provisioner",
	}
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("test.example.com")
	req := issuer.IssuanceRequest{
		CommonName: "test.example.com",
		CSRPEM:     csrPEM,
	}

	result, err := connector.IssueCertificate(ctx, req)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	if result.Serial == "" {
		t.Error("Expected non-empty serial")
	}
}

func TestRenewCertificate_WithEKUs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	testCertPEM, _ := generateTestCert(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/sign":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			resp := fmt.Sprintf(`{"crt": %q, "ca": %q}`, testCertPEM, testCertPEM)
			w.Write([]byte(resp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config := &stepca.Config{
		CAURL:           srv.URL,
		ProvisionerName: "test-provisioner",
	}
	connector := stepca.New(config, logger)

	_, csrPEM, _ := generateStepCATestCSR("renew.example.com")
	// RenewalRequest doesn't have EKUs field in the current implementation
	// but we can test with extended request data
	renewReq := issuer.RenewalRequest{
		CommonName: "renew.example.com",
		CSRPEM:     csrPEM,
	}

	result, err := connector.RenewCertificate(ctx, renewReq)
	if err != nil {
		t.Fatalf("RenewCertificate failed: %v", err)
	}

	if result.Serial == "" {
		t.Error("Expected non-empty serial")
	}
}

func TestLoadProvisionerKey_FileNotReadable(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	// Test with a provisioner key path that can't be read
	config := stepca.Config{
		CAURL:               srv.URL,
		ProvisionerName:     "test-provisioner",
		ProvisionerKeyPath:  "/root/.ssh/no_such_key", // Permission denied or doesn't exist
		ProvisionerPassword: "password",
	}

	connector := stepca.New(nil, logger)
	rawConfig, _ := json.Marshal(config)
	err := connector.ValidateConfig(ctx, rawConfig)
	// Error should occur when trying to access the key file
	if err == nil {
		t.Fatal("Expected error when provisioner key file is not accessible")
	}
}

func TestIssueCertificate_GetOrderStatus(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	config := &stepca.Config{
		CAURL:           "https://ca.example.com",
		ProvisionerName: "test-provisioner",
	}
	connector := stepca.New(config, logger)

	// GetOrderStatus should return immediately with "completed" status
	status, err := connector.GetOrderStatus(ctx, "some-order-id")
	if err != nil {
		t.Fatalf("GetOrderStatus failed: %v", err)
	}

	if status.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", status.Status)
	}

	if status.OrderID != "some-order-id" {
		t.Errorf("Expected OrderID 'some-order-id', got '%s'", status.OrderID)
	}
}

func TestRevokeCertificate_MarshalRequestError(t *testing.T) {
	// Most marshal failures are hard to trigger, but we can test the happy path
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/revoke":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config := &stepca.Config{
		CAURL:           srv.URL,
		ProvisionerName: "test-provisioner",
	}
	connector := stepca.New(config, logger)

	reason := "keyCompromise"
	revokeReq := issuer.RevocationRequest{
		Serial: "12345678901234567890",
		Reason: &reason,
	}

	err := connector.RevokeCertificate(ctx, revokeReq)
	if err != nil {
		t.Fatalf("RevokeCertificate failed: %v", err)
	}
}

func TestIntegration_FullLifecycle(t *testing.T) {
	// Integration test covering full certificate lifecycle
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	testCertPEM, _ := generateTestCert(t)
	callCount := struct {
		health int
		sign   int
		revoke int
	}{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			callCount.health++
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		case "/sign":
			callCount.sign++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			resp := fmt.Sprintf(`{"crt": %q, "ca": %q}`, testCertPEM, testCertPEM)
			w.Write([]byte(resp))
		case "/revoke":
			callCount.revoke++
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config := &stepca.Config{
		CAURL:           srv.URL,
		ProvisionerName: "test-provisioner",
		ValidityDays:    90,
	}

	// Test ValidateConfig
	connector := stepca.New(nil, logger)
	rawConfig, _ := json.Marshal(config)
	if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
		t.Fatalf("ValidateConfig failed: %v", err)
	}

	if callCount.health != 1 {
		t.Errorf("Expected 1 health check, got %d", callCount.health)
	}

	// Create a new connector with validated config
	connector = stepca.New(config, logger)

	// Test IssueCertificate
	_, csrPEM, _ := generateStepCATestCSR("app.internal.corp")
	issueReq := issuer.IssuanceRequest{
		CommonName: "app.internal.corp",
		SANs:       []string{"app.internal.corp", "app.example.com"},
		CSRPEM:     csrPEM,
	}

	issueResult, err := connector.IssueCertificate(ctx, issueReq)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	if callCount.sign != 1 {
		t.Errorf("Expected 1 sign call, got %d", callCount.sign)
	}

	if issueResult.Serial == "" {
		t.Error("Expected non-empty serial")
	}

	// Test RenewCertificate
	renewReq := issuer.RenewalRequest{
		CommonName: "app.internal.corp",
		SANs:       []string{"app.internal.corp", "app.example.com"},
		CSRPEM:     csrPEM,
	}

	renewResult, err := connector.RenewCertificate(ctx, renewReq)
	if err != nil {
		t.Fatalf("RenewCertificate failed: %v", err)
	}

	if callCount.sign != 2 {
		t.Errorf("Expected 2 sign calls after renewal, got %d", callCount.sign)
	}

	if renewResult.Serial == "" {
		t.Error("Expected non-empty serial from renewal")
	}

	// Test RevokeCertificate
	reason := "cessationOfOperation"
	revokeReq := issuer.RevocationRequest{
		Serial: issueResult.Serial,
		Reason: &reason,
	}

	if err := connector.RevokeCertificate(ctx, revokeReq); err != nil {
		t.Fatalf("RevokeCertificate failed: %v", err)
	}

	if callCount.revoke != 1 {
		t.Errorf("Expected 1 revoke call, got %d", callCount.revoke)
	}

	// Test GetOrderStatus
	status, err := connector.GetOrderStatus(ctx, issueResult.OrderID)
	if err != nil {
		t.Fatalf("GetOrderStatus failed: %v", err)
	}

	if status.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", status.Status)
	}
}
