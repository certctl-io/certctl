package openssl_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/connector/issuer/openssl"
)

func TestOpenSSLConnector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Test 1: ValidateConfig with valid config
	t.Run("ValidateConfig_Success", func(t *testing.T) {
		// Create a temporary directory for script files
		tmpDir := t.TempDir()

		// Create a minimal sign script
		signScript := filepath.Join(tmpDir, "sign.sh")
		if err := os.WriteFile(signScript, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatalf("Failed to create sign script: %v", err)
		}

		config := &openssl.Config{
			SignScript:     signScript,
			TimeoutSeconds: 30,
		}
		connector := openssl.New(config, logger)

		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
	})

	// Test 2: ValidateConfig with missing sign_script
	t.Run("ValidateConfig_MissingSignScript", func(t *testing.T) {
		config := &openssl.Config{
			SignScript: "",
		}
		connector := openssl.New(config, logger)

		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for missing sign_script, got nil")
		}
	})

	// Test 3: ValidateConfig with nonexistent script path
	t.Run("ValidateConfig_NonexistentScript", func(t *testing.T) {
		config := &openssl.Config{
			SignScript: "/nonexistent/path/to/sign.sh",
		}
		connector := openssl.New(config, logger)

		rawConfig, _ := json.Marshal(config)
		err := connector.ValidateConfig(ctx, rawConfig)
		if err == nil {
			t.Fatal("Expected error for nonexistent script, got nil")
		}
	})

	// Test 4: IssueCertificate with a real test CSR and mock sign script
	t.Run("IssueCertificate_Success", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a mock sign script that creates a self-signed cert from CSR
		signScript := filepath.Join(tmpDir, "sign.sh")
		mockCertPEM := generateMockCertPEM()
		scriptContent := "#!/bin/sh\n" +
			"CSR_FILE=\"$1\"\n" +
			"CERT_FILE=\"$2\"\n" +
			"cat > \"$CERT_FILE\" << 'EOF'\n" + mockCertPEM + "\nEOF\n" +
			"exit 0\n"
		if err := os.WriteFile(signScript, []byte(scriptContent), 0755); err != nil {
			t.Fatalf("Failed to create sign script: %v", err)
		}

		config := &openssl.Config{
			SignScript:     signScript,
			TimeoutSeconds: 30,
		}
		connector := openssl.New(config, logger)

		// Validate config first
		rawConfig, _ := json.Marshal(config)
		if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}

		// Generate test CSR
		csr, csrPEM, err := generateTestCSR("test.example.com")
		if err != nil {
			t.Fatalf("Failed to generate CSR: %v", err)
		}

		req := issuer.IssuanceRequest{
			CommonName: csr.Subject.CommonName,
			SANs:       []string{"www.test.example.com"},
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err != nil {
			t.Fatalf("IssueCertificate failed: %v", err)
		}

		if result.Serial == "" {
			t.Error("Serial is empty")
		}
		if result.CertPEM == "" {
			t.Error("CertPEM is empty")
		}
		if result.OrderID == "" {
			t.Error("OrderID is empty")
		}
		if result.NotAfter.IsZero() {
			t.Error("NotAfter is zero")
		}

		t.Logf("Certificate issued: serial=%s, orderID=%s", result.Serial, result.OrderID)
	})

	// Test 5: IssueCertificate with sign script failure
	t.Run("IssueCertificate_SignScriptFailure", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a sign script that fails
		signScript := filepath.Join(tmpDir, "sign.sh")
		if err := os.WriteFile(signScript, []byte("#!/bin/sh\nexit 1"), 0755); err != nil {
			t.Fatalf("Failed to create sign script: %v", err)
		}

		config := &openssl.Config{
			SignScript:     signScript,
			TimeoutSeconds: 30,
		}
		connector := openssl.New(config, logger)

		rawConfig, _ := json.Marshal(config)
		if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}

		csr, csrPEM, err := generateTestCSR("test.example.com")
		if err != nil {
			t.Fatalf("Failed to generate CSR: %v", err)
		}

		req := issuer.IssuanceRequest{
			CommonName: csr.Subject.CommonName,
			SANs:       []string{"www.test.example.com"},
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected error from failing sign script, got nil")
		}
		if result != nil {
			t.Error("Expected result to be nil on error")
		}
	})

	// Test 6: IssueCertificate with timeout
	t.Run("IssueCertificate_SignScriptTimeout", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a sign script that takes too long
		signScript := filepath.Join(tmpDir, "sign.sh")
		if err := os.WriteFile(signScript, []byte("#!/bin/sh\nsleep 10\nexit 0"), 0755); err != nil {
			t.Fatalf("Failed to create sign script: %v", err)
		}

		config := &openssl.Config{
			SignScript:     signScript,
			TimeoutSeconds: 1, // 1 second timeout
		}
		connector := openssl.New(config, logger)

		rawConfig, _ := json.Marshal(config)
		if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}

		csr, csrPEM, err := generateTestCSR("test.example.com")
		if err != nil {
			t.Fatalf("Failed to generate CSR: %v", err)
		}

		req := issuer.IssuanceRequest{
			CommonName: csr.Subject.CommonName,
			SANs:       []string{"www.test.example.com"},
			CSRPEM:     csrPEM,
		}

		result, err := connector.IssueCertificate(ctx, req)
		if err == nil {
			t.Fatal("Expected timeout error, got nil")
		}
		if result != nil {
			t.Error("Expected result to be nil on timeout")
		}
	})

	// Test 7: RenewCertificate delegates to IssueCertificate
	t.Run("RenewCertificate_Success", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a mock sign script
		signScript := filepath.Join(tmpDir, "sign.sh")
		mockCertPEM := generateMockCertPEM()
		scriptContent := "#!/bin/sh\n" +
			"CSR_FILE=\"$1\"\n" +
			"CERT_FILE=\"$2\"\n" +
			"cat > \"$CERT_FILE\" << 'EOF'\n" + mockCertPEM + "\nEOF\n" +
			"exit 0\n"
		if err := os.WriteFile(signScript, []byte(scriptContent), 0755); err != nil {
			t.Fatalf("Failed to create sign script: %v", err)
		}

		config := &openssl.Config{
			SignScript:     signScript,
			TimeoutSeconds: 30,
		}
		connector := openssl.New(config, logger)

		rawConfig, _ := json.Marshal(config)
		if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}

		csr, csrPEM, err := generateTestCSR("test.example.com")
		if err != nil {
			t.Fatalf("Failed to generate CSR: %v", err)
		}

		renewReq := issuer.RenewalRequest{
			CommonName: csr.Subject.CommonName,
			SANs:       []string{"www.test.example.com"},
			CSRPEM:     csrPEM,
		}

		result, err := connector.RenewCertificate(ctx, renewReq)
		if err != nil {
			t.Fatalf("RenewCertificate failed: %v", err)
		}

		if result.Serial == "" {
			t.Error("Serial is empty")
		}

		t.Logf("Certificate renewed: serial=%s", result.Serial)
	})

	// Test 8: RevokeCertificate without revoke script configured
	t.Run("RevokeCertificate_NoScript", func(t *testing.T) {
		tmpDir := t.TempDir()

		signScript := filepath.Join(tmpDir, "sign.sh")
		if err := os.WriteFile(signScript, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatalf("Failed to create sign script: %v", err)
		}

		config := &openssl.Config{
			SignScript: signScript,
			// RevokeScript not set
		}
		connector := openssl.New(config, logger)

		rawConfig, _ := json.Marshal(config)
		if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}

		revokeReq := issuer.RevocationRequest{
			Serial: "ABCDEF1234567890",
		}

		// Should return nil (no-op) when revoke script not configured
		err := connector.RevokeCertificate(ctx, revokeReq)
		if err != nil {
			t.Fatalf("RevokeCertificate failed: %v", err)
		}
	})

	// Test 9: RevokeCertificate with revoke script
	t.Run("RevokeCertificate_WithScript", func(t *testing.T) {
		tmpDir := t.TempDir()

		signScript := filepath.Join(tmpDir, "sign.sh")
		if err := os.WriteFile(signScript, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatalf("Failed to create sign script: %v", err)
		}

		revokeScript := filepath.Join(tmpDir, "revoke.sh")
		if err := os.WriteFile(revokeScript, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatalf("Failed to create revoke script: %v", err)
		}

		config := &openssl.Config{
			SignScript:   signScript,
			RevokeScript: revokeScript,
		}
		connector := openssl.New(config, logger)

		rawConfig, _ := json.Marshal(config)
		if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}

		reason := "keyCompromise"
		revokeReq := issuer.RevocationRequest{
			Serial: "ABCDEF1234567890",
			Reason: &reason,
		}

		err := connector.RevokeCertificate(ctx, revokeReq)
		if err != nil {
			t.Fatalf("RevokeCertificate failed: %v", err)
		}
	})

	// Test 15: RevokeCertificate rejects injection payloads in serial number
	t.Run("RevokeCertificate_InjectionSerial", func(t *testing.T) {
		tmpDir := t.TempDir()

		signScript := filepath.Join(tmpDir, "sign.sh")
		if err := os.WriteFile(signScript, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatalf("Failed to create sign script: %v", err)
		}
		revokeScript := filepath.Join(tmpDir, "revoke.sh")
		if err := os.WriteFile(revokeScript, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatalf("Failed to create revoke script: %v", err)
		}

		config := &openssl.Config{
			SignScript:   signScript,
			RevokeScript: revokeScript,
		}
		connector := openssl.New(config, logger)
		rawConfig, _ := json.Marshal(config)
		if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}

		injectionPayloads := []string{
			"1234;rm -rf /",
			"1234|cat /etc/passwd",
			"1234&whoami",
			"$(id)",
			"`id`",
			"1234\nid",
			"../../../etc/passwd",
			"test-serial-12345", // hyphens not allowed (not hex)
		}

		for _, payload := range injectionPayloads {
			t.Run(payload, func(t *testing.T) {
				req := issuer.RevocationRequest{Serial: payload}
				err := connector.RevokeCertificate(ctx, req)
				if err == nil {
					t.Errorf("Expected injection payload %q to be rejected, but it was accepted", payload)
				}
			})
		}
	})

	// Test 16: RevokeCertificate rejects invalid reason codes
	t.Run("RevokeCertificate_InvalidReason", func(t *testing.T) {
		tmpDir := t.TempDir()

		signScript := filepath.Join(tmpDir, "sign.sh")
		if err := os.WriteFile(signScript, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatalf("Failed to create sign script: %v", err)
		}
		revokeScript := filepath.Join(tmpDir, "revoke.sh")
		if err := os.WriteFile(revokeScript, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatalf("Failed to create revoke script: %v", err)
		}

		config := &openssl.Config{
			SignScript:   signScript,
			RevokeScript: revokeScript,
		}
		connector := openssl.New(config, logger)
		rawConfig, _ := json.Marshal(config)
		if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}

		invalidReasons := []string{
			"notARealReason",
			"keyCompromise;rm -rf /",
			"$(whoami)",
			"`id`",
		}

		for _, reason := range invalidReasons {
			t.Run(reason, func(t *testing.T) {
				r := reason
				req := issuer.RevocationRequest{
					Serial: "ABCDEF1234567890",
					Reason: &r,
				}
				err := connector.RevokeCertificate(ctx, req)
				if err == nil {
					t.Errorf("Expected invalid reason %q to be rejected, but it was accepted", reason)
				}
			})
		}
	})

	// Test 17: RevokeCertificate accepts all valid RFC 5280 reason codes
	t.Run("RevokeCertificate_ValidReasons", func(t *testing.T) {
		tmpDir := t.TempDir()

		signScript := filepath.Join(tmpDir, "sign.sh")
		if err := os.WriteFile(signScript, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatalf("Failed to create sign script: %v", err)
		}
		revokeScript := filepath.Join(tmpDir, "revoke.sh")
		if err := os.WriteFile(revokeScript, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatalf("Failed to create revoke script: %v", err)
		}

		config := &openssl.Config{
			SignScript:   signScript,
			RevokeScript: revokeScript,
		}
		connector := openssl.New(config, logger)
		rawConfig, _ := json.Marshal(config)
		if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}

		validReasons := []string{
			"unspecified", "keyCompromise", "caCompromise", "affiliationChanged",
			"superseded", "cessationOfOperation", "certificateHold", "privilegeWithdrawn",
		}

		for _, reason := range validReasons {
			t.Run(reason, func(t *testing.T) {
				r := reason
				req := issuer.RevocationRequest{
					Serial: "ABCDEF1234567890",
					Reason: &r,
				}
				err := connector.RevokeCertificate(ctx, req)
				if err != nil {
					t.Errorf("Expected valid reason %q to be accepted, got error: %v", reason, err)
				}
			})
		}
	})

	// Test 10: GetOrderStatus always returns "completed"
	t.Run("GetOrderStatus", func(t *testing.T) {
		tmpDir := t.TempDir()

		signScript := filepath.Join(tmpDir, "sign.sh")
		if err := os.WriteFile(signScript, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatalf("Failed to create sign script: %v", err)
		}

		config := &openssl.Config{
			SignScript: signScript,
		}
		connector := openssl.New(config, logger)

		rawConfig, _ := json.Marshal(config)
		if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}

		status, err := connector.GetOrderStatus(ctx, "openssl-12345")
		if err != nil {
			t.Fatalf("GetOrderStatus failed: %v", err)
		}

		if status.Status != "completed" {
			t.Errorf("Expected status 'completed', got '%s'", status.Status)
		}

		t.Logf("Order status: %s", status.Status)
	})

	// Test 11: GenerateCRL without CRL script configured
	t.Run("GenerateCRL_NoScript", func(t *testing.T) {
		tmpDir := t.TempDir()

		signScript := filepath.Join(tmpDir, "sign.sh")
		if err := os.WriteFile(signScript, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatalf("Failed to create sign script: %v", err)
		}

		config := &openssl.Config{
			SignScript: signScript,
			// CRLScript not set
		}
		connector := openssl.New(config, logger)

		rawConfig, _ := json.Marshal(config)
		if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}

		crl, err := connector.GenerateCRL(ctx, []issuer.RevokedCertEntry{})
		if err != nil {
			t.Fatalf("GenerateCRL failed: %v", err)
		}

		// Should return nil when CRL script not configured
		if crl != nil {
			t.Error("Expected nil CRL when CRL script not configured")
		}
	})

	// Test 12: GenerateCRL with CRL script
	t.Run("GenerateCRL_WithScript", func(t *testing.T) {
		tmpDir := t.TempDir()

		signScript := filepath.Join(tmpDir, "sign.sh")
		if err := os.WriteFile(signScript, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatalf("Failed to create sign script: %v", err)
		}

		crlScript := filepath.Join(tmpDir, "crl.sh")
		scriptContent := "#!/bin/sh\n" +
			"SERIALS_FILE=\"$1\"\n" +
			"CRL_FILE=\"$2\"\n" +
			"echo 'test-crl-content' > \"$CRL_FILE\"\n" +
			"exit 0\n"
		if err := os.WriteFile(crlScript, []byte(scriptContent), 0755); err != nil {
			t.Fatalf("Failed to create CRL script: %v", err)
		}

		config := &openssl.Config{
			SignScript: signScript,
			CRLScript:  crlScript,
		}
		connector := openssl.New(config, logger)

		rawConfig, _ := json.Marshal(config)
		if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}

		crl, err := connector.GenerateCRL(ctx, []issuer.RevokedCertEntry{})
		if err != nil {
			t.Fatalf("GenerateCRL failed: %v", err)
		}

		if crl == nil {
			t.Error("Expected CRL, got nil")
		}
		if len(crl) == 0 {
			t.Error("Expected non-empty CRL")
		}
	})

	// Test 13: SignOCSPResponse returns nil (not supported)
	t.Run("SignOCSPResponse_NotSupported", func(t *testing.T) {
		tmpDir := t.TempDir()

		signScript := filepath.Join(tmpDir, "sign.sh")
		if err := os.WriteFile(signScript, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatalf("Failed to create sign script: %v", err)
		}

		config := &openssl.Config{
			SignScript: signScript,
		}
		connector := openssl.New(config, logger)

		rawConfig, _ := json.Marshal(config)
		if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}

		resp, err := connector.SignOCSPResponse(ctx, issuer.OCSPSignRequest{})
		if err != nil {
			t.Fatalf("SignOCSPResponse failed: %v", err)
		}

		if resp != nil {
			t.Error("Expected nil OCSP response (not supported)")
		}
	})

	// Test 14: Default timeout
	t.Run("DefaultTimeout", func(t *testing.T) {
		tmpDir := t.TempDir()

		signScript := filepath.Join(tmpDir, "sign.sh")
		if err := os.WriteFile(signScript, []byte("#!/bin/sh\nexit 0"), 0755); err != nil {
			t.Fatalf("Failed to create sign script: %v", err)
		}

		config := &openssl.Config{
			SignScript:     signScript,
			TimeoutSeconds: 0, // Should default to 30
		}
		connector := openssl.New(config, logger)

		rawConfig, _ := json.Marshal(config)
		if err := connector.ValidateConfig(ctx, rawConfig); err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}

		// If timeout is 30 seconds, the config should validate without errors
		// (we can't easily test the actual timeout value without accessing private fields)
		t.Log("Default timeout configured (should be 30 seconds)")
	})
}

// --- Test Helpers ---

// generateTestCSR creates a test Certificate Signing Request.
func generateTestCSR(cn string) (*x509.CertificateRequest, string, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}

	subject := pkix.Name{
		CommonName: cn,
	}

	csrTemplate := x509.CertificateRequest{
		Subject: subject,
		DNSNames: []string{cn, "www." + cn},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privKey)
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

// generateMockCertPEM creates a self-signed certificate for testing.
func generateMockCertPEM() string {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	serialNumber := big.NewInt(1234567890)
	subject := pkix.Name{
		CommonName: "test.example.com",
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 90),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.example.com", "www.test.example.com"},
	}

	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, privKey.Public(), privKey)

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}))
}

// Security tests for script path validation

func TestOpenSSLConnector_ValidateConfig_RejectNonRegularFile(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Try to use a directory as a script path
	tmpDir := t.TempDir()

	config := &openssl.Config{
		SignScript: tmpDir, // This is a directory, not a regular file
	}
	connector := openssl.New(config, logger)

	rawConfig, _ := json.Marshal(config)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("Expected error when sign_script is not a regular file")
	}
}

func TestOpenSSLConnector_ValidateConfig_ValidateRevokeScriptPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	signScript := filepath.Join(tmpDir, "sign.sh")
	os.WriteFile(signScript, []byte("#!/bin/sh\nexit 0"), 0755)

	// Try to use a nonexistent file as revoke_script
	config := &openssl.Config{
		SignScript:   signScript,
		RevokeScript: "/nonexistent/revoke.sh",
	}
	connector := openssl.New(config, logger)

	rawConfig, _ := json.Marshal(config)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("Expected error when revoke_script is nonexistent")
	}
}

func TestOpenSSLConnector_ValidateConfig_ValidateCRLScriptPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	tmpDir := t.TempDir()
	signScript := filepath.Join(tmpDir, "sign.sh")
	os.WriteFile(signScript, []byte("#!/bin/sh\nexit 0"), 0755)

	// Try to use a directory as crl_script
	config := &openssl.Config{
		SignScript: signScript,
		CRLScript:  tmpDir, // This is a directory, not a regular file
	}
	connector := openssl.New(config, logger)

	rawConfig, _ := json.Marshal(config)
	err := connector.ValidateConfig(ctx, rawConfig)
	if err == nil {
		t.Fatal("Expected error when crl_script is not a regular file")
	}
}
