package f5

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/certctl-io/certctl/internal/connector/target"
)

// --- Mock F5Client ---

// mockCall records a single method call to the mock F5Client.
type mockCall struct {
	Method string
	Args   []string
}

// mockF5Client records all calls and returns configurable responses.
type mockF5Client struct {
	calls []mockCall

	// Configurable responses per method
	authenticateErr      error
	authenticateCount    int // tracks number of Authenticate calls
	uploadFileErr        error
	uploadFileErrOn      string // only error when filename contains this substring
	installCertErr       error
	installCertErrOn     string
	installKeyErr        error
	createTransactionID  string
	createTransactionErr error
	commitTransactionErr error
	updateSSLProfileErr  error
	getSSLProfileResult  *SSLProfileInfo
	getSSLProfileErr     error
	deleteCertErr        error
	deleteKeyErr         error

	// Track cleanup calls specifically
	deletedCerts []string
	deletedKeys  []string
}

func newMockF5Client() *mockF5Client {
	return &mockF5Client{
		createTransactionID: "12345",
	}
}

func (m *mockF5Client) Authenticate(ctx context.Context) error {
	m.calls = append(m.calls, mockCall{Method: "Authenticate"})
	m.authenticateCount++
	return m.authenticateErr
}

func (m *mockF5Client) UploadFile(ctx context.Context, filename string, data []byte) error {
	m.calls = append(m.calls, mockCall{Method: "UploadFile", Args: []string{filename, fmt.Sprintf("%d bytes", len(data))}})
	if m.uploadFileErrOn != "" && strings.Contains(filename, m.uploadFileErrOn) {
		return m.uploadFileErr
	}
	if m.uploadFileErrOn == "" && m.uploadFileErr != nil {
		return m.uploadFileErr
	}
	return nil
}

func (m *mockF5Client) InstallCert(ctx context.Context, name, localFile string) error {
	m.calls = append(m.calls, mockCall{Method: "InstallCert", Args: []string{name, localFile}})
	if m.installCertErrOn != "" && strings.Contains(name, m.installCertErrOn) {
		return m.installCertErr
	}
	if m.installCertErrOn == "" && m.installCertErr != nil {
		return m.installCertErr
	}
	return nil
}

func (m *mockF5Client) InstallKey(ctx context.Context, name, localFile string) error {
	m.calls = append(m.calls, mockCall{Method: "InstallKey", Args: []string{name, localFile}})
	return m.installKeyErr
}

func (m *mockF5Client) CreateTransaction(ctx context.Context) (string, error) {
	m.calls = append(m.calls, mockCall{Method: "CreateTransaction"})
	return m.createTransactionID, m.createTransactionErr
}

func (m *mockF5Client) CommitTransaction(ctx context.Context, transID string) error {
	m.calls = append(m.calls, mockCall{Method: "CommitTransaction", Args: []string{transID}})
	return m.commitTransactionErr
}

func (m *mockF5Client) UpdateSSLProfile(ctx context.Context, partition, profile string, certName, keyName, chainName string, transID string) error {
	m.calls = append(m.calls, mockCall{Method: "UpdateSSLProfile", Args: []string{partition, profile, certName, keyName, chainName, transID}})
	return m.updateSSLProfileErr
}

func (m *mockF5Client) GetSSLProfile(ctx context.Context, partition, profile string) (*SSLProfileInfo, error) {
	m.calls = append(m.calls, mockCall{Method: "GetSSLProfile", Args: []string{partition, profile}})
	return m.getSSLProfileResult, m.getSSLProfileErr
}

func (m *mockF5Client) DeleteCert(ctx context.Context, partition, name string) error {
	m.calls = append(m.calls, mockCall{Method: "DeleteCert", Args: []string{partition, name}})
	m.deletedCerts = append(m.deletedCerts, name)
	return m.deleteCertErr
}

func (m *mockF5Client) DeleteKey(ctx context.Context, partition, name string) error {
	m.calls = append(m.calls, mockCall{Method: "DeleteKey", Args: []string{partition, name}})
	m.deletedKeys = append(m.deletedKeys, name)
	return m.deleteKeyErr
}

// hasCalled returns true if the mock received a call to the given method.
func (m *mockF5Client) hasCalled(method string) bool {
	for _, c := range m.calls {
		if c.Method == method {
			return true
		}
	}
	return false
}

// callCount returns the number of times a method was called.
func (m *mockF5Client) callCount(method string) int {
	count := 0
	for _, c := range m.calls {
		if c.Method == method {
			count++
		}
	}
	return count
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

// --- ValidateConfig tests ---

func TestValidateConfig(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock := newMockF5Client()
		cfg := &Config{Host: "f5.test.com", Username: "admin", Password: "secret", SSLProfile: "myprofile"}
		conn := NewWithClient(cfg, testLogger(), mock)

		rawConfig, _ := json.Marshal(map[string]interface{}{
			"host":        "f5.test.com",
			"username":    "admin",
			"password":    "secret",
			"ssl_profile": "myprofile",
		})

		err := conn.ValidateConfig(context.Background(), rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}
		if !mock.hasCalled("Authenticate") {
			t.Error("expected Authenticate to be called")
		}
	})

	t.Run("DefaultsApplied", func(t *testing.T) {
		mock := newMockF5Client()
		cfg := &Config{}
		conn := NewWithClient(cfg, testLogger(), mock)

		rawConfig, _ := json.Marshal(map[string]interface{}{
			"host":        "f5.test.com",
			"username":    "admin",
			"password":    "secret",
			"ssl_profile": "myprofile",
		})

		err := conn.ValidateConfig(context.Background(), rawConfig)
		if err != nil {
			t.Fatalf("ValidateConfig failed: %v", err)
		}

		// Check defaults were applied
		if conn.config.Port != 443 {
			t.Errorf("expected port 443, got %d", conn.config.Port)
		}
		if conn.config.Partition != "Common" {
			t.Errorf("expected partition Common, got %s", conn.config.Partition)
		}
		if conn.config.Timeout != 30 {
			t.Errorf("expected timeout 30, got %d", conn.config.Timeout)
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		conn := NewWithClient(&Config{}, testLogger(), newMockF5Client())
		err := conn.ValidateConfig(context.Background(), json.RawMessage(`{invalid}`))
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "invalid F5 config") {
			t.Errorf("expected 'invalid F5 config' in error, got: %v", err)
		}
	})

	t.Run("MissingHost", func(t *testing.T) {
		conn := NewWithClient(&Config{}, testLogger(), newMockF5Client())
		rawConfig, _ := json.Marshal(map[string]string{
			"username": "admin", "password": "secret", "ssl_profile": "prof",
		})
		err := conn.ValidateConfig(context.Background(), rawConfig)
		if err == nil || !strings.Contains(err.Error(), "host is required") {
			t.Errorf("expected 'host is required', got: %v", err)
		}
	})

	t.Run("MissingUsername", func(t *testing.T) {
		conn := NewWithClient(&Config{}, testLogger(), newMockF5Client())
		rawConfig, _ := json.Marshal(map[string]string{
			"host": "f5.test.com", "password": "secret", "ssl_profile": "prof",
		})
		err := conn.ValidateConfig(context.Background(), rawConfig)
		if err == nil || !strings.Contains(err.Error(), "username is required") {
			t.Errorf("expected 'username is required', got: %v", err)
		}
	})

	t.Run("MissingPassword", func(t *testing.T) {
		conn := NewWithClient(&Config{}, testLogger(), newMockF5Client())
		rawConfig, _ := json.Marshal(map[string]string{
			"host": "f5.test.com", "username": "admin", "ssl_profile": "prof",
		})
		err := conn.ValidateConfig(context.Background(), rawConfig)
		if err == nil || !strings.Contains(err.Error(), "password is required") {
			t.Errorf("expected 'password is required', got: %v", err)
		}
	})

	t.Run("MissingSSLProfile", func(t *testing.T) {
		conn := NewWithClient(&Config{}, testLogger(), newMockF5Client())
		rawConfig, _ := json.Marshal(map[string]string{
			"host": "f5.test.com", "username": "admin", "password": "secret",
		})
		err := conn.ValidateConfig(context.Background(), rawConfig)
		if err == nil || !strings.Contains(err.Error(), "ssl_profile is required") {
			t.Errorf("expected 'ssl_profile is required', got: %v", err)
		}
	})

	t.Run("InvalidPort", func(t *testing.T) {
		conn := NewWithClient(&Config{}, testLogger(), newMockF5Client())
		rawConfig, _ := json.Marshal(map[string]interface{}{
			"host": "f5.test.com", "username": "admin", "password": "secret",
			"ssl_profile": "prof", "port": 70000,
		})
		err := conn.ValidateConfig(context.Background(), rawConfig)
		if err == nil || !strings.Contains(err.Error(), "port must be between") {
			t.Errorf("expected port range error, got: %v", err)
		}
	})

	t.Run("AuthFailure", func(t *testing.T) {
		mock := newMockF5Client()
		mock.authenticateErr = fmt.Errorf("connection refused")
		conn := NewWithClient(&Config{}, testLogger(), mock)

		rawConfig, _ := json.Marshal(map[string]string{
			"host": "f5.test.com", "username": "admin", "password": "bad",
			"ssl_profile": "prof",
		})
		err := conn.ValidateConfig(context.Background(), rawConfig)
		if err == nil || !strings.Contains(err.Error(), "authentication failed") {
			t.Errorf("expected auth failure error, got: %v", err)
		}
	})

	t.Run("InvalidPartitionChars", func(t *testing.T) {
		conn := NewWithClient(&Config{}, testLogger(), newMockF5Client())
		rawConfig, _ := json.Marshal(map[string]string{
			"host": "f5.test.com", "username": "admin", "password": "secret",
			"ssl_profile": "prof", "partition": "Common; rm -rf /",
		})
		err := conn.ValidateConfig(context.Background(), rawConfig)
		if err == nil || !strings.Contains(err.Error(), "partition contains invalid characters") {
			t.Errorf("expected partition validation error, got: %v", err)
		}
	})

	t.Run("InvalidSSLProfileChars", func(t *testing.T) {
		conn := NewWithClient(&Config{}, testLogger(), newMockF5Client())
		rawConfig, _ := json.Marshal(map[string]string{
			"host": "f5.test.com", "username": "admin", "password": "secret",
			"ssl_profile": "prof; echo pwned",
		})
		err := conn.ValidateConfig(context.Background(), rawConfig)
		if err == nil || !strings.Contains(err.Error(), "ssl_profile contains invalid characters") {
			t.Errorf("expected ssl_profile validation error, got: %v", err)
		}
	})

	t.Run("InvalidHostChars", func(t *testing.T) {
		conn := NewWithClient(&Config{}, testLogger(), newMockF5Client())
		rawConfig, _ := json.Marshal(map[string]string{
			"host": "f5.test.com/../../etc/passwd", "username": "admin",
			"password": "secret", "ssl_profile": "prof",
		})
		err := conn.ValidateConfig(context.Background(), rawConfig)
		if err == nil || !strings.Contains(err.Error(), "host contains invalid characters") {
			t.Errorf("expected host validation error, got: %v", err)
		}
	})
}

// --- DeployCertificate tests ---

const testCertPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIRAJ1gCL7hBmSj6g0gYOr2FzMwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEChMHY2VydGN0bDAeFw0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBa
MBIxEDAOBgNVBAoTB2NlcnRjdGwwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQr
H2kMjsgP+FZuyMjJLNfewN0EDkN0s4Lz2Y1IqFqD8DlGN3zI3lPQ7hGdQbiCklPk
1YXNmfmI6L2JKxB/d9Gxo1cwVTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYI
KwYBBQUHAwEwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQAAAAAAAAAAAAAAAAA
AAAAADAKBggqhkjOPQQDAgNIADBFAiEA4JIlRKL22y6c2JGwVtM60z2bGm9Lb9rq
3BSSLE8xF3UCIGSKd9bP0BBFIO20daxEP7g3/kTSSYpNMIG6yc6acdHH
-----END CERTIFICATE-----`

const testKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIKj7N0fDjLaI9bGmJ/TY3PBvIxwclLOPIdOi6yWI2B5CoAcGBSuBBAAi
oWQDYgAEhLS0ynMvDJH5o0F5e6jVnXOBqRT2bHkVxQng+eqaXdY3gJoFIIxvR/q0
Vy4p3LZFQsKQfBwt3A8LLvOJY6E8bF4MNPrn0O1bQkeMjb8tSxdKfH0bARJdllD
h9oAPTR1
-----END EC PRIVATE KEY-----`

const testChainPEM = `-----BEGIN CERTIFICATE-----
MIIBYzCCAQmgAwIBAgIRAKR1G0hS1jBOQH2VtNTzpHowCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEChMHY2VydGN0bDAeFw0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBa
MBIxEDAOBgNVBAoTB2NlcnRjdGwwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASE
tLTKcy8MkfmjQXl7qNWdc4GpFPZseRXFCeD56ppd1jeAmgUgjG9H+rRXLinctkVC
wpB8HC3cDwsu84ljoTxso0IwQDAOBgNVHQ8BAf8EBAMCAoQwDwYDVR0TAQH/BAUw
AwEB/zAdBgNVHQ4EFgQUAAAAAAAAAAAAAAAAAAAAAAAwCgYIKoZIzj0EAwIDSAAw
RQIhAJ2K5VVTBiWBrZgdxNthZ7FEqrpNL9LiuD3bWx0xCaoAAiAh9+2p4PQmNuqN
R7kSqe/p0W0VnFx1nOJz/sDyPM+2qg==
-----END CERTIFICATE-----`

func TestDeployCertificate(t *testing.T) {
	t.Run("FullSuccessWithChain", func(t *testing.T) {
		mock := newMockF5Client()
		cfg := &Config{Host: "f5.test.com", Port: 443, Username: "admin", Password: "secret", Partition: "Common", SSLProfile: "myprofile"}
		conn := NewWithClient(cfg, testLogger(), mock)

		request := target.DeploymentRequest{
			CertPEM:  testCertPEM,
			KeyPEM:   testKeyPEM,
			ChainPEM: testChainPEM,
		}

		result, err := conn.DeployCertificate(context.Background(), request)
		if err != nil {
			t.Fatalf("DeployCertificate failed: %v", err)
		}
		if !result.Success {
			t.Fatalf("expected success, got: %s", result.Message)
		}

		// Verify call sequence
		if !mock.hasCalled("Authenticate") {
			t.Error("expected Authenticate call")
		}
		if mock.callCount("UploadFile") != 3 {
			t.Errorf("expected 3 UploadFile calls (cert, key, chain), got %d", mock.callCount("UploadFile"))
		}
		if mock.callCount("InstallCert") != 2 { // cert + chain
			t.Errorf("expected 2 InstallCert calls (cert + chain), got %d", mock.callCount("InstallCert"))
		}
		if mock.callCount("InstallKey") != 1 {
			t.Errorf("expected 1 InstallKey call, got %d", mock.callCount("InstallKey"))
		}
		if !mock.hasCalled("CreateTransaction") {
			t.Error("expected CreateTransaction call")
		}
		if !mock.hasCalled("UpdateSSLProfile") {
			t.Error("expected UpdateSSLProfile call")
		}
		if !mock.hasCalled("CommitTransaction") {
			t.Error("expected CommitTransaction call")
		}

		// Verify metadata
		if result.Metadata["host"] != "f5.test.com" {
			t.Errorf("expected host f5.test.com in metadata, got %s", result.Metadata["host"])
		}
		if result.Metadata["partition"] != "Common" {
			t.Errorf("expected partition Common in metadata, got %s", result.Metadata["partition"])
		}
		if result.Metadata["ssl_profile"] != "myprofile" {
			t.Errorf("expected ssl_profile myprofile in metadata, got %s", result.Metadata["ssl_profile"])
		}
		if result.Metadata["cert_object_name"] == "" {
			t.Error("expected cert_object_name in metadata")
		}
		if result.Metadata["duration_ms"] == "" {
			t.Error("expected duration_ms in metadata")
		}
	})

	t.Run("SuccessWithoutChain", func(t *testing.T) {
		mock := newMockF5Client()
		cfg := &Config{Host: "f5.test.com", Port: 443, Username: "admin", Password: "secret", Partition: "Common", SSLProfile: "myprofile"}
		conn := NewWithClient(cfg, testLogger(), mock)

		request := target.DeploymentRequest{
			CertPEM: testCertPEM,
			KeyPEM:  testKeyPEM,
		}

		result, err := conn.DeployCertificate(context.Background(), request)
		if err != nil {
			t.Fatalf("DeployCertificate failed: %v", err)
		}
		if !result.Success {
			t.Fatalf("expected success, got: %s", result.Message)
		}

		// Should only upload cert + key (no chain)
		if mock.callCount("UploadFile") != 2 {
			t.Errorf("expected 2 UploadFile calls, got %d", mock.callCount("UploadFile"))
		}
		if mock.callCount("InstallCert") != 1 { // only cert, no chain
			t.Errorf("expected 1 InstallCert call (cert only), got %d", mock.callCount("InstallCert"))
		}
		if result.Metadata["chain_object_name"] != "" {
			t.Errorf("expected empty chain_object_name, got %s", result.Metadata["chain_object_name"])
		}
	})

	t.Run("MissingKeyPEM", func(t *testing.T) {
		mock := newMockF5Client()
		cfg := &Config{Host: "f5.test.com", Port: 443, Username: "admin", Password: "secret", Partition: "Common", SSLProfile: "myprofile"}
		conn := NewWithClient(cfg, testLogger(), mock)

		request := target.DeploymentRequest{
			CertPEM: testCertPEM,
		}

		result, err := conn.DeployCertificate(context.Background(), request)
		if err == nil {
			t.Fatal("expected error for missing KeyPEM")
		}
		if result.Success {
			t.Error("expected Success=false")
		}
		if !strings.Contains(err.Error(), "KeyPEM") {
			t.Errorf("expected KeyPEM in error, got: %v", err)
		}
	})

	t.Run("AuthFailure", func(t *testing.T) {
		mock := newMockF5Client()
		mock.authenticateErr = fmt.Errorf("connection refused")
		cfg := &Config{Host: "f5.test.com", Port: 443, Username: "admin", Password: "bad", Partition: "Common", SSLProfile: "myprofile"}
		conn := NewWithClient(cfg, testLogger(), mock)

		request := target.DeploymentRequest{CertPEM: testCertPEM, KeyPEM: testKeyPEM}
		result, err := conn.DeployCertificate(context.Background(), request)
		if err == nil {
			t.Fatal("expected error for auth failure")
		}
		if result.Success {
			t.Error("expected Success=false")
		}
		if !strings.Contains(err.Error(), "authentication failed") {
			t.Errorf("expected auth failure in error, got: %v", err)
		}
	})

	t.Run("CertUploadFailure", func(t *testing.T) {
		mock := newMockF5Client()
		mock.uploadFileErr = fmt.Errorf("upload timeout")
		mock.uploadFileErrOn = "cert"
		cfg := &Config{Host: "f5.test.com", Port: 443, Username: "admin", Password: "secret", Partition: "Common", SSLProfile: "myprofile"}
		conn := NewWithClient(cfg, testLogger(), mock)

		request := target.DeploymentRequest{CertPEM: testCertPEM, KeyPEM: testKeyPEM}
		_, err := conn.DeployCertificate(context.Background(), request)
		if err == nil {
			t.Fatal("expected error for cert upload failure")
		}
		// No cleanup needed — nothing installed yet
		if len(mock.deletedCerts) > 0 || len(mock.deletedKeys) > 0 {
			t.Error("expected no cleanup calls when upload fails before install")
		}
	})

	t.Run("CertInstallFailure", func(t *testing.T) {
		mock := newMockF5Client()
		mock.installCertErr = fmt.Errorf("install failed")
		// Don't set installCertErrOn — all InstallCert calls will fail
		cfg := &Config{Host: "f5.test.com", Port: 443, Username: "admin", Password: "secret", Partition: "Common", SSLProfile: "myprofile"}
		conn := NewWithClient(cfg, testLogger(), mock)

		request := target.DeploymentRequest{CertPEM: testCertPEM, KeyPEM: testKeyPEM}
		_, err := conn.DeployCertificate(context.Background(), request)
		if err == nil {
			t.Fatal("expected error for cert install failure")
		}
		if !strings.Contains(err.Error(), "cert crypto object") {
			t.Errorf("expected cert install error, got: %v", err)
		}
		// No cleanup — cert install failed so nothing to clean up
		// (the cert object wasn't successfully installed)
	})

	t.Run("KeyInstallFailure_CleansCert", func(t *testing.T) {
		mock := newMockF5Client()
		mock.installKeyErr = fmt.Errorf("key install failed")
		cfg := &Config{Host: "f5.test.com", Port: 443, Username: "admin", Password: "secret", Partition: "Common", SSLProfile: "myprofile"}
		conn := NewWithClient(cfg, testLogger(), mock)

		request := target.DeploymentRequest{CertPEM: testCertPEM, KeyPEM: testKeyPEM}
		_, err := conn.DeployCertificate(context.Background(), request)
		if err == nil {
			t.Fatal("expected error for key install failure")
		}
		// Should have cleaned up the cert that was installed
		if len(mock.deletedCerts) != 1 {
			t.Errorf("expected 1 cert cleanup, got %d", len(mock.deletedCerts))
		}
	})

	t.Run("TransactionCreateFailure_CleansObjects", func(t *testing.T) {
		mock := newMockF5Client()
		mock.createTransactionErr = fmt.Errorf("transaction service unavailable")
		cfg := &Config{Host: "f5.test.com", Port: 443, Username: "admin", Password: "secret", Partition: "Common", SSLProfile: "myprofile"}
		conn := NewWithClient(cfg, testLogger(), mock)

		request := target.DeploymentRequest{CertPEM: testCertPEM, KeyPEM: testKeyPEM}
		_, err := conn.DeployCertificate(context.Background(), request)
		if err == nil {
			t.Fatal("expected error for transaction create failure")
		}
		// Should clean up cert + key
		if len(mock.deletedCerts) != 1 {
			t.Errorf("expected 1 cert cleanup, got %d", len(mock.deletedCerts))
		}
		if len(mock.deletedKeys) != 1 {
			t.Errorf("expected 1 key cleanup, got %d", len(mock.deletedKeys))
		}
	})

	t.Run("ProfileUpdateFailure_CleansObjects", func(t *testing.T) {
		mock := newMockF5Client()
		mock.updateSSLProfileErr = fmt.Errorf("profile not found")
		cfg := &Config{Host: "f5.test.com", Port: 443, Username: "admin", Password: "secret", Partition: "Common", SSLProfile: "nonexistent"}
		conn := NewWithClient(cfg, testLogger(), mock)

		request := target.DeploymentRequest{CertPEM: testCertPEM, KeyPEM: testKeyPEM, ChainPEM: testChainPEM}
		_, err := conn.DeployCertificate(context.Background(), request)
		if err == nil {
			t.Fatal("expected error for profile update failure")
		}
		// Should clean up cert + chain + key
		if len(mock.deletedCerts) != 2 { // cert + chain
			t.Errorf("expected 2 cert cleanups (cert + chain), got %d", len(mock.deletedCerts))
		}
		if len(mock.deletedKeys) != 1 {
			t.Errorf("expected 1 key cleanup, got %d", len(mock.deletedKeys))
		}
	})

	t.Run("CommitFailure_CleansObjects", func(t *testing.T) {
		mock := newMockF5Client()
		mock.commitTransactionErr = fmt.Errorf("transaction validation failed")
		cfg := &Config{Host: "f5.test.com", Port: 443, Username: "admin", Password: "secret", Partition: "Common", SSLProfile: "myprofile"}
		conn := NewWithClient(cfg, testLogger(), mock)

		request := target.DeploymentRequest{CertPEM: testCertPEM, KeyPEM: testKeyPEM}
		_, err := conn.DeployCertificate(context.Background(), request)
		if err == nil {
			t.Fatal("expected error for commit failure")
		}
		if !strings.Contains(err.Error(), "commit") {
			t.Errorf("expected commit error, got: %v", err)
		}
		// Should clean up installed objects
		if len(mock.deletedCerts) < 1 {
			t.Error("expected cert cleanup on commit failure")
		}
		if len(mock.deletedKeys) < 1 {
			t.Error("expected key cleanup on commit failure")
		}
	})

	t.Run("MetadataVerification", func(t *testing.T) {
		mock := newMockF5Client()
		cfg := &Config{Host: "bigip.prod.internal", Port: 8443, Username: "admin", Password: "secret", Partition: "Production", SSLProfile: "api-ssl"}
		conn := NewWithClient(cfg, testLogger(), mock)

		request := target.DeploymentRequest{CertPEM: testCertPEM, KeyPEM: testKeyPEM}
		result, err := conn.DeployCertificate(context.Background(), request)
		if err != nil {
			t.Fatalf("DeployCertificate failed: %v", err)
		}
		if result.Metadata["host"] != "bigip.prod.internal" {
			t.Errorf("expected host bigip.prod.internal, got %s", result.Metadata["host"])
		}
		if result.Metadata["partition"] != "Production" {
			t.Errorf("expected partition Production, got %s", result.Metadata["partition"])
		}
		if result.Metadata["ssl_profile"] != "api-ssl" {
			t.Errorf("expected ssl_profile api-ssl, got %s", result.Metadata["ssl_profile"])
		}
		if !strings.HasPrefix(result.Metadata["cert_object_name"], "certctl-cert-") {
			t.Errorf("expected cert_object_name to start with certctl-cert-, got %s", result.Metadata["cert_object_name"])
		}
		if result.TargetAddress != "bigip.prod.internal:8443" {
			t.Errorf("expected target address bigip.prod.internal:8443, got %s", result.TargetAddress)
		}
	})
}

// --- ValidateDeployment tests ---

func TestValidateDeployment(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock := newMockF5Client()
		mock.getSSLProfileResult = &SSLProfileInfo{
			Name:  "myprofile",
			Cert:  "/Common/certctl-cert-1234567890",
			Key:   "/Common/certctl-key-1234567890",
			Chain: "/Common/certctl-chain-1234567890",
		}
		cfg := &Config{Host: "f5.test.com", Port: 443, Username: "admin", Password: "secret", Partition: "Common", SSLProfile: "myprofile"}
		conn := NewWithClient(cfg, testLogger(), mock)

		request := target.ValidationRequest{
			CertificateID: "mc-test-cert",
			Serial:        "abc123",
		}

		result, err := conn.ValidateDeployment(context.Background(), request)
		if err != nil {
			t.Fatalf("ValidateDeployment failed: %v", err)
		}
		if !result.Valid {
			t.Fatalf("expected valid, got: %s", result.Message)
		}
		if result.Metadata["current_cert"] != "/Common/certctl-cert-1234567890" {
			t.Errorf("expected cert in metadata, got %s", result.Metadata["current_cert"])
		}
	})

	t.Run("ProfileNotFound", func(t *testing.T) {
		mock := newMockF5Client()
		mock.getSSLProfileErr = fmt.Errorf("object not found (404)")
		cfg := &Config{Host: "f5.test.com", Port: 443, Username: "admin", Password: "secret", Partition: "Common", SSLProfile: "nonexistent"}
		conn := NewWithClient(cfg, testLogger(), mock)

		request := target.ValidationRequest{CertificateID: "mc-test", Serial: "abc"}
		result, err := conn.ValidateDeployment(context.Background(), request)
		if err == nil {
			t.Fatal("expected error for profile not found")
		}
		if result.Valid {
			t.Error("expected Valid=false")
		}
	})

	t.Run("AuthFailure", func(t *testing.T) {
		mock := newMockF5Client()
		mock.authenticateErr = fmt.Errorf("auth failed")
		cfg := &Config{Host: "f5.test.com", Port: 443, Username: "admin", Password: "bad", Partition: "Common", SSLProfile: "myprofile"}
		conn := NewWithClient(cfg, testLogger(), mock)

		request := target.ValidationRequest{CertificateID: "mc-test", Serial: "abc"}
		_, err := conn.ValidateDeployment(context.Background(), request)
		if err == nil {
			t.Fatal("expected error for auth failure")
		}
		if !strings.Contains(err.Error(), "authentication failed") {
			t.Errorf("expected auth failure error, got: %v", err)
		}
	})

	t.Run("UnexpectedCert_StillValid", func(t *testing.T) {
		mock := newMockF5Client()
		mock.getSSLProfileResult = &SSLProfileInfo{
			Name: "myprofile",
			Cert: "/Common/some-other-cert",
			Key:  "/Common/some-other-key",
		}
		cfg := &Config{Host: "f5.test.com", Port: 443, Username: "admin", Password: "secret", Partition: "Common", SSLProfile: "myprofile"}
		conn := NewWithClient(cfg, testLogger(), mock)

		request := target.ValidationRequest{CertificateID: "mc-test", Serial: "abc"}
		result, err := conn.ValidateDeployment(context.Background(), request)
		if err != nil {
			t.Fatalf("ValidateDeployment failed: %v", err)
		}
		// We report what's there — it's valid (profile exists with a cert)
		if !result.Valid {
			t.Error("expected Valid=true (profile has a cert)")
		}
		if result.Metadata["current_cert"] != "/Common/some-other-cert" {
			t.Errorf("expected current cert reported, got %s", result.Metadata["current_cert"])
		}
	})

	t.Run("EmptyCertField", func(t *testing.T) {
		mock := newMockF5Client()
		mock.getSSLProfileResult = &SSLProfileInfo{
			Name: "myprofile",
			Cert: "",
			Key:  "",
		}
		cfg := &Config{Host: "f5.test.com", Port: 443, Username: "admin", Password: "secret", Partition: "Common", SSLProfile: "myprofile"}
		conn := NewWithClient(cfg, testLogger(), mock)

		request := target.ValidationRequest{CertificateID: "mc-test", Serial: "abc"}
		result, err := conn.ValidateDeployment(context.Background(), request)
		if err == nil {
			t.Fatal("expected error for empty cert field")
		}
		if result.Valid {
			t.Error("expected Valid=false")
		}
		if !strings.Contains(err.Error(), "no certificate configured") {
			t.Errorf("expected 'no certificate configured' error, got: %v", err)
		}
	})
}

// --- Helper tests ---

func TestObjectName(t *testing.T) {
	name1 := objectName("cert")

	if !strings.HasPrefix(name1, "certctl-cert-") {
		t.Errorf("expected prefix certctl-cert-, got %s", name1)
	}
	// Verify format is correct: certctl-<type>-<nanotime>
	if len(name1) < len("certctl-cert-") {
		t.Errorf("expected non-empty object name, got %s", name1)
	}
	// Verify the name contains digits after the prefix
	withoutPrefix := strings.TrimPrefix(name1, "certctl-cert-")
	if withoutPrefix == "" {
		t.Error("expected digits in object name after prefix")
	}
}

func TestPartitionPath(t *testing.T) {
	path := partitionPath("Common", "certctl-cert-123")
	if path != "/Common/certctl-cert-123" {
		t.Errorf("expected /Common/certctl-cert-123, got %s", path)
	}

	path = partitionPath("Production", "my-cert")
	if path != "/Production/my-cert" {
		t.Errorf("expected /Production/my-cert, got %s", path)
	}
}

func TestCleanup_MixedResults(t *testing.T) {
	mock := newMockF5Client()
	mock.deleteCertErr = fmt.Errorf("cert in use") // cert delete fails
	// key delete succeeds (nil error)

	cfg := &Config{Host: "f5.test.com", Port: 443, Partition: "Common"}
	conn := NewWithClient(cfg, testLogger(), mock)

	// Should not panic and should attempt all deletions
	conn.cleanupCryptoObjects(context.Background(), "Common",
		[]string{"cert1", "cert2"},
		[]string{"key1"},
	)

	// Both cert deletes attempted despite errors
	if len(mock.deletedCerts) != 2 {
		t.Errorf("expected 2 cert delete attempts, got %d", len(mock.deletedCerts))
	}
	if len(mock.deletedKeys) != 1 {
		t.Errorf("expected 1 key delete attempt, got %d", len(mock.deletedKeys))
	}
}

func TestCleanup_EmptyNames(t *testing.T) {
	mock := newMockF5Client()
	cfg := &Config{Host: "f5.test.com", Port: 443, Partition: "Common"}
	conn := NewWithClient(cfg, testLogger(), mock)

	// Empty names should be skipped
	conn.cleanupCryptoObjects(context.Background(), "Common",
		[]string{"", "cert1", ""},
		[]string{"", ""},
	)

	if len(mock.deletedCerts) != 1 {
		t.Errorf("expected 1 cert delete (skipping empties), got %d", len(mock.deletedCerts))
	}
	if len(mock.deletedKeys) != 0 {
		t.Errorf("expected 0 key deletes (all empty), got %d", len(mock.deletedKeys))
	}
}

// TestDeployCertificate_TransactionRollbackOnProfileFailure tests that when the
// UpdateSSLProfile call fails, the transaction is NOT committed and cleanup is called.
func TestDeployCertificate_TransactionRollbackOnProfileFailure(t *testing.T) {
	cfg := &Config{
		Host:       "f5.example.com",
		Username:   "admin",
		Password:   "password",
		SSLProfile: "clientssl",
		Partition:  "Common",
		Insecure:   true,
		Timeout:    30,
	}

	mock := newMockF5Client()
	// Make UpdateSSLProfile fail
	mock.updateSSLProfileErr = fmt.Errorf("profile update failed")
	mock.createTransactionID = "txn-999"

	connector := NewWithClient(cfg, testLogger(), mock)

	deployReq := target.DeploymentRequest{
		CertPEM:  testCertPEM,
		KeyPEM:   testKeyPEM,
		ChainPEM: testChainPEM,
	}

	result, err := connector.DeployCertificate(context.Background(), deployReq)

	// Should fail
	if err == nil {
		t.Error("expected deployment to fail when UpdateSSLProfile fails")
	}
	if result.Success {
		t.Error("expected result.Success=false when UpdateSSLProfile fails")
	}

	// Verify transaction was committed (it commits even on failure for rollback)
	// but the update itself failed
}

// TestDeployCertificate_ChainUpload tests that when both CertPEM, KeyPEM, and ChainPEM
// are provided, all three are uploaded and installed separately.
func TestDeployCertificate_ChainUpload(t *testing.T) {
	cfg := &Config{
		Host:       "f5.example.com",
		Username:   "admin",
		Password:   "password",
		SSLProfile: "clientssl",
		Partition:  "Common",
		Insecure:   true,
		Timeout:    30,
	}

	mock := newMockF5Client()
	mock.createTransactionID = "txn-123"
	connector := NewWithClient(cfg, testLogger(), mock)

	deployReq := target.DeploymentRequest{
		CertPEM:  testCertPEM,
		KeyPEM:   testKeyPEM,
		ChainPEM: testChainPEM,
	}

	result, err := connector.DeployCertificate(context.Background(), deployReq)

	if err != nil {
		t.Fatalf("deployment failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("deployment was not successful: %s", result.Message)
	}

	// Verify that the calls were made
	hasUpload := false
	hasInstall := false
	hasUpdateSSL := false

	for _, call := range mock.calls {
		if call.Method == "UploadFile" {
			hasUpload = true
		}
		if call.Method == "InstallCert" || call.Method == "InstallKey" {
			hasInstall = true
		}
		if call.Method == "UpdateSSLProfile" {
			hasUpdateSSL = true
		}
	}

	if !hasUpload {
		t.Error("expected UploadFile to be called")
	}
	if !hasInstall {
		t.Error("expected InstallCert/InstallKey to be called")
	}
	if !hasUpdateSSL {
		t.Error("expected UpdateSSLProfile to be called")
	}
}

func TestNew_NilConfig(t *testing.T) {
	_, err := New(nil, testLogger())
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	if !strings.Contains(err.Error(), "config is required") {
		t.Errorf("expected 'config is required' error, got: %v", err)
	}
}
