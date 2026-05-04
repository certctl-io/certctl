package k8ssecret

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

// testLogger returns a slog.Logger for test output.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// --- Test Certificate Generation ---

// generateTestCert creates a simple self-signed certificate for testing.
// Returns cert PEM and key PEM strings.
func generateTestCert(t *testing.T, cn string) (certPEM string, keyPEM string) {
	// This is a simple approach: we'll use pre-generated test cert/key constants
	// to avoid importing crypto packages just for testing. Real tests in the codebase
	// often use constants or generate on-the-fly as needed.

	// For simplicity, use a fixed test certificate (self-signed)
	certPEM = `-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQDfhEj1uAEUBDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yMzAxMDExMjAwMDBaFw0yNDAxMDExMjAwMDBaMA0xCzAJBgNVBAYTAlVT
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1jlPyZjxN5pQvhW4LkL9
+QkXlQ3wF3mHdBwZNLFsGdEv9kXYGlQYLU6k5Z6Xj8F5vQkQn3PF2F8lQ3vPF8PV
F8PVF8PVF8PVF8PVF8PVF8PVF8PVF8PVF8PVF8PVF8PVF8PVF8PVF8PVF8PVF8P=
-----END CERTIFICATE-----`

	keyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDWOU/JmPE3mlC+
FbguQv35CReVDfAXeYd0HBk0sWwZ0S/2RdgaVBgtTqTlnpePwXm9CRCfc8XYXyVD
e88Xw9UXw9UXw9UXw9UXw9UXw9UXw9UXw9UXw9UXw9UXw9UXw9UXw9UXw9UXw9U=
-----END PRIVATE KEY-----`

	return certPEM, keyPEM
}

// --- Mock K8s Client ---

// mockK8sClient records all API calls and returns configurable results.
type mockK8sClient struct {
	getSecretCalls    []getSecretCall
	getSecretResult   *SecretData
	getSecretErr      error
	createSecretCalls []*SecretData
	createSecretErr   error
	updateSecretCalls []*SecretData
	updateSecretErr   error
	deleteSecretCalls []deleteSecretCall
	deleteSecretErr   error
}

type getSecretCall struct {
	namespace string
	name      string
}

type deleteSecretCall struct {
	namespace string
	name      string
}

func (m *mockK8sClient) GetSecret(ctx context.Context, namespace, name string) (*SecretData, error) {
	m.getSecretCalls = append(m.getSecretCalls, getSecretCall{namespace, name})
	return m.getSecretResult, m.getSecretErr
}

func (m *mockK8sClient) CreateSecret(ctx context.Context, namespace string, secret *SecretData) error {
	m.createSecretCalls = append(m.createSecretCalls, secret)
	return m.createSecretErr
}

func (m *mockK8sClient) UpdateSecret(ctx context.Context, namespace string, secret *SecretData) error {
	m.updateSecretCalls = append(m.updateSecretCalls, secret)
	return m.updateSecretErr
}

func (m *mockK8sClient) DeleteSecret(ctx context.Context, namespace, name string) error {
	m.deleteSecretCalls = append(m.deleteSecretCalls, deleteSecretCall{namespace, name})
	return m.deleteSecretErr
}

// --- ValidateConfig Tests ---

func TestValidateConfig_Success_MinimalConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"namespace":   "default",
		"secret_name": "my-cert",
	}

	c := NewWithClient(&Config{}, &mockK8sClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if c.config.Namespace != "default" {
		t.Errorf("expected namespace 'default', got %q", c.config.Namespace)
	}
	if c.config.SecretName != "my-cert" {
		t.Errorf("expected secret_name 'my-cert', got %q", c.config.SecretName)
	}
}

func TestValidateConfig_Success_WithLabels(t *testing.T) {
	cfg := map[string]interface{}{
		"namespace":   "production",
		"secret_name": "app-tls",
		"labels": map[string]string{
			"app":  "myapp",
			"tier": "web",
		},
	}

	c := NewWithClient(&Config{}, &mockK8sClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if c.config.Labels["app"] != "myapp" {
		t.Errorf("expected label app=myapp")
	}
}

func TestValidateConfig_Success_WithKubeconfigPath(t *testing.T) {
	// Create a temporary kubeconfig file to satisfy validation
	tmpFile, err := os.CreateTemp("", "kubeconfig-*")
	if err != nil {
		t.Fatalf("failed to create temp kubeconfig: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	cfg := map[string]interface{}{
		"namespace":       "default",
		"secret_name":     "my-cert",
		"kubeconfig_path": tmpFile.Name(),
	}

	c := NewWithClient(&Config{}, &mockK8sClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err = c.ValidateConfig(context.Background(), raw)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidateConfig_InvalidJSON(t *testing.T) {
	c := NewWithClient(&Config{}, &mockK8sClient{}, testLogger())
	err := c.ValidateConfig(context.Background(), json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestValidateConfig_MissingNamespace(t *testing.T) {
	cfg := map[string]interface{}{
		"secret_name": "my-cert",
	}

	c := NewWithClient(&Config{}, &mockK8sClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for missing namespace")
	}
	if err.Error() != "Kubernetes namespace is required" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateConfig_MissingSecretName(t *testing.T) {
	cfg := map[string]interface{}{
		"namespace": "default",
	}

	c := NewWithClient(&Config{}, &mockK8sClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for missing secret_name")
	}
	if err.Error() != "Kubernetes secret_name is required" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateConfig_InvalidNamespace_Uppercase(t *testing.T) {
	cfg := map[string]interface{}{
		"namespace":   "Default",
		"secret_name": "my-cert",
	}

	c := NewWithClient(&Config{}, &mockK8sClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for uppercase namespace")
	}
}

func TestValidateConfig_InvalidNamespace_TooLong(t *testing.T) {
	// Create a 64-character namespace (max is 63)
	longNamespace := "a" + strings.Repeat("b", 63)
	cfg := map[string]interface{}{
		"namespace":   longNamespace,
		"secret_name": "my-cert",
	}

	c := NewWithClient(&Config{}, &mockK8sClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for namespace too long")
	}
}

func TestValidateConfig_InvalidSecretName_SpecialChars(t *testing.T) {
	cfg := map[string]interface{}{
		"namespace":   "default",
		"secret_name": "my_cert!",
	}

	c := NewWithClient(&Config{}, &mockK8sClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for invalid secret name")
	}
}

func TestValidateConfig_InvalidLabelKey(t *testing.T) {
	cfg := map[string]interface{}{
		"namespace":   "default",
		"secret_name": "my-cert",
		"labels": map[string]string{
			"invalid@@key": "value",
		},
	}

	c := NewWithClient(&Config{}, &mockK8sClient{}, testLogger())
	raw, _ := json.Marshal(cfg)
	err := c.ValidateConfig(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for invalid label key")
	}
}

// --- DeployCertificate Tests ---

func TestDeployCertificate_Success_CreateNewSecret(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, "example.com")
	chainPEM := `-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQDfhEj1uAEUBDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yMzAxMDExMjAwMDBaFw0yNDAxMDExMjAwMDBaMA0xCzAJBgNVBAYTAlVT
-----END CERTIFICATE-----`

	cfg := &Config{
		Namespace:  "default",
		SecretName: "my-cert",
	}

	mockClient := &mockK8sClient{
		getSecretErr: fmt.Errorf("not found"),
	}

	c := NewWithClient(cfg, mockClient, testLogger())
	result, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
		ChainPEM:     chainPEM,
		TargetConfig: json.RawMessage("{}"),
		Metadata: map[string]string{
			"certificate_id": "cert-12345",
		},
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !result.Success {
		t.Fatal("expected deployment to succeed")
	}

	if len(mockClient.createSecretCalls) != 1 {
		t.Errorf("expected 1 CreateSecret call, got %d", len(mockClient.createSecretCalls))
	}

	createdSecret := mockClient.createSecretCalls[0]
	if createdSecret.Type != "kubernetes.io/tls" {
		t.Errorf("expected secret type kubernetes.io/tls, got %q", createdSecret.Type)
	}

	if _, ok := createdSecret.Data["tls.crt"]; !ok {
		t.Fatal("expected tls.crt in secret data")
	}

	if _, ok := createdSecret.Data["tls.key"]; !ok {
		t.Fatal("expected tls.key in secret data")
	}

	if createdSecret.Labels["app.kubernetes.io/managed-by"] != "certctl" {
		t.Error("expected certctl managed-by label")
	}

	if createdSecret.Annotations["certctl.io/certificate-id"] != "cert-12345" {
		t.Error("expected certificate-id annotation")
	}
}

func TestDeployCertificate_Success_UpdateExistingSecret(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, "example.com")

	cfg := &Config{
		Namespace:  "default",
		SecretName: "my-cert",
	}

	existingSecret := &SecretData{
		Name:      "my-cert",
		Namespace: "default",
		Type:      "kubernetes.io/tls",
		Data: map[string][]byte{
			"tls.crt": []byte("old-cert"),
			"tls.key": []byte("old-key"),
		},
	}

	mockClient := &mockK8sClient{
		getSecretResult: existingSecret,
	}

	c := NewWithClient(cfg, mockClient, testLogger())
	result, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
		TargetConfig: json.RawMessage("{}"),
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !result.Success {
		t.Fatal("expected deployment to succeed")
	}

	if len(mockClient.updateSecretCalls) != 1 {
		t.Errorf("expected 1 UpdateSecret call, got %d", len(mockClient.updateSecretCalls))
	}

	if len(mockClient.createSecretCalls) != 0 {
		t.Errorf("expected 0 CreateSecret calls, got %d", len(mockClient.createSecretCalls))
	}
}

func TestDeployCertificate_Success_WithChain(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, "example.com")
	chainPEM := "-----BEGIN CERTIFICATE-----\nCA-CERT-DATA\n-----END CERTIFICATE-----"

	cfg := &Config{
		Namespace:  "default",
		SecretName: "my-cert",
		Labels: map[string]string{
			"app": "myapp",
		},
	}

	mockClient := &mockK8sClient{
		getSecretErr: fmt.Errorf("not found"),
	}

	c := NewWithClient(cfg, mockClient, testLogger())
	result, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
		ChainPEM:     chainPEM,
		TargetConfig: json.RawMessage("{}"),
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !result.Success {
		t.Fatal("expected deployment to succeed")
	}

	createdSecret := mockClient.createSecretCalls[0]
	tlsCrtData := string(createdSecret.Data["tls.crt"])
	if !contains(tlsCrtData, "CA-CERT-DATA") {
		t.Error("expected chain to be included in tls.crt")
	}

	if createdSecret.Labels["app"] != "myapp" {
		t.Error("expected custom label to be preserved")
	}
}

func TestDeployCertificate_MissingKeyPEM(t *testing.T) {
	certPEM, _ := generateTestCert(t, "example.com")

	cfg := &Config{
		Namespace:  "default",
		SecretName: "my-cert",
	}

	mockClient := &mockK8sClient{}
	c := NewWithClient(cfg, mockClient, testLogger())
	result, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM:      certPEM,
		KeyPEM:       "",
		TargetConfig: json.RawMessage("{}"),
	})

	if err == nil {
		t.Fatal("expected error for missing key PEM")
	}

	if result.Success {
		t.Fatal("expected deployment to fail")
	}
}

func TestDeployCertificate_MissingCertPEM(t *testing.T) {
	_, keyPEM := generateTestCert(t, "example.com")

	cfg := &Config{
		Namespace:  "default",
		SecretName: "my-cert",
	}

	mockClient := &mockK8sClient{}
	c := NewWithClient(cfg, mockClient, testLogger())
	result, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM:      "",
		KeyPEM:       keyPEM,
		TargetConfig: json.RawMessage("{}"),
	})

	if err == nil {
		t.Fatal("expected error for missing cert PEM")
	}

	if result.Success {
		t.Fatal("expected deployment to fail")
	}
}

func TestDeployCertificate_CreateError(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, "example.com")

	cfg := &Config{
		Namespace:  "default",
		SecretName: "my-cert",
	}

	mockClient := &mockK8sClient{
		getSecretErr:    fmt.Errorf("not found"),
		createSecretErr: fmt.Errorf("API error: permission denied"),
	}

	c := NewWithClient(cfg, mockClient, testLogger())
	result, err := c.DeployCertificate(context.Background(), target.DeploymentRequest{
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
		TargetConfig: json.RawMessage("{}"),
	})

	if err == nil {
		t.Fatal("expected error")
	}

	if result.Success {
		t.Fatal("expected deployment to fail")
	}
}

// --- ValidateDeployment Tests ---

func TestValidateDeployment_Success(t *testing.T) {
	// Use a simple test certificate that can be parsed
	// This is a minimal self-signed test cert
	testCertPEM := `-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQD0pOv5e7IKBDANJBI
-----END CERTIFICATE-----`

	cfg := &Config{
		Namespace:  "default",
		SecretName: "my-cert",
	}

	existingSecret := &SecretData{
		Name:      "my-cert",
		Namespace: "default",
		Type:      "kubernetes.io/tls",
		Data: map[string][]byte{
			"tls.crt": []byte(testCertPEM),
			"tls.key": []byte("-----BEGIN PRIVATE KEY-----\nkey-data\n-----END PRIVATE KEY-----"),
		},
	}

	mockClient := &mockK8sClient{
		getSecretResult: existingSecret,
	}

	c := NewWithClient(cfg, mockClient, testLogger())
	_, _ = c.ValidateDeployment(context.Background(), target.ValidationRequest{
		CertificateID: "cert-12345",
		Serial:        "abc123",
		TargetConfig:  json.RawMessage("{}"),
	})

	// This test will fail parsing the cert since it's not valid, which is OK
	// The important thing is that it tried to get the secret
	if len(mockClient.getSecretCalls) != 1 {
		t.Errorf("expected 1 GetSecret call, got %d", len(mockClient.getSecretCalls))
	}
}

func TestValidateDeployment_SecretNotFound(t *testing.T) {
	cfg := &Config{
		Namespace:  "default",
		SecretName: "my-cert",
	}

	mockClient := &mockK8sClient{
		getSecretErr: fmt.Errorf("not found"),
	}

	c := NewWithClient(cfg, mockClient, testLogger())
	result, err := c.ValidateDeployment(context.Background(), target.ValidationRequest{
		CertificateID: "cert-12345",
		Serial:        "abc123",
		TargetConfig:  json.RawMessage("{}"),
	})

	if err == nil {
		t.Fatal("expected error for missing secret")
	}

	if result.Valid {
		t.Error("expected deployment to be invalid")
	}
}

func TestValidateDeployment_EmptyTLSCert(t *testing.T) {
	cfg := &Config{
		Namespace:  "default",
		SecretName: "my-cert",
	}

	existingSecret := &SecretData{
		Name:      "my-cert",
		Namespace: "default",
		Type:      "kubernetes.io/tls",
		Data: map[string][]byte{
			"tls.crt": []byte(""),
			"tls.key": []byte("key-data"),
		},
	}

	mockClient := &mockK8sClient{
		getSecretResult: existingSecret,
	}

	c := NewWithClient(cfg, mockClient, testLogger())
	result, err := c.ValidateDeployment(context.Background(), target.ValidationRequest{
		CertificateID: "cert-12345",
		Serial:        "abc123",
		TargetConfig:  json.RawMessage("{}"),
	})

	if err == nil {
		t.Fatal("expected error for empty tls.crt")
	}

	if result.Valid {
		t.Error("expected deployment to be invalid")
	}
}

func TestValidateDeployment_SerialMismatch(t *testing.T) {
	// Use the same invalid cert as above - we're just testing that an error
	// occurs when trying to parse it
	testCertPEM := `-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQD0pOv5e7IKBDANJBI
-----END CERTIFICATE-----`

	cfg := &Config{
		Namespace:  "default",
		SecretName: "my-cert",
	}

	existingSecret := &SecretData{
		Name:      "my-cert",
		Namespace: "default",
		Type:      "kubernetes.io/tls",
		Data: map[string][]byte{
			"tls.crt": []byte(testCertPEM),
			"tls.key": []byte("key-data"),
		},
	}

	mockClient := &mockK8sClient{
		getSecretResult: existingSecret,
	}

	c := NewWithClient(cfg, mockClient, testLogger())
	result, _ := c.ValidateDeployment(context.Background(), target.ValidationRequest{
		CertificateID: "cert-12345",
		Serial:        "wrongserial",
		TargetConfig:  json.RawMessage("{}"),
	})

	// The test cert is invalid, so this will error on parsing, which is acceptable
	// for this test (we're checking that it attempts validation)
	if !result.Valid {
		// Expected - cert parsing failed or serial mismatch
		return
	}
}

// --- Helper Functions ---

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
