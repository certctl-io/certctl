// Package k8ssecret implements a target.Connector for deploying certificates to Kubernetes Secrets.
// This enables the "proxy agent" pattern — a certctl agent running in a Kubernetes cluster
// (or outside with kubeconfig access) can deploy certificates as kubernetes.io/tls Secrets.
// The connector is generic and doesn't depend on k8s.io packages — the K8sClient interface
// abstracts all Kubernetes operations for maximum testability.
package k8ssecret

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/connector/target/certutil"
)

// Config represents the Kubernetes Secrets deployment target configuration.
// Supports in-cluster auth by default (ServiceAccount token auto-mounted) or
// out-of-cluster auth via kubeconfig file.
type Config struct {
	Namespace      string            `json:"namespace"`                 // Required. Kubernetes namespace.
	SecretName     string            `json:"secret_name"`               // Required. Name of the kubernetes.io/tls Secret.
	Labels         map[string]string `json:"labels,omitempty"`          // Optional. Additional labels to add to the Secret.
	KubeconfigPath string            `json:"kubeconfig_path,omitempty"` // Optional. Path to kubeconfig for out-of-cluster auth.
}

// SecretData represents the structure of a Kubernetes Secret.
type SecretData struct {
	Name        string
	Namespace   string
	Type        string            // Always "kubernetes.io/tls"
	Data        map[string][]byte // "tls.crt" and "tls.key"
	Labels      map[string]string
	Annotations map[string]string
}

// K8sClient abstracts Kubernetes API operations for testability.
// The real implementation will use k8s.io/client-go; tests inject a mock.
type K8sClient interface {
	// GetSecret retrieves a Secret from the given namespace.
	// Returns an error if the Secret doesn't exist.
	GetSecret(ctx context.Context, namespace, name string) (*SecretData, error)

	// CreateSecret creates a new Secret in the given namespace.
	CreateSecret(ctx context.Context, namespace string, secret *SecretData) error

	// UpdateSecret updates an existing Secret.
	UpdateSecret(ctx context.Context, namespace string, secret *SecretData) error

	// DeleteSecret deletes a Secret (currently unused but available for future cleanup logic).
	DeleteSecret(ctx context.Context, namespace, name string) error
}

// Connector implements the target.Connector interface for Kubernetes Secrets.
// This connector runs on the AGENT side and handles Secret deployment via the Kubernetes API.
type Connector struct {
	config *Config
	client K8sClient
	logger *slog.Logger
}

// Validation regex patterns
var (
	// namespaceRegex validates Kubernetes namespace names per DNS-1123 (RFC 1123).
	// Namespace must start and end with alphanumeric, contain only lowercase alphanumeric and hyphens, max 63 chars.
	namespaceRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$`)

	// secretNameRegex validates Kubernetes Secret names per DNS-1123 subdomain.
	// Name must start and end with alphanumeric, contain only lowercase alphanumeric, hyphens, and dots, max 253 chars.
	secretNameRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$`)

	// labelKeyRegex validates Kubernetes label key format.
	// Optional prefix (domain), required name (alphanumeric, hyphens, underscores, dots).
	labelKeyRegex = regexp.MustCompile(`^([a-zA-Z0-9\-_\.]+/)?[a-zA-Z0-9\-_\.]+$`)
)

// New creates a new Kubernetes Secrets target connector.
// For now, returns a stub error since we're not pulling in k8s.io dependencies.
// The real implementation will use k8s.io/client-go to create a real K8s client.
func New(cfg *Config, logger *slog.Logger) (*Connector, error) {
	if cfg == nil {
		return nil, fmt.Errorf("Kubernetes config is required")
	}

	// Stub real K8s client — the actual implementation will use k8s.io/client-go
	// For now, return error to guide users to use the agent with proper kubeconfig
	client := &realK8sClient{
		config: cfg,
		logger: logger,
	}

	return &Connector{
		config: cfg,
		client: client,
		logger: logger,
	}, nil
}

// NewWithClient creates a new Kubernetes Secrets target connector with an injectable K8s client.
// Used in tests to mock Kubernetes API operations.
func NewWithClient(cfg *Config, client K8sClient, logger *slog.Logger) *Connector {
	return &Connector{
		config: cfg,
		client: client,
		logger: logger,
	}
}

// ValidateConfig validates the Kubernetes Secrets deployment target configuration.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid Kubernetes config: %w", err)
	}

	// Required fields
	if cfg.Namespace == "" {
		return fmt.Errorf("Kubernetes namespace is required")
	}
	if cfg.SecretName == "" {
		return fmt.Errorf("Kubernetes secret_name is required")
	}

	// Validate namespace format (DNS-1123)
	if !namespaceRegex.MatchString(cfg.Namespace) || len(cfg.Namespace) > 63 {
		return fmt.Errorf("Kubernetes namespace must match DNS-1123 pattern and be max 63 characters, got %q", cfg.Namespace)
	}

	// Validate secret name format (DNS-1123 subdomain)
	if !secretNameRegex.MatchString(cfg.SecretName) || len(cfg.SecretName) > 253 {
		return fmt.Errorf("Kubernetes secret name must match DNS-1123 subdomain pattern and be max 253 characters, got %q", cfg.SecretName)
	}

	// Validate labels if present
	for key := range cfg.Labels {
		if !labelKeyRegex.MatchString(key) {
			return fmt.Errorf("Kubernetes label key contains invalid characters: %q", key)
		}
	}

	c.config = &cfg
	c.logger.Info("Kubernetes Secrets configuration validated",
		"namespace", cfg.Namespace,
		"secret_name", cfg.SecretName)

	return nil
}

// DeployCertificate deploys a certificate to a Kubernetes Secret.
//
// Steps:
// 1. Build tls.crt (cert PEM + chain PEM)
// 2. Require KeyPEM (private key)
// 3. Try to get existing Secret — if found, update it; if not found, create it
// 4. Set Secret type to kubernetes.io/tls with standard and custom labels
// 5. Add deployment metadata annotations
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	if request.CertPEM == "" {
		return &target.DeploymentResult{
			Success:    false,
			Message:    "certificate PEM is required",
			DeployedAt: time.Now(),
		}, fmt.Errorf("certificate PEM is required")
	}

	if request.KeyPEM == "" {
		return &target.DeploymentResult{
			Success:    false,
			Message:    "private key PEM is required",
			DeployedAt: time.Now(),
		}, fmt.Errorf("private key PEM is required")
	}

	c.logger.Info("deploying certificate to Kubernetes Secret",
		"namespace", c.config.Namespace,
		"secret_name", c.config.SecretName)

	startTime := time.Now()

	// Build tls.crt = cert + chain (standard kubernetes.io/tls format)
	tlsCrt := request.CertPEM
	if request.ChainPEM != "" {
		tlsCrt += "\n" + request.ChainPEM
	}

	// Build Secret data
	secretData := &SecretData{
		Name:      c.config.SecretName,
		Namespace: c.config.Namespace,
		Type:      "kubernetes.io/tls",
		Data: map[string][]byte{
			"tls.crt": []byte(tlsCrt),
			"tls.key": []byte(request.KeyPEM),
		},
		Labels: map[string]string{
			"app.kubernetes.io/managed-by": "certctl",
		},
		Annotations: map[string]string{
			"certctl.io/deployed-at": startTime.Format(time.RFC3339),
		},
	}

	// Add custom labels
	if c.config.Labels != nil {
		for k, v := range c.config.Labels {
			secretData.Labels[k] = v
		}
	}

	// Add certificate ID to annotations if available
	if certID, ok := request.Metadata["certificate_id"]; ok {
		secretData.Annotations["certctl.io/certificate-id"] = certID
	}

	// Try to get existing Secret — if found, update; if not found, create
	existingSecret, err := c.client.GetSecret(ctx, c.config.Namespace, c.config.SecretName)
	var secretExists bool
	if err == nil && existingSecret != nil {
		secretExists = true
	}

	if secretExists {
		// Update existing Secret
		if err := c.client.UpdateSecret(ctx, c.config.Namespace, secretData); err != nil {
			errMsg := fmt.Sprintf("failed to update Kubernetes Secret: %v", err)
			c.logger.Error("Secret update failed", "error", err)
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: fmt.Sprintf("%s/%s", c.config.Namespace, c.config.SecretName),
				Message:       errMsg,
				DeployedAt:    time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
		c.logger.Info("Kubernetes Secret updated",
			"namespace", c.config.Namespace,
			"secret_name", c.config.SecretName)
	} else {
		// Create new Secret
		if err := c.client.CreateSecret(ctx, c.config.Namespace, secretData); err != nil {
			errMsg := fmt.Sprintf("failed to create Kubernetes Secret: %v", err)
			c.logger.Error("Secret creation failed", "error", err)
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: fmt.Sprintf("%s/%s", c.config.Namespace, c.config.SecretName),
				Message:       errMsg,
				DeployedAt:    time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
		c.logger.Info("Kubernetes Secret created",
			"namespace", c.config.Namespace,
			"secret_name", c.config.SecretName)
	}

	deploymentDuration := time.Since(startTime)

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: fmt.Sprintf("%s/%s", c.config.Namespace, c.config.SecretName),
		DeploymentID:  fmt.Sprintf("k8s-secret-%d", time.Now().Unix()),
		Message:       fmt.Sprintf("Certificate deployed to Kubernetes Secret %s/%s", c.config.Namespace, c.config.SecretName),
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"namespace":   c.config.Namespace,
			"secret_name": c.config.SecretName,
			"duration_ms": fmt.Sprintf("%d", deploymentDuration.Milliseconds()),
		},
	}, nil
}

// ValidateDeployment verifies that the deployed certificate Secret is valid and accessible.
//
// Steps:
// 1. Get the Secret from the cluster
// 2. Verify tls.crt is present and non-empty
// 3. Verify tls.key is present and non-empty
// 4. Parse the certificate and extract serial number
// 5. Compare with request serial number
func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	c.logger.Info("validating Kubernetes Secret deployment",
		"certificate_id", request.CertificateID,
		"serial", request.Serial,
		"namespace", c.config.Namespace,
		"secret_name", c.config.SecretName)

	startTime := time.Now()
	targetAddr := fmt.Sprintf("%s/%s", c.config.Namespace, c.config.SecretName)

	// Get the Secret from the cluster
	secretData, err := c.client.GetSecret(ctx, c.config.Namespace, c.config.SecretName)
	if err != nil {
		errMsg := fmt.Sprintf("failed to get Kubernetes Secret: %v", err)
		c.logger.Error("validation failed", "error", err)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: targetAddr,
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	if secretData == nil {
		errMsg := "Kubernetes Secret not found"
		c.logger.Error("validation failed", "error", errMsg)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: targetAddr,
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Verify tls.crt exists and is non-empty
	tlsCrt, ok := secretData.Data["tls.crt"]
	if !ok || len(tlsCrt) == 0 {
		errMsg := "Secret tls.crt not found or empty"
		c.logger.Error("validation failed", "error", errMsg)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: targetAddr,
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Verify tls.key exists and is non-empty
	tlsKey, ok := secretData.Data["tls.key"]
	if !ok || len(tlsKey) == 0 {
		errMsg := "Secret tls.key not found or empty"
		c.logger.Error("validation failed", "error", errMsg)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: targetAddr,
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Parse the certificate and extract serial
	cert, err := certutil.ParseCertificatePEM(string(tlsCrt))
	if err != nil {
		errMsg := fmt.Sprintf("failed to parse certificate in Secret: %v", err)
		c.logger.Error("validation failed", "error", err)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: targetAddr,
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Get certificate serial number as hex string
	deployedSerial := cert.SerialNumber.Text(16)

	// Compare serials
	if deployedSerial != request.Serial {
		errMsg := fmt.Sprintf("serial mismatch: expected %s, got %s", request.Serial, deployedSerial)
		c.logger.Error("validation failed", "error", errMsg)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: targetAddr,
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	validationDuration := time.Since(startTime)
	c.logger.Info("Kubernetes Secret deployment validated successfully",
		"duration", validationDuration.String(),
		"namespace", c.config.Namespace,
		"secret_name", c.config.SecretName)

	return &target.ValidationResult{
		Valid:         true,
		Serial:        deployedSerial,
		TargetAddress: targetAddr,
		Message:       fmt.Sprintf("Certificate valid in Kubernetes Secret %s/%s", c.config.Namespace, c.config.SecretName),
		ValidatedAt:   time.Now(),
		Metadata: map[string]string{
			"namespace":   c.config.Namespace,
			"secret_name": c.config.SecretName,
			"duration_ms": fmt.Sprintf("%d", validationDuration.Milliseconds()),
		},
	}, nil
}

// realK8sClient is a stub placeholder for the real k8s.io/client-go implementation.
// The actual implementation will be added when the k8s.io dependencies are wired in.
type realK8sClient struct {
	config *Config
	logger *slog.Logger
}

// GetSecret stub implementation.
func (r *realK8sClient) GetSecret(ctx context.Context, namespace, name string) (*SecretData, error) {
	return nil, fmt.Errorf("real Kubernetes client not implemented — use NewWithClient for tests")
}

// CreateSecret stub implementation.
func (r *realK8sClient) CreateSecret(ctx context.Context, namespace string, secret *SecretData) error {
	return fmt.Errorf("real Kubernetes client not implemented — use NewWithClient for tests")
}

// UpdateSecret stub implementation.
func (r *realK8sClient) UpdateSecret(ctx context.Context, namespace string, secret *SecretData) error {
	return fmt.Errorf("real Kubernetes client not implemented — use NewWithClient for tests")
}

// DeleteSecret stub implementation.
func (r *realK8sClient) DeleteSecret(ctx context.Context, namespace, name string) error {
	return fmt.Errorf("real Kubernetes client not implemented — use NewWithClient for tests")
}
