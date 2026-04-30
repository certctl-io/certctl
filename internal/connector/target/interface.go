package target

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// ErrValidateOnlyNotSupported is returned by ValidateOnly when the
// connector cannot dry-run a deploy (e.g., K8s — there is no API
// for "would this Secret update succeed without modifying state?").
//
// Frozen decision 0.6 of the deploy-hardening I master bundle:
// ValidateOnly returns this sentinel rather than nil so operators
// can errors.Is to distinguish "validated successfully" from
// "validation not supported on this connector type."
var ErrValidateOnlyNotSupported = errors.New("target connector does not support ValidateOnly dry-run")

// Connector defines the interface for certificate deployment operations.
type Connector interface {
	// ValidateConfig validates the deployment target configuration.
	ValidateConfig(ctx context.Context, config json.RawMessage) error

	// DeployCertificate deploys a certificate to the target.
	// The request contains the certificate and chain in PEM format, but never a private key.
	DeployCertificate(ctx context.Context, request DeploymentRequest) (*DeploymentResult, error)

	// ValidateOnly runs the validate step (PreCommit) of a deploy
	// WITHOUT touching the live cert. Returns nil when the deploy
	// would succeed at the validate stage; returns
	// ErrValidateOnlyNotSupported when the connector cannot dry-run
	// (e.g., K8s — there's no API for "would this Secret update
	// succeed without modifying state?"); returns any other error
	// from the connector's validate step.
	//
	// Operators preview a deploy via this method before committing.
	// Phase 3 of the deploy-hardening I master bundle adds the
	// interface method; Phases 4-9 implement the meaningful path
	// per connector.
	ValidateOnly(ctx context.Context, request DeploymentRequest) error

	// ValidateDeployment verifies that a deployed certificate is valid and accessible.
	ValidateDeployment(ctx context.Context, request ValidationRequest) (*ValidationResult, error)
}

// DeploymentRequest contains the parameters for deploying a certificate to a target.
// In agent keygen mode, KeyPEM is populated from the agent's local key store.
// In server keygen mode (demo only), KeyPEM may be empty if the key was embedded in the cert version.
type DeploymentRequest struct {
	CertPEM      string            `json:"cert_pem"`
	KeyPEM       string            `json:"key_pem,omitempty"`
	ChainPEM     string            `json:"chain_pem"`
	TargetConfig json.RawMessage   `json:"target_config"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// DeploymentResult contains the result of a successful certificate deployment.
type DeploymentResult struct {
	Success       bool              `json:"success"`
	TargetAddress string            `json:"target_address"`
	DeploymentID  string            `json:"deployment_id"`
	Message       string            `json:"message"`
	DeployedAt    time.Time         `json:"deployed_at"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// ValidationRequest contains the parameters for validating a deployed certificate.
type ValidationRequest struct {
	CertificateID string            `json:"certificate_id"`
	Serial        string            `json:"serial"`
	TargetConfig  json.RawMessage   `json:"target_config"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// ValidationResult contains the result of a certificate validation check.
type ValidationResult struct {
	Valid         bool              `json:"valid"`
	Serial        string            `json:"serial"`
	TargetAddress string            `json:"target_address"`
	Message       string            `json:"message"`
	ValidatedAt   time.Time         `json:"validated_at"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}
