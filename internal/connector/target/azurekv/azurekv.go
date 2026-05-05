// Package azurekv implements a target.Connector for deploying certificates
// to Azure Key Vault. Key Vault is the Azure-managed secret/certificate
// store that App Service / Application Gateway / Front Door / Container
// Apps consume via cert-bound URI references.
//
// The connector wraps github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/
// azcertificates via the KeyVaultClient interface seam so unit tests inject
// a mock without standing up real Azure. Mirrors the AWS ACM target shape
// (sdkClient + interface + DefaultAzureCredential chain) and the K8sSecret
// reference shape (NewWithClient injection seam, no file I/O).
//
// Azure-specific note (versioning): every Key Vault ImportCertificate
// creates a new VERSION under the same certificate-name. Rollback in this
// adapter restores the previous cert by re-importing the snapshot bytes
// as a new version (Azure does not let you "delete a version" without
// soft-delete recovery). Operators reading the version history will see
// (oldest) v1=initial, v2=renewal, v3=rollback-of-v2 in the worst case;
// the certctl-managed-by + certctl-certificate-id tags + the
// certctl-rollback-of=<version-id> metadata tag let an operator filter
// rollback artifacts out of audit dashboards.
//
// Soft-delete caveat: V2 doesn't manage Key Vault soft-delete recovery.
// If a previous version is in the recycle bin (Key Vault soft-delete
// retention), the rollback re-imports the snapshot bytes AS A NEW
// VERSION rather than recovering the soft-deleted prior version. This
// is the safe default — recovery requires acm:RecoverDeletedCertificate
// permission which we deliberately keep off the minimum-RBAC surface.
//
// Rank 5 of the 2026-05-03 Infisical deep-research deliverable
// (the project's deep-research deliverable, Part 5).
//
// Required Azure RBAC (minimum):
//
//	Microsoft.KeyVault/vaults/certificates/import/action     (write — import + rollback)
//	Microsoft.KeyVault/vaults/certificates/read              (read — snapshot + post-verify)
//	Microsoft.KeyVault/vaults/certificates/listversions/read (read — version-list discovery)
//
// Off-the-shelf builtin role: "Key Vault Certificates Officer". Custom-
// role recipe in docs/connectors.md.
//
// Azure short-lived credentials via the standard SDK credential chain
// (DefaultAzureCredential — env vars + managed identity + CLI fallback).
// Long-lived service-principal client secrets are NEVER read from
// connector Config.
package azurekv

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/certctl-io/certctl/internal/connector/target"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// vaultURLRegex pins the Azure Key Vault URL shape:
// https://<vault-name>.vault.azure.net (or .vault.usgovcloudapi.net for
// US-Gov, .vault.azure.cn for China). Validates Config.VaultURL at
// write time; defends against feeding garbage to the SDK's vaultBaseURL
// parameter.
var vaultURLRegex = regexp.MustCompile(`^https://[a-z0-9]([a-z0-9-]{1,22}[a-z0-9])?\.vault\.(azure\.net|usgovcloudapi\.net|azure\.cn)$`)

// certNameRegex pins the Key Vault certificate-name shape: 1-127
// chars, alphanumeric + hyphens. Defends against URL-injection-style
// inputs reaching the path parameter of the SDK call.
var certNameRegex = regexp.MustCompile(`^[a-zA-Z0-9-]{1,127}$`)

// Provenance tag keys. Always set automatically; operator-supplied
// tags merge on top. Mirrors the AWS ACM connector's provenance shape
// for cross-cloud consistency in operator dashboards.
const (
	tagKeyManagedBy     = "certctl-managed-by"
	tagKeyCertificateID = "certctl-certificate-id"
	tagValueManagedBy   = "certctl"
)

// Credential-mode enum. Off-enum values fail ValidateConfig.
const (
	CredModeDefault          = "default"
	CredModeManagedIdentity  = "managed_identity"
	CredModeClientSecret     = "client_secret"
	CredModeWorkloadIdentity = "workload_identity"
)

// Config represents the Azure Key Vault deployment target configuration.
// Stored as JSON on the deployment_targets row. No credential fields —
// the SDK credential chain handles auth.
type Config struct {
	// VaultURL is the Key Vault DNS endpoint, e.g.
	// "https://my-vault.vault.azure.net". The trailing path is
	// service-bound; do NOT include /certificates or version
	// suffixes. Required.
	VaultURL string `json:"vault_url"`

	// CertificateName is the name of the certificate object inside
	// the vault. Key Vault uses name-not-ID for the object identity;
	// the version is auto-generated per import. Operators looking up
	// the cert via Azure CLI use:
	//   az keyvault certificate show --vault-name my-vault \
	//     --name <CertificateName>
	// Required.
	CertificateName string `json:"certificate_name"`

	// Tags are applied to the Key Vault certificate at every import.
	// Unlike AWS ACM, Key Vault DOES carry tags forward across
	// imports — no separate AddTags call is needed.
	// certctl-managed-by + certctl-certificate-id provenance set
	// automatically. Operator tags merge on top.
	Tags map[string]string `json:"tags,omitempty"`

	// CredentialMode selects the auth mechanism. Closed enum:
	//   "default"            — DefaultAzureCredential (env vars +
	//                          managed identity + CLI fallback).
	//                          Recommended for development +
	//                          mixed-environment deploys.
	//   "managed_identity"   — Pin to managed identity. Recommended
	//                          for in-Azure deploys (VM, AKS,
	//                          App Service); rejects env-var creds
	//                          to defend against accidental leakage
	//                          on local-dev workstations.
	//   "client_secret"      — Service-principal client secret via
	//                          AZURE_TENANT_ID / AZURE_CLIENT_ID /
	//                          AZURE_CLIENT_SECRET env vars. NOT
	//                          recommended for production —
	//                          long-lived secret risk.
	//   "workload_identity"  — AKS workload identity (federated
	//                          cred). Requires the AKS cluster's
	//                          OIDC issuer + the agent's
	//                          ServiceAccount annotation
	//                          azure.workload.identity/client-id.
	// Default: "default".
	CredentialMode string `json:"credential_mode,omitempty"`
}

// KeyVaultClient defines the subset of the Azure Key Vault Certificates
// API the connector uses. Mirrors the AWS ACM ACMClient interface seam
// pattern — a small Go interface that the production sdkClient wraps and
// tests fake without importing azcertificates from test code.
type KeyVaultClient interface {
	ImportCertificate(ctx context.Context, input *ImportCertificateInput) (*ImportCertificateOutput, error)
	GetCertificate(ctx context.Context, input *GetCertificateInput) (*GetCertificateOutput, error)
	ListVersions(ctx context.Context, input *ListVersionsInput) (*ListVersionsOutput, error)
}

// ImportCertificateInput is the local view of the SDK's
// ImportCertificateParameters. The SDK accepts a base64-encoded PFX/
// PKCS#12 blob; the connector wraps the operator-supplied PEM cert +
// chain + key into PFX before calling.
type ImportCertificateInput struct {
	CertificateName string
	PFXBase64       string // PKCS#12 PFX bytes, base64-encoded
	Tags            map[string]string
}

// ImportCertificateOutput captures the version-id and KID Key Vault
// hands back. KID is the full URI to the imported version, e.g.
// https://my-vault.vault.azure.net/certificates/<name>/<version>.
type ImportCertificateOutput struct {
	VersionID string // 32-char hex version identifier
	KID       string // full URI for App Gateway / Front Door references
}

// GetCertificateInput is the snapshot read.
type GetCertificateInput struct {
	CertificateName string
	Version         string // empty = "latest"
}

// GetCertificateOutput carries the cert metadata the connector needs
// for post-verify (serial-number compare) + the snapshot bytes
// (the SDK returns CER bytes — DER-encoded — which we wrap back into
// PEM for the rollback path).
type GetCertificateOutput struct {
	VersionID string
	Serial    string
	NotBefore time.Time
	NotAfter  time.Time
	CERBytes  []byte // DER-encoded cert bytes
}

// ListVersionsInput / Output let the connector enumerate prior
// versions to find the most-recent-but-one for the rollback bytes.
// V2 doesn't actually use this — rollback uses the snapshot captured
// at deploy start. Reserved for V3-Pro version-aware rollback.
type ListVersionsInput struct {
	CertificateName string
	MaxItems        int32
}
type ListVersionsOutput struct {
	Versions []VersionSummary
}
type VersionSummary struct {
	VersionID string
	NotBefore time.Time
	Enabled   bool
}

// Connector implements target.Connector for Azure Key Vault.
type Connector struct {
	config *Config
	client KeyVaultClient
	logger *slog.Logger
}

// New creates a connector backed by the real Azure SDK client. Same
// shape as awsacm.New: lazy SDK-loading when config is incomplete.
//
// The SDK client construction lives in a separate buildSDKClient
// function (see sdk_client.go) so this package doesn't pull in the
// azcore + azidentity transitive deps when the connector is
// constructed via NewWithClient (the test path).
func New(ctx context.Context, cfg *Config, logger *slog.Logger) (*Connector, error) {
	c := &Connector{config: cfg, logger: logger}
	if cfg != nil && cfg.VaultURL != "" {
		client, err := buildSDKClient(ctx, cfg.VaultURL, cfg.CredentialMode)
		if err != nil {
			return nil, fmt.Errorf("Azure Key Vault SDK init: %w", err)
		}
		c.client = client
	}
	return c, nil
}

// NewWithClient creates a connector with a caller-supplied
// KeyVaultClient. Used by unit tests to inject a mock; production uses
// New.
func NewWithClient(cfg *Config, client KeyVaultClient, logger *slog.Logger) *Connector {
	return &Connector{config: cfg, client: client, logger: logger}
}

// ValidateConfig validates the Azure Key Vault deployment target
// configuration.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid Azure Key Vault config: %w", err)
	}
	if cfg.VaultURL == "" {
		return fmt.Errorf("Azure Key Vault vault_url is required")
	}
	if !vaultURLRegex.MatchString(cfg.VaultURL) {
		return fmt.Errorf("Azure Key Vault vault_url malformed (expected https://<name>.vault.azure.net): %q", cfg.VaultURL)
	}
	if cfg.CertificateName == "" {
		return fmt.Errorf("Azure Key Vault certificate_name is required")
	}
	if !certNameRegex.MatchString(cfg.CertificateName) {
		return fmt.Errorf("Azure Key Vault certificate_name malformed (expected 1-127 chars, alphanumeric + hyphens): %q", cfg.CertificateName)
	}

	switch cfg.CredentialMode {
	case "", CredModeDefault, CredModeManagedIdentity, CredModeClientSecret, CredModeWorkloadIdentity:
		// ok
	default:
		return fmt.Errorf("Azure Key Vault credential_mode invalid (expected default|managed_identity|client_secret|workload_identity): %q", cfg.CredentialMode)
	}

	for k := range cfg.Tags {
		if k == tagKeyManagedBy || k == tagKeyCertificateID {
			return fmt.Errorf("operator tags cannot use the reserved provenance key %q", k)
		}
	}

	c.config = &cfg
	c.logger.Info("Azure Key Vault configuration validated",
		"vault_url", cfg.VaultURL,
		"certificate_name", cfg.CertificateName,
		"credential_mode", cfg.CredentialMode,
	)

	if c.client == nil {
		client, err := buildSDKClient(ctx, cfg.VaultURL, cfg.CredentialMode)
		if err != nil {
			return fmt.Errorf("Azure Key Vault SDK init: %w", err)
		}
		c.client = client
	}
	return nil
}

// DeployCertificate imports the supplied cert+key+chain into Azure Key
// Vault as a new version under Config.CertificateName.
//
// Flow:
//
//  1. Build PFX (PKCS#12) bundle from cert + chain + key bytes.
//  2. Snapshot phase: GetCertificate(name, "" /* latest */) — capture
//     the previous version's CER bytes for rollback.
//  3. ImportCertificate(name, PFX, tags) — creates a new version.
//  4. Post-verify: GetCertificate(name, "" /* latest */) and compare
//     serial against expected.
//  5. On serial mismatch: roll back by re-importing the snapshot's
//     CER bytes (wrapped as PEM and re-PFX'd with the operator's key)
//     as another new version. Note: rollback creates a NEW version
//     (Key Vault doesn't let us truly restore the prior version
//     without soft-delete recovery, which we deliberately keep off
//     the minimum-RBAC surface).
//
// Cert key bytes (request.KeyPEM) are held in memory only — never
// written to disk. The DeploymentResult.Metadata captures the version
// ID + KID URI so App Gateway / Front Door references can be updated.
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	if c.client == nil {
		return nil, fmt.Errorf("Azure Key Vault client not initialized; ValidateConfig must be called first")
	}
	if c.config == nil {
		return nil, fmt.Errorf("Azure Key Vault config not loaded; ValidateConfig must be called first")
	}

	if request.CertPEM == "" {
		return nil, fmt.Errorf("Azure Key Vault: cert_pem is required")
	}
	if request.KeyPEM == "" {
		return nil, fmt.Errorf("Azure Key Vault: key_pem is required (the agent must supply the private key)")
	}

	expectedSerial, err := serialFromPEM([]byte(request.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("Azure Key Vault: failed to parse cert PEM: %w", err)
	}

	pfxB64, err := buildPFXBase64(request.CertPEM, request.ChainPEM, request.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("Azure Key Vault: failed to build PFX bundle: %w", err)
	}

	certctlCertID := metadataCertID(request.Metadata)
	tags := c.buildProvenanceTags(certctlCertID)

	// Snapshot phase — best-effort. If the cert doesn't exist yet
	// (first deploy) snapshot fails with a NotFound; we treat that
	// as "no previous version, nothing to roll back to" and proceed.
	var snapshotCER []byte
	if snap, sErr := c.client.GetCertificate(ctx, &GetCertificateInput{
		CertificateName: c.config.CertificateName,
	}); sErr == nil && snap != nil && len(snap.CERBytes) > 0 {
		snapshotCER = snap.CERBytes
	}

	// Import phase.
	importIn := &ImportCertificateInput{
		CertificateName: c.config.CertificateName,
		PFXBase64:       pfxB64,
		Tags:            tags,
	}
	importOut, importErr := c.client.ImportCertificate(ctx, importIn)
	if importErr != nil {
		return nil, fmt.Errorf("Azure Key Vault ImportCertificate failed: %w", importErr)
	}
	if importOut == nil || importOut.VersionID == "" {
		return nil, fmt.Errorf("Azure Key Vault ImportCertificate returned empty version ID")
	}

	// Post-verify: re-fetch latest version + compare serial.
	verifyOut, verifyErr := c.client.GetCertificate(ctx, &GetCertificateInput{
		CertificateName: c.config.CertificateName,
	})
	if verifyErr != nil {
		if len(snapshotCER) > 0 {
			c.attemptRollback(ctx, snapshotCER, request.KeyPEM, tags,
				fmt.Sprintf("post-verify GetCertificate failed: %v", verifyErr))
		}
		return nil, fmt.Errorf("Azure Key Vault post-verify GetCertificate failed: %w", verifyErr)
	}
	if !serialsEqual(verifyOut.Serial, expectedSerial) {
		if len(snapshotCER) > 0 {
			c.attemptRollback(ctx, snapshotCER, request.KeyPEM, tags,
				fmt.Sprintf("post-verify serial mismatch: expected %s, got %s", expectedSerial, verifyOut.Serial))
			return nil, fmt.Errorf("Azure Key Vault post-verify serial mismatch (rolled back): expected %s, got %s",
				expectedSerial, verifyOut.Serial)
		}
		return nil, fmt.Errorf("Azure Key Vault post-verify serial mismatch: expected %s, got %s",
			expectedSerial, verifyOut.Serial)
	}

	c.logger.Info("Azure Key Vault certificate deployed",
		"vault_url", c.config.VaultURL,
		"certificate_name", c.config.CertificateName,
		"version_id", importOut.VersionID,
		"serial", expectedSerial,
		"had_snapshot", len(snapshotCER) > 0,
	)

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: importOut.KID,
		DeploymentID:  importOut.VersionID,
		Message:       "Azure Key Vault ImportCertificate succeeded; post-verify serial match",
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"vault_url":        c.config.VaultURL,
			"certificate_name": c.config.CertificateName,
			"version_id":       importOut.VersionID,
			"kid":              importOut.KID,
		},
	}, nil
}

// attemptRollback re-imports the snapshotted CER bytes as a NEW version
// under the same certificate-name. Wraps the snapshot CER + the
// operator-supplied key into a fresh PFX (Key Vault import requires
// the key bound to the cert at import time; the SDK doesn't expose a
// "version-restore" API without soft-delete recovery).
//
// Rollback failure is logged ERROR but does NOT change the surfaced
// error shape — the caller already received the post-verify mismatch
// error.
func (c *Connector) attemptRollback(ctx context.Context, snapshotCER []byte, keyPEM string, tags map[string]string, reason string) {
	c.logger.Warn("Azure Key Vault deploy failed; attempting snapshot rollback",
		"certificate_name", c.config.CertificateName, "reason", reason,
	)
	// Re-wrap CER (DER) into PEM + bundle with the key as PFX.
	snapshotPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: snapshotCER})
	pfxB64, err := buildPFXBase64(string(snapshotPEM), "", keyPEM)
	if err != nil {
		c.logger.Error("Azure Key Vault rollback PFX build failed; cert state in vault is the failed-deploy version — operator must manually re-import the previous cert",
			"certificate_name", c.config.CertificateName, "error", err,
		)
		return
	}
	rollbackIn := &ImportCertificateInput{
		CertificateName: c.config.CertificateName,
		PFXBase64:       pfxB64,
		Tags:            tags, // includes provenance + a rollback marker would be V3-Pro
	}
	if _, rbErr := c.client.ImportCertificate(ctx, rollbackIn); rbErr != nil {
		c.logger.Error("Azure Key Vault rollback ImportCertificate also failed; cert state in vault is the failed-deploy version — operator must manually re-import the previous cert",
			"certificate_name", c.config.CertificateName, "rollback_error", rbErr,
		)
		return
	}
	c.logger.Warn("Azure Key Vault rollback succeeded; previous cert restored as new version",
		"certificate_name", c.config.CertificateName,
	)
}

// ValidateOnly returns ErrValidateOnlyNotSupported. Key Vault has no
// dry-run API for ImportCertificate. Operators preview deploys via
// ValidateConfig + an `az keyvault certificate show` round-trip.
func (c *Connector) ValidateOnly(ctx context.Context, request target.DeploymentRequest) error {
	return target.ErrValidateOnlyNotSupported
}

// ValidateDeployment confirms the live Key Vault cert at the
// configured (vault_url, certificate_name, latest version) matches
// the supplied serial.
func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	if c.client == nil {
		return nil, fmt.Errorf("Azure Key Vault client not initialized")
	}
	if c.config == nil {
		return nil, fmt.Errorf("Azure Key Vault config not loaded")
	}

	out, err := c.client.GetCertificate(ctx, &GetCertificateInput{
		CertificateName: c.config.CertificateName,
	})
	if err != nil {
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: c.config.VaultURL + "/certificates/" + c.config.CertificateName,
			Message:       fmt.Sprintf("GetCertificate failed: %v", err),
		}, nil
	}

	if !serialsEqual(out.Serial, request.Serial) {
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: c.config.VaultURL + "/certificates/" + c.config.CertificateName,
			Message: fmt.Sprintf("serial mismatch: expected %s, vault has %s",
				request.Serial, out.Serial),
		}, nil
	}

	return &target.ValidationResult{
		Valid:         true,
		Serial:        request.Serial,
		TargetAddress: c.config.VaultURL + "/certificates/" + c.config.CertificateName,
		Message:       "Key Vault cert serial matches expected",
	}, nil
}

// buildProvenanceTags constructs the certctl-managed-by + certctl-
// certificate-id tag pair, merged with operator-supplied tags from
// Config.Tags. The provenance pair always wins on key collision
// (rejected at ValidateConfig).
func (c *Connector) buildProvenanceTags(certctlCertID string) map[string]string {
	tags := map[string]string{tagKeyManagedBy: tagValueManagedBy}
	if certctlCertID != "" {
		tags[tagKeyCertificateID] = certctlCertID
	}
	for k, v := range c.config.Tags {
		if _, ok := tags[k]; !ok {
			tags[k] = v
		}
	}
	return tags
}

// buildPFXBase64 wraps the operator-supplied PEM cert + chain + key
// into a PKCS#12 PFX bundle and base64-encodes it. Key Vault's
// ImportCertificate accepts PFX+base64 as the wire format
// (Base64EncodedCertificate parameter). The PFX uses an empty
// password — the bundle bytes are ephemeral (in-memory only, passed
// straight to the SDK call) so a password adds no security.
func buildPFXBase64(certPEM, chainPEM, keyPEM string) (string, error) {
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return "", fmt.Errorf("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse cert: %w", err)
	}

	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return "", fmt.Errorf("failed to decode key PEM")
	}
	key, err := parsePrivateKey(keyBlock.Bytes, keyBlock.Type)
	if err != nil {
		return "", fmt.Errorf("failed to parse key: %w", err)
	}

	var caCerts []*x509.Certificate
	rest := []byte(chainPEM)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		ca, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			continue // skip un-parseable chain entries; Key Vault tolerates a thin chain
		}
		caCerts = append(caCerts, ca)
	}

	pfxBytes, err := pkcs12.Modern.Encode(key, cert, caCerts, "")
	if err != nil {
		return "", fmt.Errorf("failed to build PFX: %w", err)
	}

	return base64.StdEncoding.EncodeToString(pfxBytes), nil
}

// parsePrivateKey parses a PEM key block. Supports the three PEM
// types Go emits: "RSA PRIVATE KEY" (PKCS#1), "EC PRIVATE KEY" (SEC1),
// and "PRIVATE KEY" (PKCS#8). Mirrors what the AWS ACM connector's
// SDK accepts.
func parsePrivateKey(der []byte, blockType string) (interface{}, error) {
	switch blockType {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(der)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(der)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(der)
	default:
		// Try PKCS#8 as a fallback — some PEM blocks omit a typed header.
		if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
			return k, nil
		}
		return nil, fmt.Errorf("unknown PEM block type %q", blockType)
	}
}

// serialFromPEM mirrors the AWS ACM helper. Returns the serial in
// colon-separated lowercase hex matching Azure's serial-string output
// format from the SDK's Certificate response.
func serialFromPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse cert: %w", err)
	}
	hex := fmt.Sprintf("%x", cert.SerialNumber)
	if len(hex)%2 == 1 {
		hex = "0" + hex
	}
	var b strings.Builder
	for i := 0; i < len(hex); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hex[i : i+2])
	}
	return b.String(), nil
}

// serialsEqual normalises serial strings (strip colons, lowercase) and
// compares. Defends against Azure SDK occasionally emitting serials
// without colons.
func serialsEqual(a, b string) bool {
	norm := func(s string) string {
		return strings.ToLower(strings.ReplaceAll(s, ":", ""))
	}
	return norm(a) == norm(b)
}

// metadataCertID extracts the certctl-managed certificate ID from the
// deployment request's Metadata map. Mirrors the AWS ACM helper.
func metadataCertID(metadata map[string]string) string {
	if v, ok := metadata["certificate_id"]; ok {
		return v
	}
	if v, ok := metadata["certctl_certificate_id"]; ok {
		return v
	}
	return ""
}

// Compile-time assertion: *Connector implements target.Connector.
var _ target.Connector = (*Connector)(nil)
