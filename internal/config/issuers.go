// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package config

// Phase 9 ARCH-M2 closure Sprint 7 (2026-05-14): extracted from
// config.go. The LAST in-config cut of Phase 9. Sprint 7 collects
// the issuer-connector configurations — every external CA the local
// server talks UP to (StepCA, Vault, DigiCert, Sectigo, GoogleCAS,
// AWS ACM PCA, Entrust, GlobalSign, EJBCA, OpenSSL) plus the
// local CA mode + key-generation policy.
//
// Twelve structs move:
//
//   KeygenConfig       — global key-generation policy (Mode: "agent"
//                        production default, or "server" demo-only).
//   CAConfig           — Local CA mode: self-signed vs sub-CA
//                        (CertPath + KeyPath).
//   StepCAConfig       — step-ca issuer (URL + JWK provisioner).
//   VaultConfig        — HashiCorp Vault PKI (Addr + Token + Mount +
//                        Role + TTL).
//   DigiCertConfig     — DigiCert CertCentral (APIKey + OrgID +
//                        ProductType + BaseURL + PollMaxWait).
//   SectigoConfig      — Sectigo Certificate Manager (CustomerURI +
//                        Login + Password + OrgID + CertType + Term +
//                        BaseURL + PollMaxWait).
//   GoogleCASConfig    — Google Cloud CA Service (Project + Location +
//                        CAPool + Credentials + TTL).
//   AWSACMPCAConfig    — AWS ACM Private CA (Region + CAArn +
//                        SigningAlgorithm + ValidityDays +
//                        TemplateArn).
//   EntrustConfig      — Entrust Certificate Services (APIUrl + mTLS
//                        client cert/key + CAId + ProfileId +
//                        PollMaxWait).
//   GlobalSignConfig   — GlobalSign Atlas HVCA (APIUrl + APIKey +
//                        APISecret + mTLS client cert/key + ServerCA
//                        + PollMaxWait).
//   EJBCAConfig        — EJBCA / Keyfactor (APIUrl + AuthMode +
//                        mTLS / OAuth2 token + CAName + cert profile
//                        + EE profile).
//   OpenSSLConfig      — OpenSSL / custom CA (SignScript + RevokeScript
//                        + CRLScript + TimeoutSeconds).
//
// No helpers move. The bodies are pure-data field declarations —
// the simplest possible split shape since every issuer config
// struct uses only stdlib primitive types (string, int, bool) and
// no time.Duration, no nested struct, no helper-function reference.
// Verified by: `awk 'NR>=136 && NR<=269 || NR>=355 && NR<=527 ||
// NR>=586 && NR<=609' internal/config/config.go | grep -E '\btime\.
// |\bos\.|\bfmt\.'` → empty pre-move. issuers.go therefore needs
// ZERO imports beyond the package declaration.
//
// Edit shape
// ==========
// Sprint 7 used three independent sed deletes from highest-line to
// lowest-line (same pattern Sprint 6 introduced) because the 12
// issuer structs were SCATTERED across config.go interleaved with
// non-issuer types:
//
//   Block 1 (top of file, after Config + OCSPResponderConfig):
//     AWSACMPCAConfig (137) + EntrustConfig (168) +
//     GlobalSignConfig (199) + EJBCAConfig (236).
//     Followed by EncryptionConfig (271) — NOT an issuer; stays.
//
//   Block 2 (middle, after the discovery configs):
//     KeygenConfig (356) + CAConfig (367) + StepCAConfig (382) +
//     VaultConfig (401) + DigiCertConfig (429) + SectigoConfig (458) +
//     GoogleCASConfig (501).
//     Followed by DigestConfig (529) — notifier-policy; stays.
//
//   Block 3 (single, between HealthCheck and NetworkScan):
//     OpenSSLConfig (587).
//
// What stayed in config.go
// ========================
// - OCSPResponderConfig (114) — server-side OCSP responder, not
//   issuer-side; conceptually adjacent to ServerConfig (already
//   moved). Could be folded into server.go in a future cut; left
//   in place this sprint to keep the cut scope tight.
// - EncryptionConfig (271 pre-move) — config-at-rest encryption,
//   not issuer-side.
// - The cloud-discovery family (CloudDiscoveryConfig +
//   AWSSecretsMgrDiscoveryConfig + AzureKVDiscoveryConfig +
//   GCPSecretMgrDiscoveryConfig) — those are DISCOVERY sources,
//   not ISSUER connectors. Reading from cloud secret managers to
//   find certificates someone else issued; not signing.
// - DigestConfig + HealthCheckConfig — notifier/health-monitor
//   policy, not issuer-related.
// - NetworkScanConfig + VerificationConfig — discovery / verify,
//   not issuer-related.
// - ApprovalConfig — RBAC issuance-approval workflow; stays per
//   Sprint 6's reasoning.
// - All Load() / Validate() bodies that reference the moved
//   issuer-config types (cross-cutting validation logic stays
//   in config.go).
//
// Public-surface invariant
// ========================
// Every type, exported field, and doc-comment is byte-identical to
// pre-split. Package stays `config`. Every external caller of
// `config.AWSACMPCAConfig` / `config.EntrustConfig` /
// `config.KeygenConfig` / etc. resolves the same way. None of these
// types declare an exported method; the entire surface is fields,
// preserved verbatim.

// AWSACMPCAConfig contains AWS ACM Private CA issuer connector configuration.
type AWSACMPCAConfig struct {
	// Region is the AWS region where the Private CA resides (e.g., "us-east-1").
	// Required for AWS ACM PCA integration.
	// Setting: CERTCTL_AWS_PCA_REGION environment variable.
	Region string

	// CAArn is the ARN of the ACM Private CA certificate authority.
	// Format: arn:aws:acm-pca:<region>:<account>:certificate-authority/<id>
	// Required for AWS ACM PCA integration.
	// Setting: CERTCTL_AWS_PCA_CA_ARN environment variable.
	CAArn string

	// SigningAlgorithm is the signing algorithm for certificate issuance.
	// Valid: SHA256WITHRSA, SHA384WITHRSA, SHA512WITHRSA, SHA256WITHECDSA, SHA384WITHECDSA, SHA512WITHECDSA.
	// Default: "SHA256WITHRSA".
	// Setting: CERTCTL_AWS_PCA_SIGNING_ALGORITHM environment variable.
	SigningAlgorithm string

	// ValidityDays is the certificate validity period in days.
	// Default: 365.
	// Setting: CERTCTL_AWS_PCA_VALIDITY_DAYS environment variable.
	ValidityDays int

	// TemplateArn is the optional ARN of an ACM PCA certificate template.
	// Used for constrained subordinate CAs or custom certificate profiles.
	// Setting: CERTCTL_AWS_PCA_TEMPLATE_ARN environment variable.
	TemplateArn string
}

// EntrustConfig contains Entrust Certificate Services issuer connector configuration.
// Entrust uses mTLS client certificate authentication.
type EntrustConfig struct {
	// APIUrl is the Entrust CA Gateway base URL.
	// Setting: CERTCTL_ENTRUST_API_URL environment variable.
	APIUrl string

	// ClientCertPath is the path to the mTLS client certificate PEM file.
	// Setting: CERTCTL_ENTRUST_CLIENT_CERT_PATH environment variable.
	ClientCertPath string

	// ClientKeyPath is the path to the mTLS client private key PEM file.
	// Setting: CERTCTL_ENTRUST_CLIENT_KEY_PATH environment variable.
	ClientKeyPath string

	// CAId is the Entrust CA identifier.
	// Setting: CERTCTL_ENTRUST_CA_ID environment variable.
	CAId string

	// ProfileId is the optional enrollment profile identifier.
	// Setting: CERTCTL_ENTRUST_PROFILE_ID environment variable.
	ProfileId string

	// PollMaxWaitSeconds caps GetOrderStatus's bounded-polling
	// deadline. Approval-pending workflows should bump this (e.g.,
	// 86400 = 24h) so a single tick can wait through the approval
	// window. Default 600. Audit fix #5.
	// Setting: CERTCTL_ENTRUST_POLL_MAX_WAIT_SECONDS.
	PollMaxWaitSeconds int
}

// GlobalSignConfig contains GlobalSign Atlas HVCA issuer connector configuration.
// GlobalSign uses mTLS client certificate authentication plus API key/secret headers.
type GlobalSignConfig struct {
	// APIUrl is the GlobalSign Atlas HVCA base URL (region-aware).
	// Setting: CERTCTL_GLOBALSIGN_API_URL environment variable.
	APIUrl string

	// APIKey is the GlobalSign API key.
	// Setting: CERTCTL_GLOBALSIGN_API_KEY environment variable.
	APIKey string

	// APISecret is the GlobalSign API secret.
	// Setting: CERTCTL_GLOBALSIGN_API_SECRET environment variable.
	APISecret string

	// ClientCertPath is the path to the mTLS client certificate PEM file.
	// Setting: CERTCTL_GLOBALSIGN_CLIENT_CERT_PATH environment variable.
	ClientCertPath string

	// ClientKeyPath is the path to the mTLS client private key PEM file.
	// Setting: CERTCTL_GLOBALSIGN_CLIENT_KEY_PATH environment variable.
	ClientKeyPath string

	// ServerCAPath is the optional path to a PEM file containing the CA
	// certificate(s) used to verify the GlobalSign Atlas HVCA API server
	// certificate. If empty, the system trust store is used. Set this
	// for private/lab Atlas deployments whose server TLS chain is not
	// present in the host's default trust bundle.
	// Setting: CERTCTL_GLOBALSIGN_SERVER_CA_PATH environment variable.
	ServerCAPath string

	// PollMaxWaitSeconds caps GetOrderStatus's bounded-polling
	// deadline. Default 600 (10 minutes). Audit fix #5.
	// Setting: CERTCTL_GLOBALSIGN_POLL_MAX_WAIT_SECONDS.
	PollMaxWaitSeconds int
}

// EJBCAConfig contains EJBCA (Keyfactor) issuer connector configuration.
// EJBCA supports dual authentication: mTLS or OAuth2 Bearer token.
type EJBCAConfig struct {
	// APIUrl is the EJBCA REST API base URL.
	// Setting: CERTCTL_EJBCA_API_URL environment variable.
	APIUrl string

	// AuthMode selects the authentication method: "mtls" or "oauth2". Default: "mtls".
	// Setting: CERTCTL_EJBCA_AUTH_MODE environment variable.
	AuthMode string

	// ClientCertPath is the path to the mTLS client certificate PEM file (required when auth_mode=mtls).
	// Setting: CERTCTL_EJBCA_CLIENT_CERT_PATH environment variable.
	ClientCertPath string

	// ClientKeyPath is the path to the mTLS client private key PEM file (required when auth_mode=mtls).
	// Setting: CERTCTL_EJBCA_CLIENT_KEY_PATH environment variable.
	ClientKeyPath string

	// Token is the OAuth2 Bearer token (required when auth_mode=oauth2).
	// Setting: CERTCTL_EJBCA_TOKEN environment variable.
	Token string

	// CAName is the EJBCA CA name. Required.
	// Setting: CERTCTL_EJBCA_CA_NAME environment variable.
	CAName string

	// CertProfile is the optional EJBCA certificate profile name.
	// Setting: CERTCTL_EJBCA_CERT_PROFILE environment variable.
	CertProfile string

	// EEProfile is the optional EJBCA end-entity profile name.
	// Setting: CERTCTL_EJBCA_EE_PROFILE environment variable.
	EEProfile string
}

// KeygenConfig controls where private keys are generated.
type KeygenConfig struct {
	// Mode determines where certificate private keys are generated.
	// Valid values: "agent" (default, production) or "server" (demo only).
	// In "agent" mode, renewal/issuance jobs enter AwaitingCSR state and agents
	// generate ECDSA P-256 keys locally. Private keys never leave agent infrastructure.
	// In "server" mode, the control plane generates RSA keys — demo only, not for production
	// as private keys touch the server. Requires explicit opt-in.
	Mode string
}

// CAConfig controls the Local CA's operating mode.
type CAConfig struct {
	// CertPath is the path to a PEM-encoded CA certificate for sub-CA mode.
	// When set with KeyPath, the Local CA loads this cert instead of generating a self-signed root.
	// Required: sub-CA mode must have both CertPath and KeyPath set.
	// Optional: leave empty for self-signed mode (development/demo). Path must be absolute.
	CertPath string

	// KeyPath is the path to a PEM-encoded CA private key for sub-CA mode.
	// Supports RSA, ECDSA, and PKCS#8 encoded keys.
	// Required: must be set together with CertPath for sub-CA mode.
	// Optional: leave empty for self-signed mode (development/demo). Path must be absolute.
	KeyPath string
}

// StepCAConfig contains step-ca issuer connector configuration.
type StepCAConfig struct {
	// URL is the base URL of the step-ca server.
	// Example: "https://ca.example.com:9000". Required for step-ca integration.
	URL string

	// ProvisionerName is the name of the JWK provisioner configured in step-ca.
	// Used to select which provisioner signs the certificate requests.
	ProvisionerName string

	// ProvisionerKeyPath is the path to the PEM-encoded JWK provisioner private key.
	// Authenticates with the step-ca /sign API. Must be absolute path.
	ProvisionerKeyPath string

	// ProvisionerPassword is the optional password for the provisioner private key.
	// Leave empty if the key file is not encrypted.
	ProvisionerPassword string
}

// VaultConfig contains HashiCorp Vault PKI issuer connector configuration.
type VaultConfig struct {
	// Addr is the Vault server address (e.g., "https://vault.example.com:8200").
	// Required for Vault PKI integration.
	// Setting: CERTCTL_VAULT_ADDR environment variable.
	Addr string

	// Token is the Vault token for authentication.
	// Required for Vault PKI integration.
	// Setting: CERTCTL_VAULT_TOKEN environment variable.
	Token string

	// Mount is the PKI secrets engine mount path.
	// Default: "pki".
	// Setting: CERTCTL_VAULT_MOUNT environment variable.
	Mount string

	// Role is the PKI role name used for signing certificates.
	// Required for Vault PKI integration.
	// Setting: CERTCTL_VAULT_ROLE environment variable.
	Role string

	// TTL is the requested certificate time-to-live.
	// Default: "8760h" (1 year).
	// Setting: CERTCTL_VAULT_TTL environment variable.
	TTL string
}

// DigiCertConfig contains DigiCert CertCentral issuer connector configuration.
type DigiCertConfig struct {
	// APIKey is the CertCentral API key for authentication.
	// Required for DigiCert integration.
	// Setting: CERTCTL_DIGICERT_API_KEY environment variable.
	APIKey string

	// OrgID is the DigiCert organization ID for certificate orders.
	// Required for DigiCert integration.
	// Setting: CERTCTL_DIGICERT_ORG_ID environment variable.
	OrgID string

	// ProductType is the DigiCert product type for certificate orders.
	// Default: "ssl_basic". Common values: "ssl_basic", "ssl_wildcard", "ssl_ev_basic".
	// Setting: CERTCTL_DIGICERT_PRODUCT_TYPE environment variable.
	ProductType string

	// BaseURL is the DigiCert CertCentral API base URL.
	// Default: "https://www.digicert.com/services/v2".
	// Setting: CERTCTL_DIGICERT_BASE_URL environment variable.
	BaseURL string

	// PollMaxWaitSeconds caps how long GetOrderStatus blocks doing
	// internal exponential-backoff polling before returning. Default
	// 600 (10 minutes); 0 falls back to asyncpoll default.
	// Setting: CERTCTL_DIGICERT_POLL_MAX_WAIT_SECONDS. Audit fix #5.
	PollMaxWaitSeconds int
}

// SectigoConfig contains Sectigo Certificate Manager issuer connector configuration.
type SectigoConfig struct {
	// CustomerURI is the Sectigo customer URI (organization identifier).
	// Required for Sectigo integration.
	// Setting: CERTCTL_SECTIGO_CUSTOMER_URI environment variable.
	CustomerURI string

	// Login is the Sectigo API account login.
	// Required for Sectigo integration.
	// Setting: CERTCTL_SECTIGO_LOGIN environment variable.
	Login string

	// Password is the Sectigo API account password or API key.
	// Required for Sectigo integration.
	// Setting: CERTCTL_SECTIGO_PASSWORD environment variable.
	Password string

	// OrgID is the Sectigo organization ID for certificate enrollments.
	// Required for Sectigo integration.
	// Setting: CERTCTL_SECTIGO_ORG_ID environment variable.
	OrgID int

	// CertType is the Sectigo certificate type ID (from GET /ssl/v1/types).
	// Required for enrollment. Set via CERTCTL_SECTIGO_CERT_TYPE environment variable.
	CertType int

	// Term is the certificate validity in days (e.g., 365, 730).
	// Default: 365.
	// Setting: CERTCTL_SECTIGO_TERM environment variable.
	Term int

	// BaseURL is the Sectigo SCM API base URL.
	// Default: "https://cert-manager.com/api".
	// Setting: CERTCTL_SECTIGO_BASE_URL environment variable.
	BaseURL string

	// PollMaxWaitSeconds caps how long GetOrderStatus blocks doing
	// internal exponential-backoff polling. Default 600. Sectigo's
	// collectNotReady sentinel rides the backoff schedule.
	// Setting: CERTCTL_SECTIGO_POLL_MAX_WAIT_SECONDS. Audit fix #5.
	PollMaxWaitSeconds int
}

// GoogleCASConfig contains Google Cloud Certificate Authority Service configuration.
type GoogleCASConfig struct {
	// Project is the GCP project ID.
	// Required for Google CAS integration.
	// Setting: CERTCTL_GOOGLE_CAS_PROJECT environment variable.
	Project string

	// Location is the GCP region (e.g., "us-central1").
	// Required for Google CAS integration.
	// Setting: CERTCTL_GOOGLE_CAS_LOCATION environment variable.
	Location string

	// CAPool is the Certificate Authority pool name.
	// Required for Google CAS integration.
	// Setting: CERTCTL_GOOGLE_CAS_CA_POOL environment variable.
	CAPool string

	// Credentials is the path to the service account JSON credentials file.
	// Required for Google CAS integration.
	// Setting: CERTCTL_GOOGLE_CAS_CREDENTIALS environment variable.
	Credentials string

	// TTL is the default certificate time-to-live.
	// Default: "8760h" (1 year).
	// Setting: CERTCTL_GOOGLE_CAS_TTL environment variable.
	TTL string
}

// OpenSSLConfig contains OpenSSL/Custom CA issuer connector configuration.
type OpenSSLConfig struct {
	// SignScript is the path to a shell script that signs certificate requests.
	// Script receives: CSR_PATH, COMMON_NAME, OUTPUT_CERT_PATH as env vars.
	// Must output the signed certificate PEM to OUTPUT_CERT_PATH.
	// Example: /opt/ca-scripts/sign.sh
	SignScript string

	// RevokeScript is the path to a shell script that revokes certificates.
	// Script receives: SERIAL_NUMBER, REASON_CODE as env vars.
	// Best-effort: script failures do not block revocation recording.
	// Leave empty if revocation is not supported by the custom CA.
	RevokeScript string

	// CRLScript is the path to a shell script that generates CRL (Certificate Revocation List).
	// Script should output the DER-encoded CRL to stdout.
	// Leave empty if CRL generation is not supported by the custom CA.
	CRLScript string

	// TimeoutSeconds is the maximum execution time for any shell script invocation.
	// Default: 30 seconds. Prevents hung processes from blocking certificate operations.
	TimeoutSeconds int
}
