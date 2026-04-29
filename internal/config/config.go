package config

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config represents the complete application configuration.
// All configuration values are read from environment variables with CERTCTL_ prefix.
type Config struct {
	Server         ServerConfig
	Database       DatabaseConfig
	Scheduler      SchedulerConfig
	Log            LogConfig
	Auth           AuthConfig
	RateLimit      RateLimitConfig
	CORS           CORSConfig
	Keygen         KeygenConfig
	CA             CAConfig
	Notifiers      NotifierConfig
	NetworkScan    NetworkScanConfig
	EST            ESTConfig
	SCEP           SCEPConfig
	Verification   VerificationConfig
	ACME           ACMEConfig
	Vault          VaultConfig
	DigiCert       DigiCertConfig
	Sectigo        SectigoConfig
	GoogleCAS      GoogleCASConfig
	AWSACMPCA      AWSACMPCAConfig
	Entrust        EntrustConfig
	GlobalSign     GlobalSignConfig
	EJBCA          EJBCAConfig
	Digest         DigestConfig
	HealthCheck    HealthCheckConfig
	Encryption     EncryptionConfig
	CloudDiscovery CloudDiscoveryConfig
	OCSPResponder  OCSPResponderConfig
}

// OCSPResponderConfig configures the dedicated OCSP-responder cert
// per issuer (RFC 6960 §2.6 + §4.2.2.2). When unset, the local issuer
// falls back to signing OCSP responses with the CA key directly.
//
// Bundle CRL/OCSP-Responder Phase 2.
type OCSPResponderConfig struct {
	// KeyDir is the filesystem directory where FileDriver-backed
	// responder keys are written. Operators MUST set this in
	// production (the default of "" maps to cwd, which is fine for
	// tests but not for serious deployments).
	// Setting: CERTCTL_OCSP_RESPONDER_KEY_DIR.
	KeyDir string

	// RotationGrace is the window before NotAfter at which the
	// responder cert is rotated. Default: 7 days. Operators with
	// stricter relying-party caching expectations may shorten;
	// operators with looser ones may lengthen.
	// Setting: CERTCTL_OCSP_RESPONDER_ROTATION_GRACE.
	RotationGrace time.Duration

	// Validity is how long a freshly-bootstrapped responder cert is
	// valid for. Default: 30 days. Shorter validity means more
	// frequent rotations + smaller revocation-list windows.
	// Setting: CERTCTL_OCSP_RESPONDER_VALIDITY.
	Validity time.Duration
}

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

// EncryptionConfig contains configuration for encrypting sensitive data at rest.
type EncryptionConfig struct {
	// ConfigEncryptionKey is the passphrase used to derive AES-256-GCM keys for encrypting
	// issuer config secrets in the database. If empty, configs are stored in plaintext (development only).
	ConfigEncryptionKey string
}

// CloudDiscoveryConfig contains configuration for cloud secret manager discovery sources.
// Each source is enabled by setting its required env var(s).
type CloudDiscoveryConfig struct {
	// Enabled controls whether cloud discovery sources run on a schedule.
	// Default: false. Setting: CERTCTL_CLOUD_DISCOVERY_ENABLED.
	Enabled bool

	// Interval is the scheduler loop interval for cloud discovery.
	// Default: 6 hours. Setting: CERTCTL_CLOUD_DISCOVERY_INTERVAL.
	Interval time.Duration

	// AWS Secrets Manager discovery
	AWSSM AWSSecretsMgrDiscoveryConfig

	// Azure Key Vault discovery
	AzureKV AzureKVDiscoveryConfig

	// GCP Secret Manager discovery
	GCPSM GCPSecretMgrDiscoveryConfig
}

// AWSSecretsMgrDiscoveryConfig contains AWS Secrets Manager discovery settings.
type AWSSecretsMgrDiscoveryConfig struct {
	// Enabled controls whether AWS SM discovery is active.
	// Default: false. Setting: CERTCTL_AWS_SM_DISCOVERY_ENABLED.
	Enabled bool

	// Region is the AWS region to scan (e.g., "us-east-1").
	// Setting: CERTCTL_AWS_SM_REGION.
	Region string

	// TagFilter is the tag key=value used to identify certificate secrets.
	// Default: "type=certificate". Setting: CERTCTL_AWS_SM_TAG_FILTER.
	TagFilter string

	// NamePrefix filters secrets by name prefix (optional).
	// Setting: CERTCTL_AWS_SM_NAME_PREFIX.
	NamePrefix string
}

// AzureKVDiscoveryConfig contains Azure Key Vault discovery settings.
type AzureKVDiscoveryConfig struct {
	// Enabled controls whether Azure KV discovery is active.
	// Default: false. Setting: CERTCTL_AZURE_KV_DISCOVERY_ENABLED.
	Enabled bool

	// VaultURL is the Azure Key Vault URL (e.g., "https://myvault.vault.azure.net").
	// Setting: CERTCTL_AZURE_KV_VAULT_URL.
	VaultURL string

	// TenantID is the Azure AD tenant ID.
	// Setting: CERTCTL_AZURE_KV_TENANT_ID.
	TenantID string

	// ClientID is the Azure AD application (client) ID.
	// Setting: CERTCTL_AZURE_KV_CLIENT_ID.
	ClientID string

	// ClientSecret is the Azure AD application secret.
	// Setting: CERTCTL_AZURE_KV_CLIENT_SECRET.
	ClientSecret string
}

// GCPSecretMgrDiscoveryConfig contains GCP Secret Manager discovery settings.
type GCPSecretMgrDiscoveryConfig struct {
	// Enabled controls whether GCP SM discovery is active.
	// Default: false. Setting: CERTCTL_GCP_SM_DISCOVERY_ENABLED.
	Enabled bool

	// Project is the GCP project ID.
	// Setting: CERTCTL_GCP_SM_PROJECT.
	Project string

	// Credentials is the path to the GCP service account JSON file.
	// Setting: CERTCTL_GCP_SM_CREDENTIALS.
	Credentials string
}

// NotifierConfig contains configuration for notification connectors.
// Each notifier is enabled by setting its required env var (webhook URL or API key).
type NotifierConfig struct {
	// SlackWebhookURL is the incoming webhook URL for Slack notifications.
	// Format: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
	// Optional: leave empty to disable Slack notifications.
	SlackWebhookURL string

	// SlackChannel optionally overrides the default channel in the Slack webhook.
	// Example: "#alerts" or "@user". Leave empty to use webhook's default channel.
	SlackChannel string

	// SlackUsername sets the display name for Slack bot messages.
	// Default: "certctl". Used in webhook message formatting.
	SlackUsername string

	// TeamsWebhookURL is the incoming webhook URL for Microsoft Teams notifications.
	// Format: https://outlook.webhook.office.com/webhookb2/...
	// Optional: leave empty to disable Teams notifications.
	TeamsWebhookURL string

	// PagerDutyRoutingKey is the integration key for PagerDuty Events API v2.
	// Obtain from PagerDuty integration settings.
	// Optional: leave empty to disable PagerDuty notifications.
	PagerDutyRoutingKey string

	// PagerDutySeverity sets the default severity level for PagerDuty events.
	// Valid values: "info", "warning", "error", "critical". Default: "warning".
	PagerDutySeverity string

	// OpsGenieAPIKey is the API key for OpsGenie Alert API v2.
	// Obtain from OpsGenie organization settings.
	// Optional: leave empty to disable OpsGenie notifications.
	OpsGenieAPIKey string

	// OpsGeniePriority sets the default priority for OpsGenie alerts.
	// Valid values: "P1", "P2", "P3", "P4", "P5". Default: "P3".
	OpsGeniePriority string

	// SMTPHost is the SMTP server hostname for sending email notifications.
	// Example: "smtp.gmail.com", "smtp.sendgrid.net". Required for email notifications.
	// Setting: CERTCTL_SMTP_HOST environment variable.
	SMTPHost string

	// SMTPPort is the SMTP server port. Default: 587 (STARTTLS).
	// Common values: 25 (plain), 465 (implicit TLS), 587 (STARTTLS).
	// Setting: CERTCTL_SMTP_PORT environment variable.
	SMTPPort int

	// SMTPUsername is the SMTP authentication username.
	// Setting: CERTCTL_SMTP_USERNAME environment variable.
	SMTPUsername string

	// SMTPPassword is the SMTP authentication password or app-specific password.
	// Setting: CERTCTL_SMTP_PASSWORD environment variable.
	SMTPPassword string

	// SMTPFromAddress is the sender email address for outbound notifications.
	// Example: "certctl@example.com", "noreply@company.com".
	// Setting: CERTCTL_SMTP_FROM_ADDRESS environment variable.
	SMTPFromAddress string

	// SMTPUseTLS enables TLS for the SMTP connection.
	// Default: true. Set to false for plain SMTP (not recommended).
	// Setting: CERTCTL_SMTP_USE_TLS environment variable.
	SMTPUseTLS bool
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

// DigestConfig controls the scheduled certificate digest email feature.
type DigestConfig struct {
	// Enabled controls whether periodic digest emails are generated and sent.
	// Default: false. When enabled, requires SMTP to be configured.
	// Setting: CERTCTL_DIGEST_ENABLED environment variable.
	Enabled bool

	// Interval is how often digest emails are generated and sent.
	// Default: 24 hours. Minimum: 1 hour.
	// Setting: CERTCTL_DIGEST_INTERVAL environment variable.
	Interval time.Duration

	// Recipients is a comma-separated list of email addresses to receive digest emails.
	// If empty, digests are sent to all certificate owners.
	// Setting: CERTCTL_DIGEST_RECIPIENTS environment variable.
	Recipients []string
}

// HealthCheckConfig contains configuration for continuous TLS health monitoring (M48).
type HealthCheckConfig struct {
	// Enabled controls whether health checks are enabled.
	// Default: false.
	// Setting: CERTCTL_HEALTH_CHECK_ENABLED environment variable.
	Enabled bool

	// CheckInterval is the main scheduler loop interval for polling due checks.
	// Default: 60 seconds. Each endpoint has its own check_interval_seconds.
	// Setting: CERTCTL_HEALTH_CHECK_INTERVAL environment variable.
	CheckInterval time.Duration

	// DefaultInterval is the default probe interval in seconds for each endpoint (per-endpoint basis).
	// Default: 300 seconds (5 minutes).
	// Setting: CERTCTL_HEALTH_CHECK_DEFAULT_INTERVAL environment variable.
	DefaultInterval int

	// DefaultTimeout is the default TLS connection timeout in milliseconds.
	// Default: 5000 milliseconds (5 seconds).
	// Setting: CERTCTL_HEALTH_CHECK_DEFAULT_TIMEOUT environment variable.
	DefaultTimeout int

	// MaxConcurrent is the maximum number of concurrent TLS probes.
	// Default: 20.
	// Setting: CERTCTL_HEALTH_CHECK_MAX_CONCURRENT environment variable.
	MaxConcurrent int

	// HistoryRetention controls how long probe history records are kept.
	// Default: 30 days. Older records are purged by the scheduler.
	// Setting: CERTCTL_HEALTH_CHECK_HISTORY_RETENTION environment variable.
	HistoryRetention time.Duration

	// AutoCreate controls whether health checks are auto-created when:
	// - A deployment job completes with verification success
	// - A network scan target has health_check_enabled=true
	// Default: true.
	// Setting: CERTCTL_HEALTH_CHECK_AUTO_CREATE environment variable.
	AutoCreate bool
}

// ACMEConfig contains ACME issuer connector configuration.
type ACMEConfig struct {
	// DirectoryURL is the ACME directory URL for certificate issuance.
	// Examples: "https://acme-v02.api.letsencrypt.org/directory" (Let's Encrypt),
	// "https://acme.zerossl.com/v2/DV90" (ZeroSSL), or custom CA directory.
	DirectoryURL string

	// Email is the email address for ACME account registration.
	// Used for certificate expiration notices and account recovery by ACME CA.
	Email string

	// ChallengeType selects the ACME challenge mechanism for domain validation.
	// Valid values: "http-01" (default, requires public HTTP endpoint),
	// "dns-01" (DNS TXT record per renewal), or "dns-persist-01" (standing DNS record).
	// Default: "http-01".
	ChallengeType string

	// DNSPresentScript is the path to a shell script that creates DNS TXT records.
	// Required for dns-01 and dns-persist-01 challenge types.
	// Script receives these environment variables:
	// - CERTCTL_DNS_DOMAIN: domain being validated (e.g., "example.com")
	// - CERTCTL_DNS_FQDN: full record name (e.g., "_acme-challenge.example.com" or "_validation-persist.example.com")
	// - CERTCTL_DNS_VALUE: TXT record value (key authorization digest for dns-01, or issuer domain info for dns-persist-01)
	// - CERTCTL_DNS_TOKEN: ACME challenge token
	// Example: /opt/dns-scripts/add-record.sh
	DNSPresentScript string

	// DNSCleanUpScript is the path to a shell script that removes DNS TXT records.
	// Used only for dns-01 challenges to clean up temporary validation records.
	// Script receives the same environment variables as DNSPresentScript.
	// Leave empty if cleanup is not needed (e.g., dns-persist-01).
	DNSCleanUpScript string

	// DNSPersistIssuerDomain is the issuer domain for dns-persist-01 standing records.
	// Example: "letsencrypt.org" or "zerossl.com". Only used if ChallengeType is "dns-persist-01".
	// The record value becomes: "<issuer_domain>; accounturi=<acme_account_uri>"
	DNSPersistIssuerDomain string

	// Profile selects the ACME certificate profile for newOrder requests.
	// Let's Encrypt supports "tlsserver" (standard TLS) and "shortlived" (6-day certs).
	// Leave empty for the CA's default profile (backward-compatible).
	// Setting: CERTCTL_ACME_PROFILE environment variable.
	Profile string

	// ARIEnabled enables ACME Renewal Information (RFC 9773) support.
	// When enabled, the renewal scheduler queries the CA for suggested renewal windows
	// instead of relying solely on static expiration thresholds.
	// Default: false. Requires a CA that supports ARI (e.g., Let's Encrypt).
	// Setting: CERTCTL_ACME_ARI_ENABLED environment variable.
	ARIEnabled bool

	// Insecure skips TLS certificate verification when connecting to the ACME directory.
	// Only use for testing with self-signed ACME servers like Pebble. Never in production.
	// Setting: CERTCTL_ACME_INSECURE environment variable.
	Insecure bool
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

// ESTConfig controls the RFC 7030 Enrollment over Secure Transport server.
type ESTConfig struct {
	// Enabled controls whether EST endpoints are available for device enrollment.
	// Default: false (EST disabled). Set to true to enable RFC 7030 endpoints
	// under /.well-known/est/ (cacerts, simpleenroll, simplereenroll, csrattrs).
	Enabled bool

	// IssuerID selects which issuer connector processes EST certificate requests.
	// Valid values: "iss-local" (default), "iss-acme", "iss-stepca", "iss-openssl".
	// Default: "iss-local". Must reference a configured issuer.
	IssuerID string

	// ProfileID optionally constrains EST enrollments to a specific certificate profile.
	// When set, all EST enrollments must match the profile's crypto constraints.
	// Leave empty to allow EST to use any configured issuer's defaults.
	ProfileID string
}

// SCEPConfig controls the RFC 8894 Simple Certificate Enrollment Protocol server.
type SCEPConfig struct {
	// Enabled controls whether SCEP endpoints are available for device enrollment.
	// Default: false (SCEP disabled). Set to true to enable SCEP endpoints under /scep/.
	Enabled bool

	// IssuerID selects which issuer connector processes SCEP certificate requests.
	// Default: "iss-local". Must reference a configured issuer.
	IssuerID string

	// ProfileID optionally constrains SCEP enrollments to a specific certificate profile.
	// Leave empty to allow SCEP to use any configured issuer's defaults.
	ProfileID string

	// ChallengePassword is the shared secret used to authenticate SCEP enrollment requests.
	// Clients include this in the PKCS#10 CSR challengePassword attribute.
	//
	// REQUIRED when Enabled is true. Config.Validate() below refuses to start the
	// server if SCEP is enabled and this value is empty (H-2, CWE-306): post-M-001
	// under option (D), the /scep endpoint rides the no-auth middleware chain per
	// RFC 8894 §3.2, so the challenge password is the sole application-layer
	// authentication boundary for SCEP enrollment. An empty shared secret would
	// allow any client that can reach /scep to enroll a CSR against the configured
	// issuer. The service-layer PKCSReq path also rejects this configuration
	// defense-in-depth.
	ChallengePassword string
}

// NetworkScanConfig controls the server-side active TLS scanner.
type NetworkScanConfig struct {
	Enabled      bool          // Enable network scanning (default false)
	ScanInterval time.Duration // How often to run network scans (default 6h)
}

// VerificationConfig controls post-deployment TLS verification behavior.
type VerificationConfig struct {
	Enabled bool          // Enable verification (default true)
	Timeout time.Duration // Timeout for TLS probe (default 10s)
	Delay   time.Duration // Wait before verification after deployment (default 2s)
}

// ServerConfig contains HTTP server configuration.
type ServerConfig struct {
	Host        string          // Server host (default: 127.0.0.1). Set via CERTCTL_SERVER_HOST.
	Port        int             // Server port (default: 8080). Set via CERTCTL_SERVER_PORT.
	MaxBodySize int64           // Maximum request body size in bytes (default: 1MB). Set via CERTCTL_MAX_BODY_SIZE.
	TLS         ServerTLSConfig // HTTPS-only TLS configuration. Both CertPath and KeyPath are required.

	// AuditFlushTimeoutSeconds is the budget (in seconds) main.go gives the
	// audit middleware to drain in-flight recordings during graceful
	// shutdown. Bundle-5 / Audit M-011: pre-Bundle-5 this was hard-coded
	// 30s, which dropped events silently in high-volume environments
	// because the same context governed HTTP server shutdown + audit
	// flush. Post-Bundle-5: configurable; default 30s preserves prior
	// behaviour. WARN-log on deadline exceeded, but never exit hard.
	// Setting: CERTCTL_AUDIT_FLUSH_TIMEOUT_SECONDS environment variable.
	AuditFlushTimeoutSeconds int
}

// ServerTLSConfig holds the server-side TLS material.
//
// The control plane is HTTPS-only as of the HTTPS-everywhere milestone
// (§3 locked decisions: no `http` mode, no dual-listener, TLS 1.3 only).
// Both CertPath and KeyPath are required; an empty value causes
// Config.Validate() to return a fail-loud error and the server refuses
// to start. There is no plaintext HTTP fallback, no N-release migration
// bridge, and no auto-generated self-signed cert — operators either
// supply a cert on disk (docker-compose init container, operator-managed
// file, cert-manager mount) or the process exits non-zero.
type ServerTLSConfig struct {
	// CertPath is the filesystem path to the server's PEM-encoded X.509
	// certificate. Set via CERTCTL_SERVER_TLS_CERT_PATH. Required.
	CertPath string

	// KeyPath is the filesystem path to the server's PEM-encoded private
	// key that signs CertPath. Set via CERTCTL_SERVER_TLS_KEY_PATH. Required.
	KeyPath string
}

// DatabaseConfig contains database connection configuration.
type DatabaseConfig struct {
	URL            string
	MaxConnections int
	MigrationsPath string

	// DemoSeed, when true, makes the server apply
	// `<MigrationsPath>/seed_demo.sql` after the baseline `seed.sql`. Set
	// via CERTCTL_DEMO_SEED. The compose demo overlay
	// (deploy/docker-compose.demo.yml) sets this to keep the demo path
	// alive after U-3 dropped initdb-mounted seed files. The seed file
	// uses ON CONFLICT (id) DO NOTHING so re-running on a populated
	// database is safe; missing-file is a no-op (returns nil) so a
	// minimal-image deploy that strips seed_demo.sql still boots cleanly.
	DemoSeed bool
}

// SchedulerConfig contains scheduler timing configuration.
type SchedulerConfig struct {
	// RenewalCheckInterval is how often the renewal scheduler checks for expiring certs.
	// Default: 1 hour. Minimum: 1 minute. Certs are flagged for renewal at configured thresholds.
	// Setting: CERTCTL_SCHEDULER_RENEWAL_CHECK_INTERVAL environment variable.
	RenewalCheckInterval time.Duration

	// JobProcessorInterval is how often the job scheduler processes pending jobs.
	// Default: 30 seconds. Minimum: 1 second. Controls issuance, renewal, and deployment latency.
	// Setting: CERTCTL_SCHEDULER_JOB_PROCESSOR_INTERVAL environment variable.
	JobProcessorInterval time.Duration

	// AgentHealthCheckInterval is how often the scheduler checks agent heartbeats.
	// Default: 2 minutes. Minimum: 1 second. Marks agents offline if no recent heartbeat.
	// Setting: CERTCTL_SCHEDULER_AGENT_HEALTH_CHECK_INTERVAL environment variable.
	AgentHealthCheckInterval time.Duration

	// NotificationProcessInterval is how often the scheduler processes pending notifications.
	// Default: 1 minute. Minimum: 1 second. Sends notifications to Slack, Teams, PagerDuty, etc.
	// Setting: CERTCTL_SCHEDULER_NOTIFICATION_PROCESS_INTERVAL environment variable.
	NotificationProcessInterval time.Duration

	// NotificationRetryInterval is how often the scheduler retries failed
	// notifications whose retry_count is below the service-layer 5-attempt
	// DLQ budget. Default: 2 minutes. Minimum: 1 second. Mirrors the I-001
	// RetryInterval knob: transitions eligible Failed notifications whose
	// next_retry_at has arrived back to Pending so the notification processor
	// picks them up on its next tick (closes coverage gap I-005 — HEAD had
	// no retry path for transient SMTP/webhook failures and notifications
	// stayed Failed forever).
	// Setting: CERTCTL_NOTIFICATION_RETRY_INTERVAL environment variable.
	NotificationRetryInterval time.Duration

	// RetryInterval is how often the scheduler retries failed jobs whose Attempts
	// counter is below MaxAttempts. Default: 5 minutes. Minimum: 1 second.
	// Transitions eligible Failed jobs back to Pending so the job processor can
	// pick them up again (closes coverage gap I-001 — JobService.RetryFailedJobs
	// had no caller prior to this loop being wired).
	// Setting: CERTCTL_SCHEDULER_RETRY_INTERVAL environment variable.
	RetryInterval time.Duration

	// JobTimeoutInterval is how often the reaper loop sweeps AwaitingCSR and
	// AwaitingApproval jobs for TTL expiration. Default: 10 minutes. Minimum: 1
	// second. Timed-out jobs are transitioned to Failed with a descriptive error
	// message; I-001's retry loop then auto-promotes eligible Failed jobs back
	// to Pending (closes coverage gap I-003).
	// Setting: CERTCTL_JOB_TIMEOUT_INTERVAL environment variable.
	JobTimeoutInterval time.Duration

	// AwaitingCSRTimeout is the maximum age an AwaitingCSR job can remain in
	// that state before the reaper transitions it to Failed. Default: 24 hours.
	// An agent that hasn't submitted a CSR within this window is presumed
	// unreachable. Minimum: 1 second.
	// Setting: CERTCTL_JOB_AWAITING_CSR_TIMEOUT environment variable.
	AwaitingCSRTimeout time.Duration

	// AwaitingApprovalTimeout is the maximum age an AwaitingApproval job can
	// remain in that state before the reaper transitions it to Failed. Default:
	// 168 hours (7 days). Reviewers who haven't approved within this window
	// force the renewal to fail loudly rather than silently stall. Minimum: 1
	// second.
	// Setting: CERTCTL_JOB_AWAITING_APPROVAL_TIMEOUT environment variable.
	AwaitingApprovalTimeout time.Duration

	// ShortLivedExpiryCheckInterval is how often the scheduler scans
	// short-lived certificates and marks expired rows as Expired. Default:
	// 30 seconds (matches the in-memory default in scheduler.NewScheduler).
	// C-1 closure (cat-g-7e38f9708e20 + diff-10xmain-2bf4a0a60388):
	// pre-C-1 the setter scheduler.SetShortLivedExpiryCheckInterval was
	// defined + tested but never called from cmd/server/main.go, so the
	// 30-second default was effectively hardcoded. Operators who needed
	// to tune the cadence (e.g. a high-churn short-lived cert tenant)
	// had no path. Post-C-1 main.go wires this knob.
	// Setting: CERTCTL_SHORT_LIVED_EXPIRY_CHECK_INTERVAL environment variable.
	ShortLivedExpiryCheckInterval time.Duration

	// CRLGenerationInterval is how often the scheduler pre-generates
	// CRLs into the crl_cache table. The /.well-known/pki/crl/{issuer_id}
	// HTTP endpoint reads from this cache instead of regenerating per
	// request. Default: 1 hour.
	// Setting: CERTCTL_CRL_GENERATION_INTERVAL environment variable.
	// Bundle CRL/OCSP-Responder Phase 3.
	CRLGenerationInterval time.Duration
}

// LogConfig contains logging configuration.
type LogConfig struct {
	// Level sets the minimum log level for output.
	// Valid values: "debug" (verbose), "info" (default), "warn" (warnings), "error" (errors only).
	// Setting: CERTCTL_LOG_LEVEL environment variable. Default: "info".
	Level string

	// Format sets the output format for logs.
	// Valid values: "json" (structured, for parsing), "text" (human-readable).
	// Setting: CERTCTL_LOG_FORMAT environment variable. Default: "json".
	Format string
}

// NamedAPIKey represents a single named API key with an optional admin flag.
// Named keys allow real actor attribution in the audit trail (M-002) and provide
// the admin-gate basis for privileged endpoints like bulk revocation (M-003).
type NamedAPIKey struct {
	// Name is the identifier for the key (alphanumeric, hyphens, underscores).
	// This value is recorded as the actor on every audit event the key authenticates.
	Name string
	// Key is the raw API-key secret the client presents as `Authorization: Bearer <key>`.
	Key string
	// Admin controls whether the key has admin privileges (bulk revocation, etc.).
	Admin bool
}

// AuthType is the discriminator for the API auth middleware shape. The
// string alias preserves env-var roundtrip (the value flows through getEnv
// as a plain string) while giving us a typed surface for switches and
// validation. Use the named constants below rather than string literals
// so future enum additions/removals are caught at compile time.
//
// G-1 (P1): the pre-G-1 validAuthTypes map literal accepted "jwt" with no
// JWT middleware behind it (silent auth downgrade — the configured type
// was logged as "jwt" but every request routed through the api-key bearer
// middleware regardless). Operators who set CERTCTL_AUTH_TYPE=jwt thought
// they had JWT auth; they didn't. The typed alias + ValidAuthTypes()
// helper make the allowed set the single source of truth across config
// validation, the runtime defense-in-depth switch in main.go, and the
// helm-chart template guard (`certctl.validateAuthType`).
type AuthType string

const (
	// AuthTypeAPIKey routes requests through the api-key bearer middleware.
	// CERTCTL_AUTH_SECRET (or CERTCTL_API_KEYS_NAMED) is required.
	AuthTypeAPIKey AuthType = "api-key"

	// AuthTypeNone disables authentication entirely. Development only —
	// the server logs a loud Warn at startup. Operators who need
	// JWT/OIDC/mTLS run an authenticating gateway (oauth2-proxy / Envoy
	// ext_authz / Traefik ForwardAuth / Pomerium) in front of certctl
	// and set this value on the upstream certctl process. See
	// docs/architecture.md "Authenticating-gateway pattern".
	AuthTypeNone AuthType = "none"
)

// ValidAuthTypes returns the allowed CERTCTL_AUTH_TYPE values. The set is
// intentionally narrow — JWT was accepted pre-G-1 with no middleware
// implementation behind it. Single source of truth referenced by the
// validator below, the runtime guard in cmd/server/main.go, the helm
// chart template (`certctl.validateAuthType`), and the property test in
// config_test.go that pins "jwt" out of the slice forever.
func ValidAuthTypes() []AuthType {
	return []AuthType{AuthTypeAPIKey, AuthTypeNone}
}

// AuthConfig contains authentication configuration.
type AuthConfig struct {
	// Type sets the authentication mechanism for the REST API.
	// Valid values: "api-key" (default, production) and "none" (development
	// only — disables authentication on the API and logs a loud Warn at
	// startup). For JWT/OIDC, run an authenticating gateway (oauth2-proxy /
	// Envoy / Traefik ForwardAuth / Pomerium) in front of certctl and set
	// CERTCTL_AUTH_TYPE=none on the upstream — see docs/architecture.md
	// "Authenticating-gateway pattern" and docs/upgrade-to-v2-jwt-removal.md.
	// Setting: CERTCTL_AUTH_TYPE environment variable. Default: "api-key".
	// Use the AuthType constants (AuthTypeAPIKey / AuthTypeNone) for typed
	// comparisons; the field stays `string` to preserve env-var roundtrip
	// shape used by getEnv() and downstream Helm/compose interpolation.
	Type string

	// Secret is the legacy authentication secret (comma-separated API keys).
	// DEPRECATED in favor of NamedKeys — retained for backward compatibility.
	// When NamedKeys is empty and Secret is set, each comma-separated key is
	// registered as a synthesized named key (legacy-key-0, legacy-key-1, ...)
	// with actor attribution defaulting to "legacy-key-<index>".
	// Setting: CERTCTL_AUTH_SECRET environment variable.
	Secret string

	// NamedKeys is the parsed set of named API keys. Populated from
	// CERTCTL_API_KEYS_NAMED via ParseNamedAPIKeys during Load(). When
	// non-empty, this takes precedence over the legacy Secret field.
	// Setting: CERTCTL_API_KEYS_NAMED="name1:key1,name2:key2:admin"
	NamedKeys []NamedAPIKey

	// AgentBootstrapToken is the pre-shared secret enforced on the agent
	// registration endpoint (POST /api/v1/agents). Bundle-5 / Audit H-007 /
	// CWE-306 + CWE-288: pre-Bundle-5, any host with network reach to the
	// server could self-register an agent and start polling for work — no
	// shared secret required. Post-Bundle-5: when this field is non-empty,
	// the registration handler requires `Authorization: Bearer <token>`
	// (constant-time comparison via crypto/subtle.ConstantTimeCompare); 401
	// on missing/wrong/malformed.
	//
	// Backwards compatibility: when empty (the v2.0.x default), the server
	// logs a startup WARN announcing the v2.2.0 deprecation — the field
	// will become required in v2.2.0 and unset will fail-loud — and accepts
	// registrations as today. Existing demo deploys that don't set it keep
	// working through v2.1.x.
	//
	// Generation guidance: `openssl rand -hex 32` (256-bit entropy).
	// Setting: CERTCTL_AGENT_BOOTSTRAP_TOKEN environment variable.
	AgentBootstrapToken string
}

// RateLimitConfig contains rate limiting configuration.
//
// Bundle B / Audit M-025 (OWASP ASVS L2 §11.2.1): pre-bundle the rate
// limiter was global (a single token bucket shared across every request);
// post-bundle it is per-key with separate budgets for IP-keyed and
// user-keyed buckets. RPS / BurstSize are PER-KEY budgets.
type RateLimitConfig struct {
	// Enabled controls whether rate limiting is enforced on API endpoints.
	// Default: true. Set to false to disable rate limits (not recommended for production).
	// Setting: CERTCTL_RATE_LIMIT_ENABLED environment variable.
	Enabled bool

	// RPS is the target requests per second allowed PER KEY (token bucket
	// rate). For unauthenticated callers the key is the source IP; for
	// authenticated callers the key is the API-key name (UserKey context
	// value populated by NewAuthWithNamedKeys).
	// Default: 50. Higher values allow burst throughput; lower values restrict load.
	// Setting: CERTCTL_RATE_LIMIT_RPS environment variable.
	RPS float64

	// BurstSize is the maximum number of requests allowed in a single burst.
	// Default: 100. Allows clients to exceed RPS briefly when BurstSize tokens available.
	// Must be at least as large as RPS. Higher = more lenient burst handling.
	// Setting: CERTCTL_RATE_LIMIT_BURST environment variable.
	BurstSize int

	// PerUserRPS overrides RPS for authenticated callers. When zero, RPS is
	// used for both keying dimensions. Set this higher than RPS to grant
	// authenticated clients a more generous budget than anonymous probes.
	// Default: 0 (use RPS).
	// Setting: CERTCTL_RATE_LIMIT_PER_USER_RPS environment variable.
	PerUserRPS float64

	// PerUserBurstSize overrides BurstSize for authenticated callers. When
	// zero, BurstSize is used. Default: 0 (use BurstSize).
	// Setting: CERTCTL_RATE_LIMIT_PER_USER_BURST environment variable.
	PerUserBurstSize int
}

// CORSConfig contains CORS configuration.
type CORSConfig struct {
	// AllowedOrigins is a list of allowed origins for CORS requests.
	// Security default: empty list denies all CORS requests (same-origin only).
	// ["*"] allows all origins (development/demo mode only, security risk).
	// Specific origins (e.g., ["https://app.example.com"]) whitelist only those origins.
	AllowedOrigins []string
}

// Load reads configuration from environment variables and returns a Config.
// Environment variables must have the CERTCTL_ prefix.
// Example: CERTCTL_SERVER_HOST, CERTCTL_DATABASE_URL, etc.
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Host:        getEnv("CERTCTL_SERVER_HOST", "127.0.0.1"),
			Port:        getEnvInt("CERTCTL_SERVER_PORT", 8080),
			MaxBodySize: getEnvInt64("CERTCTL_MAX_BODY_SIZE", 1024*1024), // 1MB default
			// HTTPS-everywhere milestone §2.1: both paths REQUIRED. Empty defaults
			// are intentional so Validate() emits a fail-loud error pointing at
			// docs/tls.md rather than silently binding plaintext HTTP.
			TLS: ServerTLSConfig{
				CertPath: getEnv("CERTCTL_SERVER_TLS_CERT_PATH", ""),
				KeyPath:  getEnv("CERTCTL_SERVER_TLS_KEY_PATH", ""),
			},
			// Bundle-5 / M-011: configurable shutdown audit-flush budget.
			// Default 30s preserves pre-Bundle-5 behaviour.
			AuditFlushTimeoutSeconds: getEnvInt("CERTCTL_AUDIT_FLUSH_TIMEOUT_SECONDS", 30),
		},
		Database: DatabaseConfig{
			URL:            getEnv("CERTCTL_DATABASE_URL", "postgres://localhost/certctl"),
			MaxConnections: getEnvInt("CERTCTL_DATABASE_MAX_CONNS", 25),
			MigrationsPath: getEnv("CERTCTL_DATABASE_MIGRATIONS_PATH", "./migrations"),
			DemoSeed:       getEnvBool("CERTCTL_DEMO_SEED", false),
		},
		Scheduler: SchedulerConfig{
			RenewalCheckInterval:        getEnvDuration("CERTCTL_SCHEDULER_RENEWAL_CHECK_INTERVAL", 1*time.Hour),
			JobProcessorInterval:        getEnvDuration("CERTCTL_SCHEDULER_JOB_PROCESSOR_INTERVAL", 30*time.Second),
			AgentHealthCheckInterval:    getEnvDuration("CERTCTL_SCHEDULER_AGENT_HEALTH_CHECK_INTERVAL", 2*time.Minute),
			NotificationProcessInterval: getEnvDuration("CERTCTL_SCHEDULER_NOTIFICATION_PROCESS_INTERVAL", 1*time.Minute),
			// I-005: retry sweep for failed notifications. Mirrors RetryInterval
			// (I-001 job retry) but scoped to the notification DLQ machinery.
			// Default 2 minutes — fast enough to absorb transient SMTP/webhook
			// blips, slow enough to respect the service-layer 5-attempt budget
			// without hammering external notifier endpoints.
			NotificationRetryInterval: getEnvDuration("CERTCTL_NOTIFICATION_RETRY_INTERVAL", 2*time.Minute),
			RetryInterval:             getEnvDuration("CERTCTL_SCHEDULER_RETRY_INTERVAL", 5*time.Minute),
			JobTimeoutInterval:        getEnvDuration("CERTCTL_JOB_TIMEOUT_INTERVAL", 10*time.Minute),
			AwaitingCSRTimeout:        getEnvDuration("CERTCTL_JOB_AWAITING_CSR_TIMEOUT", 24*time.Hour),
			AwaitingApprovalTimeout:   getEnvDuration("CERTCTL_JOB_AWAITING_APPROVAL_TIMEOUT", 168*time.Hour),
			// C-1 closure: matches the in-memory default at
			// internal/scheduler/scheduler.go:145 (30 * time.Second).
			ShortLivedExpiryCheckInterval: getEnvDuration("CERTCTL_SHORT_LIVED_EXPIRY_CHECK_INTERVAL", 30*time.Second),
			// CRL/OCSP-Responder Phase 3: pre-generation cadence.
			// Default 1h matches the in-scheduler default; relying-party
			// CRL refresh expectations under RFC 5280 are typically
			// hourly to daily, so 1h gives operators plenty of margin.
			CRLGenerationInterval: getEnvDuration("CERTCTL_CRL_GENERATION_INTERVAL", 1*time.Hour),
		},
		Log: LogConfig{
			Level:  getEnv("CERTCTL_LOG_LEVEL", "info"),
			Format: getEnv("CERTCTL_LOG_FORMAT", "json"),
		},
		Auth: AuthConfig{
			Type:   getEnv("CERTCTL_AUTH_TYPE", "api-key"),
			Secret: getEnv("CERTCTL_AUTH_SECRET", ""),
			// NamedKeys is populated from CERTCTL_API_KEYS_NAMED below so Load()
			// can surface parse errors alongside other config errors.

			// Bundle-5 / Audit H-007: agent-registration bootstrap secret.
			// Empty (default) = warn-mode pass-through; v2.2.0 will require it.
			AgentBootstrapToken: getEnv("CERTCTL_AGENT_BOOTSTRAP_TOKEN", ""),
		},
		RateLimit: RateLimitConfig{
			Enabled:          getEnvBool("CERTCTL_RATE_LIMIT_ENABLED", true),
			RPS:              getEnvFloat("CERTCTL_RATE_LIMIT_RPS", 50),
			BurstSize:        getEnvInt("CERTCTL_RATE_LIMIT_BURST", 100),
			PerUserRPS:       getEnvFloat("CERTCTL_RATE_LIMIT_PER_USER_RPS", 0),
			PerUserBurstSize: getEnvInt("CERTCTL_RATE_LIMIT_PER_USER_BURST", 0),
		},
		CORS: CORSConfig{
			AllowedOrigins: getEnvList("CERTCTL_CORS_ORIGINS", nil),
		},
		Keygen: KeygenConfig{
			Mode: getEnv("CERTCTL_KEYGEN_MODE", "agent"),
		},
		CA: CAConfig{
			CertPath: getEnv("CERTCTL_CA_CERT_PATH", ""),
			KeyPath:  getEnv("CERTCTL_CA_KEY_PATH", ""),
		},
		Notifiers: NotifierConfig{
			SlackWebhookURL:     getEnv("CERTCTL_SLACK_WEBHOOK_URL", ""),
			SlackChannel:        getEnv("CERTCTL_SLACK_CHANNEL", ""),
			SlackUsername:       getEnv("CERTCTL_SLACK_USERNAME", "certctl"),
			TeamsWebhookURL:     getEnv("CERTCTL_TEAMS_WEBHOOK_URL", ""),
			PagerDutyRoutingKey: getEnv("CERTCTL_PAGERDUTY_ROUTING_KEY", ""),
			PagerDutySeverity:   getEnv("CERTCTL_PAGERDUTY_SEVERITY", "warning"),
			OpsGenieAPIKey:      getEnv("CERTCTL_OPSGENIE_API_KEY", ""),
			OpsGeniePriority:    getEnv("CERTCTL_OPSGENIE_PRIORITY", "P3"),
			SMTPHost:            getEnv("CERTCTL_SMTP_HOST", ""),
			SMTPPort:            getEnvInt("CERTCTL_SMTP_PORT", 587),
			SMTPUsername:        getEnv("CERTCTL_SMTP_USERNAME", ""),
			SMTPPassword:        getEnv("CERTCTL_SMTP_PASSWORD", ""),
			SMTPFromAddress:     getEnv("CERTCTL_SMTP_FROM_ADDRESS", ""),
			SMTPUseTLS:          getEnvBool("CERTCTL_SMTP_USE_TLS", true),
		},
		NetworkScan: NetworkScanConfig{
			Enabled:      getEnvBool("CERTCTL_NETWORK_SCAN_ENABLED", false),
			ScanInterval: getEnvDuration("CERTCTL_NETWORK_SCAN_INTERVAL", 6*time.Hour),
		},
		EST: ESTConfig{
			Enabled:   getEnvBool("CERTCTL_EST_ENABLED", false),
			IssuerID:  getEnv("CERTCTL_EST_ISSUER_ID", "iss-local"),
			ProfileID: getEnv("CERTCTL_EST_PROFILE_ID", ""),
		},
		SCEP: SCEPConfig{
			Enabled:           getEnvBool("CERTCTL_SCEP_ENABLED", false),
			IssuerID:          getEnv("CERTCTL_SCEP_ISSUER_ID", "iss-local"),
			ProfileID:         getEnv("CERTCTL_SCEP_PROFILE_ID", ""),
			ChallengePassword: getEnv("CERTCTL_SCEP_CHALLENGE_PASSWORD", ""),
		},
		Verification: VerificationConfig{
			Enabled: getEnvBool("CERTCTL_VERIFY_DEPLOYMENT", true),
			Timeout: getEnvDuration("CERTCTL_VERIFY_TIMEOUT", 10*time.Second),
			Delay:   getEnvDuration("CERTCTL_VERIFY_DELAY", 2*time.Second),
		},
		Vault: VaultConfig{
			Addr:  getEnv("CERTCTL_VAULT_ADDR", ""),
			Token: getEnv("CERTCTL_VAULT_TOKEN", ""),
			Mount: getEnv("CERTCTL_VAULT_MOUNT", "pki"),
			Role:  getEnv("CERTCTL_VAULT_ROLE", ""),
			TTL:   getEnv("CERTCTL_VAULT_TTL", "8760h"),
		},
		DigiCert: DigiCertConfig{
			APIKey:      getEnv("CERTCTL_DIGICERT_API_KEY", ""),
			OrgID:       getEnv("CERTCTL_DIGICERT_ORG_ID", ""),
			ProductType: getEnv("CERTCTL_DIGICERT_PRODUCT_TYPE", "ssl_basic"),
			BaseURL:     getEnv("CERTCTL_DIGICERT_BASE_URL", "https://www.digicert.com/services/v2"),
		},
		Sectigo: SectigoConfig{
			CustomerURI: getEnv("CERTCTL_SECTIGO_CUSTOMER_URI", ""),
			Login:       getEnv("CERTCTL_SECTIGO_LOGIN", ""),
			Password:    getEnv("CERTCTL_SECTIGO_PASSWORD", ""),
			OrgID:       getEnvInt("CERTCTL_SECTIGO_ORG_ID", 0),
			CertType:    getEnvInt("CERTCTL_SECTIGO_CERT_TYPE", 0),
			Term:        getEnvInt("CERTCTL_SECTIGO_TERM", 365),
			BaseURL:     getEnv("CERTCTL_SECTIGO_BASE_URL", "https://cert-manager.com/api"),
		},
		GoogleCAS: GoogleCASConfig{
			Project:     getEnv("CERTCTL_GOOGLE_CAS_PROJECT", ""),
			Location:    getEnv("CERTCTL_GOOGLE_CAS_LOCATION", ""),
			CAPool:      getEnv("CERTCTL_GOOGLE_CAS_CA_POOL", ""),
			Credentials: getEnv("CERTCTL_GOOGLE_CAS_CREDENTIALS", ""),
			TTL:         getEnv("CERTCTL_GOOGLE_CAS_TTL", "8760h"),
		},
		AWSACMPCA: AWSACMPCAConfig{
			Region:           getEnv("CERTCTL_AWS_PCA_REGION", ""),
			CAArn:            getEnv("CERTCTL_AWS_PCA_CA_ARN", ""),
			SigningAlgorithm: getEnv("CERTCTL_AWS_PCA_SIGNING_ALGORITHM", "SHA256WITHRSA"),
			ValidityDays:     getEnvInt("CERTCTL_AWS_PCA_VALIDITY_DAYS", 365),
			TemplateArn:      getEnv("CERTCTL_AWS_PCA_TEMPLATE_ARN", ""),
		},
		Entrust: EntrustConfig{
			APIUrl:         getEnv("CERTCTL_ENTRUST_API_URL", ""),
			ClientCertPath: getEnv("CERTCTL_ENTRUST_CLIENT_CERT_PATH", ""),
			ClientKeyPath:  getEnv("CERTCTL_ENTRUST_CLIENT_KEY_PATH", ""),
			CAId:           getEnv("CERTCTL_ENTRUST_CA_ID", ""),
			ProfileId:      getEnv("CERTCTL_ENTRUST_PROFILE_ID", ""),
		},
		GlobalSign: GlobalSignConfig{
			APIUrl:         getEnv("CERTCTL_GLOBALSIGN_API_URL", ""),
			APIKey:         getEnv("CERTCTL_GLOBALSIGN_API_KEY", ""),
			APISecret:      getEnv("CERTCTL_GLOBALSIGN_API_SECRET", ""),
			ClientCertPath: getEnv("CERTCTL_GLOBALSIGN_CLIENT_CERT_PATH", ""),
			ClientKeyPath:  getEnv("CERTCTL_GLOBALSIGN_CLIENT_KEY_PATH", ""),
			ServerCAPath:   getEnv("CERTCTL_GLOBALSIGN_SERVER_CA_PATH", ""),
		},
		EJBCA: EJBCAConfig{
			APIUrl:         getEnv("CERTCTL_EJBCA_API_URL", ""),
			AuthMode:       getEnv("CERTCTL_EJBCA_AUTH_MODE", "mtls"),
			ClientCertPath: getEnv("CERTCTL_EJBCA_CLIENT_CERT_PATH", ""),
			ClientKeyPath:  getEnv("CERTCTL_EJBCA_CLIENT_KEY_PATH", ""),
			Token:          getEnv("CERTCTL_EJBCA_TOKEN", ""),
			CAName:         getEnv("CERTCTL_EJBCA_CA_NAME", ""),
			CertProfile:    getEnv("CERTCTL_EJBCA_CERT_PROFILE", ""),
			EEProfile:      getEnv("CERTCTL_EJBCA_EE_PROFILE", ""),
		},
		ACME: ACMEConfig{
			DirectoryURL:           getEnv("CERTCTL_ACME_DIRECTORY_URL", ""),
			Email:                  getEnv("CERTCTL_ACME_EMAIL", ""),
			ChallengeType:          getEnv("CERTCTL_ACME_CHALLENGE_TYPE", "http-01"),
			DNSPresentScript:       getEnv("CERTCTL_ACME_DNS_PRESENT_SCRIPT", ""),
			DNSCleanUpScript:       getEnv("CERTCTL_ACME_DNS_CLEANUP_SCRIPT", ""),
			DNSPersistIssuerDomain: getEnv("CERTCTL_ACME_DNS_PERSIST_ISSUER_DOMAIN", ""),
			Profile:                getEnv("CERTCTL_ACME_PROFILE", ""),
			ARIEnabled:             getEnvBool("CERTCTL_ACME_ARI_ENABLED", false),
			Insecure:               getEnvBool("CERTCTL_ACME_INSECURE", false),
		},
		Digest: DigestConfig{
			Enabled:    getEnvBool("CERTCTL_DIGEST_ENABLED", false),
			Interval:   getEnvDuration("CERTCTL_DIGEST_INTERVAL", 24*time.Hour),
			Recipients: getEnvList("CERTCTL_DIGEST_RECIPIENTS", nil),
		},
		HealthCheck: HealthCheckConfig{
			Enabled:          getEnvBool("CERTCTL_HEALTH_CHECK_ENABLED", false),
			CheckInterval:    getEnvDuration("CERTCTL_HEALTH_CHECK_INTERVAL", 60*time.Second),
			DefaultInterval:  getEnvInt("CERTCTL_HEALTH_CHECK_DEFAULT_INTERVAL", 300),
			DefaultTimeout:   getEnvInt("CERTCTL_HEALTH_CHECK_DEFAULT_TIMEOUT", 5000),
			MaxConcurrent:    getEnvInt("CERTCTL_HEALTH_CHECK_MAX_CONCURRENT", 20),
			HistoryRetention: getEnvDuration("CERTCTL_HEALTH_CHECK_HISTORY_RETENTION", 30*24*time.Hour),
			AutoCreate:       getEnvBool("CERTCTL_HEALTH_CHECK_AUTO_CREATE", true),
		},
		Encryption: EncryptionConfig{
			ConfigEncryptionKey: getEnv("CERTCTL_CONFIG_ENCRYPTION_KEY", ""),
		},
		CloudDiscovery: CloudDiscoveryConfig{
			Enabled:  getEnvBool("CERTCTL_CLOUD_DISCOVERY_ENABLED", false),
			Interval: getEnvDuration("CERTCTL_CLOUD_DISCOVERY_INTERVAL", 6*time.Hour),
			AWSSM: AWSSecretsMgrDiscoveryConfig{
				Enabled:    getEnvBool("CERTCTL_AWS_SM_DISCOVERY_ENABLED", false),
				Region:     getEnv("CERTCTL_AWS_SM_REGION", ""),
				TagFilter:  getEnv("CERTCTL_AWS_SM_TAG_FILTER", "type=certificate"),
				NamePrefix: getEnv("CERTCTL_AWS_SM_NAME_PREFIX", ""),
			},
			AzureKV: AzureKVDiscoveryConfig{
				Enabled:      getEnvBool("CERTCTL_AZURE_KV_DISCOVERY_ENABLED", false),
				VaultURL:     getEnv("CERTCTL_AZURE_KV_VAULT_URL", ""),
				TenantID:     getEnv("CERTCTL_AZURE_KV_TENANT_ID", ""),
				ClientID:     getEnv("CERTCTL_AZURE_KV_CLIENT_ID", ""),
				ClientSecret: getEnv("CERTCTL_AZURE_KV_CLIENT_SECRET", ""),
			},
			GCPSM: GCPSecretMgrDiscoveryConfig{
				Enabled:     getEnvBool("CERTCTL_GCP_SM_DISCOVERY_ENABLED", false),
				Project:     getEnv("CERTCTL_GCP_SM_PROJECT", ""),
				Credentials: getEnv("CERTCTL_GCP_SM_CREDENTIALS", ""),
			},
		},
		OCSPResponder: OCSPResponderConfig{
			KeyDir:        getEnv("CERTCTL_OCSP_RESPONDER_KEY_DIR", ""),
			RotationGrace: getEnvDuration("CERTCTL_OCSP_RESPONDER_ROTATION_GRACE", 7*24*time.Hour),
			Validity:      getEnvDuration("CERTCTL_OCSP_RESPONDER_VALIDITY", 30*24*time.Hour),
		},
	}

	// Parse CERTCTL_API_KEYS_NAMED for named key authentication (M-002).
	// Parse errors surface here so invalid config fails fast at startup.
	named, err := ParseNamedAPIKeys(getEnv("CERTCTL_API_KEYS_NAMED", ""))
	if err != nil {
		return nil, fmt.Errorf("parse CERTCTL_API_KEYS_NAMED: %w", err)
	}
	cfg.Auth.NamedKeys = named

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	// Validate server configuration
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	// HTTPS-everywhere milestone §2.1 + §3 locked decisions: the control plane
	// is TLS-only and refuses to start without a cert. No plaintext HTTP fallback,
	// no auto-generated self-signed cert, no N-release migration window. An empty
	// CertPath or KeyPath is operator-visible misconfiguration, not a soft warning.
	if c.Server.TLS.CertPath == "" {
		return fmt.Errorf("server TLS cert path is required — refuse to start (HTTPS-only: set CERTCTL_SERVER_TLS_CERT_PATH to a PEM-encoded certificate; see docs/tls.md)")
	}
	if c.Server.TLS.KeyPath == "" {
		return fmt.Errorf("server TLS key path is required — refuse to start (HTTPS-only: set CERTCTL_SERVER_TLS_KEY_PATH to the PEM-encoded private key matching CERTCTL_SERVER_TLS_CERT_PATH; see docs/tls.md)")
	}

	// Files must exist and be readable. Catches typos and missing mount paths
	// up-front so the operator gets a structured error on startup instead of
	// a deferred ListenAndServeTLS failure after the scheduler has already
	// fanned out its goroutines.
	if _, err := os.Stat(c.Server.TLS.CertPath); err != nil {
		return fmt.Errorf("server TLS cert file unreadable at %q: %w — refuse to start (HTTPS-only; see docs/tls.md)", c.Server.TLS.CertPath, err)
	}
	if _, err := os.Stat(c.Server.TLS.KeyPath); err != nil {
		return fmt.Errorf("server TLS key file unreadable at %q: %w — refuse to start (HTTPS-only; see docs/tls.md)", c.Server.TLS.KeyPath, err)
	}

	// Parse the cert+key pair up-front. tls.LoadX509KeyPair verifies that the
	// key signs the cert (prevents the classic footgun of shipping a pair
	// whose private key doesn't match). Discard the returned Certificate — the
	// server constructs its own holder from fresh reads so SIGHUP reload is
	// authoritative.
	if _, err := tls.LoadX509KeyPair(c.Server.TLS.CertPath, c.Server.TLS.KeyPath); err != nil {
		return fmt.Errorf("server TLS cert/key pair invalid (cert=%q key=%q): %w — refuse to start (HTTPS-only; see docs/tls.md)", c.Server.TLS.CertPath, c.Server.TLS.KeyPath, err)
	}

	// H-1 closure (cat-r-encryption_key_no_length_validation): if
	// CERTCTL_CONFIG_ENCRYPTION_KEY is set, enforce a minimum length of
	// 32 bytes. Pre-H-1 the field was accepted with any non-empty value
	// — including a single character — and PBKDF2-SHA256 (100k rounds)
	// alone does not compensate for low-entropy passphrases at scale
	// (CWE-916 Use of Password Hash With Insufficient Computational
	// Effort + CWE-329 Generation of Predictable IV with CBC Mode).
	// 32 bytes ≈ 256 bits when generated via `openssl rand -base64 32`,
	// matching the AES-256-GCM key size the passphrase derives. An
	// empty key remains accepted — the fail-closed sentinel
	// crypto.ErrEncryptionKeyRequired triggers downstream when an
	// empty key is asked to encrypt or decrypt sensitive config.
	const minEncryptionKeyLength = 32
	if c.Encryption.ConfigEncryptionKey != "" && len(c.Encryption.ConfigEncryptionKey) < minEncryptionKeyLength {
		return fmt.Errorf(
			"CERTCTL_CONFIG_ENCRYPTION_KEY too short (%d bytes; minimum %d). Generate with: openssl rand -base64 32",
			len(c.Encryption.ConfigEncryptionKey), minEncryptionKeyLength,
		)
	}

	// Validate database configuration
	if c.Database.URL == "" {
		return fmt.Errorf("database URL is required")
	}

	if c.Database.MaxConnections < 1 {
		return fmt.Errorf("database max_connections must be at least 1")
	}

	// Validate log level
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[c.Log.Level] {
		return fmt.Errorf("invalid log level: %s", c.Log.Level)
	}

	// Validate log format
	validFormats := map[string]bool{
		"json": true,
		"text": true,
	}
	if !validFormats[c.Log.Format] {
		return fmt.Errorf("invalid log format: %s", c.Log.Format)
	}

	// Validate auth type.
	//
	// G-1 (P1): the pre-G-1 set was {"api-key", "jwt", "none"} with "jwt"
	// accepted but no JWT middleware shipped — silent auth downgrade.
	// Post-G-1 we route a literal "jwt" value through a dedicated
	// rejection that gives operators actionable guidance (the
	// authenticating-gateway pattern) instead of the generic
	// "invalid auth type". Then we cross-check against ValidAuthTypes()
	// so any value outside {api-key, none} surfaces uniformly.
	if c.Auth.Type == "jwt" {
		return fmt.Errorf(
			"CERTCTL_AUTH_TYPE=jwt is no longer accepted (G-1 silent auth " +
				"downgrade): no JWT middleware ships with certctl. To use " +
				"JWT/OIDC, run an authenticating gateway (oauth2-proxy / " +
				"Envoy ext_authz / Traefik ForwardAuth / Pomerium) in " +
				"front of certctl and set CERTCTL_AUTH_TYPE=none on the " +
				"upstream. See docs/architecture.md \"Authenticating-" +
				"gateway pattern\" and docs/upgrade-to-v2-jwt-removal.md " +
				"for the migration walkthrough")
	}
	authTypeValid := false
	for _, t := range ValidAuthTypes() {
		if AuthType(c.Auth.Type) == t {
			authTypeValid = true
			break
		}
	}
	if !authTypeValid {
		return fmt.Errorf("invalid auth type: %s (valid: %v)", c.Auth.Type, ValidAuthTypes())
	}

	// If using API-key, secret is required. (Secret was previously also
	// required for "jwt"; removed with the jwt rejection above.)
	if c.Auth.Type == string(AuthTypeAPIKey) && c.Auth.Secret == "" {
		return fmt.Errorf("auth secret is required for auth type %s", c.Auth.Type)
	}

	// Validate keygen mode
	validKeygenModes := map[string]bool{
		"agent":  true,
		"server": true,
	}
	if !validKeygenModes[c.Keygen.Mode] {
		return fmt.Errorf("invalid keygen mode: %s (must be 'agent' or 'server')", c.Keygen.Mode)
	}

	// SCEP fail-loud startup gate (H-2, CWE-306).
	//
	// Post-M-001 option (D) routes /scep through the no-auth middleware chain per
	// RFC 8894 §3.2 — SCEP clients authenticate via the challengePassword attribute
	// in the PKCS#10 CSR, not via HTTP Bearer tokens or TLS client certs. That makes
	// CERTCTL_SCEP_CHALLENGE_PASSWORD the sole application-layer authentication
	// boundary for SCEP enrollment. Refuse to start if it is empty when SCEP is
	// enabled: an empty shared secret would allow any client that can reach /scep to
	// enroll a CSR against the configured issuer (anonymous issuance).
	if c.SCEP.Enabled && c.SCEP.ChallengePassword == "" {
		return fmt.Errorf("SCEP is enabled but CERTCTL_SCEP_CHALLENGE_PASSWORD is empty — refuse to start (CWE-306: anonymous SCEP issuance is insecure; set a non-empty shared secret or disable SCEP with CERTCTL_SCEP_ENABLED=false). This gate duplicates cmd/server/main.go:preflightSCEPChallengePassword for defense in depth")
	}

	// Validate scheduler intervals
	if c.Scheduler.RenewalCheckInterval < 1*time.Minute {
		return fmt.Errorf("renewal check interval must be at least 1 minute")
	}

	if c.Scheduler.JobProcessorInterval < 1*time.Second {
		return fmt.Errorf("job processor interval must be at least 1 second")
	}

	if c.Scheduler.AgentHealthCheckInterval < 1*time.Second {
		return fmt.Errorf("agent health check interval must be at least 1 second")
	}

	if c.Scheduler.NotificationProcessInterval < 1*time.Second {
		return fmt.Errorf("notification process interval must be at least 1 second")
	}

	// I-005: guard against a misconfigured retry sweep that would either
	// spin-wait or never fire. Matches the NotificationProcessInterval
	// minimum (1s) so operators can tune both knobs from the same floor.
	if c.Scheduler.NotificationRetryInterval < 1*time.Second {
		return fmt.Errorf("notification retry interval must be at least 1 second")
	}

	if c.Scheduler.RetryInterval < 1*time.Second {
		return fmt.Errorf("retry interval must be at least 1 second")
	}

	if c.Scheduler.JobTimeoutInterval < 1*time.Second {
		return fmt.Errorf("job timeout interval must be at least 1 second")
	}

	if c.Scheduler.AwaitingCSRTimeout < 1*time.Second {
		return fmt.Errorf("awaiting CSR timeout must be at least 1 second")
	}

	if c.Scheduler.AwaitingApprovalTimeout < 1*time.Second {
		return fmt.Errorf("awaiting approval timeout must be at least 1 second")
	}

	return nil
}

// getEnv reads a string environment variable with the given key and default value.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt reads an integer environment variable with the given key and default value.
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		intVal, err := strconv.Atoi(value)
		if err != nil {
			return defaultValue
		}
		return intVal
	}
	return defaultValue
}

// getEnvInt64 reads an int64 environment variable with the given key and default value.
func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		intVal, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return defaultValue
		}
		return intVal
	}
	return defaultValue
}

// getEnvDuration reads a time.Duration environment variable.
// The value should be a valid Go duration string (e.g., "1h", "30s", "5m").
func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return defaultValue
		}
		return duration
	}
	return defaultValue
}

// getEnvBool reads a boolean environment variable.
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1" || value == "yes"
	}
	return defaultValue
}

// getEnvFloat reads a float64 environment variable.
func getEnvFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return defaultValue
		}
		return f
	}
	return defaultValue
}

// getEnvList reads a comma-separated list environment variable.
func getEnvList(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		var result []string
		for _, s := range splitComma(value) {
			s = trimSpace(s)
			if s != "" {
				result = append(result, s)
			}
		}
		return result
	}
	return defaultValue
}

// splitComma splits a string by commas (no strings import needed).
func splitComma(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// trimSpace trims leading/trailing whitespace.
func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// GetLogLevel returns the appropriate slog.Level from the configured log level.
func (c *Config) GetLogLevel() slog.Level {
	switch c.Log.Level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// ParseNamedAPIKeys parses the CERTCTL_API_KEYS_NAMED environment variable.
// Format: "name1:key1,name2:key2:admin,name3:key3"
// The ":admin" suffix is optional; if present, the key has admin privileges.
// Returns a typed []NamedAPIKey so main.go can pass it directly to the
// middleware layer without type assertion gymnastics.
//
// Audit L-004 (CWE-924) — graceful key rotation contract:
//
//	Two entries MAY share the same Name during a rotation overlap window:
//	    CERTCTL_API_KEYS_NAMED="alice:OLDKEY:admin,alice:NEWKEY:admin"
//	When duplicates appear, both keys validate at the auth middleware
//	(NewAuthWithNamedKeys iterates every entry on every request, so the
//	match is by hash regardless of name collisions). Both produce the
//	same UserKey context value (the shared name), which keeps the audit
//	trail and per-user rate-limit bucket (Bundle B M-025) consistent
//	across the rollover.
//
//	The duplicate-name path is restricted: every entry sharing a name
//	MUST carry the same admin flag — mixing admin=true with admin=false
//	under the same identity would let a non-admin caller present the
//	admin-flagged key and bypass the gate (or vice-versa). The contract
//	is "rotate ONE key at a time"; the privilege level stays constant
//	within the overlap window.
//
//	Exact (name,key) duplicates are still rejected — that's a typo,
//	not a rotation. Rotation requires DIFFERENT keys under the same
//	name.
//
//	Once the rollover is complete, the operator removes the OLDKEY
//	entry and restarts. Single-entry steady state resumes.
//
//	See docs/security.md::API key rotation for the full operator runbook.
func ParseNamedAPIKeys(input string) ([]NamedAPIKey, error) {
	if input == "" {
		return nil, nil
	}

	parts := splitComma(input)
	var keys []NamedAPIKey
	// nameToAdmin pins the admin flag for any name we've seen before; it
	// is consulted on subsequent duplicate-name entries to enforce the
	// "matching admin" contract above.
	nameToAdmin := make(map[string]bool)
	// nameSeen records whether we've seen a name at all (used to
	// distinguish first-occurrence from duplicate-occurrence; we need
	// this separate from nameToAdmin because admin=false is a valid
	// recorded state).
	nameSeen := make(map[string]bool)
	// pairSeen rejects exact (name,key) duplicates as typos.
	pairSeen := make(map[string]bool)

	for _, part := range parts {
		part = trimSpace(part)
		if part == "" {
			continue
		}

		// Split by colon: name:key or name:key:admin
		fields := strings.Split(part, ":")
		if len(fields) < 2 || len(fields) > 3 {
			return nil, fmt.Errorf("invalid named key format: %s (expected name:key or name:key:admin)", part)
		}

		name := trimSpace(fields[0])
		key := trimSpace(fields[1])
		admin := false

		if len(fields) == 3 {
			adminStr := trimSpace(fields[2])
			if adminStr == "admin" {
				admin = true
			} else {
				return nil, fmt.Errorf("invalid admin flag: %s (expected 'admin')", adminStr)
			}
		}

		// Validate name format: alphanumeric, hyphens, underscores
		if !isValidKeyName(name) {
			return nil, fmt.Errorf("invalid key name: %s (must be alphanumeric, hyphens, underscores)", name)
		}

		if key == "" {
			return nil, fmt.Errorf("empty key for name: %s", name)
		}

		// Typo guard: same (name,key) pair twice is never legitimate —
		// rotation requires DIFFERENT keys under the same name.
		pairKey := name + "\x00" + key
		if pairSeen[pairKey] {
			return nil, fmt.Errorf("duplicate (name,key) entry for name %q — rotation requires DIFFERENT keys under the same name", name)
		}
		pairSeen[pairKey] = true

		// Duplicate-name path: allowed iff admin flag matches the prior
		// entry for the same name (L-004 rotation overlap contract).
		if nameSeen[name] {
			priorAdmin := nameToAdmin[name]
			if priorAdmin != admin {
				return nil, fmt.Errorf("duplicate key name %q with mismatched admin flag — rotation overlap requires both entries carry the same privilege level (prior=%v, this=%v)", name, priorAdmin, admin)
			}
		} else {
			nameSeen[name] = true
			nameToAdmin[name] = admin
		}

		keys = append(keys, NamedAPIKey{
			Name:  name,
			Key:   key,
			Admin: admin,
		})
	}

	// Rotation-window observability: emit a one-shot startup INFO log
	// per name with multiple entries so operators can see the active
	// overlap state in logs. (Single-entry steady state stays silent.)
	nameCounts := make(map[string]int)
	for _, k := range keys {
		nameCounts[k.Name]++
	}
	for name, count := range nameCounts {
		if count > 1 {
			slog.Info("api-key rotation window active",
				"name", name,
				"entries", count,
				"see", "docs/security.md::api-key-rotation",
			)
		}
	}

	return keys, nil
}

// isValidKeyName checks if a key name is valid (alphanumeric, hyphens, underscores).
func isValidKeyName(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
