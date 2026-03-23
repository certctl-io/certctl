# Connector Development Guide

Connectors extend certctl to integrate with external systems for certificate issuance, deployment, and notifications. This guide covers the connector interfaces, built-in implementations, and how to build your own.

## Overview

Three types of connectors:

1. **Issuer Connector** — Obtains certificates from CAs (Local CA with sub-CA support, ACME with HTTP-01 + DNS-01, step-ca, OpenSSL/Custom CA implemented; additional CA integrations planned)
2. **Target Connector** — Deploys certificates to infrastructure (NGINX, Apache httpd, HAProxy implemented; F5 via proxy agent, IIS dual-mode interface only; additional cloud and network targets planned)
3. **Notifier Connector** — Sends alerts about certificate events (Email, Webhooks, Slack, Microsoft Teams, PagerDuty, OpsGenie implemented)

All connectors accept JSON configuration at initialization, support config validation, and are registered in the service layer. Issuer connectors run on the control plane; target connectors run on agents. For network appliances where agents can't be installed, a **proxy agent** in the same network zone handles deployment — the server never initiates outbound connections.

## Issuer Connector

Issuer connectors obtain signed certificates from Certificate Authorities.

### Interface

```go
// internal/connector/issuer/interface.go
package issuer

type Connector interface {
    // ValidateConfig checks that the issuer configuration is valid
    ValidateConfig(ctx context.Context, config json.RawMessage) error

    // IssueCertificate submits a CSR and returns a signed certificate
    IssueCertificate(ctx context.Context, request IssuanceRequest) (*IssuanceResult, error)

    // RenewCertificate renews an existing certificate
    RenewCertificate(ctx context.Context, request RenewalRequest) (*IssuanceResult, error)

    // RevokeCertificate revokes a previously issued certificate
    RevokeCertificate(ctx context.Context, request RevocationRequest) error

    // GetOrderStatus checks the status of an async issuance order
    GetOrderStatus(ctx context.Context, orderID string) (*OrderStatus, error)
}

type IssuanceRequest struct {
    CommonName string
    SANs       []string
    CSRPEM     string
}

type IssuanceResult struct {
    CertPEM   string
    ChainPEM  string
    Serial    string
    NotBefore time.Time
    NotAfter  time.Time
    OrderID   string
}

type RenewalRequest struct {
    CommonName string
    SANs       []string
    CSRPEM     string
    OrderID    *string // optional, for tracking (pointer — nil when not provided)
}

type RevocationRequest struct {
    Serial string
    Reason *string // optional (pointer — nil when not provided)
}

type OrderStatus struct {
    OrderID   string
    Status    string     // "pending", "valid", "invalid", "expired"
    Message   *string    // optional (pointer fields are omitted from JSON when nil)
    CertPEM   *string    // populated when order is complete
    ChainPEM  *string    // populated when order is complete
    Serial    *string    // populated when order is complete
    NotBefore *time.Time // populated when order is complete
    NotAfter  *time.Time // populated when order is complete
    UpdatedAt time.Time
}
```

### Built-in: Local CA

The Local CA issuer signs certificates using Go's `crypto/x509` library. It supports two modes:

**Self-signed mode (default):** Creates a CA on first use (in memory), issues certificates with proper serial numbers, validity periods, SANs, and key usage extensions. Designed for development and demos — certificates are self-signed and not trusted by browsers.

**Sub-CA mode:** Loads a CA certificate and private key from disk (`CERTCTL_CA_CERT_PATH` + `CERTCTL_CA_KEY_PATH`). The CA cert is signed by an upstream CA (e.g., ADCS), so all issued certificates chain to the enterprise root trust hierarchy. Clients that already trust the enterprise root automatically trust certctl-issued certs. Supports RSA, ECDSA, and PKCS#8 key formats. If the paths are not set, falls back to self-signed mode. The loaded certificate must have `IsCA=true` and `KeyUsageCertSign`.

**CRL and OCSP support (M15b):** The Local CA supports DER-encoded X.509 CRL generation via `GET /api/v1/crl/{issuer_id}` with 24-hour validity. An embedded OCSP responder at `GET /api/v1/ocsp/{issuer_id}/{serial}` returns signed OCSP responses for issued certificates (good/revoked/unknown status). Certificates with profile TTL < 1 hour automatically skip CRL/OCSP — expiry is treated as sufficient revocation for short-lived credentials.

Configuration:
```json
{
  "ca_common_name": "CertCtl Local CA",
  "validity_days": 90,
  "ca_cert_path": "/etc/certctl/ca/ca.pem",
  "ca_key_path": "/etc/certctl/ca/ca-key.pem"
}
```

Location: `internal/connector/issuer/local/local.go`

### Built-in: ACME v2 (Let's Encrypt, Sectigo, ZeroSSL)

The ACME connector implements the full ACME v2 protocol using Go's `golang.org/x/crypto/acme` package. It supports two challenge methods:

**HTTP-01 (default):** A built-in temporary HTTP server starts on demand during certificate issuance. The domain being validated must resolve to the machine running the connector, and the configured HTTP port must be reachable from the internet.

**DNS-01 (for wildcards):** Creates DNS TXT records via user-provided scripts. Required for wildcard certificates (`*.example.com`) and hosts that can't serve HTTP on port 80. The connector invokes external scripts to create and clean up `_acme-challenge` TXT records, making it compatible with any DNS provider (Cloudflare, Route53, Azure DNS, etc.).

HTTP-01 configuration:
```json
{
  "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
  "email": "admin@example.com",
  "http_port": 80
}
```

DNS-01 configuration:
```json
{
  "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
  "email": "admin@example.com",
  "challenge_type": "dns-01",
  "dns_present_script": "/etc/certctl/dns/create-record.sh",
  "dns_cleanup_script": "/etc/certctl/dns/delete-record.sh",
  "dns_propagation_wait": 30
}
```

DNS hook scripts receive these environment variables: `CERTCTL_DNS_DOMAIN` (domain being validated), `CERTCTL_DNS_FQDN` (full record name, e.g., `_acme-challenge.example.com`), `CERTCTL_DNS_VALUE` (TXT record value), `CERTCTL_DNS_TOKEN` (ACME challenge token). The present script must create the TXT record and exit 0; the cleanup script removes it.

Environment variables for the default ACME connector:
- `CERTCTL_ACME_DIRECTORY_URL` — ACME directory URL
- `CERTCTL_ACME_EMAIL` — Contact email for account registration
- `CERTCTL_ACME_CHALLENGE_TYPE` — `http-01` (default) or `dns-01`
- `CERTCTL_ACME_DNS_PRESENT_SCRIPT` — Path to DNS record creation script (dns-01 only)
- `CERTCTL_ACME_DNS_CLEANUP_SCRIPT` — Path to DNS record cleanup script (dns-01 only)

The connector is registered in the issuer registry under `iss-acme-staging` and `iss-acme-prod`. Use `iss-acme-staging` for Let's Encrypt staging (rate-limit-friendly testing) and `iss-acme-prod` for production certificates.

**Note:** ACME-issued certificates rely on the Local CA for CRL/OCSP endpoints if they are stored in certctl's inventory. For issuers with their own public CRL/OCSP infrastructure (e.g., Let's Encrypt), clients should validate against the issuer's endpoints instead.

Location: `internal/connector/issuer/acme/acme.go`, `internal/connector/issuer/acme/dns.go`

### Built-in: step-ca (Smallstep Private CA)

The step-ca connector integrates with Smallstep's step-ca private certificate authority using its native `/sign` API with JWK provisioner authentication. This is simpler than ACME for internal PKI — no challenge solving, no domain validation, just CSR + auth token → signed certificate.

Configuration:
```json
{
  "ca_url": "https://ca.internal:9000",
  "provisioner_name": "certctl",
  "provisioner_key_path": "/etc/certctl/stepca/provisioner.json",
  "provisioner_password": "...",
  "root_cert_path": "/etc/certctl/stepca/root_ca.crt",
  "validity_days": 90
}
```

Environment variables:
- `CERTCTL_STEPCA_URL` — step-ca server URL
- `CERTCTL_STEPCA_PROVISIONER` — JWK provisioner name
- `CERTCTL_STEPCA_KEY_PATH` — Path to provisioner private key (JWK JSON)
- `CERTCTL_STEPCA_PASSWORD` — Provisioner key password

The connector is registered in the issuer registry under `iss-stepca`. step-ca also works with the existing ACME connector (point `iss-acme-*` at step-ca's ACME directory URL for ACME-based issuance).

**Note:** step-ca-issued certificates rely on step-ca's own CRL/OCSP infrastructure. certctl's local CRL/OCSP endpoints (`GET /api/v1/crl/{issuer_id}` and `GET /api/v1/ocsp/{issuer_id}/{serial}`) are populated from step-ca's revocation data if available, but clients should validate against step-ca's endpoints for the authoritative status.

Location: `internal/connector/issuer/stepca/stepca.go`

### OpenSSL / Custom CA

Script-based issuer connector for organizations with existing CA tooling. Delegates certificate signing, revocation, and CRL generation to user-provided shell scripts.

**Configuration:**
| Variable | Required | Description |
|----------|----------|-------------|
| `CERTCTL_OPENSSL_SIGN_SCRIPT` | Yes | Script that receives CSR on stdin and outputs signed PEM cert on stdout |
| `CERTCTL_OPENSSL_REVOKE_SCRIPT` | No | Script to revoke a certificate (receives serial number as argument) |
| `CERTCTL_OPENSSL_CRL_SCRIPT` | No | Script that outputs DER-encoded CRL on stdout |
| `CERTCTL_OPENSSL_TIMEOUT_SECONDS` | No | Script execution timeout (default: 30s) |

The sign script receives the CSR PEM on stdin and should output the signed certificate PEM on stdout. The connector parses the certificate to extract serial number, validity dates, and chain information.

### Planned Issuers

The following issuer connectors are planned for future milestones:

- **Vault PKI** — HashiCorp Vault's PKI secrets engine for organizations using Vault as their internal CA.
- **DigiCert** — Commercial CA integration via DigiCert's REST API.

Note: ADCS (Active Directory Certificate Services) integration is handled via the **sub-CA mode** of the Local CA issuer, not as a separate connector. certctl operates as a subordinate CA with its signing certificate issued by ADCS, so all certctl-issued certs chain to the enterprise ADCS root. See the Local CA section above.

### Building a Custom Issuer

Here's the structure for a HashiCorp Vault PKI issuer:

```go
package vault

import (
    "context"
    "encoding/json"
    "fmt"

    vaultapi "github.com/hashicorp/vault/api"
    "github.com/shankar0123/certctl/internal/connector/issuer"
)

type Config struct {
    Address  string `json:"address"`
    Token    string `json:"token"`
    PKIPath  string `json:"pki_path"`
    RoleName string `json:"role_name"`
}

type VaultIssuer struct {
    config *Config
    client *vaultapi.Client
}

func New(cfg *Config) (*VaultIssuer, error) {
    client, err := vaultapi.NewClient(&vaultapi.Config{Address: cfg.Address})
    if err != nil {
        return nil, fmt.Errorf("vault client: %w", err)
    }
    client.SetToken(cfg.Token)
    return &VaultIssuer{config: cfg, client: client}, nil
}

func (v *VaultIssuer) ValidateConfig(ctx context.Context, config json.RawMessage) error {
    var cfg Config
    if err := json.Unmarshal(config, &cfg); err != nil {
        return fmt.Errorf("invalid config: %w", err)
    }
    if cfg.Address == "" || cfg.Token == "" {
        return fmt.Errorf("address and token are required")
    }
    return nil
}

func (v *VaultIssuer) IssueCertificate(ctx context.Context, req issuer.IssuanceRequest) (*issuer.IssuanceResult, error) {
    path := fmt.Sprintf("%s/sign/%s", v.config.PKIPath, v.config.RoleName)
    secret, err := v.client.Logical().Write(path, map[string]interface{}{
        "common_name": req.CommonName,
        "alt_names":   req.SANs,
        "csr":         req.CSRPEM,
    })
    if err != nil {
        return nil, fmt.Errorf("vault sign: %w", err)
    }

    return &issuer.IssuanceResult{
        CertPEM:  secret.Data["certificate"].(string),
        ChainPEM: secret.Data["ca_chain"].(string),
        Serial:   secret.Data["serial_number"].(string),
    }, nil
}

// ... implement RenewCertificate, RevokeCertificate, GetOrderStatus
```

## Target Connector

Target connectors deploy certificates to infrastructure systems. They run on agents, not on the control plane.

### Interface

```go
// internal/connector/target/interface.go
package target

type Connector interface {
    // ValidateConfig checks target configuration
    ValidateConfig(ctx context.Context, config json.RawMessage) error

    // DeployCertificate pushes a certificate to the target system
    DeployCertificate(ctx context.Context, request DeploymentRequest) (*DeploymentResult, error)

    // ValidateDeployment verifies a certificate was deployed correctly
    ValidateDeployment(ctx context.Context, request ValidationRequest) (*ValidationResult, error)
}

type DeploymentRequest struct {
    CertPEM      string            // Signed certificate (PEM), from control plane
    ChainPEM     string            // CA chain (PEM), from control plane
    KeyPEM       string            // Private key (PEM), from agent's local key store
    TargetConfig json.RawMessage   // Target-specific config (NGINX paths, F5 API, IIS site)
    Metadata     map[string]string // Arbitrary context (cert ID, environment, etc.)
    // NOTE: KeyPEM is populated by the agent from its local key store
    // (CERTCTL_KEY_DIR). It is NEVER sent from the control plane.
    // The control plane only provides CertPEM and ChainPEM (public material).
    // The agent combines the locally-generated private key with the signed
    // certificate to create the full deployment payload.
}

type DeploymentResult struct {
    Success       bool
    TargetAddress string
    DeploymentID  string
    Message       string
    DeployedAt    time.Time
    Metadata      map[string]string
}

type ValidationRequest struct {
    CertificateID string
    Serial        string
    TargetConfig  json.RawMessage
    Metadata      map[string]string
}

type ValidationResult struct {
    Valid        bool
    Serial       string
    TargetAddress string
    Message      string
    ValidatedAt  time.Time
    Metadata     map[string]string
}
```

### Built-in: NGINX

The NGINX connector writes certificate, chain, and key files to disk, validates the NGINX configuration, and reloads the server. This is a common deployment pattern for teams running NGINX as a reverse proxy or TLS termination point.

Configuration:
```json
{
  "cert_path": "/etc/nginx/certs/cert.pem",
  "chain_path": "/etc/nginx/certs/chain.pem",
  "key_path": "/etc/nginx/certs/key.pem",
  "reload_command": "systemctl reload nginx",
  "validate_command": "nginx -t"
}
```

The deployment flow is designed to be safe and atomic where possible: the connector writes cert and chain files with mode 0644 and the key file with mode 0600 (read-only by owner), runs the validation command first (so a bad config doesn't take down NGINX), and only reloads if validation passes. If the validation command fails, the connector rolls back the file writes and returns an error with the validation output — this prevents a partial deployment from breaking a running NGINX instance.

The `reload_command` defaults to `systemctl reload nginx` but can be overridden for custom setups (e.g., `nginx -s reload` for non-systemd environments, or `docker exec nginx nginx -s reload` for containerized NGINX).

Location: `internal/connector/target/nginx/nginx.go`

### Built-in: Apache httpd

The Apache httpd connector follows the same pattern as NGINX: it writes separate certificate, chain, and key files to disk, validates the Apache configuration with `apachectl configtest`, and performs a graceful reload. The key difference is that private keys are written with 0600 permissions (owner-only read) for security, while cert and chain files use 0644.

Configuration:
```json
{
  "cert_path": "/etc/apache2/ssl/cert.pem",
  "chain_path": "/etc/apache2/ssl/chain.pem",
  "key_path": "/etc/apache2/ssl/key.pem",
  "reload_command": "apachectl graceful",
  "validate_command": "apachectl configtest"
}
```

The `reload_command` can be customized for different environments (e.g., `systemctl reload apache2` for systemd, `httpd -k graceful` for RHEL/CentOS). Validation output is captured and included in error messages for debugging.

Location: `internal/connector/target/apache/apache.go`

### Built-in: HAProxy

The HAProxy connector differs from NGINX and Apache because HAProxy expects all TLS material in a single combined PEM file (certificate + chain + private key concatenated). The connector builds this combined file, writes it with 0600 permissions (since it contains the private key), optionally validates the HAProxy configuration, and reloads.

Configuration:
```json
{
  "pem_path": "/etc/haproxy/certs/site.pem",
  "reload_command": "systemctl reload haproxy",
  "validate_command": "haproxy -c -f /etc/haproxy/haproxy.cfg"
}
```

The combined PEM is built in this order: server certificate, intermediate/chain certificates, private key. The `validate_command` is optional — if omitted, the connector skips config validation and goes straight to reload.

Location: `internal/connector/target/haproxy/haproxy.go`

### Planned: F5 BIG-IP (Interface Only)

The F5 BIG-IP target connector interface is built with the iControl REST flow mapped out, but the actual API calls are not yet implemented. F5 appliances can't run agents directly, so this connector uses the **proxy agent pattern**: a designated agent in the same network zone picks up F5 deployment jobs and calls the iControl REST API. The server assigns the work; the proxy agent executes it.

The planned flow is: authenticate via `POST /mgmt/shared/authn/login`, upload cert PEM via `POST /mgmt/tm/ltm/certificate`, update the SSL profile via `PATCH /mgmt/tm/ltm/profile/client-ssl/{profile}`, and validate deployment by checking profile status. Implementation is planned for a future release.

Configuration (defined, not yet functional):
```json
{
  "host": "f5.internal.example.com",
  "username": "admin",
  "password": "...",
  "partition": "Common",
  "ssl_profile": "/Common/clientssl_api"
}
```

Note: F5 credentials are stored on the proxy agent, not on the control plane server. This limits the credential blast radius to the proxy agent's network zone.

Location: `internal/connector/target/f5/f5.go`

### Planned: IIS (Interface Only, Dual-Mode)

The IIS target connector supports two deployment modes:

**Agent-local (recommended):** A Windows agent runs directly on the IIS server and deploys certificates using PowerShell — `Import-PfxCertificate` to install into the certificate store and `Set-WebBinding` to bind to the IIS site. This is the preferred approach: no remote access needed, no credential management, same pull-based model as NGINX/Apache/HAProxy.

**Proxy agent WinRM (for agentless targets):** For Windows servers where you don't want to install an agent, a nearby Windows agent acts as a proxy and reaches the IIS box via WinRM. The proxy agent picks up the deployment job, transfers the PFX bundle over WinRM, and runs the PowerShell commands remotely. WinRM credentials are stored on the proxy agent, not on the control plane.

Configuration (defined, not yet functional):
```json
{
  "mode": "local",
  "site_name": "Default Web Site",
  "cert_store": "WebHosting",
  "winrm_host": "",
  "winrm_username": "",
  "winrm_password": "",
  "winrm_use_https": true
}
```

When `mode` is `"local"`, the `winrm_*` fields are ignored. When `mode` is `"proxy"`, the agent connects to the remote IIS server via WinRM using the provided credentials.

Location: `internal/connector/target/iis/iis.go`

## Notifier Connector

Notifier connectors send alerts about certificate lifecycle events (expiration warnings, renewal success/failure, deployment status, policy violations).

### Interface

The service layer defines a simple notifier interface:

```go
// internal/service/notification.go

type Notifier interface {
    Send(ctx context.Context, recipient string, subject string, body string) error
    Channel() string
}
```

The connector layer has a richer interface:

```go
// internal/connector/notifier/interface.go

type Connector interface {
    ValidateConfig(ctx context.Context, config json.RawMessage) error
    SendAlert(ctx context.Context, alert Alert) error
    SendEvent(ctx context.Context, event Event) error
}
```

Built-in notifiers: **Email** (SMTP), **Webhook** (HTTP POST), **Slack** (incoming webhook), **Microsoft Teams** (MessageCard webhook), **PagerDuty** (Events API v2), and **OpsGenie** (Alert API v2).

Each notifier is enabled by its configuration env var:

| Notifier | Env Var | Description |
|----------|---------|-------------|
| Slack | `CERTCTL_SLACK_WEBHOOK_URL` | Incoming webhook URL. Optional: `CERTCTL_SLACK_CHANNEL`, `CERTCTL_SLACK_USERNAME` |
| Teams | `CERTCTL_TEAMS_WEBHOOK_URL` | Incoming webhook URL (MessageCard format) |
| PagerDuty | `CERTCTL_PAGERDUTY_ROUTING_KEY` | Events API v2 routing key. Optional: `CERTCTL_PAGERDUTY_SEVERITY` (default: "warning") |
| OpsGenie | `CERTCTL_OPSGENIE_API_KEY` | Alert API GenieKey. Optional: `CERTCTL_OPSGENIE_PRIORITY` (default: "P3") |

In demo mode, notifications are marked as "sent" even without a configured notifier — this prevents error spam in the logs while still generating notification records for the dashboard to display.

## Registering a Connector

To add a new connector:

1. Create a package under the appropriate directory:
   - `internal/connector/issuer/myissuer/`
   - `internal/connector/target/mytarget/`
   - `internal/connector/notifier/mynotifier/`

2. Implement the interface (all methods required)

3. Register it in the service layer during server initialization in `cmd/server/main.go`.

### IssuerConnectorAdapter

Issuer connectors use an adapter pattern to bridge the connector-layer `issuer.Connector` interface with the service-layer `service.IssuerConnector` interface. This maintains dependency inversion — the service package never imports the connector package directly.

The adapter (`internal/service/issuer_adapter.go`) translates between the two interface types:

```go
// Wrap your connector implementation with the adapter
import "github.com/shankar0123/certctl/internal/service"

myIssuer := myissuer.New(config)
adapted := service.NewIssuerConnectorAdapter(myIssuer)
```

Register adapted connectors keyed by the issuer ID from the database:

```go
// In cmd/server/main.go
localCA := local.New(nil, logger)
issuerRegistry := map[string]service.IssuerConnector{
    "iss-local": service.NewIssuerConnectorAdapter(localCA),
    "iss-vault": service.NewIssuerConnectorAdapter(vaultIssuer),  // your new issuer
}
```

### Notifier Registration

```go
// For notifiers
notifierRegistry := map[string]service.Notifier{
    "Email":   emailNotifier,
    "Webhook": webhookNotifier,
    "Slack":   slackNotifier,  // your new notifier
}
```

## Testing Connectors

### Unit Tests

```go
func TestNginxDeploy(t *testing.T) {
    cfg := &nginx.Config{
        CertPath:        "/tmp/test-cert.pem",
        ChainPath:       "/tmp/test-chain.pem",
        ReloadCommand:   "echo reloaded",
        ValidateCommand: "echo valid",
    }
    connector := nginx.New(cfg, slog.Default())

    result, err := connector.DeployCertificate(ctx, target.DeploymentRequest{
        CertPEM:  testCertPEM,
        ChainPEM: testChainPEM,
        KeyPEM:   testKeyPEM,
    })
    if err != nil {
        t.Fatalf("deploy failed: %v", err)
    }
    if !result.Success {
        t.Fatal("expected success")
    }
}
```

### Integration Tests

```bash
# Start dependent service
docker run -d --name nginx -p 8080:80 nginx:latest

# Run tests
go test -tags=integration ./internal/connector/target/nginx/

# Cleanup
docker rm -f nginx
```

## Best Practices

1. **Always validate config** — Check all required fields in `ValidateConfig` before any operation
2. **Use context for timeouts** — All connector methods accept `context.Context`; honor cancellation and deadlines
3. **Return descriptive errors** — Wrap errors with context so failures are diagnosable from logs
4. **Never log secrets** — Don't log API tokens, passwords, or private key material
5. **Support dry-run** — Where possible, support a validation/dry-run mode for deployment testing
6. **Idempotent operations** — Deploying the same certificate twice should succeed, not fail
7. **Report metadata** — Return deployment duration, target address, and other useful data in results

## What's Next

- [Architecture Guide](architecture.md) — Understanding the full system design
- [Quick Start](quickstart.md) — Get certctl running locally
- [Advanced Demo](demo-advanced.md) — See the full certificate lifecycle in action
