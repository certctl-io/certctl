# Connector Development Guide

Connectors extend certctl to integrate with external systems for certificate issuance, deployment, and notifications. This guide covers the connector interfaces, built-in implementations, and how to build your own.

## Overview

Three types of connectors:

1. **Issuer Connector** — Obtains certificates from CAs (Local CA, ACME implemented; step-ca, ADCS, OpenSSL planned V2; DigiCert, Entrust, GlobalSign, EJBCA, Vault PKI, Google CAS planned V3)
2. **Target Connector** — Deploys certificates to infrastructure (NGINX implemented; F5, IIS interface only; Apache httpd, HAProxy planned V2; AWS ALB, Azure Key Vault, Palo Alto, FortiGate, Citrix ADC, Kubernetes Secrets planned V3)
3. **Notifier Connector** — Sends alerts about certificate events (Email, Webhooks; Slack, Teams, PagerDuty, OpsGenie planned V2.1)

All connectors accept JSON configuration at initialization, support config validation, and are registered in the service layer. Issuer connectors run on the control plane; target connectors run on agents.

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
    OrderID    string // optional, for tracking
}

type RevocationRequest struct {
    Serial string
    Reason string // optional
}

type OrderStatus struct {
    OrderID   string
    Status    string // "pending", "valid", "invalid", "expired"
    Message   string
    CertPEM   string
    ChainPEM  string
    Serial    string
    NotBefore time.Time
    NotAfter  time.Time
    UpdatedAt time.Time
}
```

### Built-in: Local CA

The Local CA issuer generates self-signed certificates using Go's `crypto/x509` library. It creates a CA on first use (in memory), issues certificates with proper serial numbers, validity periods, SANs, and key usage extensions.

This issuer is designed for development and demos only — certificates are self-signed and not trusted by browsers.

Configuration:
```json
{
  "ca_common_name": "CertCtl Local CA",
  "validity_days": 90
}
```

Location: `internal/connector/issuer/local/local.go`

### Built-in: ACME v2 (Let's Encrypt, Sectigo, ZeroSSL)

The ACME connector implements the full ACME v2 protocol using Go's `golang.org/x/crypto/acme` package. It supports HTTP-01 challenge solving via a built-in temporary HTTP server that starts on demand during certificate issuance.

Configuration:
```json
{
  "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
  "email": "admin@example.com",
  "http_port": 80
}
```

For HTTP-01 to work, the domain being validated must resolve to the machine running the connector, and the configured HTTP port must be reachable from the internet. The connector automatically registers an ACME account, creates orders, solves challenges, finalizes with the CSR, and downloads the issued certificate chain.

**Limitation:** v1 supports HTTP-01 challenges only. DNS-01 challenge support (required for wildcard certificates and hosts that can't serve HTTP on port 80) is planned for V2, including provider-specific DNS adapters (Cloudflare, Route53, etc.) and custom validation script hooks.

Environment variables for the default ACME connector:
- `CERTCTL_ACME_DIRECTORY_URL` — ACME directory URL
- `CERTCTL_ACME_EMAIL` — Contact email for account registration

The connector is registered in the issuer registry under `iss-acme-staging` and `iss-acme-prod`. Use `iss-acme-staging` for Let's Encrypt staging (rate-limit-friendly testing) and `iss-acme-prod` for production certificates.

Location: `internal/connector/issuer/acme/acme.go`

### Planned Issuers (V2)

The following issuer connectors are planned for V2:

- **step-ca** — Smallstep's private CA and ACME server. Would allow certctl to issue certificates from a self-hosted step-ca instance via its ACME or provisioner APIs.
- **OpenSSL / Custom CA** — Support for external CAs that use OpenSSL-based signing workflows, including custom script hooks for organizations with existing CA tooling.
- **ADCS (Active Directory Certificate Services)** — Microsoft's enterprise CA. Would allow certctl to request certificates from an existing ADCS infrastructure, useful for organizations that need lifecycle management around their Windows PKI.
- **Vault PKI** — HashiCorp Vault's PKI secrets engine for organizations using Vault as their internal CA.
- **DigiCert** — Commercial CA integration via DigiCert's REST API.

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

### Planned: F5 BIG-IP (Interface Only)

The F5 BIG-IP target connector interface is built with the iControl REST flow mapped out, but the actual API calls are not yet implemented. The planned flow is: authenticate via `POST /mgmt/shared/authn/login`, upload cert PEM via `POST /mgmt/tm/ltm/certificate`, update the SSL profile via `PATCH /mgmt/tm/ltm/profile/client-ssl/{profile}`, and validate deployment by checking profile status. Implementation is planned for V2.

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

Location: `internal/connector/target/f5/f5.go`

### Planned: IIS (Interface Only)

The IIS target connector interface is built with the WinRM/PowerShell flow mapped out, but the actual remote execution is not yet implemented. The planned flow is: transfer a PFX bundle to the Windows server via WinRM, run `Import-PfxCertificate` to install it into the certificate store, and run `Set-WebBinding` to bind the certificate to the IIS site. Implementation is planned for V2.

Configuration (defined, not yet functional):
```json
{
  "host": "iis-server.internal.example.com",
  "username": "Administrator",
  "password": "...",
  "site_name": "Default Web Site",
  "cert_store": "WebHosting",
  "use_https": true
}
```

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

Built-in notifiers: **Email** (SMTP) and **Webhook** (HTTP POST).

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
