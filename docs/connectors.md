# Connector Development Guide

Connectors extend certctl to integrate with external systems for certificate issuance, deployment, and notifications. This guide covers the connector interfaces, built-in implementations, and how to build your own.

## Contents

1. [Overview](#overview)
2. [Issuer Connector](#issuer-connector)
   - [Interface](#interface)
   - [Built-in: Local CA](#built-in-local-ca)
   - [Built-in: ACME v2 (Let's Encrypt, Sectigo, ZeroSSL)](#built-in-acme-v2-lets-encrypt-sectigo-zerossl)
   - [Built-in: step-ca (Smallstep Private CA)](#built-in-step-ca-smallstep-private-ca)
   - [OpenSSL / Custom CA](#openssl--custom-ca)
   - [Revocation Across Issuers](#revocation-across-issuers)
   - [EST Integration (GetCACertPEM)](#est-integration-getcacertpem)
   - [Planned Issuers](#planned-issuers)
   - [Building a Custom Issuer](#building-a-custom-issuer)
3. [Target Connector](#target-connector)
   - [Interface](#interface-1)
   - [Built-in: NGINX](#built-in-nginx)
   - [Built-in: Apache httpd](#built-in-apache-httpd)
   - [Built-in: HAProxy](#built-in-haproxy)
   - [Built-in: Traefik](#built-in-traefik)
   - [Built-in: Caddy](#built-in-caddy)
   - [F5 BIG-IP (Interface Only)](#f5-big-ip-interface-only)
   - [IIS (Implemented, Dual-Mode)](#iis-implemented-dual-mode)
4. [Notifier Connector](#notifier-connector)
   - [Interface](#interface-2)
5. [Registering a Connector](#registering-a-connector)
   - [IssuerConnectorAdapter](#issuerconnectoradapter)
   - [Notifier Registration](#notifier-registration)
6. [Testing Connectors](#testing-connectors)
   - [Unit Tests](#unit-tests)
   - [Integration Tests](#integration-tests)
7. [Best Practices](#best-practices)
8. [Agent Discovery Scanner](#agent-discovery-scanner)
   - [Configuration](#configuration)
   - [How It Works](#how-it-works)
   - [API Endpoints](#api-endpoints)
   - [Use Cases](#use-cases)
9. [Network Certificate Scanner (M21)](#network-certificate-scanner-m21)
   - [Configuration](#configuration-1)
   - [Creating Scan Targets](#creating-scan-targets)
   - [How It Works](#how-it-works-1)
   - [API Endpoints](#api-endpoints-1)
   - [Scheduler Integration](#scheduler-integration)
   - [Use Cases](#use-cases-1)
10. [What's Next](#whats-next)

## Overview

Three types of connectors:

1. **Issuer Connector** — Obtains certificates from CAs (Local CA with sub-CA support, ACME with HTTP-01 + DNS-01 + DNS-PERSIST-01, step-ca, OpenSSL/Custom CA implemented; additional CA integrations planned)
2. **Target Connector** — Deploys certificates to infrastructure (NGINX, Apache httpd, HAProxy, Traefik, Caddy, IIS implemented; F5 via proxy agent planned; additional cloud and network targets planned)
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

    // GenerateCRL generates a DER-encoded X.509 CRL signed by this issuer.
    // Returns nil if the issuer does not support CRL generation (e.g., ACME).
    GenerateCRL(ctx context.Context, revokedCerts []RevokedCertEntry) ([]byte, error)

    // SignOCSPResponse signs an OCSP response for the given certificate serial.
    // Returns nil if the issuer does not support OCSP (e.g., ACME).
    SignOCSPResponse(ctx context.Context, req OCSPSignRequest) ([]byte, error)

    // GetCACertPEM returns the PEM-encoded CA certificate chain for this issuer.
    // Used by the EST server's /cacerts endpoint (RFC 7030).
    // Returns error if the issuer doesn't provide a static CA chain (e.g., ACME, step-ca).
    GetCACertPEM(ctx context.Context) (string, error)
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

**Extended Key Usage (EKU) support (M27):** The Local CA respects EKU constraints from certificate profiles and adjusts key usage flags accordingly. For S/MIME certificates (emailProtection EKU), it uses `DigitalSignature | ContentCommitment` instead of the TLS default. For TLS certificates (serverAuth/clientAuth EKU), it uses `DigitalSignature | KeyEncipherment`. This enables support for multiple certificate types — TLS, S/MIME, code signing, timestamping — from a single CA.

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

The ACME connector implements the full ACME v2 protocol using Go's `golang.org/x/crypto/acme` package. It supports three challenge methods:

**HTTP-01 (default):** A built-in temporary HTTP server starts on demand during certificate issuance. The domain being validated must resolve to the machine running the connector, and the configured HTTP port must be reachable from the internet.

**DNS-01 (for wildcards):** Creates DNS TXT records via user-provided scripts. Required for wildcard certificates (`*.example.com`) and hosts that can't serve HTTP on port 80. The connector invokes external scripts to create and clean up `_acme-challenge` TXT records, making it compatible with any DNS provider (Cloudflare, Route53, Azure DNS, etc.).

**DNS-PERSIST-01 (standing record):** Creates a one-time persistent TXT record at `_validation-persist.<domain>` containing the CA's issuer domain and your ACME account URI. Once set, this record authorizes unlimited future certificate issuances without per-renewal DNS updates. Based on [draft-ietf-acme-dns-persist](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-persist/) and CA/Browser Forum ballot SC-088v3. If the CA doesn't offer dns-persist-01 yet, the connector falls back to dns-01 automatically.

**ACME Renewal Information (ARI, RFC 9702):** Instead of using fixed renewal thresholds (e.g., renew 30 days before expiry), certctl can ask the CA when it should renew. Enable with `CERTCTL_ACME_ARI_ENABLED=true`. The ARI protocol lets the CA specify a `suggestedWindow` (start and end times) for when you should renew — useful for distributing load during maintenance windows or coordinating mass revocation scenarios. Cert ID is computed as `base64url(SHA-256(DER cert))`. If the CA doesn't support ARI (404 response), certctl automatically falls back to threshold-based renewal with no operator intervention required.

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

DNS-PERSIST-01 configuration:
```json
{
  "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
  "email": "admin@example.com",
  "challenge_type": "dns-persist-01",
  "dns_present_script": "/etc/certctl/dns/create-record.sh",
  "dns_persist_issuer_domain": "letsencrypt.org",
  "dns_propagation_wait": 30
}
```

The present script creates a TXT record at `_validation-persist.<domain>` with the value `letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/<your-id>`. This record is permanent — no cleanup script is needed.

ZeroSSL configuration (requires External Account Binding):
```json
{
  "directory_url": "https://acme.zerossl.com/v2/DV90",
  "email": "admin@example.com",
  "eab_kid": "your-zerossl-eab-kid",
  "eab_hmac": "your-zerossl-eab-hmac-base64url"
}
```

ZeroSSL, Google Trust Services, and SSL.com require External Account Binding (EAB) for ACME account registration. For most CAs, get your EAB credentials from the CA's dashboard and provide them via `eab_kid` and `eab_hmac`. The HMAC key must be base64url-encoded (no padding). CAs that don't require EAB (Let's Encrypt, Buypass) ignore these fields.

**ZeroSSL auto-EAB:** When the directory URL points to ZeroSSL and no EAB credentials are provided, certctl automatically fetches them from ZeroSSL's public API (`api.zerossl.com/acme/eab-credentials-email`) using your configured email address. No dashboard visit required — just set the directory URL and email, and it works. This is the same approach used by Caddy and acme.sh.

Minimal ZeroSSL configuration (auto-EAB):
```json
{
  "directory_url": "https://acme.zerossl.com/v2/DV90",
  "email": "admin@example.com"
}
```

DNS hook scripts receive these environment variables: `CERTCTL_DNS_DOMAIN` (domain being validated), `CERTCTL_DNS_FQDN` (full record name — `_acme-challenge.<domain>` for dns-01, `_validation-persist.<domain>` for dns-persist-01), `CERTCTL_DNS_VALUE` (TXT record value), `CERTCTL_DNS_TOKEN` (ACME challenge token). The present script must create the TXT record and exit 0; the cleanup script removes it (dns-01 only).

Environment variables for the default ACME connector:
- `CERTCTL_ACME_DIRECTORY_URL` — ACME directory URL
- `CERTCTL_ACME_EMAIL` — Contact email for account registration
- `CERTCTL_ACME_EAB_KID` — External Account Binding Key ID (required by ZeroSSL, Google Trust Services, SSL.com)
- `CERTCTL_ACME_EAB_HMAC` — External Account Binding HMAC key (base64url-encoded)
- `CERTCTL_ACME_CHALLENGE_TYPE` — `http-01` (default), `dns-01`, or `dns-persist-01`
- `CERTCTL_ACME_DNS_PRESENT_SCRIPT` — Path to DNS record creation script (dns-01 and dns-persist-01)
- `CERTCTL_ACME_DNS_CLEANUP_SCRIPT` — Path to DNS record cleanup script (dns-01 only, not used by dns-persist-01)
- `CERTCTL_ACME_DNS_PERSIST_ISSUER_DOMAIN` — CA issuer domain for persistent record (dns-persist-01 only, e.g., `letsencrypt.org`)

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

The sign script receives the CSR PEM on stdin and should output the signed certificate PEM on stdout. The connector parses the certificate to extract serial number, validity dates, and chain information. Before shell execution, serial numbers are validated as hex-only (`^[0-9a-fA-F]+$`) and revocation reason codes are validated against the RFC 5280 specification to prevent command injection.

### Revocation Across Issuers

All issuer connectors implement `RevokeCertificate(ctx, serial, reason)`. When a certificate is revoked via `POST /api/v1/certificates/{id}/revoke`, certctl notifies the issuing CA on a best-effort basis — the revocation succeeds in certctl's inventory even if the CA notification fails (e.g., CA is temporarily unreachable). This ensures revocation is never blocked by external dependencies.

Each issuer handles revocation differently:

- **Local CA**: Updates the in-memory revocation list. DER-encoded CRLs and OCSP responses are generated from this list.
- **ACME**: ACME v2 has limited revocation support — certctl records the revocation locally and serves it via CRL/OCSP.
- **step-ca**: Calls step-ca's `/revoke` API endpoint. Clients should check step-ca's own CRL/OCSP for authoritative status.
- **OpenSSL/Custom CA**: Invokes the configured revoke script (`CERTCTL_OPENSSL_REVOKE_SCRIPT`) with the serial number as an argument.

### EST Integration (GetCACertPEM)

The `GetCACertPEM()` method returns the PEM-encoded CA certificate chain, used by the EST server's `/.well-known/est/cacerts` endpoint (RFC 7030) to distribute the CA chain to enrolling devices. Each issuer handles this differently:

- **Local CA**: Returns the CA certificate PEM (self-signed or sub-CA cert). This is the primary EST issuer.
- **ACME**: Returns error — ACME CAs provide chains per-issuance, not statically.
- **step-ca**: Returns error — step-ca serves its own `/root` endpoint for CA distribution.
- **OpenSSL/Custom CA**: Returns error — custom script-based CAs have no CA cert access through certctl.

Note: EST (Enrollment over Secure Transport) is not a connector — it's a protocol handler (`internal/api/handler/est.go`) that delegates certificate issuance to whichever issuer connector is configured via `CERTCTL_EST_ISSUER_ID`. See the [Architecture Guide](architecture.md#est-server-rfc-7030) for details.

### Built-in: Vault PKI

The Vault PKI connector integrates with HashiCorp Vault's PKI secrets engine using its native `/sign` API with token-based authentication. This is ideal for organizations using Vault as their internal certificate authority — synchronous issuance without the complexity of ACME or challenge solving.

**Configuration:**

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_VAULT_ADDR` | — | Vault server address (e.g., `https://vault.internal:8200`) |
| `CERTCTL_VAULT_TOKEN` | — | Vault auth token with permissions on the PKI mount |
| `CERTCTL_VAULT_MOUNT` | `pki` | PKI secrets engine mount path |
| `CERTCTL_VAULT_ROLE` | — | PKI role name for certificate signing |
| `CERTCTL_VAULT_TTL` | `8760h` | Certificate validity period (TTL) |

The connector is registered in the issuer registry under `iss-vault`. Vault issues certificates synchronously via the `/v1/{mount}/sign/{role}` API with `X-Vault-Token` header authentication. The issued certificate is parsed to extract serial number, validity dates, and chain information.

**Note:** CRL and OCSP are managed by Vault itself. Clients should validate certificate status against Vault's own CRL/OCSP endpoints (`GET /v1/{mount}/crl` and Vault's OCSP responder). certctl does not generate local CRL/OCSP for Vault-issued certificates. Revocation is recorded locally but Vault is the authoritative source.

Location: `internal/connector/issuer/vault/vault.go`

### Built-in: DigiCert CertCentral

The DigiCert connector integrates with DigiCert's CertCentral REST API for ordering and managing certificates from DigiCert's commercial CA. It supports both Domain Validated (DV) and Organization/Extended Validated (OV/EV) certificates, with async order processing.

**Configuration:**

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_DIGICERT_API_KEY` | — | DigiCert API key (X-DC-DEVKEY header) |
| `CERTCTL_DIGICERT_ORG_ID` | — | DigiCert organization ID |
| `CERTCTL_DIGICERT_PRODUCT_TYPE` | `ssl_basic` | Certificate product (e.g., `ssl_basic`, `ssl_plus`, `ssl_ev`) |
| `CERTCTL_DIGICERT_BASE_URL` | `https://www.digicert.com/services/v2` | DigiCert API base URL |

The connector submits certificate orders to DigiCert's `/order/certificate/create` API. DV certificates may issue immediately; OV/EV certificates require validation (handled by DigiCert) and poll-based completion. The connector periodically checks order status via `/order/certificate/{order_id}` until the certificate is available.

**Authentication:** API key passed via `X-DC-DEVKEY` header, with organization ID in request body.

**Note:** CRL and OCSP are managed by DigiCert. Clients should validate certificate status against DigiCert's infrastructure. certctl records the revocation locally but does not notify DigiCert for revocation — use DigiCert's dashboard for revocation management.

Location: `internal/connector/issuer/digicert/digicert.go`

### Coming in V2.2+

The following issuer connectors are planned for future releases:

- **Entrust** — Enterprise CA via Entrust API
- **Sectigo** — Commercial CA integration via Sectigo REST API
- **Google CAS** — Google Cloud Certificate Authority Service
- **AWS ACM Private CA** — AWS-managed private CA

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

### Built-in: Traefik

The Traefik connector uses Traefik's file provider — it writes certificate and key files to a watched directory, and Traefik automatically picks up the changes without any explicit reload command. This is the simplest deployment model: write the files, and Traefik does the rest.

Configuration:
```json
{
  "cert_dir": "/etc/traefik/certs",
  "cert_file": "site.crt",
  "key_file": "site.key"
}
```

The `cert_dir` is the directory Traefik is configured to watch via its file provider (e.g., `providers.file.directory` in Traefik's static config). The connector writes `cert_file` and `key_file` into this directory with appropriate permissions. Traefik's file watcher detects the change and reloads the TLS configuration automatically.

Location: `internal/connector/target/traefik/traefik.go`

### Built-in: Caddy

The Caddy connector supports two deployment modes — choose based on your Caddy setup:

**API mode (recommended):** Posts the certificate directly to Caddy's admin API (`POST /load` or certificate-specific endpoints) for zero-downtime hot reload. Requires Caddy's admin API to be enabled and accessible from the agent.

**File mode (fallback):** Writes cert and key files to disk, relying on Caddy's built-in file watcher or a manual reload. Use this when the admin API isn't available or when Caddy is configured to read certificates from disk.

Configuration:
```json
{
  "mode": "api",
  "admin_api": "http://localhost:2019",
  "cert_dir": "/etc/caddy/certs",
  "cert_file": "site.crt",
  "key_file": "site.key"
}
```

When `mode` is `"api"`, the connector posts the certificate to the admin API endpoint. When `mode` is `"file"`, it writes files to `cert_dir` (same pattern as Traefik). The `admin_api` field is ignored in file mode.

Location: `internal/connector/target/caddy/caddy.go`

### F5 BIG-IP (Interface Only)

The F5 BIG-IP target connector interface is defined with the iControl REST flow mapped out, but the actual API calls are not yet implemented. F5 appliances can't run agents directly, so this connector uses the **proxy agent pattern**: a designated agent in the same network zone picks up F5 deployment jobs and calls the iControl REST API. The server assigns the work; the proxy agent executes it.

The planned flow is: authenticate via `POST /mgmt/shared/authn/login`, upload cert PEM via `POST /mgmt/tm/ltm/certificate`, update the SSL profile via `PATCH /mgmt/tm/ltm/profile/client-ssl/{profile}`, and validate deployment by checking profile status.

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

### IIS (Implemented, Dual-Mode)

The IIS target connector supports two deployment modes — agent-local (recommended) and proxy agent WinRM for agentless targets.

**Agent-local (recommended):** A Windows agent runs directly on the IIS server and deploys certificates using PowerShell — `Import-PfxCertificate` to install into the certificate store and `Set-WebBinding` to bind to the IIS site. The agent handles PEM-to-PFX conversion via `go-pkcs12`, computes SHA-1 thumbprint from the certificate, and executes parameterized PowerShell scripts for injection-safe binding management. This is the preferred approach: no remote access needed, no credential management, same pull-based model as NGINX/Apache/HAProxy.

**Proxy agent WinRM (for agentless targets):** For Windows servers where you don't want to install an agent, a nearby Windows agent acts as a proxy and reaches the IIS box via WinRM. The proxy agent picks up the deployment job, transfers the PFX bundle over WinRM, and runs the PowerShell commands remotely. WinRM credentials are stored on the proxy agent, not on the control plane.

Configuration:
```json
{
  "hostname": "iis-server.example.com",
  "site_name": "Default Web Site",
  "cert_store": "WebHosting",
  "port": 443,
  "sni": true,
  "ip_address": "*",
  "binding_info": "IP:443:iis-server.example.com"
}
```

**Configuration Fields:**
- `hostname` (string, required): IIS server hostname or FQDN
- `site_name` (string, required): IIS website name (e.g., "Default Web Site")
- `cert_store` (string, required): Certificate store for import (e.g., "WebHosting", "My")
- `port` (number, default 443): HTTPS binding port
- `sni` (boolean, default true): Enable Server Name Indication (SNI)
- `ip_address` (string, default "*"): Specific IP to bind to, or "*" for all IPs
- `binding_info` (string, optional): Custom binding string for advanced scenarios

**Security Model:**
- PFX files are transient — generated with random passwords, deleted after import
- PowerShell commands are parameterized (no string interpolation) to prevent injection
- Field names are regex-validated before script execution
- Certificate thumbprints computed via SHA-1 for IIS binding lookups

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

### Email (SMTP) Notifier

The Email notifier sends transactional alerts and scheduled digests via SMTP. It bridges the connector-layer SMTP connector to the service-layer `Notifier` interface via the `NotifierAdapter`. Supports both plain text and HTML emails.

Configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_SMTP_HOST` | — | SMTP server hostname (required to enable) |
| `CERTCTL_SMTP_PORT` | 587 | SMTP port (TLS) |
| `CERTCTL_SMTP_USERNAME` | — | SMTP authentication username (optional) |
| `CERTCTL_SMTP_PASSWORD` | — | SMTP authentication password (optional) |
| `CERTCTL_SMTP_FROM_ADDRESS` | — | Email from address (required) |
| `CERTCTL_SMTP_USE_TLS` | true | Enable TLS encryption |

Example:
```bash
export CERTCTL_SMTP_HOST=smtp.gmail.com
export CERTCTL_SMTP_PORT=587
export CERTCTL_SMTP_USERNAME=admin@example.com
export CERTCTL_SMTP_PASSWORD=app-password-123
export CERTCTL_SMTP_FROM_ADDRESS=certctl@example.com
```

### Scheduled Certificate Digest

The `DigestService` generates aggregated certificate digest emails and sends them on a configurable schedule. This is useful for periodic briefings on certificate inventory health — expiring certs, status summary, active agents, job trends.

The digest HTML template includes:
- Total certificates, expiring soon, expired, active agents (stats grid)
- Jobs completed/failed summary (30 days)
- Expiring certificates table (color-coded by urgency: 7d, 14d, 30d)
- Auto-refresh and responsive email layout

**Scheduler Integration:** The 7th scheduler loop runs on configurable interval (default 24 hours). It does NOT run on startup — waits for first scheduled tick. Operation timeout is 5 minutes. Each loop execution is guarded by `sync/atomic.Bool` idempotency.

Configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_DIGEST_ENABLED` | false | Enable scheduled digest emails |
| `CERTCTL_DIGEST_INTERVAL` | 24h | How often to send digest (any duration, e.g. 12h, 7d) |
| `CERTCTL_DIGEST_RECIPIENTS` | — | Comma-separated email addresses. Falls back to certificate owner emails if empty |

API Endpoints:

- **`GET /api/v1/digest/preview`** — Render digest HTML for preview (no email sent)
- **`POST /api/v1/digest/send`** — Trigger digest send immediately (outside of schedule)

Example:
```bash
# Preview digest
curl http://localhost:8443/api/v1/digest/preview | jq '.html'

# Send digest immediately
curl -X POST http://localhost:8443/api/v1/digest/send
```

Each notifier is enabled by its configuration env var:

| Notifier | Env Var | Description |
|----------|---------|-------------|
| Email | `CERTCTL_SMTP_HOST` | SMTP email delivery. See Email Notifier section above |
| Webhook | `CERTCTL_WEBHOOK_URL` | HTTP POST to any endpoint. Optional: `CERTCTL_WEBHOOK_SECRET` for HMAC signing |
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

## Agent Discovery Scanner

Agents include a built-in certificate discovery scanner that walks configured directories and reports unmanaged certificates to the control plane. This is useful for discovering existing certificates already deployed in your infrastructure, so you can bring them under certctl's management.

### Configuration

Enable discovery on an agent by setting `CERTCTL_DISCOVERY_DIRS` to a comma-separated list of directories:

```bash
export CERTCTL_DISCOVERY_DIRS="/etc/nginx/certs,/etc/ssl/certs,/etc/apache2/ssl"
```

Or via command-line flag:

```bash
./agent --agent-id agent-nginx-01 --discovery-dirs "/etc/nginx/certs,/etc/ssl/certs"
```

The agent scans these directories on startup and every 6 hours, looking for certificate files in PEM or DER format (extensions: `.pem`, `.crt`, `.cer`, `.cert`, `.der`).

### How It Works

1. **Scan**: Agent recursively walks directories, extracts certificates
2. **Deduplicate**: Control plane deduplicates by SHA-256 fingerprint (same cert in multiple locations is one discovery)
3. **Store**: Discovered certificates stored with metadata (agent ID, file path, found date, fingerprint)
4. **Triage**: Operators review discovered certs in the **Discovery** dashboard page (or via API) — claim to link to managed certificates, or dismiss false positives. The dashboard shows summary stats, filters by status and agent, and provides one-click claim/dismiss actions.

### API Endpoints

```bash
# List discovered certificates (filter by agent, status)
curl -s "http://localhost:8443/api/v1/discovered-certificates?agent_id=agent-nginx-01&status=new" | jq .

# Get discovery detail
curl -s http://localhost:8443/api/v1/discovered-certificates/DISCOVERY_ID | jq .

# Claim a discovered cert (link to managed certificate)
curl -s -X POST http://localhost:8443/api/v1/discovered-certificates/DISCOVERY_ID/claim \
  -H "Content-Type: application/json" \
  -d '{"managed_certificate_id": "mc-api-prod"}' | jq .

# Dismiss a discovery
curl -s -X POST http://localhost:8443/api/v1/discovered-certificates/DISCOVERY_ID/dismiss | jq .

# View discovery scan history
curl -s http://localhost:8443/api/v1/discovery-scans | jq .

# Summary counts (new, claimed, dismissed)
curl -s http://localhost:8443/api/v1/discovery-summary | jq .
```

### Use Cases

- **Inventory audit** — Find all TLS certificates running in your infrastructure
- **Migration** — Onboard existing certificates that were issued outside certctl
- **Compliance** — Detect rogue/unauthorized certificates in monitored directories
- **Integration** — Pull certificate data from systems that pre-generate certs (e.g., Kubernetes CertManager)

## Network Certificate Scanner (M21)

The control plane includes a built-in active TLS scanner that probes network endpoints and discovers certificates without requiring agent deployment. This complements the agent-based filesystem discovery with network-level visibility.

### Configuration

Enable network scanning on the server:

```bash
export CERTCTL_NETWORK_SCAN_ENABLED=true
export CERTCTL_NETWORK_SCAN_INTERVAL=6h  # default
```

### Creating Scan Targets

Network scan targets can be managed from the **Network Scans** dashboard page (create, edit, enable/disable, trigger on-demand scans) or via the API. Targets define which CIDR ranges and ports to probe:

```bash
# Create a scan target for your internal network (or use the dashboard's "+ New Target" button)
curl -s -X POST http://localhost:8443/api/v1/network-scan-targets \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Web Servers",
    "cidrs": ["10.0.1.0/24", "10.0.2.0/24"],
    "ports": [443, 8443, 6443],
    "enabled": true,
    "scan_interval_hours": 6,
    "timeout_ms": 5000
  }' | jq .
```

### How It Works

1. **Expand**: CIDR ranges are expanded to individual IPs (safety cap at /20 = 4096 IPs)
2. **Probe**: Concurrent TLS connections (50 goroutines) with configurable timeout per endpoint
3. **Extract**: Certificate metadata extracted from TLS handshake (CN, SANs, serial, issuer, key info, fingerprint)
4. **Pipeline**: Results fed into the same `DiscoveryService.ProcessDiscoveryReport()` as filesystem discovery
5. **Deduplicate**: Sentinel agent ID (`server-scanner`) with source_path as `ip:port` ensures proper dedup
6. **Triage**: Discovered certs appear in the **Discovery** dashboard page (and via `GET /api/v1/discovered-certificates`) with `agent_id=server-scanner`

### API Endpoints

```bash
# List all scan targets
curl -s http://localhost:8443/api/v1/network-scan-targets | jq .

# Create a scan target
curl -s -X POST http://localhost:8443/api/v1/network-scan-targets \
  -H "Content-Type: application/json" \
  -d '{"name": "DMZ", "cidrs": ["172.16.0.0/24"], "ports": [443]}' | jq .

# Get a specific target (includes last_scan_at, last_scan_certs_found)
curl -s http://localhost:8443/api/v1/network-scan-targets/nst-dmz | jq .

# Trigger an immediate scan (doesn't wait for scheduler)
curl -s -X POST http://localhost:8443/api/v1/network-scan-targets/nst-dmz/scan | jq .

# Update scan configuration
curl -s -X PUT http://localhost:8443/api/v1/network-scan-targets/nst-dmz \
  -H "Content-Type: application/json" \
  -d '{"ports": [443, 8443, 9443], "timeout_ms": 3000}' | jq .

# Delete a scan target
curl -s -X DELETE http://localhost:8443/api/v1/network-scan-targets/nst-dmz
```

### Scheduler Integration

When `CERTCTL_NETWORK_SCAN_ENABLED=true`, the server runs a 6th scheduler loop (alongside renewal, jobs, health, notifications, and short-lived expiry). It scans all enabled targets at the configured interval (default 6h). Each target tracks `last_scan_at`, `last_scan_duration_ms`, and `last_scan_certs_found` for monitoring scan health.

### Use Cases

- **Network inventory** — "What TLS certs are deployed across my network?" without deploying agents
- **Shadow certificate detection** — Find certificates on services you didn't know were running TLS
- **Compliance scanning** — Prove to auditors that all TLS endpoints are inventoried
- **Migration assessment** — Scan a network range before onboarding to certctl management
- **Expiration monitoring** — Discover soon-to-expire certs on network endpoints before they cause outages

## What's Next

- [Architecture Guide](architecture.md) — Understanding the full system design
- [Quick Start](quickstart.md) — Get certctl running locally
- [Advanced Demo](demo-advanced.md) — See the full certificate lifecycle in action
