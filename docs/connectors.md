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
   - [Built-in: Vault PKI](#built-in-vault-pki)
   - [Built-in: DigiCert CertCentral](#built-in-digicert-certcentral)
   - [Built-in: Sectigo SCM](#built-in-sectigo-scm)
   - [Built-in: Google CAS](#built-in-google-cas)
   - [Built-in: AWS ACM Private CA](#built-in-aws-acm-private-ca)
   - [Revocation Across Issuers](#revocation-across-issuers)
   - [EST Integration (GetCACertPEM)](#est-integration-getcacertpem)
   - [Building a Custom Issuer](#building-a-custom-issuer)
3. [Target Connector](#target-connector)
   - [Interface](#interface-1)
   - [Built-in: NGINX](#built-in-nginx)
   - [Built-in: Apache httpd](#built-in-apache-httpd)
   - [Built-in: HAProxy](#built-in-haproxy)
   - [Built-in: Traefik](#built-in-traefik)
   - [Built-in: Envoy](#built-in-envoy)
   - [Built-in: Postfix / Dovecot](#built-in-postfix--dovecot)
   - [Built-in: Caddy](#built-in-caddy)
   - [F5 BIG-IP (Implemented)](#f5-big-ip-implemented)
   - [IIS (Implemented, Dual-Mode)](#iis-implemented-dual-mode)
   - [SSH (Agentless Deployment)](#ssh-agentless-deployment)
   - [Windows Certificate Store](#windows-certificate-store)
   - [Java Keystore (JKS / PKCS#12)](#java-keystore-jks--pkcs12)
   - [Kubernetes Secrets](#kubernetes-secrets)
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

1. **Issuer Connector** — Obtains certificates from CAs. 9 built-in: Local CA (self-signed + sub-CA), ACME v2 (HTTP-01, DNS-01, DNS-PERSIST-01, ARI, EAB, profile selection), step-ca, OpenSSL/Custom CA, Vault PKI, DigiCert CertCentral, Sectigo SCM, Google CAS, AWS ACM Private CA
2. **Target Connector** — Deploys certificates to infrastructure. 14 built-in: NGINX, Apache httpd, HAProxy, Traefik, Caddy, Envoy, Postfix, Dovecot, IIS (local + WinRM), F5 BIG-IP (proxy agent), SSH (agentless), Windows Certificate Store, Java Keystore, Kubernetes Secrets
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

**CRL and OCSP support (M15b):** The Local CA supports DER-encoded X.509 CRL generation served unauthenticated at `GET /.well-known/pki/crl/{issuer_id}` (RFC 5280 §5, RFC 8615, `Content-Type: application/pkix-crl`) with 24-hour validity. An embedded OCSP responder at `GET /.well-known/pki/ocsp/{issuer_id}/{serial}` (RFC 6960, `Content-Type: application/ocsp-response`) returns signed OCSP responses for issued certificates (good/revoked/unknown status). Both endpoints are reachable by relying parties with no certctl API credentials, which is how standard TLS clients, browsers, and hardware appliances consume these resources. Certificates with profile TTL < 1 hour automatically skip CRL/OCSP — expiry is treated as sufficient revocation for short-lived credentials.

**Extended Key Usage (EKU) support (M27):** The Local CA respects EKU constraints from certificate profiles and adjusts key usage flags accordingly. For S/MIME certificates (emailProtection EKU), it uses `DigitalSignature | ContentCommitment` instead of the TLS default. For TLS certificates (serverAuth/clientAuth EKU), it uses `DigitalSignature | KeyEncipherment`. This enables support for multiple certificate types — TLS, S/MIME, code signing, timestamping — from a single CA.

**MaxTTL enforcement (M11c):** When a certificate profile defines a maximum TTL, the Local CA caps the `NotAfter` field to `min(validity_days, maxTTL)`. This ensures certificates never exceed the profile's configured lifetime regardless of the issuer's `validity_days` setting.

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

**ACME Renewal Information (ARI, RFC 9773):** Instead of using fixed renewal thresholds (e.g., renew 30 days before expiry), certctl can ask the CA when it should renew. Enable with `CERTCTL_ACME_ARI_ENABLED=true`. The ARI protocol lets the CA specify a `suggestedWindow` (start and end times) for when you should renew — useful for distributing load during maintenance windows or coordinating mass revocation scenarios. Cert ID is computed as `base64url(SHA-256(DER cert))`. If the CA doesn't support ARI (404 response), certctl automatically falls back to threshold-based renewal with no operator intervention required.

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
- `CERTCTL_ACME_PROFILE` — Certificate profile for the newOrder request. Let's Encrypt supports `tlsserver` (standard TLS, default) and `shortlived` (6-day certs). Leave empty for the CA's default profile.

**Certificate Profiles:** Let's Encrypt (GA January 2026) supports ACME certificate profile selection. Set `CERTCTL_ACME_PROFILE=shortlived` to request 6-day certificates — ideal for ephemeral workloads where short validity substitutes for revocation. The `tlsserver` profile produces standard TLS certificates. When the profile field is empty (default), the CA uses its default profile, maintaining full backward compatibility.

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

**Note:** step-ca-issued certificates rely on step-ca's own CRL/OCSP infrastructure. certctl's local CRL/OCSP endpoints (`GET /.well-known/pki/crl/{issuer_id}` and `GET /.well-known/pki/ocsp/{issuer_id}/{serial}`, served unauthenticated per RFC 5280 §5 / RFC 6960 / RFC 8615) are populated from step-ca's revocation data if available, but clients should validate against step-ca's endpoints for the authoritative status.

**MaxTTL enforcement (M11c):** When a certificate profile defines a maximum TTL, the step-ca connector caps the `NotAfter` field to ensure the issued certificate does not exceed the profile limit, regardless of the step-ca provisioner's own maximum.

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

### EST/SCEP Integration (GetCACertPEM)

The `GetCACertPEM()` method returns the PEM-encoded CA certificate chain, used by both the EST server's `/.well-known/est/cacerts` endpoint (RFC 7030) and the SCEP server's `GetCACert` operation (RFC 8894) to distribute the CA chain to enrolling devices. Each issuer handles this differently:

- **Local CA**: Returns the CA certificate PEM (self-signed or sub-CA cert). This is the primary EST/SCEP issuer.
- **ACME**: Returns error — ACME CAs provide chains per-issuance, not statically.
- **step-ca**: Returns error — step-ca serves its own `/root` endpoint for CA distribution.
- **OpenSSL/Custom CA**: Returns error — custom script-based CAs have no CA cert access through certctl.

Note: EST and SCEP are not connectors — they are protocol handlers (`internal/api/handler/est.go` and `internal/api/handler/scep.go`) that delegate certificate issuance to whichever issuer connector is configured via `CERTCTL_EST_ISSUER_ID` or `CERTCTL_SCEP_ISSUER_ID`. Both share a common `internal/pkcs7` package for PKCS#7 response encoding. See the [Architecture Guide](architecture.md#est-server-rfc-7030) for details.

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

**MaxTTL enforcement (M11c):** When a certificate profile defines a maximum TTL, the Vault connector overrides the TTL string in the signing request to ensure the issued certificate does not exceed the profile limit. This is applied before Vault's own role-level max TTL.

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

### Built-in: Sectigo SCM

The Sectigo connector integrates with Sectigo Certificate Manager's REST API for ordering and managing DV, OV, and EV certificates. Like DigiCert, it uses an async order model: submit an enrollment, receive an sslId, then poll for completion.

**Configuration:**

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTCTL_SECTIGO_CUSTOMER_URI` | — | Sectigo customer URI (organization identifier) |
| `CERTCTL_SECTIGO_LOGIN` | — | API account login |
| `CERTCTL_SECTIGO_PASSWORD` | — | API account password |
| `CERTCTL_SECTIGO_ORG_ID` | — | Organization ID (integer) |
| `CERTCTL_SECTIGO_CERT_TYPE` | — | Certificate type ID (integer, from `/ssl/v1/types`) |
| `CERTCTL_SECTIGO_TERM` | `365` | Certificate validity in days |
| `CERTCTL_SECTIGO_BASE_URL` | `https://cert-manager.com/api` | Sectigo API base URL |

The connector submits certificate enrollments to Sectigo's `/ssl/v1/enroll` API. DV certificates may issue immediately; OV/EV certificates require validation (handled by Sectigo) and poll-based completion. The connector periodically checks enrollment status via `/ssl/v1/{sslId}` and downloads the PEM bundle via `/ssl/v1/collect/{sslId}/pem` when issued.

**Authentication:** Three custom headers on every request — `customerUri`, `login`, and `password`.

**Note:** CRL and OCSP are managed by Sectigo. certctl records revocations locally and notifies Sectigo via `/ssl/v1/revoke/{sslId}`.

Location: `internal/connector/issuer/sectigo/sectigo.go`

### Built-in: Google CAS

Google Cloud Certificate Authority Service — managed private CA on GCP. Synchronous issuance via CAS REST API with OAuth2 service account auth.

| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| `CERTCTL_GOOGLE_CAS_PROJECT` | Yes | — | GCP project ID |
| `CERTCTL_GOOGLE_CAS_LOCATION` | Yes | — | GCP region (e.g., `us-central1`) |
| `CERTCTL_GOOGLE_CAS_CA_POOL` | Yes | — | CA pool name |
| `CERTCTL_GOOGLE_CAS_CREDENTIALS` | Yes | — | Path to service account JSON |
| `CERTCTL_GOOGLE_CAS_TTL` | No | `8760h` | Default certificate TTL |

**Authentication:** OAuth2 service account. The connector reads a service account JSON file, signs a JWT with the private key, and exchanges it for an access token at Google's token endpoint. Tokens are cached and refreshed automatically (5 min before expiry).

**Note:** CRL and OCSP are managed by Google CAS directly. certctl records revocations locally and notifies Google CAS via the revoke endpoint.

Location: `internal/connector/issuer/googlecas/googlecas.go`

### Built-in: AWS ACM Private CA

AWS Certificate Manager Private Certificate Authority — managed private CA on AWS. Synchronous issuance via ACM PCA API with standard AWS credential chain (env vars, IAM roles, instance profiles, SSO).

| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| `CERTCTL_AWS_PCA_REGION` | Yes | — | AWS region (e.g., `us-east-1`) |
| `CERTCTL_AWS_PCA_CA_ARN` | Yes | — | ARN of the ACM Private CA |
| `CERTCTL_AWS_PCA_SIGNING_ALGORITHM` | No | `SHA256WITHRSA` | Signing algorithm |
| `CERTCTL_AWS_PCA_VALIDITY_DAYS` | No | `365` | Certificate validity in days |
| `CERTCTL_AWS_PCA_TEMPLATE_ARN` | No | — | Optional certificate template ARN |

**Supported signing algorithms:** SHA256WITHRSA, SHA384WITHRSA, SHA512WITHRSA, SHA256WITHECDSA, SHA384WITHECDSA, SHA512WITHECDSA.

**Authentication:** Standard AWS credential chain. The connector uses `aws-sdk-go-v2/config.LoadDefaultConfig()` which supports environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), IAM roles (EC2/ECS), instance profiles, and SSO credentials.

**Note:** CRL and OCSP are managed by AWS ACM PCA directly. certctl records revocations locally and notifies AWS via the RevokeCertificate API with RFC 5280 reason mapping.

Location: `internal/connector/issuer/awsacmpca/awsacmpca.go`

### Built-in: Entrust Certificate Services

Entrust CA Gateway REST API with mutual TLS (mTLS) client certificate authentication. Supports synchronous issuance (200 OK with PEM) and approval-pending flows (201 Accepted with async polling).

| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| `CERTCTL_ENTRUST_API_URL` | Yes | — | Entrust CA Gateway base URL |
| `CERTCTL_ENTRUST_CLIENT_CERT_PATH` | Yes | — | Path to mTLS client certificate PEM |
| `CERTCTL_ENTRUST_CLIENT_KEY_PATH` | Yes | — | Path to mTLS client private key PEM |
| `CERTCTL_ENTRUST_CA_ID` | Yes | — | Certificate Authority ID (from `GET /certificate-authorities`) |
| `CERTCTL_ENTRUST_PROFILE_ID` | No | — | Optional enrollment profile ID |

**Authentication:** Mutual TLS — the client certificate and key are loaded via `tls.LoadX509KeyPair()` and attached to the HTTP transport. No API key or token required.

**Issuance model:** Enrollment via `POST /v1/certificate-authorities/{caId}/enrollments`. Returns 200 with PEM immediately for auto-approved enrollments, or 201 Accepted with a tracking ID for approval-pending orders. `GetOrderStatus` polls the enrollment endpoint.

**Note:** CRL and OCSP are managed by Entrust. certctl records revocations locally and notifies Entrust via `PUT /v1/certificate-authorities/{caId}/certificates/{serial}/revoke`.

Location: `internal/connector/issuer/entrust/entrust.go`

### Built-in: GlobalSign Atlas HVCA

GlobalSign Atlas High Volume CA REST API with dual authentication: mTLS for the TLS handshake and API key/secret headers for request authorization. Region-aware base URLs (EMEA, APAC, Americas).

| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| `CERTCTL_GLOBALSIGN_API_URL` | Yes | — | Atlas HVCA API URL (region-specific) |
| `CERTCTL_GLOBALSIGN_API_KEY` | Yes | — | API key for request authentication |
| `CERTCTL_GLOBALSIGN_API_SECRET` | Yes | — | API secret for request authentication |
| `CERTCTL_GLOBALSIGN_CLIENT_CERT_PATH` | Yes | — | Path to mTLS client certificate PEM |
| `CERTCTL_GLOBALSIGN_CLIENT_KEY_PATH` | Yes | — | Path to mTLS client private key PEM |
| `CERTCTL_GLOBALSIGN_SERVER_CA_PATH` | No | system trust store | PEM bundle used to verify the Atlas API server certificate. Set this for private/lab Atlas deployments whose server TLS chain is not in the host's default trust bundle. |

**Authentication:** Dual — mTLS client certificate for TLS handshake plus `X-API-Key` and `X-API-Secret` headers on every request.

**TLS verification:** The connector always verifies the server certificate. When `server_ca_path` is set, the PEM bundle at that path is used as the trust anchor; otherwise the host's system trust store is used. TLS 1.2 is the minimum protocol version.

**Issuance model:** `POST /v2/certificates` returns a serial number. Certificate PEM is available after validation completes. Typically resolves within seconds for DV. `GetOrderStatus` polls the certificate endpoint.

**Note:** CRL and OCSP are managed by GlobalSign. certctl records revocations locally and notifies GlobalSign via `PUT /v2/certificates/{serial}/revoke`.

Location: `internal/connector/issuer/globalsign/globalsign.go`

### Built-in: EJBCA (Keyfactor)

EJBCA REST API for self-hosted open-source and enterprise CAs. Supports dual authentication: mTLS (default) or OAuth2 Bearer token, selectable via configuration.

| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| `CERTCTL_EJBCA_API_URL` | Yes | — | EJBCA REST API base URL |
| `CERTCTL_EJBCA_AUTH_MODE` | No | `mtls` | Auth mode: `mtls` or `oauth2` |
| `CERTCTL_EJBCA_CLIENT_CERT_PATH` | mTLS | — | Path to client certificate PEM (mTLS mode) |
| `CERTCTL_EJBCA_CLIENT_KEY_PATH` | mTLS | — | Path to client key PEM (mTLS mode) |
| `CERTCTL_EJBCA_TOKEN` | OAuth2 | — | Bearer token (oauth2 mode) |
| `CERTCTL_EJBCA_CA_NAME` | Yes | — | EJBCA CA name |
| `CERTCTL_EJBCA_CERT_PROFILE` | No | — | EJBCA certificate profile |
| `CERTCTL_EJBCA_EE_PROFILE` | No | — | EJBCA end-entity profile |

**Authentication:** Configurable via `auth_mode`. In mTLS mode, client certificate and key are loaded for the TLS handshake. In OAuth2 mode, the token is sent as `Authorization: Bearer {token}`.

**Issuance model:** `POST /v1/certificate/pkcs10enroll` with base64-encoded CSR. Returns base64-encoded certificate PEM. EJBCA 9.3+ creates end-entity and issues cert in a single call. Approval-pending enrollments return 201.

**Revocation note:** EJBCA requires both issuer DN and serial number for revocation. The connector stores these as a composite `OrderID` in `issuer_dn::serial` format.

**Note:** CRL and OCSP are managed by the EJBCA instance. certctl records revocations locally and notifies EJBCA via `PUT /v1/certificate/{issuer_dn}/{serial}/revoke`.

Location: `internal/connector/issuer/ejbca/ejbca.go`

### ADCS Integration

Active Directory Certificate Services integration is handled via the **sub-CA mode** of the Local CA issuer, not as a separate connector. certctl operates as a subordinate CA with its signing certificate issued by ADCS, so all certctl-issued certs chain to the enterprise ADCS root. See the Local CA section above.

### Building a Custom Issuer

Here's a simplified example showing the connector pattern (using a hypothetical Vault-like CA):

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

### Built-in: Envoy

The Envoy connector uses file-based certificate delivery — it writes certificate and key files to a directory that Envoy watches via its SDS (Secret Discovery Service) file-based configuration or static `filename` references in the bootstrap config. When files change, Envoy automatically picks up the new certificates without requiring a reload command.

Configuration:
```json
{
  "cert_dir": "/etc/envoy/certs",
  "cert_filename": "cert.pem",
  "key_filename": "key.pem",
  "chain_filename": "chain.pem",
  "sds_config": true
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cert_dir` | string | (required) | Directory where Envoy watches for certificate files |
| `cert_filename` | string | `cert.pem` | Filename for the certificate (leaf + chain unless `chain_filename` is set) |
| `key_filename` | string | `key.pem` | Filename for the private key |
| `chain_filename` | string | (empty) | If set, chain is written to a separate file instead of appended to the cert |
| `sds_config` | bool | `false` | If true, writes an `sds.json` file for Envoy's file-based SDS provider |

When `sds_config` is `true`, the connector writes an SDS JSON file (`{cert_dir}/sds.json`) containing a `tls_certificate` resource that points to the cert and key file paths. Envoy's file-based SDS (`path_config_source`) watches this file for changes, providing automatic hot-reload of certificates. This is the recommended approach for production Envoy deployments using dynamic TLS configuration.

When `sds_config` is `false` (the default), the connector simply writes cert and key files. Use this mode when Envoy's bootstrap config references the cert/key files directly via static `filename` fields in the TLS context.

Location: `internal/connector/target/envoy/envoy.go`

### Built-in: Postfix / Dovecot

The Postfix/Dovecot connector is a dual-mode mail server TLS connector. It writes certificate, key, and chain files to configured paths and reloads the mail service. The `mode` field selects between Postfix MTA and Dovecot IMAP/POP3, which determines default file paths and reload commands.

This connector pairs with certctl's S/MIME certificate support (email protection EKU, email SAN routing) for a complete email infrastructure story — TLS for transport encryption, S/MIME for end-to-end message signing and encryption.

**Postfix configuration:**
```json
{
  "mode": "postfix",
  "cert_path": "/etc/postfix/certs/cert.pem",
  "key_path": "/etc/postfix/certs/key.pem",
  "chain_path": "/etc/postfix/certs/chain.pem",
  "reload_command": "postfix reload",
  "validate_command": "postfix check"
}
```

**Dovecot configuration:**
```json
{
  "mode": "dovecot",
  "cert_path": "/etc/dovecot/certs/cert.pem",
  "key_path": "/etc/dovecot/certs/key.pem",
  "chain_path": "/etc/dovecot/certs/chain.pem",
  "reload_command": "doveadm reload",
  "validate_command": "doveconf -n"
}
```

| Field | Type | Default (Postfix) | Default (Dovecot) | Description |
|-------|------|-------------------|-------------------|-------------|
| `mode` | string | `postfix` | `dovecot` | Service mode — determines defaults |
| `cert_path` | string | `/etc/postfix/certs/cert.pem` | `/etc/dovecot/certs/cert.pem` | Path for certificate file |
| `key_path` | string | `/etc/postfix/certs/key.pem` | `/etc/dovecot/certs/key.pem` | Path for private key (0600 permissions) |
| `chain_path` | string | (empty) | (empty) | If set, chain written separately; otherwise appended to cert |
| `reload_command` | string | `postfix reload` | `doveadm reload` | Command to reload the mail service |
| `validate_command` | string | `postfix check` | `doveconf -n` | Optional config validation before reload |

All commands are validated against shell injection via `validation.ValidateShellCommand()`. File permissions: cert/chain 0644, key 0600.

Location: `internal/connector/target/postfix/postfix.go`

### F5 BIG-IP (Implemented)

The F5 BIG-IP target connector deploys certificates to F5 load balancers via the iControl REST API. F5 appliances can't run agents directly, so this connector uses the **proxy agent pattern**: a designated certctl agent in the same network zone polls for F5 deployment jobs and executes iControl REST calls on behalf of the control plane. Minimum supported BIG-IP version: 12.0+.

The deployment flow uses F5's transaction API for atomic updates: authenticate via token auth, upload cert/key/chain PEM files, install as crypto objects, update the SSL client profile within a transaction, and commit. If the transaction fails, F5 rolls back automatically and the connector cleans up uploaded crypto objects. Updating an SSL profile automatically takes effect on all bound virtual servers — no separate virtual server binding step is needed.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | *(required)* | F5 BIG-IP management hostname or IP |
| `port` | int | `443` | iControl REST API port |
| `username` | string | *(required)* | Administrative username |
| `password` | string | *(required)* | Administrative password |
| `partition` | string | `Common` | F5 partition for crypto objects and profiles |
| `ssl_profile` | string | *(required)* | SSL client profile name to update |
| `insecure` | bool | `true` | Skip TLS verification for management interface (self-signed certs common) |
| `timeout` | int | `30` | HTTP timeout in seconds |

```json
{
  "host": "f5.internal.example.com",
  "port": 443,
  "username": "admin",
  "password": "...",
  "partition": "Common",
  "ssl_profile": "clientssl_api",
  "insecure": true,
  "timeout": 30
}
```

F5 credentials are stored on the proxy agent, not on the control plane server. This limits the credential blast radius to the proxy agent's network zone. Config fields are validated against regex patterns to prevent injection.

Location: `internal/connector/target/f5/f5.go`

### IIS (Implemented, Dual-Mode)

The IIS target connector supports two deployment modes — agent-local (recommended) and proxy agent WinRM for agentless targets.

**Agent-local (recommended):** A Windows agent runs directly on the IIS server and deploys certificates using PowerShell — `Import-PfxCertificate` to install into the certificate store and `Set-WebBinding` to bind to the IIS site. The agent handles PEM-to-PFX conversion via `go-pkcs12`, computes SHA-1 thumbprint from the certificate, and executes parameterized PowerShell scripts for injection-safe binding management. This is the preferred approach: no remote access needed, no credential management, same pull-based model as NGINX/Apache/HAProxy.

**Proxy agent WinRM (for agentless targets):** For Windows servers where you don't want to install an agent, a Linux or Windows proxy agent in the same network zone connects via WinRM (Windows Remote Management) and executes PowerShell commands remotely. The PFX bundle is base64-encoded, transferred inline in the WinRM session, decoded to a temp file on the remote host, imported, and the temp file is cleaned up in a `try/finally` block. WinRM credentials are configured on the target, not on the control plane. Uses the `masterzen/winrm` Go library with support for Basic, NTLM, and Kerberos authentication.

**Agent-local configuration:**
```json
{
  "hostname": "iis-server.example.com",
  "site_name": "Default Web Site",
  "cert_store": "WebHosting",
  "port": 443,
  "sni": true,
  "ip_address": "*",
  "binding_info": "www.example.com"
}
```

**WinRM proxy configuration:**
```json
{
  "hostname": "iis-server.example.com",
  "site_name": "Default Web Site",
  "cert_store": "WebHosting",
  "port": 443,
  "sni": true,
  "ip_address": "*",
  "mode": "winrm",
  "winrm": {
    "winrm_host": "iis-server.example.com",
    "winrm_port": 5985,
    "winrm_username": "Administrator",
    "winrm_password": "...",
    "winrm_https": false,
    "winrm_insecure": false,
    "winrm_timeout": 60
  }
}
```

**Configuration Fields:**
- `hostname` (string, required): IIS server hostname or FQDN
- `site_name` (string, required): IIS website name (e.g., "Default Web Site")
- `cert_store` (string, required): Certificate store for import (e.g., "WebHosting", "My")
- `port` (number, default 443): HTTPS binding port
- `sni` (boolean, default false): Enable Server Name Indication (SNI)
- `ip_address` (string, default "*"): Specific IP to bind to, or "*" for all IPs
- `binding_info` (string, optional): Host header for SNI bindings
- `mode` (string, default "local"): Deployment mode — `local` (agent-local PowerShell) or `winrm` (remote via WinRM)

**WinRM fields (required when `mode` is `winrm`):**
- `winrm.winrm_host` (string, required): Remote Windows server hostname or IP
- `winrm.winrm_port` (number, default 5985 HTTP / 5986 HTTPS): WinRM listener port
- `winrm.winrm_username` (string, required): Windows account with admin privileges
- `winrm.winrm_password` (string, required): Account password
- `winrm.winrm_https` (boolean, default false): Use HTTPS transport
- `winrm.winrm_insecure` (boolean, default false): Skip TLS certificate verification
- `winrm.winrm_timeout` (number, default 60): Operation timeout in seconds

**Security Model:**
- PFX files are transient — generated with random passwords, deleted after import
- In WinRM mode, PFX data is base64-encoded and transferred inline (no SMB/file share needed), with remote temp file cleanup in `try/finally`
- PowerShell commands use parameterized values — IIS names and cert stores are regex-validated before script execution
- Field names are validated against `^[a-zA-Z0-9 _\-\.]+$` to prevent PowerShell injection
- Certificate thumbprints computed via SHA-1 for IIS binding lookups

Location: `internal/connector/target/iis/iis.go`, `internal/connector/target/iis/winrm.go`

### SSH (Agentless Deployment)

The SSH target connector enables agentless certificate deployment to any Linux/Unix server via SSH/SFTP. Instead of installing the certctl agent binary on every target, a single "proxy agent" in the same network zone deploys certificates to remote servers over SSH. This is ideal for environments where installing agents on every server is impractical.

**Key authentication (recommended):**
```json
{
  "host": "web-server.internal",
  "port": 22,
  "user": "certctl",
  "auth_method": "key",
  "private_key_path": "/home/certctl/.ssh/id_ed25519",
  "cert_path": "/etc/ssl/certs/cert.pem",
  "key_path": "/etc/ssl/private/key.pem",
  "chain_path": "/etc/ssl/certs/chain.pem",
  "reload_command": "systemctl reload nginx",
  "timeout": 30
}
```

**Password authentication:**
```json
{
  "host": "legacy-server.internal",
  "user": "deploy",
  "auth_method": "password",
  "password": "s3cret",
  "cert_path": "/etc/ssl/cert.pem",
  "key_path": "/etc/ssl/key.pem",
  "reload_command": "systemctl reload apache2"
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | *(required)* | SSH hostname or IP address |
| `port` | number | 22 | SSH port |
| `user` | string | *(required)* | SSH username |
| `auth_method` | string | `"key"` | `"key"` or `"password"` |
| `private_key_path` | string | | Path to SSH private key file (key auth) |
| `private_key` | string | | Inline SSH private key PEM (alternative to path) |
| `password` | string | | SSH password (password auth) |
| `passphrase` | string | | Passphrase for encrypted private keys |
| `cert_path` | string | *(required)* | Remote path for certificate file |
| `key_path` | string | *(required)* | Remote path for private key file |
| `chain_path` | string | | Remote path for chain file (if empty, chain appended to cert) |
| `cert_mode` | string | `"0644"` | File permissions for cert (octal) |
| `key_mode` | string | `"0600"` | File permissions for private key (octal) |
| `reload_command` | string | | Command to execute after deployment |
| `timeout` | number | 30 | SSH connection timeout in seconds |

**Security:**
- Key-based authentication is recommended over password authentication
- Reload commands are validated against shell injection (same validation as Postfix/Dovecot connectors)
- Host field is regex-validated to prevent shell metacharacters
- Private keys are written with 0600 permissions by default
- Host key verification is intentionally skipped (same rationale as network scanner and F5 connector — deploying to known, operator-configured infrastructure)
- Encrypted private keys supported via passphrase

Location: `internal/connector/target/ssh/ssh.go`

### Windows Certificate Store

The Windows Certificate Store connector imports certificates into the Windows cert store via PowerShell, without managing IIS site bindings. Use this for non-IIS Windows services that read certificates from the cert store (Exchange, RDP, SQL Server, ADFS, etc.). Same injectable `PowerShellExecutor` pattern as the IIS connector, with optional WinRM proxy mode.

```json
{
  "store_name": "My",
  "store_location": "LocalMachine",
  "friendly_name": "Production API Cert",
  "remove_expired": true
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `store_name` | string | `"My"` | Windows cert store name (My, Root, WebHosting, etc.) |
| `store_location` | string | `"LocalMachine"` | `"LocalMachine"` or `"CurrentUser"` |
| `friendly_name` | string | | Optional friendly name for the imported certificate |
| `remove_expired` | boolean | `false` | Remove expired certs with same CN after import |
| `mode` | string | `"local"` | `"local"` (agent-local) or `"winrm"` (remote) |
| `winrm_host` | string | | WinRM hostname (required for winrm mode) |
| `winrm_port` | number | 5985 | WinRM port (5985 HTTP, 5986 HTTPS) |
| `winrm_username` | string | | WinRM username (required for winrm mode) |
| `winrm_password` | string | | WinRM password (required for winrm mode) |
| `winrm_https` | boolean | `false` | Use HTTPS for WinRM |
| `winrm_insecure` | boolean | `false` | Skip TLS verification for WinRM |

Location: `internal/connector/target/wincertstore/wincertstore.go`

### Java Keystore (JKS / PKCS#12)

The Java Keystore connector deploys certificates to JKS or PKCS#12 keystores via the `keytool` CLI. This enables TLS cert deployment for Tomcat, Jetty, Kafka, Elasticsearch, and any JVM-based service. Flow: PEM to temp PKCS#12, then `keytool -importkeystore` into the target keystore.

```json
{
  "keystore_path": "/opt/tomcat/conf/keystore.p12",
  "keystore_password": "changeit",
  "keystore_type": "PKCS12",
  "alias": "server",
  "reload_command": "systemctl restart tomcat"
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `keystore_path` | string | *(required)* | Absolute path to the keystore file |
| `keystore_password` | string | *(required)* | Keystore password |
| `keystore_type` | string | `"PKCS12"` | `"PKCS12"` or `"JKS"` |
| `alias` | string | `"server"` | Key entry alias in the keystore |
| `reload_command` | string | | Optional command to run after keystore update |
| `create_keystore` | boolean | `true` | Create keystore if it doesn't exist |
| `keytool_path` | string | `"keytool"` | Override keytool binary path |

**Security:**
- Reload commands validated against shell injection via `validation.ValidateShellCommand()`
- Alias validated against injection (alphanumeric, hyphens, underscores only)
- Path traversal prevention on keystore path
- Transient PKCS#12 temp file cleaned up after import (even on error)

Location: `internal/connector/target/javakeystore/javakeystore.go`

### Kubernetes Secrets

The Kubernetes Secrets connector deploys certificates as `kubernetes.io/tls` Secrets, compatible with Ingress controllers (nginx-ingress, Traefik, HAProxy), service meshes (Istio, Linkerd), and any Kubernetes workload that reads TLS Secrets.

```json
{
  "namespace": "production",
  "secret_name": "api-tls",
  "labels": {"app": "api-gateway"},
  "kubeconfig_path": "/home/agent/.kube/config"
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `namespace` | string | *(required)* | Kubernetes namespace (DNS-1123, max 63 chars) |
| `secret_name` | string | *(required)* | Secret name (DNS subdomain, max 253 chars) |
| `labels` | object | | Additional labels to apply to the Secret |
| `kubeconfig_path` | string | | Path to kubeconfig for out-of-cluster agents |

**Deployment modes:**
- **In-cluster (default):** Agent runs as a Pod with a ServiceAccount. Authentication via auto-mounted token. Requires RBAC (`secrets.get`, `secrets.create`, `secrets.update`, `secrets.list`) — see Helm chart.
- **Out-of-cluster:** Agent runs outside the cluster with `kubeconfig_path` pointing to a kubeconfig file. Useful for proxy agent pattern.

**Secret format:** Standard `kubernetes.io/tls` with `tls.crt` (cert + chain PEM) and `tls.key` (private key PEM). Managed labels (`app.kubernetes.io/managed-by: certctl`) and annotations (`certctl.io/deployed-at`, `certctl.io/certificate-id`) are applied automatically.

**Validation:** After deployment, the connector reads the Secret back and compares the certificate serial number to verify successful deployment.

Location: `internal/connector/target/k8ssecret/k8ssecret.go`

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

**Scheduler Integration:** The opt-in digest scheduler loop runs on configurable interval (default 24 hours). It does NOT run on startup — waits for first scheduled tick. Operation timeout is 5 minutes. Each loop execution is guarded by `sync/atomic.Bool` idempotency. See `docs/architecture.md` for the full scheduler topology (12 loops, 8 always-on + 4 opt-in).

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

When `CERTCTL_NETWORK_SCAN_ENABLED=true`, the server runs the opt-in network scanner scheduler loop alongside the always-on loops (renewal, jobs, job retry, job timeout, agent health, notifications, notification retry, short-lived expiry). It scans all enabled targets at the configured interval (default 6h). Each target tracks `last_scan_at`, `last_scan_duration_ms`, and `last_scan_certs_found` for monitoring scan health. See `docs/architecture.md` for the full 12-loop scheduler topology.

### Use Cases

- **Network inventory** — "What TLS certs are deployed across my network?" without deploying agents
- **Shadow certificate detection** — Find certificates on services you didn't know were running TLS
- **Compliance scanning** — Prove to auditors that all TLS endpoints are inventoried
- **Migration assessment** — Scan a network range before onboarding to certctl management
- **Expiration monitoring** — Discover soon-to-expire certs on network endpoints before they cause outages

## Cloud Secret Manager Discovery

certctl extends the existing filesystem and network discovery pipeline to cloud secret managers. Certificates stored in cloud vaults are automatically discovered, inventoried, and available for triage in the Discovery page.

Each cloud source runs as a pluggable `DiscoverySource` with its own sentinel agent ID. Discovered certificates flow through the same `ProcessDiscoveryReport` pipeline used by filesystem and network discovery — dedup by fingerprint, audit trail, status tracking.

### AWS Secrets Manager

Discovers certificates stored as secrets in AWS Secrets Manager. Filters by tag (`type=certificate` by default) and optional name prefix.

| Variable | Description | Default |
|---|---|---|
| `CERTCTL_CLOUD_DISCOVERY_ENABLED` | Enable cloud discovery scheduler | `false` |
| `CERTCTL_AWS_SM_DISCOVERY_ENABLED` | Enable AWS SM source | `false` |
| `CERTCTL_AWS_SM_REGION` | AWS region (e.g., `us-east-1`) | — |
| `CERTCTL_AWS_SM_TAG_FILTER` | Tag key=value filter | `type=certificate` |
| `CERTCTL_AWS_SM_NAME_PREFIX` | Secret name prefix filter | — |

Source path format: `aws-sm://{region}/{secret-name}`. Sentinel agent: `cloud-aws-sm`.

### Azure Key Vault

Discovers certificates from Azure Key Vault using OAuth2 client credentials authentication. No Azure SDK dependency — uses stdlib HTTP with Azure AD token exchange.

| Variable | Description | Default |
|---|---|---|
| `CERTCTL_AZURE_KV_DISCOVERY_ENABLED` | Enable Azure KV source | `false` |
| `CERTCTL_AZURE_KV_VAULT_URL` | Vault URL (e.g., `https://myvault.vault.azure.net`) | — |
| `CERTCTL_AZURE_KV_TENANT_ID` | Azure AD tenant ID | — |
| `CERTCTL_AZURE_KV_CLIENT_ID` | Azure AD application (client) ID | — |
| `CERTCTL_AZURE_KV_CLIENT_SECRET` | Azure AD application secret | — |

Source path format: `azure-kv://{cert-name}/{version}`. Sentinel agent: `cloud-azure-kv`.

### GCP Secret Manager

Discovers certificates stored in GCP Secret Manager. Filters by label (`type=certificate`). Uses JWT-based OAuth2 service account auth — no Google SDK dependency.

| Variable | Description | Default |
|---|---|---|
| `CERTCTL_GCP_SM_DISCOVERY_ENABLED` | Enable GCP SM source | `false` |
| `CERTCTL_GCP_SM_PROJECT` | GCP project ID | — |
| `CERTCTL_GCP_SM_CREDENTIALS` | Path to service account JSON file | — |

Source path format: `gcp-sm://{project}/{secret-name}`. Sentinel agent: `cloud-gcp-sm`.

### Cloud Discovery Scheduler

All enabled cloud sources run on a shared opt-in cloud discovery scheduler loop (see `docs/architecture.md` for the full 12-loop scheduler topology). The interval is configurable:

| Variable | Description | Default |
|---|---|---|
| `CERTCTL_CLOUD_DISCOVERY_ENABLED` | Master switch | `false` |
| `CERTCTL_CLOUD_DISCOVERY_INTERVAL` | Scan interval | `6h` |

The loop runs immediately on startup and then on each tick. Each source runs sequentially within the loop. Errors from one source do not prevent other sources from running.

## What's Next

- [Architecture Guide](architecture.md) — Understanding the full system design
- [Quick Start](quickstart.md) — Get certctl running locally
- [Advanced Demo](demo-advanced.md) — See the full certificate lifecycle in action
