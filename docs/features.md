# certctl Feature Inventory

Complete reference of every feature shipped in certctl through v2.1.0 (April 2026). Every claim in this document is verified against source code. If a number, default, or behavior isn't here, check the source file listed in the margin.

---

## At a Glance

| Metric | Count |
|---|---|
| HTTP routes | 107 (103 under `/api/v1/` + 4 EST) |
| OpenAPI 3.1 operations | 97 |
| MCP tools | 80 |
| CLI commands | 12 |
| Issuer connectors | 9 (+ EST server) |
| Target connectors | 14 |
| Notifier connectors | 6 channels |
| Database tables | 21 (across 10 migrations) |
| Background scheduler loops | 7 |
| Web dashboard pages | 24 |
| Test functions | 1850+ |
| Supported platforms | linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 |

---

## API Surface

<!-- Source: internal/api/router/router.go (HandlerRegistry struct, 20 fields, 107 route registrations) -->

### Authentication

Every API call requires authentication by default. Configurable via `CERTCTL_AUTH_TYPE`.

| Setting | Behavior |
|---|---|
| `api-key` (default) | SHA-256 hashed keys, constant-time comparison, `Authorization: Bearer {key}` |
| `none` | Disables auth with a log warning at startup |

Two endpoints are served without auth so the GUI can detect auth mode before login:

- `GET /api/v1/auth/info` — returns `{"auth_type":"api-key"}`
- `GET /api/v1/auth/check` — validates credentials

<!-- Source: internal/api/middleware/middleware.go -->

### Rate Limiting

Token bucket algorithm protecting the control plane from misbehaving clients.

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_RATE_LIMIT_ENABLED` | `true` | Enable/disable |
| `CERTCTL_RATE_LIMIT_RPS` | `50` | Requests per second |
| `CERTCTL_RATE_LIMIT_BURST` | `100` | Burst capacity |

Exceeded requests receive `429 Too Many Requests` with a `Retry-After` header.

### CORS

Deny-by-default. Empty `CERTCTL_CORS_ORIGINS` blocks all cross-origin requests.

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_CORS_ORIGINS` | `""` (deny all) | Comma-separated origins or `*` |

Preflight responses include `Access-Control-Max-Age` for caching.

### Request Body Size Limits

<!-- Source: internal/api/middleware/bodylimit.go -->

`http.MaxBytesReader` middleware positioned before auth in the middleware chain.

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_MAX_BODY_SIZE` | `1048576` (1 MB) | Maximum request body in bytes |

### Query Features

All list endpoints support:

- **Pagination** — page-based (`?page=2&per_page=50`) and cursor-based (`?cursor=<token>&page_size=100`)
- **Sparse fields** — `?fields=id,common_name,status` returns only requested fields
- **Sorting** — `?sort=-notAfter` (prefix `-` for descending). Whitelist: `notAfter`, `expiresAt`, `createdAt`, `updatedAt`, `commonName`, `name`, `status`, `environment`
- **Time-range filters** — `?expires_before=`, `?expires_after=`, `?created_after=`, `?updated_after=` (RFC 3339)
- **Resource filters** — `?agent_id=`, `?profile_id=`, `?owner_id=`, `?team_id=`, `?issuer_id=`, `?status=`

<!-- Source: internal/repository/filters.go, internal/api/handler/certificates.go -->

### API Audit Log

<!-- Source: internal/api/middleware/audit.go -->

Every API call is recorded to the immutable audit trail. Best-effort (non-blocking) via goroutine. Fields: method, path, actor (from auth context, falls back to "anonymous"), SHA-256 request body hash (truncated 16 chars), response status, latency. Health/readiness endpoints excluded via `ExcludePaths`.

---

## Certificate Lifecycle

<!-- Source: internal/domain/certificate.go -->

### Certificate Statuses

| Status | Description |
|---|---|
| `Pending` | Created, awaiting issuance |
| `Active` | Issued and valid |
| `Expiring` | Within configured alert threshold |
| `Expired` | Past notAfter |
| `RenewalInProgress` | Renewal job in flight |
| `Failed` | Issuance or renewal failed |
| `Revoked` | Explicitly revoked |
| `Archived` | Superseded by newer version |

### Key Generation Modes

<!-- Source: internal/config/config.go (KeygenConfig), cmd/agent/main.go -->

| Mode | Env Var Value | Behavior |
|---|---|---|
| Agent-side (default) | `CERTCTL_KEYGEN_MODE=agent` | Agent generates ECDSA P-256 key pair locally, submits CSR only. Private keys never leave agent infrastructure. Keys stored at `CERTCTL_KEY_DIR` (default `/var/lib/certctl/keys`) with `0600` permissions. |
| Server-side (demo only) | `CERTCTL_KEYGEN_MODE=server` | Server generates RSA key + CSR. Logs a warning at startup. Used in Docker Compose demo for convenience. |

### Issuance Flow

1. Certificate created (status: Pending)
2. Renewal/issuance job created (status: Pending or AwaitingCSR in agent keygen mode)
3. Agent polls `GET /agents/{id}/work`, receives job with `common_name` and `sans`
4. Agent generates ECDSA P-256 key pair, creates CSR, submits via `POST /agents/{id}/csr`
5. Server forwards CSR to issuer connector, stores signed certificate
6. Deployment jobs created for each target (scoped to assigned agent via `agent_id`)
7. Agent polls for deployment work, deploys to target connector
8. Optional: post-deployment TLS verification

### Renewal

<!-- Source: internal/scheduler/scheduler.go (renewalCheckLoop, 1-hour default interval) -->

The renewal scheduler runs every hour (configurable via `CERTCTL_RENEWAL_CHECK_INTERVAL`). For each certificate approaching expiration:

1. Checks ACME ARI (RFC 9773) if available — CA-directed renewal timing takes priority
2. Falls back to threshold-based logic using per-policy `alert_thresholds_days` (default `[30, 14, 7, 0]`)
3. Creates renewal job if thresholds are met and no duplicate job exists

### Interactive Approval

<!-- Source: internal/domain/job.go (JobStatusAwaitingApproval) -->

Jobs can require manual approval before execution. The `AwaitingApproval` state pauses the job until an operator acts.

- `POST /api/v1/jobs/{id}/approve` — approve with optional reason
- `POST /api/v1/jobs/{id}/reject` — reject with reason tracking

### Expiration Alerting

Configurable per-policy thresholds stored as `alert_thresholds_days` JSONB (default `[30, 14, 7, 0]`). The scheduler:

- Sends deduplicated notifications at each threshold crossing
- Transitions certificate status: Active → Expiring → Expired
- Short-lived certs (profile TTL < 1 hour) get a dedicated scheduler loop running every 30 seconds

---

## Revocation Infrastructure

<!-- Source: internal/domain/revocation.go, internal/service/certificate.go, internal/service/revocation_svc.go -->

### Revocation API

`POST /api/v1/certificates/{id}/revoke` with RFC 5280 reason codes:

| Reason | CRL Code |
|---|---|
| `unspecified` | 0 |
| `keyCompromise` | 1 |
| `caCompromise` | 2 |
| `affiliationChanged` | 3 |
| `superseded` | 4 |
| `cessationOfOperation` | 5 |
| `certificateHold` | 6 |
| `privilegeWithdrawn` | 9 |

Revocation is a 7-step process: validate eligibility → get serial → update status → record in `certificate_revocations` table → notify issuer (best-effort) → audit → send notification.

### CRL Endpoints

- `GET /api/v1/crl` — JSON-formatted CRL (version, entries array, total count, timestamp)
- `GET /api/v1/crl/{issuer_id}` — DER-encoded X.509 CRL signed by issuing CA, 24-hour validity

### OCSP Responder

`GET /api/v1/ocsp/{issuer_id}/{serial}` — signed OCSP responses (good/revoked/unknown). Signs with issuing CA key. Requires CA key access (Local CA, step-CA connectors).

### Short-Lived Certificate Exemption

Certificates with profile TTL < 1 hour skip CRL/OCSP. Expiry is sufficient revocation for short-lived credentials.

---

## Certificate Export

<!-- Source: internal/service/export.go, internal/api/handler/export.go -->

Two export formats. Private keys are never included — they live on agents only.

| Endpoint | Format | Notes |
|---|---|---|
| `GET /api/v1/certificates/{id}/export/pem` | PEM JSON or file download (`?download=true`) | Splits leaf from chain |
| `POST /api/v1/certificates/{id}/export/pkcs12` | Binary .p12 with `Content-Disposition` | Cert-only bundle via `go-pkcs12` `EncodeTrustStore` |

All exports generate audit events (`export_pem`, `export_pkcs12`) with serial number tracking.

---

## Certificate Profiles

<!-- Source: internal/domain/certificate.go (CertificateProfile), migrations/000003_certificate_profiles.up.sql -->

Named enrollment profiles defining crypto constraints and certificate properties. Stored in PostgreSQL with full CRUD API and GUI page.

### Profile Fields

- Allowed key types (RSA 2048/4096, ECDSA P-256/P-384)
- Maximum TTL
- Required SANs
- Permitted Extended Key Usages (EKUs)

### Crypto Policy Enforcement (M11c)

<!-- Source: internal/service/crypto_validation.go (ValidateCSRAgainstProfile), internal/service/renewal.go (resolveMaxTTL) -->

CSR validation is enforced at all five issuance paths: server-side renewal, agent-CSR renewal, agent fallback CSR submission, EST enrollment, and SCEP enrollment. When a certificate profile defines `AllowedKeyAlgorithms`, every incoming CSR is checked against the profile's rules — if the key algorithm or minimum size doesn't match, the request is rejected before reaching the issuer connector.

**MaxTTL enforcement** caps certificate validity at the profile's configured maximum. Behavior varies by issuer: the Local CA, Vault PKI, and step-ca enforce the cap directly (capping `NotAfter` or overriding TTL). OpenSSL logs an advisory warning. ACME, DigiCert, Sectigo, Google CAS, and AWS ACM PCA pass through because the CA controls validity. MaxTTL is resolved from the certificate profile at each issuance call site via `resolveMaxTTL()`.

**Key metadata persistence** — when a certificate version is created from a CSR, the key algorithm (RSA, ECDSA, Ed25519) and key size (in bits) are extracted from the CSR and stored in the `certificate_versions` table (`key_algorithm`, `key_size` columns) for post-hoc compliance auditing.

### Supported EKUs

<!-- Source: internal/connector/issuer/local/local.go (ekuNameToX509 map) -->

| EKU Name | x509 Constant | Typical Use |
|---|---|---|
| `serverAuth` | `ExtKeyUsageServerAuth` | TLS servers |
| `clientAuth` | `ExtKeyUsageClientAuth` | Mutual TLS |
| `codeSigning` | `ExtKeyUsageCodeSigning` | Code signing |
| `emailProtection` | `ExtKeyUsageEmailProtection` | S/MIME |
| `timeStamping` | `ExtKeyUsageTimeStamping` | Timestamping |

### Adaptive KeyUsage

The Local CA adjusts `KeyUsage` flags based on EKU:

- TLS profiles: `DigitalSignature | KeyEncipherment`
- S/MIME profiles: `DigitalSignature | ContentCommitment`

### S/MIME Support

EKU threading from profile through the entire issuance flow. Agent CSR generation splits SANs by type — `strings.Contains(san, "@")` routes to `EmailAddresses` instead of `DNSNames`. Demo seed includes `prof-smime` profile with `emailProtection` EKU.

---

## Policy Engine

<!-- Source: internal/domain/policy.go -->

5 rule types with violation tracking and severity levels:

- Key algorithm requirements
- Minimum key size
- Maximum certificate lifetime
- Required SAN patterns
- Issuer restrictions

Policies can be scoped to agent groups via `agent_group_id` foreign key. Violations are tracked and surfaced in the dashboard.

---

## Issuer Connectors

<!-- Source: internal/domain/connector.go (9 IssuerType constants), internal/connector/issuer/ -->

9 issuer connectors implementing the `issuer.Connector` interface. All support `ValidateConfig`, `IssueCertificate`, `RenewCertificate`, `RevokeCertificate`, `GetOrderStatus`, `GenerateCRL`, `SignOCSPResponse`, `GetCACertPEM`, `GetRenewalInfo`.

### Local CA

<!-- Source: internal/connector/issuer/local/local.go -->

Self-signed or sub-CA mode using `crypto/x509`.

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_CA_CERT_PATH` | (none) | Path to CA certificate PEM. When set, enables sub-CA mode. |
| `CERTCTL_CA_KEY_PATH` | (none) | Path to CA private key PEM (RSA, ECDSA, PKCS#8). |

Sub-CA mode validates `IsCA=true` and `KeyUsageCertSign` on the loaded certificate. Falls back to self-signed when paths are not set. Supports CRL generation (`GenerateCRL`) and OCSP response signing (`SignOCSPResponse`).

### ACME

<!-- Source: internal/connector/issuer/acme/acme.go -->

Full ACME v2 protocol via `golang.org/x/crypto/acme`.

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_ACME_DIRECTORY_URL` | `https://acme-v02.api.letsencrypt.org/directory` | ACME directory |
| `CERTCTL_ACME_EMAIL` | (required) | Account email |
| `CERTCTL_ACME_CHALLENGE_TYPE` | `http-01` | Challenge type: `http-01`, `dns-01`, `dns-persist-01` |
| `CERTCTL_ACME_DNS_PRESENT_SCRIPT` | (none) | Script to create DNS-01 TXT record |
| `CERTCTL_ACME_DNS_CLEANUP_SCRIPT` | (none) | Script to remove DNS-01 TXT record |
| `CERTCTL_ACME_DNS_PROPAGATION_WAIT` | `10s` | Wait after DNS record creation |
| `CERTCTL_ACME_DNS_PERSIST_ISSUER_DOMAIN` | (none) | Issuer domain for DNS-PERSIST-01 |
| `CERTCTL_ACME_EAB_KID` | (none) | External Account Binding key ID |
| `CERTCTL_ACME_EAB_HMAC` | (none) | EAB HMAC key (base64url) |
| `CERTCTL_ACME_ARI_ENABLED` | `false` | Enable ACME Renewal Information (RFC 9773) |
| `CERTCTL_ACME_PROFILE` | (none) | Certificate profile for newOrder (e.g., `tlsserver`, `shortlived`) |

**Challenge types:**

- **HTTP-01** — Standard HTTP challenge via `/.well-known/acme-challenge/` token
- **DNS-01** — Pluggable DNS solver with script-based hooks. User-provided scripts create/cleanup `_acme-challenge` TXT records. Compatible with any DNS provider.
- **DNS-PERSIST-01** — Standing `_validation-persist` TXT record per IETF draft. Record value: `<issuer-domain>; accounturi=<account-uri>`. Set once, reused on every renewal. Auto-fallback to DNS-01 if CA doesn't support it.

**External Account Binding (EAB):** Required by ZeroSSL, Google Trust Services, SSL.com. For ZeroSSL, credentials are auto-fetched from `api.zerossl.com/acme/eab-credentials-email` when no EAB credentials are provided — zero-friction onboarding.

**Certificate Profile Selection:** Custom JWS-signed `newOrder` POST when profile is set (the `golang.org/x/crypto/acme` library lacks profile support). ES256 JWS signing with kid mode, nonce management, directory discovery. Empty profile delegates to the standard library path.

### step-ca

<!-- Source: internal/connector/issuer/stepca/stepca.go -->

Smallstep private CA via native `/sign` API with JWK provisioner authentication. Synchronous issuance.

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_STEPCA_URL` | (required) | step-ca server URL |
| `CERTCTL_STEPCA_ROOT_CA` | (required) | Path to step-ca root CA PEM |
| `CERTCTL_STEPCA_PROVISIONER_NAME` | (required) | JWK provisioner name |
| `CERTCTL_STEPCA_PROVISIONER_KEY` | (required) | Path to provisioner private key |
| `CERTCTL_STEPCA_PROVISIONER_PASSWORD` | (none) | Provisioner key password |

### OpenSSL / Custom CA

<!-- Source: internal/connector/issuer/openssl/openssl.go -->

Script-based signing delegating to user-provided shell scripts. Configurable timeout.

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_OPENSSL_SIGN_SCRIPT` | (required) | Script that signs a CSR (receives CSR on stdin, outputs PEM on stdout) |
| `CERTCTL_OPENSSL_REVOKE_SCRIPT` | (none) | Script for revocation |
| `CERTCTL_OPENSSL_CRL_SCRIPT` | (none) | Script for CRL generation |
| `CERTCTL_OPENSSL_TIMEOUT_SECONDS` | `30` | Script execution timeout |

### Vault PKI

<!-- Source: internal/connector/issuer/vault/vault.go -->

HashiCorp Vault `/v1/{mount}/sign/{role}` API. Token auth, synchronous issuance.

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_VAULT_ADDR` | (required) | Vault server URL |
| `CERTCTL_VAULT_TOKEN` | (required) | Vault token |
| `CERTCTL_VAULT_MOUNT` | `pki` | PKI secrets engine mount path |
| `CERTCTL_VAULT_ROLE` | (required) | PKI role name |
| `CERTCTL_VAULT_TTL` | `8760h` | Certificate TTL |

CRL/OCSP delegated to Vault. Revocation via `POST /v1/{mount}/revoke` with serial number normalization.

### DigiCert CertCentral

<!-- Source: internal/connector/issuer/digicert/digicert.go -->

Async order model: submit → poll → download. OV/EV support.

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_DIGICERT_API_KEY` | (required) | `X-DC-DEVKEY` auth header |
| `CERTCTL_DIGICERT_ORG_ID` | (required) | Organization ID |
| `CERTCTL_DIGICERT_PRODUCT_TYPE` | `ssl_basic` | Product type |
| `CERTCTL_DIGICERT_BASE_URL` | `https://www.digicert.com/services/v2` | API base URL |

Issuance returns `OrderID` when pending. `GetOrderStatus` polls via `GET /order/certificate/{order_id}`, downloads PEM bundle when issued.

### Sectigo SCM

<!-- Source: internal/connector/issuer/sectigo/sectigo.go -->

Async order model: enroll → poll → collect PEM. 3-header auth.

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_SECTIGO_CUSTOMER_URI` | (required) | Customer URI header |
| `CERTCTL_SECTIGO_LOGIN` | (required) | Login header |
| `CERTCTL_SECTIGO_PASSWORD` | (required) | Password header |
| `CERTCTL_SECTIGO_ORG_ID` | (required) | Organization ID |
| `CERTCTL_SECTIGO_CERT_TYPE` | (required) | Certificate type ID |
| `CERTCTL_SECTIGO_TERM` | `365` | Certificate term in days |
| `CERTCTL_SECTIGO_BASE_URL` | `https://cert-manager.com/api` | API base URL |

Handles `collect-not-ready` (HTTP 400 / error code -183) gracefully — cert approved but not yet generated.

### Google CAS

<!-- Source: internal/connector/issuer/googlecas/googlecas.go -->

Google Cloud Certificate Authority Service. OAuth2 service account auth (JWT → access token), synchronous issuance. No Google SDK dependency — all stdlib.

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_GOOGLE_CAS_PROJECT` | (required) | GCP project ID |
| `CERTCTL_GOOGLE_CAS_LOCATION` | (required) | GCP region |
| `CERTCTL_GOOGLE_CAS_CA_POOL` | (required) | CA pool name |
| `CERTCTL_GOOGLE_CAS_CREDENTIALS` | (required) | Path to service account JSON |
| `CERTCTL_GOOGLE_CAS_TTL` | `8760h` | Certificate TTL |

Token caching with `sync.Mutex` and 5-minute refresh buffer. RS256 JWT signing.

### AWS ACM Private CA

<!-- Source: internal/connector/issuer/awsacmpca/awsacmpca.go -->

Synchronous issuance via `IssueCertificate` + `GetCertificate` AWS APIs. Injectable `ACMPCAClient` interface.

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_AWS_PCA_REGION` | (required) | AWS region |
| `CERTCTL_AWS_PCA_CA_ARN` | (required) | CA ARN |
| `CERTCTL_AWS_PCA_SIGNING_ALGORITHM` | `SHA256WITHRSA` | Signing algorithm |
| `CERTCTL_AWS_PCA_VALIDITY_DAYS` | `365` | Certificate validity |
| `CERTCTL_AWS_PCA_TEMPLATE_ARN` | (none) | Optional template ARN |

Revocation with RFC 5280 reason mapping. CRL/OCSP delegated to AWS.

### EST Server (RFC 7030)

<!-- Source: internal/service/est.go, internal/api/handler/est.go -->

Enrollment over Secure Transport for device/WiFi/IoT certificate enrollment. 4 endpoints under `/.well-known/est/`:

| Endpoint | Method | Description |
|---|---|---|
| `/cacerts` | GET | CA certificate chain (PKCS#7 certs-only, base64-encoded) |
| `/simpleenroll` | POST | New certificate enrollment |
| `/simplereenroll` | POST | Certificate re-enrollment |
| `/csrattrs` | GET | CSR attributes |

Accepts both base64-encoded DER (EST standard) and PEM-encoded PKCS#10 CSR input. PKCS#7 output built with hand-rolled ASN.1 (no external PKCS#7 dependency). Configurable issuer and profile binding.

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_EST_ENABLED` | `false` | Enable EST endpoints |
| `CERTCTL_EST_ISSUER_ID` | `iss-local` | Issuer for EST enrollments |
| `CERTCTL_EST_PROFILE_ID` | (none) | Optional profile constraint |

### SCEP Server (RFC 8894)

<!-- Source: internal/service/scep.go, internal/api/handler/scep.go -->

Simple Certificate Enrollment Protocol for MDM platforms and network devices. Single endpoint with operation-based dispatch:

| Operation | Method | Description |
|---|---|---|
| `GetCACaps` | GET | Server capabilities (plaintext, one per line) |
| `GetCACert` | GET | CA certificate (DER for single cert, PKCS#7 for chain) |
| `PKIOperation` | POST | Certificate enrollment (PKCS#7-wrapped or raw CSR) |

SCEP uses a single URL (`/scep?operation=...`). The handler extracts PKCS#10 CSRs from PKCS#7 SignedData envelopes, with fallback support for base64-encoded and raw CSR submissions. Challenge password authentication via CSR attributes (OID 1.2.840.113549.1.9.7). Responses are PKCS#7 certs-only (same shared `internal/pkcs7` package as EST).

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_SCEP_ENABLED` | `false` | Enable SCEP endpoint |
| `CERTCTL_SCEP_ISSUER_ID` | `iss-local` | Issuer for SCEP enrollments |
| `CERTCTL_SCEP_PROFILE_ID` | (none) | Optional profile constraint |
| `CERTCTL_SCEP_CHALLENGE_PASSWORD` | (none) | Shared secret for enrollment authentication |

---

## ACME Renewal Information (RFC 9773)

<!-- Source: internal/domain/ari.go, internal/connector/issuer/acme/ari.go -->

CA-directed renewal timing. Instead of hardcoded expiration thresholds, the CA tells certctl when to renew.

### How It Works

1. `GetRenewalInfo` computes an RFC 9773 cert ID (base64url-encoded SHA-256 of DER cert)
2. Queries the CA's Renewal Information endpoint (discovered from ACME directory or constructed via fallback URL)
3. Returns a `SuggestedWindow` (start/end), optional `RetryAfter`, and `ExplanationURL`
4. `ShouldRenewNow()` returns true if the current time is past `SuggestedWindowStart`
5. `OptimalRenewalTime()` picks a random time within the window for load distribution

### Scheduler Integration

The renewal scheduler (`CheckExpiringCertificates`) queries ARI before creating renewal jobs:

- If ARI says "not yet" → skip renewal
- If ARI says "renew now" → create renewal job with `renewal_trigger: ari` audit event
- If ARI errors → log warning, fall back to threshold-based logic
- Non-ARI issuers return nil (Local CA, step-ca, OpenSSL, Vault, DigiCert, Sectigo, Google CAS, AWS ACM PCA)

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_ACME_ARI_ENABLED` | `false` | Enable ARI queries |

### Shorter Certificate Validity Readiness

certctl's default thresholds `[30, 14, 7, 0]` work correctly at all CA/Browser Forum SC-081v3 validity reduction phases:

- 200-day certs (Phase 1, March 2026)
- 100-day certs (Phase 2, March 2027)
- 47-day certs (Phase 3, March 2029)

For Let's Encrypt 6-day `shortlived` certificates, ARI is the expected renewal path — threshold-based logic alone is insufficient at that lifetime.

---

## Target Connectors

<!-- Source: internal/domain/connector.go (14 TargetType constants), internal/connector/target/ -->

14 target connector types implementing the `target.Connector` interface. All support `ValidateConfig`, `DeployCertificate`, `ValidateDeployment`.

### Deployment Model

Pull-only. The server never initiates outbound connections to agents or targets. Agents poll for work. For network appliances and agentless servers, a "proxy agent" in the same network zone executes deployment via the target's API.

### NGINX

<!-- Source: internal/connector/target/nginx/nginx.go -->

File write → `nginx -t` validation → `nginx -s reload`. Config: `cert_path`, `key_path`, `chain_path`, `reload_command`, `validate_command`.

### Apache httpd

<!-- Source: internal/connector/target/apache/apache.go -->

Separate cert/chain/key files → `apachectl configtest` → `apachectl graceful`. Config: `cert_path`, `key_path`, `chain_path`, `reload_command`, `validate_command`.

### HAProxy

<!-- Source: internal/connector/target/haproxy/haproxy.go -->

Combined PEM file (cert + chain + key) → optional validation → reload via socket/signal. Config: `pem_path`, `reload_command`, `validate_command`.

### Traefik

<!-- Source: internal/connector/target/traefik/traefik.go -->

File provider deployment: writes cert/key to Traefik's watched directory. Traefik auto-reloads via filesystem watch. Config: `cert_dir`, `cert_filename`, `key_filename`.

### Caddy

<!-- Source: internal/connector/target/caddy/caddy.go -->

Dual-mode: `api` (POST to Caddy admin endpoint for hot-reload) or `file` (file-based with configurable paths). Config: `mode` (`api`/`file`), `admin_url`, `cert_path`, `key_path`.

### Envoy

<!-- Source: internal/connector/target/envoy/envoy.go -->

File-based deployment with optional SDS JSON config. Envoy auto-reloads via filesystem watch. Path traversal prevention on all file paths. Optional SDS JSON bootstrap (`type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret`). Config: `cert_dir`, `cert_filename`, `key_filename`, `chain_filename`, `sds_config`.

### F5 BIG-IP

<!-- Source: internal/connector/target/f5/f5.go -->

iControl REST API via proxy agent. Token auth (`POST /mgmt/shared/authn/login`, `X-F5-Auth-Token`), 401 auto-retry. Transaction-based atomic SSL profile updates with auto-rollback on failure. Injectable `F5Client` interface.

Config: `host`, `port` (443), `username`, `password`, `partition` (Common), `ssl_profile`, `insecure` (true), `timeout` (30). Minimum BIG-IP v12.0+.

Deployment: file upload with `Content-Range` → crypto object install (cert/key/chain) → transaction create → SSL profile PATCH → transaction commit. `cleanupCryptoObjects()` removes installed objects on failure.

### IIS

<!-- Source: internal/connector/target/iis/iis.go -->

Dual-mode: agent-local PowerShell or WinRM proxy agent. PEM → PFX conversion via `go-pkcs12`, `Import-PfxCertificate`, IIS binding management (`New-WebBinding` + `AddSslCertificate`), SHA-1 thumbprint computation, SNI support.

**Local mode** config: `site_name`, `cert_store` (My), `port` (443), `sni` (false), `ip_address` (*).

**WinRM mode** config: adds `mode` (winrm), `winrm_host`, `winrm_port` (5985/5986), `winrm_username`, `winrm_password`, `winrm_https`, `winrm_insecure`, `winrm_timeout` (60s). Base64 PFX transfer via PowerShell with `try/finally` cleanup. Uses `masterzen/winrm`.

Injectable `PowerShellExecutor` interface for cross-platform testing. Regex-validated config fields prevent PowerShell injection.

### SSH (Agentless)

<!-- Source: internal/connector/target/ssh/ssh.go -->

Agentless deployment via SSH/SFTP to any Linux/Unix server. Uses `golang.org/x/crypto/ssh` + `github.com/pkg/sftp`.

Config: `host`, `port` (22), `user`, `auth_method` (key/password), `private_key_path`, `password`, `cert_path`, `key_path`, `chain_path`, `reload_command`, `timeout` (30s). Optional octal permission strings (e.g., `"0644"`, `"0600"`).

Shell injection prevention via `validation.ValidateShellCommand()` on reload commands. Injectable `SSHClient` interface.

### Postfix / Dovecot

<!-- Source: internal/connector/target/postfix/postfix.go -->

Dual-mode mail server TLS connector. File write → validation → reload.

- **Postfix mode**: `postfix check` → `postfix reload`
- **Dovecot mode**: `doveconf -n` → `doveadm reload`

Config: `mode` (postfix/dovecot), `cert_path`, `key_path`, `chain_path`, `reload_command`, `validate_command`. Shell injection prevention.

### Windows Certificate Store

<!-- Source: internal/connector/target/wincertstore/wincertstore.go -->

PowerShell-based cert import via `Import-PfxCertificate`. PEM → PFX → base64 → PowerShell script with `try/finally` cleanup.

Config: `store` (My/Root/CA/WebHosting), `store_location` (LocalMachine/CurrentUser), `friendly_name`, `cleanup_expired` (bool). Dual-mode: local or WinRM (same pattern as IIS). Reuses shared `certutil` package.

### Java Keystore

<!-- Source: internal/connector/target/javakeystore/javakeystore.go -->

PEM → PKCS#12 (via `certutil.CreatePFX`) → temp file → `keytool -importkeystore` pipeline. JKS and PKCS12 format support.

Config: `keystore_path`, `keystore_password`, `keystore_type` (JKS/PKCS12), `alias` (server), `reload_command`. Path traversal prevention, existing alias deletion before import. Reuses shared `certutil` package.

### Kubernetes Secrets

<!-- Source: internal/connector/target/k8ssecret/k8ssecret.go -->

Deploys certificates as `kubernetes.io/tls` Secrets. Injectable `K8sClient` interface (proxy agent pattern). In-cluster auth by default, out-of-cluster via kubeconfig.

Config: `namespace`, `secret_name`, `labels` (map), `kubeconfig_path` (optional). Fingerprint-based validation in `ValidateDeployment`.

### Shared certutil Package

<!-- Source: internal/connector/target/certutil/certutil.go -->

Extracted from IIS connector. Reused by IIS, WinCertStore, and JavaKeystore:

- `CreatePFX` — PEM → PKCS#12 via `go-pkcs12`
- `ParsePrivateKey` — PKCS#1, PKCS#8, EC key formats
- `ComputeThumbprint` — SHA-1 of DER cert (matches Windows `certutil`)
- `GenerateRandomPassword` — 32-char crypto/rand password
- `ParseCertificatePEM` — PEM → `*x509.Certificate`

---

## Notifier Connectors

<!-- Source: internal/domain/notification.go, internal/connector/notifier/ -->

### Notification Types

| Type | Description |
|---|---|
| `ExpirationWarning` | Certificate approaching threshold |
| `RenewalSuccess` | Renewal completed |
| `RenewalFailure` | Renewal failed |
| `DeploymentSuccess` | Deployment completed |
| `DeploymentFailure` | Deployment failed |
| `PolicyViolation` | Policy rule violated |
| `Revocation` | Certificate revoked |

### Notification Channels

| Channel | Auth | Config Env Vars |
|---|---|---|
| **Email** | SMTP | `CERTCTL_SMTP_HOST`, `CERTCTL_SMTP_PORT` (587), `CERTCTL_SMTP_USERNAME`, `CERTCTL_SMTP_PASSWORD`, `CERTCTL_SMTP_FROM_ADDRESS`, `CERTCTL_SMTP_USE_TLS` (true) |
| **Webhook** | URL-based | `CERTCTL_WEBHOOK_URL` |
| **Slack** | Incoming webhook | `CERTCTL_SLACK_WEBHOOK_URL`, `CERTCTL_SLACK_CHANNEL`, `CERTCTL_SLACK_USERNAME` |
| **Microsoft Teams** | Incoming webhook (MessageCard) | `CERTCTL_TEAMS_WEBHOOK_URL` |
| **PagerDuty** | Events API v2 | `CERTCTL_PAGERDUTY_ROUTING_KEY`, `CERTCTL_PAGERDUTY_SEVERITY` (warning) |
| **OpsGenie** | Alert API v2, GenieKey | `CERTCTL_OPSGENIE_API_KEY`, `CERTCTL_OPSGENIE_PRIORITY` (P3) |

All notifier connectors have 10-second HTTP client timeouts.

---

## Certificate Digest

<!-- Source: internal/service/digest.go, internal/api/handler/digest.go -->

Scheduled HTML email digest with aggregated certificate status.

### Content

- Stats grid: total certs, expiring, expired, active agents
- Jobs summary
- Expiring certificates table with color-coded badges
- Responsive CSS for email clients

### Configuration

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_DIGEST_ENABLED` | `false` | Enable digest |
| `CERTCTL_DIGEST_INTERVAL` | `24h` | Send interval |
| `CERTCTL_DIGEST_RECIPIENTS` | (none) | Comma-separated emails. Falls back to certificate owner emails when empty. |

### API

- `GET /api/v1/digest/preview` — HTML preview of current digest
- `POST /api/v1/digest/send` — trigger immediate send

Both endpoints return 503 when digest is not configured (nil-safe handler).

---

## Post-Deployment TLS Verification

<!-- Source: internal/domain/verification.go, internal/service/verification.go, cmd/agent/verify.go -->

After deploying a certificate, the agent probes the live TLS endpoint and compares SHA-256 fingerprints.

### Verification Statuses

| Status | Description |
|---|---|
| `pending` | Verification not yet attempted |
| `success` | Deployed cert matches live endpoint |
| `failed` | Fingerprint mismatch or connection error |
| `skipped` | Verification disabled or not applicable |

### Flow

1. Agent completes deployment
2. Agent waits `CERTCTL_VERIFY_DELAY` (configurable)
3. Agent connects via `crypto/tls.DialWithDialer` with `InsecureSkipVerify=true`
4. Compares SHA-256 fingerprint of served cert against deployed cert
5. Submits result via `POST /api/v1/jobs/{id}/verify`

Best-effort — failures are recorded but don't block or rollback deployments.

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_VERIFY_DEPLOYMENT` | `false` | Enable verification |
| `CERTCTL_VERIFY_TIMEOUT` | `5s` | TLS connection timeout |
| `CERTCTL_VERIFY_DELAY` | `2s` | Wait after deployment before probing |

---

## Discovery

### Filesystem Discovery

<!-- Source: cmd/agent/scanner.go, internal/service/discovery.go -->

Agents scan configured directories for existing certificates.

- Runs on agent startup and every 6 hours
- Walks directories recursively, parses PEM (`.pem`, `.crt`, `.cer`, `.cert`) and DER (`.der`) files
- Extracts: common name, SANs, serial, issuer DN, subject DN, validity, key algorithm, key size, is_ca, SHA-256 fingerprint
- Reports to server via `POST /api/v1/agents/{id}/discoveries`
- Server deduplicates by `(fingerprint_sha256, agent_id, source_path)` unique constraint

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_DISCOVERY_DIRS` | (none) | Comma-separated directories for agent to scan |

### Discovery Statuses

| Status | Description |
|---|---|
| `Unmanaged` | Discovered, not yet triaged |
| `Managed` | Claimed and linked to a managed certificate |
| `Dismissed` | Explicitly dismissed from triage queue |

### Discovery API

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/agents/{id}/discoveries` | POST | Agent submits scan results |
| `/api/v1/discovered-certificates` | GET | List with `?agent_id`, `?status` filters |
| `/api/v1/discovered-certificates/{id}` | GET | Detail |
| `/api/v1/discovered-certificates/{id}/claim` | POST | Link to managed certificate |
| `/api/v1/discovered-certificates/{id}/dismiss` | POST | Dismiss from triage |
| `/api/v1/discovery-scans` | GET | Scan history |
| `/api/v1/discovery-summary` | GET | Aggregate status counts |

### Network Certificate Discovery

<!-- Source: internal/service/network_scan.go -->

Server-side active TLS scanning of CIDR ranges. Concurrent probing with semaphore (50 goroutines). Feeds into the existing discovery pipeline via `server-scanner` sentinel agent.

- CIDR expansion with `/20` safety cap (4,096 IPs max per scan)
- `crypto/tls.DialWithDialer` with `InsecureSkipVerify=true` to discover all certs (including self-signed, expired, internal CA)
- SSRF protection: reserved IP ranges filtered (loopback, link-local, multicast, broadcast)

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_NETWORK_SCAN_ENABLED` | `false` | Enable network scanning |
| `CERTCTL_NETWORK_SCAN_INTERVAL` | `6h` | Scan interval |

### Network Scan Target API

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/network-scan-targets` | GET | List targets |
| `/api/v1/network-scan-targets/{id}` | GET | Detail |
| `/api/v1/network-scan-targets` | POST | Create target (name, CIDRs, ports, interval, timeout) |
| `/api/v1/network-scan-targets/{id}` | PUT | Update |
| `/api/v1/network-scan-targets/{id}` | DELETE | Delete |
| `/api/v1/network-scan-targets/{id}/scan` | POST | Trigger immediate scan |

---

## Ownership and Teams

<!-- Source: internal/domain/certificate.go (owner fields), internal/domain/team.go -->

### Certificate Ownership

Certificates have an `owner` field linking to an owner record with email and team assignment. Notification routing uses owner email when no explicit recipients are configured.

### Teams

Organizational grouping for owners. Full CRUD API and GUI page.

### Agent Groups

<!-- Source: internal/domain/agent_group.go -->

Dynamic device grouping by matching criteria:

- OS (e.g., `linux`, `darwin`, `windows`)
- Architecture (e.g., `amd64`, `arm64`)
- IP CIDR range
- Agent version

Plus manual include/exclude membership lists. Agent groups can be referenced by renewal policies via `agent_group_id` FK.

`MatchesAgent()` method on the domain model evaluates all criteria against an agent's metadata.

---

## Observability

### Metrics

<!-- Source: internal/api/handler/metrics.go -->

**JSON metrics:** `GET /api/v1/metrics` — gauges (cert totals by status, agent counts, pending jobs), counters (completed/failed jobs), uptime.

**Prometheus metrics:** `GET /api/v1/metrics/prometheus` — `text/plain; version=0.0.4` exposition format. 11 metrics with `certctl_` prefix:

| Metric | Type |
|---|---|
| `certctl_certificate_total` | gauge |
| `certctl_certificate_active` | gauge |
| `certctl_certificate_expiring_soon` | gauge |
| `certctl_certificate_expired` | gauge |
| `certctl_certificate_revoked` | gauge |
| `certctl_agent_total` | gauge |
| `certctl_agent_online` | gauge |
| `certctl_job_pending` | gauge |
| `certctl_job_completed_total` | counter |
| `certctl_job_failed_total` | counter |
| `certctl_uptime_seconds` | gauge |

Compatible with Prometheus, Grafana Agent, Datadog Agent, Victoria Metrics.

### Stats API

| Endpoint | Description |
|---|---|
| `GET /api/v1/stats/summary` | Dashboard summary (total, active, expiring, expired) |
| `GET /api/v1/stats/certificates-by-status` | Status distribution |
| `GET /api/v1/stats/expiration-timeline?days=N` | Expiration buckets |
| `GET /api/v1/stats/job-trends?days=N` | Job completion trends |
| `GET /api/v1/stats/issuance-rate?days=N` | Issuance rate |

### Structured Logging

`slog`-based middleware with request ID propagation. No `fmt.Printf` in production code paths.

### Immutable Audit Trail

Append-only `audit_events` table. No UPDATE or DELETE permitted. Records:

- All API calls (via audit middleware)
- Certificate lifecycle events (issuance, renewal, deployment, revocation, export)
- Discovery events (scan completed, cert claimed, cert dismissed)
- Job lifecycle events (created, completed, failed, cancelled, verified)
- Approval events (approved, rejected with reason)

---

## Job System

<!-- Source: internal/domain/job.go -->

### Job Types

| Type | Description |
|---|---|
| `Issuance` | New certificate issuance |
| `Renewal` | Certificate renewal |
| `Deployment` | Deploy cert to target |
| `Validation` | Validate deployment |

### Job Statuses

| Status | Description |
|---|---|
| `Pending` | Queued for processing |
| `AwaitingCSR` | Waiting for agent to submit CSR (agent keygen mode) |
| `AwaitingApproval` | Paused for manual approval |
| `Running` | In progress |
| `Completed` | Successfully finished |
| `Failed` | Failed with error |
| `Cancelled` | Cancelled by operator |

### Agent Work Routing

<!-- Source: internal/service/agent.go, internal/repository/postgres/job.go (ListPendingByAgentID) -->

`GetPendingWork()` returns only jobs scoped to the requesting agent:

- Deployment jobs: matched by `jobs.agent_id` (set at creation from target → agent relationship)
- AwaitingCSR jobs: matched via certificate → target → agent chain
- Legacy fallback: target JOIN for jobs with NULL `agent_id`

Single SQL `UNION` query replaces the previous "fetch all, filter in Go" approach.

---

## Background Scheduler

<!-- Source: internal/scheduler/scheduler.go -->

7 background loops, each with an `atomic.Bool` idempotency guard preventing concurrent tick execution. `sync.WaitGroup` + `WaitForCompletion()` for graceful shutdown.

| Loop | Default Interval | Description |
|---|---|---|
| Renewal check | 1 hour | Check expiring certs, query ARI, create renewal jobs |
| Job processor | 30 seconds | Process pending jobs |
| Agent health check | 2 minutes | Check agent heartbeat staleness |
| Notification processor | 1 minute | Send queued notifications |
| Short-lived expiry check | 30 seconds | Mark short-lived certs expired |
| Network scan | 6 hours | Run network discovery scans |
| Digest | 24 hours | Send certificate digest email (does not run on startup) |

---

## Dynamic Configuration (GUI)

### Issuer Configuration

<!-- Source: internal/service/issuer.go, migrations/000009_issuer_config.up.sql -->

GUI-driven issuer CRUD with AES-256-GCM encrypted config storage in PostgreSQL.

- Per-type config schema validation for all 9 issuer types
- Test connection flow (instantiates throwaway connector, calls `ValidateConfig`)
- Dynamic `sync.RWMutex`-guarded `IssuerRegistry` — rebuilds without server restart
- Env var backward compatibility: seeds DB on first boot if no DB config exists
- Source tracking: `env` (seeded from env vars) or `database` (created via GUI)

| Env Var | Default | Description |
|---|---|---|
| `CERTCTL_CONFIG_ENCRYPTION_KEY` | (none) | AES-256-GCM encryption key for stored configs |

<!-- Source: internal/crypto/encryption.go -->

Encryption: AES-256-GCM with PBKDF2-SHA256 key derivation, 12-byte random nonce. Exported functions: `EncryptAESGCM`, `DecryptAESGCM`, `DeriveKey`, `EncryptIfKeySet`, `DecryptIfEncrypted`.

### Target Configuration

<!-- Source: internal/service/target.go, migrations/000010_target_config.up.sql -->

Same pattern as issuer configuration:

- Per-type config validation for all 14 target types
- AES-256-GCM encrypted config storage
- Test connection via agent heartbeat status (online within 5 minutes)
- Source badge (database vs env), enabled/disabled toggle

---

## Web Dashboard

<!-- Source: web/src/main.tsx (25 Route elements, 24 pages), Vite + React 18 + TypeScript + TanStack Query + Recharts -->

24 pages wired to real API endpoints.

### Pages

| Page | Route | Description |
|---|---|---|
| Dashboard | `/` | Summary stats, 4 charts (status donut, expiration heatmap, renewal trends, issuance rate) |
| Certificates | `/certificates` | List with bulk ops (renew, revoke, reassign owner), multi-select |
| Certificate Detail | `/certificates/:id` | Versions, deployment timeline, inline policy editor, export buttons |
| Agents | `/agents` | List with OS/arch metadata |
| Agent Detail | `/agents/:id` | System info, heartbeat status, capabilities, recent jobs |
| Fleet Overview | `/fleet` | OS/arch grouping, status/version distribution charts |
| Jobs | `/jobs` | List with status filter, approval buttons, verification badges |
| Job Detail | `/jobs/:id` | Full details, verification section (deployment jobs), timeline, audit events |
| Notifications | `/notifications` | Grouped by cert, read/unread state, mark-read |
| Policies | `/policies` | CRUD, severity summary bar, config preview |
| Profiles | `/profiles` | CRUD, EKU configuration |
| Issuers | `/issuers` | Catalog (10 cards), 3-step create wizard, config detail modal |
| Issuer Detail | `/issuers/:id` | Config (sensitive redacted), test connection, issued certs list |
| Targets | `/targets` | List with create wizard (3-step), per-type config fields for all 14 types |
| Target Detail | `/targets/:id` | Config, agent link, deployment history with verification badges |
| Owners | `/owners` | Team resolution, notification routing |
| Teams | `/teams` | CRUD |
| Agent Groups | `/agent-groups` | Dynamic criteria badges, manual membership |
| Audit | `/audit` | Time range/actor/resource/action filters, CSV/JSON export |
| Short-Lived | `/short-lived` | Filtered by profile TTL < 1 hour, live TTL countdown, auto-refresh 10s |
| Discovery | `/discovery` | Triage GUI with summary stats, claim/dismiss, scan history |
| Network Scans | `/network-scans` | CRUD for scan targets, Scan Now button |
| Digest | `/digest` | Preview iframe + send button |
| Observability | `/observability` | Health, metrics, Prometheus config, live output |

### Onboarding Wizard

<!-- Source: web/src/pages/OnboardingWizard.tsx -->

4-step first-run wizard shown when no user-configured issuers or certificates exist:

1. **Connect a CA** — issuer catalog with 6+ types, config form, create + test connection
2. **Deploy Agent** — OS tabs (Linux/macOS/Docker) with install commands, agent polling every 5s
3. **Add Certificate** — CN, SANs, issuer/profile dropdowns, trigger issuance
4. **Done** — summary, doc links

Latching state prevents refetch-driven dismissal. `localStorage` dismissal key: `certctl:onboarding-dismissed`.

---

## CLI

<!-- Source: cmd/cli/main.go, internal/cli/client.go -->

`certctl-cli` — stdlib-only (`flag` + `text/tabwriter`), no Cobra dependency.

### Commands

| Command | Description |
|---|---|
| `certs list` | List certificates |
| `certs get ID` | Certificate details |
| `certs renew ID` | Trigger renewal |
| `certs revoke ID` | Revoke (with `--reason`) |
| `agents list` | List agents |
| `agents get ID` | Agent details |
| `jobs list` | List jobs |
| `jobs get ID` | Job details |
| `jobs cancel ID` | Cancel pending job |
| `import FILE` | Bulk import from PEM file(s) |
| `status` | Server health + summary |
| `version` | CLI version |

### Global Flags

| Flag | Env Var | Default | Description |
|---|---|---|---|
| `--server` | `CERTCTL_SERVER_URL` | `http://localhost:8443` | Server URL |
| `--api-key` | `CERTCTL_API_KEY` | (none) | API key |
| `--format` | (none) | `table` | Output: `table` or `json` |

---

## MCP Server

<!-- Source: cmd/mcp-server/main.go, internal/mcp/ -->

Separate standalone binary (`cmd/mcp-server/`) using the official MCP Go SDK (`modelcontextprotocol/go-sdk`). Stdio transport for Claude, Cursor, and similar AI tool integrations.

- 80 MCP tools covering all API endpoints
- Stateless HTTP proxy — translates MCP tool calls to REST API calls
- Typed input structs with `jsonschema` struct tags for automatic schema generation
- Binary response support (DER CRL, OCSP)

| Env Var | Description |
|---|---|
| `CERTCTL_SERVER_URL` | certctl server URL |
| `CERTCTL_API_KEY` | API key for authentication |

---

## Agent

<!-- Source: cmd/agent/main.go -->

Standalone binary that runs on managed infrastructure. Communicates with the control plane via HTTP polling.

### Capabilities

- Heartbeat reporting (OS, architecture, IP address, version via `runtime.GOOS`/`runtime.GOARCH`/`net` stdlib)
- Work polling (`GET /agents/{id}/work`)
- ECDSA P-256 key generation + CSR submission
- Target connector deployment (instantiates local connector based on job config)
- Post-deployment TLS verification
- Filesystem certificate discovery
- Exponential backoff on errors

### Agent Metadata

Reported via heartbeat, stored in `agents` table: OS, platform, architecture, IP address, hostname, version.

### Configuration

| Flag / Env Var | Default | Description |
|---|---|---|
| `--server-url` / `CERTCTL_SERVER_URL` | `http://localhost:8443` | Control plane URL |
| `--agent-id` / `CERTCTL_AGENT_ID` | (required) | Agent identifier |
| `--api-key` / `CERTCTL_API_KEY` | (none) | Auth key |
| `--key-dir` / `CERTCTL_KEY_DIR` | `/var/lib/certctl/keys` | Local key storage |
| `--discovery-dirs` / `CERTCTL_DISCOVERY_DIRS` | (none) | Comma-separated scan directories |

---

## Deployment

### Docker Compose

- `deploy/docker-compose.yml` — clean default (server + postgres + agent), wizard-compatible
- `deploy/docker-compose.demo.yml` — override adding `seed_demo.sql` for demo mode
- `deploy/docker-compose.test.yml` — 7-container test environment (PostgreSQL, certctl-server, certctl-agent, step-ca, Pebble ACME, pebble-challtestsrv, NGINX) on static IP subnet `10.30.50.0/24`

### Helm Chart

<!-- Source: deploy/helm/certctl/ -->

Production-ready Kubernetes deployment.

| Component | Kind | Notes |
|---|---|---|
| Server | Deployment | Configurable replicas (default 1), health probes, non-root, read-only rootfs |
| PostgreSQL | StatefulSet | Single replica, PVC (`10Gi` default, configurable storage class) |
| Agent | DaemonSet | One per node, key storage volume, server URL auto-discovery |
| Ingress | Ingress | Optional, configurable `className`, annotations, TLS |
| ServiceAccount | ServiceAccount | Optional with configurable annotations |

Config via `values.yaml`. Secrets for API key, database password, SMTP password.

### Install Script

`install-agent.sh` — detects OS/arch via `uname`, downloads binary from GitHub Releases, installs to `/usr/local/bin/certctl-agent`, creates systemd unit (Linux) or launchd plist (macOS), prompts for server URL + API key.

### Release Workflow

`.github/workflows/release.yml` — on tag push: cross-compiles server + agent for 4 targets, attaches as GitHub Release assets, pushes Docker images to `ghcr.io`.

---

## Database Schema

<!-- Source: migrations/ -->

21 tables across 10 numbered migrations. PostgreSQL 16. `database/sql` + `lib/pq` (no ORM). TEXT primary keys with human-readable prefixed IDs.

### Migrations

| Migration | Tables Added |
|---|---|
| `000001_initial_schema` | `managed_certificates`, `certificate_versions`, `agents`, `targets`, `issuers`, `renewal_policies`, `jobs`, `audit_events`, `notifications`, `owners`, `teams` |
| `000002_agent_metadata` | Columns on `agents` (os, platform, architecture, ip_address, hostname, version) |
| `000003_certificate_profiles` | `certificate_profiles` |
| `000004_agent_groups` | `agent_groups`, `agent_group_members` |
| `000005_revocation` | `certificate_revocations` + columns on `managed_certificates` |
| `000006_discovery` | `discovered_certificates`, `discovery_scans` |
| `000007_network_discovery` | `network_scan_targets` |
| `000008_verification` | Columns on `jobs` (verification fields) |
| `000009_issuer_config` | Columns on `issuers` (encrypted_config, source, test_status) |
| `000010_target_config` | Columns on `targets` (encrypted_config, source, test_status) |

All migrations are idempotent (`IF NOT EXISTS`, `ON CONFLICT`).

---

## Security

### Input Validation

<!-- Source: internal/validation/command.go -->

Centralized `validation` package with shell injection prevention. 80+ adversarial test cases. Used by all target connectors that execute shell commands (NGINX, Apache, HAProxy, Traefik, Caddy, Postfix/Dovecot, SSH, Java Keystore).

### SSRF Protection

Network scanner filters reserved IP ranges before CIDR expansion: loopback, link-local, multicast, broadcast.

### Encryption at Rest

AES-256-GCM with PBKDF2-SHA256 key derivation for issuer and target configs stored in PostgreSQL.

### Agent Key Security

- Agent-side key generation (ECDSA P-256) — private keys never leave agent infrastructure
- Keys stored with `0600` file permissions
- Docker volumes persist keys across container restarts

---

## CI/CD

<!-- Source: .github/workflows/ci.yml -->

GitHub Actions with parallel Go and Frontend jobs.

### Go Pipeline

- `go build` (server, agent, CLI, MCP server)
- `go vet`
- `go test -race` (race detection)
- `golangci-lint` (11 linters)
- `govulncheck` (vulnerability scanning)
- Test coverage with per-layer thresholds:

| Layer | Threshold |
|---|---|
| Service | 55% |
| Handler | 60% |
| Domain | 40% |
| Middleware | 30% |

### Frontend Pipeline

- `tsc` (TypeScript compilation)
- `vitest` (213 tests)
- `vite build`

---

## Test Suite

1850+ tests across multiple layers:

| Layer | Approximate Count | Description |
|---|---|---|
| Service | ~400 | Unit tests for all service methods |
| Handler | ~200 | HTTP handler tests with mocked services |
| Domain | ~80 | Domain model validation and logic |
| Connector (issuer) | ~130 | Per-connector tests with httptest mocks |
| Connector (target) | ~200 | Per-connector tests with injectable interfaces |
| Middleware | ~30 | Auth, CORS, audit, rate limiting, body limit |
| Integration | ~50 | Multi-layer integration tests |
| Go integration | 34 subtests | Live Docker Compose environment (12 phases) |
| Repository | ~50 | testcontainers-go PostgreSQL tests |
| CLI | ~14 | Command tests with httptest mock server |
| Fuzz | ~5 | Validation and domain parsing |
| Frontend | 213 | Vitest (API client, components, utilities) |

### Go Integration Tests

`deploy/test/integration_test.go` — `//go:build integration` tag, runs against live `docker-compose.test.yml`. 12 phases, 34 subtests: health, agent heartbeat, Local CA issuance, ACME issuance, renewal, step-ca issuance, revocation + CRL + OCSP, EST enrollment, S/MIME (EKU/KeyUsage/email SAN), discovery, network scan, deployment verification. Uses `crypto/x509` for cert parsing, `crypto/tls` for NGINX verification, `database/sql` + `lib/pq` for PostgreSQL direct access.

---

## Examples

5 turnkey Docker Compose scenarios in `examples/`:

| Directory | Scenario |
|---|---|
| `acme-nginx/` | Let's Encrypt + NGINX |
| `acme-wildcard-dns01/` | Wildcard with DNS-01 via Cloudflare hooks |
| `private-ca-traefik/` | Local CA sub-CA mode + Traefik file provider |
| `step-ca-haproxy/` | step-ca + HAProxy |
| `multi-issuer/` | ACME (public) + Local CA (internal) from one dashboard |

---

## Compliance Mapping

Pre-mapped to three compliance frameworks in `docs/`:

- **SOC 2 Type II** — CC6 (logical access), CC7 (system operations), CC8 (change management), A1 (availability)
- **PCI-DSS 4.0** — Req 3 (key management), Req 4 (TLS inventory), Req 7 (access control), Req 8 (authentication), Req 10 (audit logging)
- **NIST SP 800-57** — Key generation, storage, cryptoperiods, key states, algorithms, revocation

---

## Architecture Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language | Go 1.25 | stdlib routing, `net/http`, `slog`, `crypto/x509` |
| Database | PostgreSQL 16 + `database/sql` + `lib/pq` | No ORM, raw SQL |
| Primary keys | TEXT | Human-readable prefixed IDs (`mc-api-prod`) |
| Layering | Handler → Service → Repository | Dependency inversion (handlers define interfaces) |
| Frontend | Vite + React 18 + TypeScript + TanStack Query | Served from `web/dist/` with SPA fallback |
| Deployment model | Pull-only | Server never initiates outbound to agents/targets |
| Service decomposition | Facade/delegation | `CertificateService` delegates to `RevocationSvc` + `CAOperationsSvc` |
| Handler wiring | `HandlerRegistry` struct (20 fields) | Replaced 18-positional-parameter function |
| License | BSL 1.1 | Source-available, converts to Apache 2.0 in March 2033 |
