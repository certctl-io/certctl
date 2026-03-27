# Architecture Guide

## Contents

1. [Overview](#overview)
2. [System Components](#system-components)
   - [Control Plane (Server)](#control-plane-server)
   - [Agents](#agents)
   - [Web Dashboard](#web-dashboard)
   - [PostgreSQL Database](#postgresql-database)
3. [Data Flow: Certificate Lifecycle](#data-flow-certificate-lifecycle)
   - [Create Managed Certificate](#1-create-managed-certificate)
   - [Certificate Issuance](#2-certificate-issuance)
   - [Deploy Certificate to Target](#3-deploy-certificate-to-target)
   - [Revoke a Certificate](#35-revoke-a-certificate)
   - [Automatic Renewal](#4-automatic-renewal)
4. [Connector Architecture](#connector-architecture)
   - [IssuerConnectorAdapter (Dependency Inversion)](#issuerconnectoradapter-dependency-inversion)
   - [Issuer Connector](#issuer-connector)
   - [Target Connector](#target-connector)
   - [Notifier Connector](#notifier-connector)
   - [EST Server (RFC 7030)](#est-server-rfc-7030)
5. [Security Model](#security-model)
   - [Private Key Management](#private-key-management)
   - [Authentication](#authentication)
   - [Audit Trail](#audit-trail)
   - [API Audit Log](#api-audit-log)
   - [Logging](#logging)
6. [API Design](#api-design)
7. [MCP Server](#mcp-server)
8. [CLI Tool](#cli-tool)
9. [Deployment Topologies](#deployment-topologies)
   - [Docker Compose (Development / Small Deployments)](#docker-compose-development--small-deployments)
   - [Production (Kubernetes)](#production-kubernetes)
10. [Discovery Data Flow (M18b + M21)](#discovery-data-flow-m18b--m21)
11. [Testing Strategy](#testing-strategy)
12. [What's Next](#whats-next)

## Overview

Certctl is a certificate management platform with a **decoupled control-plane and agent architecture**. The control plane orchestrates certificate issuance and renewal, while agents deployed across your infrastructure handle key generation, certificate deployment, and local validation — private keys never leave the infrastructure they were generated on.

New to certificates? Read the [Concepts Guide](concepts.md) first.

### Design Principles

1. **Private Key Isolation** — Agents generate ECDSA P-256 keys locally and submit CSRs only. Private keys never touch the control plane. Server-side keygen available via `CERTCTL_KEYGEN_MODE=server` for demo only.
2. **Pull-Only Deployment** — The server never initiates outbound connections to agents or targets. Agents poll for work. For network appliances and agentless targets, a proxy agent in the same network zone executes deployments via the target's API. This keeps the control plane firewalled off and limits credential scope to the proxy agent's zone.
3. **Sub-CA Capable** — The Local CA can operate as a subordinate CA under an enterprise root (e.g., ADCS). Load a pre-signed CA cert+key from disk and all issued certs chain to the enterprise trust hierarchy. Self-signed mode remains the default for development/demos.
4. **GUI as Primary Interface** — The web dashboard is the operational control plane, not a secondary viewer. Every backend feature ships with its corresponding GUI surface.
5. **Decoupled Operations** — Agents operate autonomously; the control plane coordinates but doesn't block agent function
6. **Audit-First** — Complete traceability of all issuance, deployment, and rotation events
7. **Connector Architecture** — Pluggable issuers, targets, and notifiers for extensibility
8. **Self-Hosted** — No cloud lock-in; run with Docker Compose, Kubernetes, or bare metal

## System Components

```mermaid
flowchart TB
    subgraph "Control Plane"
        API["REST API\n(Go net/http, :8443)"]
        SVC["Service Layer"]
        REPO["Repository Layer\n(database/sql + lib/pq)"]
        SCHED["Background Scheduler\n6 loops"]
        DASH["Web Dashboard\n(React SPA)"]
    end

    subgraph "Data Store"
        PG[("PostgreSQL 16\n21 tables\nTEXT primary keys")]
    end

    subgraph "Agent Fleet"
        A1["Agent: nginx-prod\n(heartbeat + work poll)"]
        A2["Agent: f5-prod"]
        A3["Agent: iis-prod"]
    end

    subgraph "Issuer Backends"
        CA1["Local CA\n(crypto/x509, sub-CA)"]
        CA2["ACME\n(HTTP-01 + DNS-01 + DNS-PERSIST-01)"]
        CA3["step-ca\n(/sign API)"]
        CA4["OpenSSL / Custom CA\n(script-based)"]
        CA6["Vault PKI\n(planned)"]
    end

    subgraph "Target Systems"
        T1["NGINX\n(file write + reload)"]
        T4["Apache httpd\n(file write + reload)"]
        T5["HAProxy\n(combined PEM + reload)"]
        T2["F5 BIG-IP\n(proxy agent + iControl REST, planned)"]
        T3["IIS\n(agent-local PowerShell, planned)"]
    end

    DASH --> API
    API --> SVC
    SVC --> REPO
    REPO --> PG
    SCHED --> SVC
    SVC -->|"Issue/Renew"| CA1 & CA2 & CA3

    A1 & A2 & A3 -->|"CSR + Heartbeat"| API
    API -->|"Cert + Chain\n(NO private key)"| A1 & A2 & A3

    A1 -->|"Deploy"| T1
    A2 -->|"Deploy"| T2
    A3 -->|"Deploy"| T3
```

### Control Plane (Server)

The control plane is a Go HTTP server backed by PostgreSQL. It manages state (certificates, agents, targets, issuers, policies), orchestrates issuance by coordinating with CAs through issuer connectors, tracks jobs for certificate issuance/renewal/deployment workflows, maintains an immutable audit trail, and dispatches work via a background scheduler.

The server exposes a REST API under `/api/v1/` and optionally serves the web dashboard as static files from the `web/` directory.

**Key internals**: The server uses Go 1.25's `net/http` stdlib routing (no external router framework), structured logging via `slog`, and a handler → service → repository layered architecture. Handlers define their own service interfaces for clean dependency inversion.

### Agents

Lightweight Go processes that run on or near your infrastructure. Agents generate ECDSA P-256 private keys locally, create CSRs, and submit them to the control plane for signing — private keys never leave agent infrastructure. Agents also handle certificate deployment to target systems (NGINX, Apache httpd, HAProxy fully implemented; F5 BIG-IP, IIS interface only with V2 implementations planned) and report job status. They communicate with the control plane via HTTP and authenticate with API keys.

The agent runs two background loops: a heartbeat (every 60 seconds) to signal it's alive, and a work poll (every 30 seconds) to check for actionable jobs via `GET /api/v1/agents/{id}/work`. Jobs may be `AwaitingCSR` (agent needs to generate key + submit CSR) or `Deployment` (agent needs to deploy a certificate). Private keys are stored in `CERTCTL_KEY_DIR` (default `/var/lib/certctl/keys`) with 0600 permissions.

**Agent metadata (M10):** Agents report OS, architecture, IP address, hostname, and version via heartbeat using `runtime.GOOS`, `runtime.GOARCH`, and `net` stdlib. This metadata is stored on the `agents` table and displayed in the GUI (agent list shows OS/Arch column, detail page shows full system info).

**Agent groups (M11b):** Dynamic device grouping allows organizing agents by metadata criteria. Agent groups can match by OS, architecture, IP CIDR, and version. Groups support both dynamic matching (agents automatically join when criteria match) and manual membership (explicit include/exclude). Renewal policies can be scoped to agent groups via the `agent_group_id` foreign key. The GUI provides full CRUD management for agent groups with visual match criteria badges.

### Web Dashboard

The web dashboard is the primary operational interface for certctl. It is built with Vite + React + TypeScript and uses TanStack Query for server state management (caching, background refetching, optimistic updates).

**Current views**: certificate inventory (list with multi-select bulk operations + "New Certificate" creation modal + detail with deployment status timeline, inline policy/profile editor, version history, deploy, revoke, archive, and trigger renewal actions), agent fleet (list + detail with system info + OS/architecture grouping with charts), job queue (status, retry, cancel, approve/reject), notification inbox (threshold alert grouping, mark-as-read), audit trail (time range, actor, action filters + CSV/JSON export), policy management (rules with enable/disable toggle + delete + violations), issuers (list with test connection + delete), targets (list with 3-step configuration wizard + delete), owners (list with team resolution + delete), teams (list with delete), agent groups (list with dynamic match criteria badges + enable/disable + delete), certificate profiles (list with crypto constraints), short-lived credentials dashboard (TTL countdown, profile filtering, auto-refresh), summary dashboard with charts (expiration heatmap, renewal success rate, status distribution, issuance rate), and login page.

The dashboard includes an **ErrorBoundary component** for graceful error recovery — if a view crashes, the boundary catches the error and displays a user-friendly message instead of breaking the entire dashboard. It also includes a **demo mode** that activates when the API is unreachable — it renders realistic mock data for screenshots and offline presentations.

**Tech decisions**:
- Vite for fast builds and HMR during development
- TanStack Query over manual fetch/useEffect for automatic cache invalidation and refetching
- Light content area with branded dark teal sidebar, Inter + JetBrains Mono typography
- SSE/WebSocket planned for real-time job status updates

### PostgreSQL Database

All state is stored in PostgreSQL 16. The schema uses TEXT primary keys (not UUIDs) with human-readable prefixed IDs like `mc-api-prod`, `t-platform`, `o-alice`.

```mermaid
erDiagram
    teams ||--o{ owners : "has members"
    teams ||--o{ managed_certificates : "owns"
    owners ||--o{ managed_certificates : "responsible for"
    issuers ||--o{ managed_certificates : "signs"
    renewal_policies ||--o{ managed_certificates : "governs"
    managed_certificates ||--o{ certificate_versions : "has versions"
    managed_certificates ||--o{ certificate_target_mappings : "deployed to"
    deployment_targets ||--o{ certificate_target_mappings : "receives"
    agents ||--o{ deployment_targets : "manages"
    managed_certificates ||--o{ jobs : "triggers"
    policy_rules ||--o{ policy_violations : "produces"
    managed_certificates ||--o{ policy_violations : "violates"
    managed_certificates ||--o{ audit_events : "logged in"
    managed_certificates ||--o{ notification_events : "generates"
    managed_certificates ||--o{ certificate_revocations : "revoked via"
    agent_groups ||--o{ agent_group_members : "has members"
    agents ||--o{ agent_group_members : "belongs to"
    agents ||--o{ discovered_certificates : "discovers"
    agents ||--o{ discovery_scans : "performs"

    teams {
        text id PK
        text name
        text description
    }
    owners {
        text id PK
        text name
        text email
        text team_id FK
    }
    managed_certificates {
        text id PK
        text name
        text common_name
        text[] sans
        text environment
        text owner_id FK
        text team_id FK
        text issuer_id FK
        text renewal_policy_id FK
        text status
        timestamp expires_at
        jsonb tags
    }
    certificate_versions {
        text id PK
        text certificate_id FK
        text serial_number
        text fingerprint_sha256
        text pem_chain
        text csr_pem
    }
    agents {
        text id PK
        text name
        text hostname
        text status
        text api_key_hash
        varchar os
        varchar architecture
        varchar ip_address
        varchar version
    }
    deployment_targets {
        text id PK
        text name
        text type
        text agent_id FK
        jsonb config
    }
    issuers {
        text id PK
        text name
        text type
        jsonb config
        boolean enabled
    }
    jobs {
        text id PK
        text type
        text certificate_id FK
        text target_id FK
        text status
        int attempts
    }
    policy_rules {
        text id PK
        text name
        text type
        jsonb config
        boolean enabled
    }
    policy_violations {
        text id PK
        text certificate_id FK
        text rule_id FK
        text message
        text severity
    }
    audit_events {
        text id PK
        text actor
        text actor_type
        text action
        text resource_type
        text resource_id
        jsonb details
    }
    notification_events {
        text id PK
        text type
        text certificate_id FK
        text channel
        text recipient
        text status
    }
    certificate_profiles {
        text id PK
        text name
        text description
        jsonb allowed_key_types
        int max_validity_days
    }
    agent_groups {
        text id PK
        text name
        text description
        jsonb match_criteria
        boolean enabled
    }
    agent_group_members {
        text id PK
        text agent_group_id FK
        text agent_id FK
        text membership_type
    }
    renewal_policies {
        text id PK
        text certificate_id FK
        int renewal_days_before
        jsonb alert_thresholds_days
        boolean auto_renew
        text agent_group_id FK
    }
    certificate_revocations {
        text id PK
        text certificate_id FK
        text serial_number
        text reason
        timestamp revoked_at
        boolean issuer_notified
    }
    discovered_certificates {
        text id PK
        text agent_id FK
        text fingerprint_sha256
        text common_name
        text source_path
        text status
    }
    discovery_scans {
        text id PK
        text agent_id FK
        int certs_found
        timestamp scanned_at
    }
    network_scan_targets {
        text id PK
        text name
        text[] cidrs
        int[] ports
        boolean enabled
    }
```

Migrations are idempotent (`IF NOT EXISTS` on all CREATE statements, `ON CONFLICT (id) DO NOTHING` on all seed data) so they're safe to run multiple times — important for Docker Compose where both initdb and the server may run the same SQL.

## Data Flow: Certificate Lifecycle

### 1. Create Managed Certificate

```mermaid
sequenceDiagram
    participant U as User / API Client
    participant API as REST API
    participant SVC as CertificateService
    participant DB as PostgreSQL
    participant AUD as AuditService

    U->>API: POST /api/v1/certificates<br/>{name, common_name, sans, ...}
    API->>SVC: Create(ctx, certificate)
    SVC->>SVC: Validate required fields
    SVC->>DB: INSERT INTO managed_certificates
    SVC->>AUD: Create(audit_event: certificate_created)
    AUD->>DB: INSERT INTO audit_events
    SVC-->>API: ManagedCertificate
    API-->>U: 201 Created + JSON body
```

### 2. Certificate Issuance

#### Agent-Side Key Generation (Default)

In the default `agent` keygen mode (`CERTCTL_KEYGEN_MODE=agent`), the control plane never touches private keys. When a renewal or issuance job is created, it enters `AwaitingCSR` state. The agent picks it up, generates an ECDSA P-256 key pair locally, and submits only the CSR (public key).

```mermaid
sequenceDiagram
    participant S as Scheduler
    participant SVC as RenewalService
    participant DB as PostgreSQL
    participant A as Agent
    participant API as Control Plane API
    participant ISS as Issuer Connector

    S->>SVC: ProcessRenewalJob(job)
    SVC->>DB: UPDATE job SET status='AwaitingCSR'
    SVC->>DB: UPDATE cert SET status='RenewalInProgress'

    A->>API: GET /agents/{id}/work
    API-->>A: [{id, type:"Renewal", status:"AwaitingCSR", common_name, sans}]

    A->>A: Generate ECDSA P-256 key pair
    A->>A: Store key to CERTCTL_KEY_DIR/certId.key (0600)
    A->>A: Create CSR with CN + SANs

    A->>API: POST /agents/{id}/csr<br/>{csr_pem, certificate_id}
    API->>SVC: CompleteAgentCSRRenewal(job, cert, csrPEM)
    SVC->>ISS: RenewCertificate(CN, SANs, csrPEM)
    ISS-->>SVC: IssuanceResult{cert_pem, chain_pem, serial}
    SVC->>DB: INSERT INTO certificate_versions (PEM chain + CSR only)
    SVC->>DB: UPDATE cert SET status='Active', expires_at
    SVC->>DB: CREATE deployment jobs for targets

    Note over A: Agent deploys using locally-held private key
```

**Profile enforcement:** If the certificate is assigned to a profile (`certificate_profile_id`), the profile's `allowed_key_algorithms` and `max_validity_days` constraints are checked during CSR validation. A CSR with a disallowed key type or a validity period exceeding the profile maximum is rejected before reaching the issuer connector.

#### Server-Side Key Generation (Demo Only)

Set `CERTCTL_KEYGEN_MODE=server` for development/demo with Local CA. The control plane generates RSA-2048 keys server-side. A log warning is emitted at startup.

```mermaid
sequenceDiagram
    participant U as User / Scheduler
    participant SVC as RenewalService
    participant ISS as IssuerConnector
    participant DB as PostgreSQL

    U->>SVC: ProcessRenewalJob(job)
    SVC->>SVC: Generate RSA-2048 key pair (server-side)
    SVC->>SVC: Create CSR with CN + SANs
    SVC->>ISS: RenewCertificate(CN, SANs, csrPEM)
    ISS-->>SVC: IssuanceResult{cert_pem, chain_pem, serial}
    SVC->>DB: INSERT INTO certificate_versions (PEM + private key)
    SVC->>DB: UPDATE cert SET status='Active'
    SVC->>DB: CREATE deployment jobs

    Note over SVC: WARNING: Private keys touch control plane
```

### 3. Deploy Certificate to Target

The agent deploys certificates using target connectors. Each connector knows how to push certificates to a specific system:

- **NGINX**: Writes cert/chain/key files to disk, validates config with `nginx -t`, reloads with `nginx -s reload` or `systemctl reload nginx`
- **Apache httpd**: Writes separate cert/chain/key files, validates with `apachectl configtest`, graceful reload
- **HAProxy**: Builds a combined PEM file (cert + chain + key), optionally validates config, reloads via systemctl or signal
- **F5 BIG-IP** (planned): A proxy agent in the same network zone calls the iControl REST API to upload certificate and update SSL profile bindings. The server assigns the work; the proxy agent executes it.
- **IIS** (planned, dual-mode): (1) Agent-local (recommended) — a Windows agent on the IIS box runs PowerShell `Import-PfxCertificate` + `Set-WebBinding` directly. (2) Proxy agent WinRM — for agentless IIS targets, a nearby Windows agent reaches the IIS box via WinRM.

The agent handles both the certificate (public) and the private key (read from local key store at `CERTCTL_KEY_DIR`). The control plane never sees the private key and never initiates outbound connections to agents or targets (pull-only model).

### 3.5 Revoke a Certificate

When a certificate needs immediate revocation (key compromise, decommission, etc.), the control plane executes a 7-step process:

```mermaid
sequenceDiagram
    participant U as User / API Client
    participant API as REST API
    participant SVC as CertificateService
    participant DB as PostgreSQL
    participant ISS as Issuer Connector
    participant NOT as Notification Service

    U->>API: POST /api/v1/certificates/{id}/revoke<br/>{reason: "keyCompromise"}
    API->>SVC: RevokeCertificateWithActor(id, reason, actor)
    SVC->>DB: Validate cert is not already revoked/archived
    SVC->>DB: Get latest certificate version (serial number)
    SVC->>DB: UPDATE managed_certificates SET status='Revoked'
    SVC->>DB: INSERT INTO certificate_revocations<br/>(ON CONFLICT DO NOTHING for idempotency)
    SVC->>ISS: RevokeCertificate(serial, reason)<br/>(best-effort — failure doesn't block)
    SVC->>DB: INSERT audit_event (certificate_revoked)
    SVC->>NOT: SendRevocationNotification(cert, reason)
    SVC-->>API: Updated certificate with Revoked status
    API-->>U: 200 OK
```

The revocation is recorded in the `certificate_revocations` table (separate from the certificate status update) for CRL generation. The DER-encoded CRL at `GET /api/v1/crl/{issuer_id}` is generated on-demand by querying this table and signing with the issuing CA's key. The OCSP responder at `GET /api/v1/ocsp/{issuer_id}/{serial}` checks both the certificate status and the revocations table to return signed good/revoked/unknown responses.

Short-lived certificates (those with profile TTL < 1 hour) return "good" from OCSP and are excluded from CRL — their rapid expiry is treated as sufficient revocation.

### 4. Automatic Renewal

The control plane runs a scheduler with six background loops:

```mermaid
flowchart LR
    subgraph "Scheduler (Background Goroutines)"
        R["Renewal Checker\n⏱ every 1h"]
        J["Job Processor\n⏱ every 30s"]
        H["Agent Health\n⏱ every 2m"]
        N["Notification Processor\n⏱ every 1m"]
        SL["Short-Lived Expiry\n⏱ every 30s"]
        NS["Network Scanner\n⏱ every 6h"]
    end

    R -->|"Find expiring certs\nCreate renewal jobs"| DB[("PostgreSQL")]
    J -->|"Process pending jobs\nCoordinate issuance"| DB
    H -->|"Check heartbeat staleness\nMark agents offline"| DB
    N -->|"Send pending notifications\nEmail / Webhook / Slack"| DB
    SL -->|"Expire short-lived certs\nMark as Expired"| DB
    NS -->|"Probe TLS endpoints\nStore discovered certs"| DB
```

| Loop | Interval | Timeout | Purpose |
|------|----------|---------|---------|
| Renewal checker | 1 hour | 5 minutes | Finds certificates approaching expiry, creates renewal jobs |
| Job processor | 30 seconds | 2 minutes | Processes pending jobs (issuance, renewal, deployment) |
| Agent health check | 2 minutes | 1 minute | Marks agents as offline if heartbeat is stale |
| Notification processor | 1 minute | 1 minute | Sends pending notifications via configured channels |
| Short-lived expiry | 30 seconds | 30 seconds | Marks expired short-lived certificates (profile TTL < 1 hour) |
| Network scanner | 6 hours | 30 minutes | Probes TLS endpoints on configured CIDR ranges, stores discovered certs (M21, opt-in via `CERTCTL_NETWORK_SCAN_ENABLED`) |

Each operation has a context timeout to prevent indefinite hangs if external services become unresponsive.

When the renewal checker finds a certificate within its renewal window, it performs two tasks: threshold-based alerting and renewal job creation.

**Threshold-Based Expiration Alerting**: Each renewal policy defines configurable alert thresholds (default: 30, 14, 7, 0 days before expiry). For each certificate approaching expiry, the scheduler checks which thresholds have been crossed and sends deduplicated notifications. A certificate that crosses the 14-day threshold only gets one 14-day alert, even though the renewal checker runs every hour. Deduplication is tracked via threshold tags embedded in the notification message and queried with the `MessageLike` filter. Certificates are also transitioned to `Expiring` status when they enter the alert window and `Expired` when they hit 0 days.

**Renewal Job Creation**: If the certificate's issuer has a registered connector, the scheduler creates a renewal job. The job processor picks it up, coordinates with the issuer, and triggers deployment. All steps are logged in the audit trail and generate notifications.

## Connector Architecture

Certctl uses connector interfaces for extensibility. Each connector type has a standard interface that implementations must satisfy.

```mermaid
flowchart TB
    subgraph "Issuer Connectors"
        direction TB
        II["IssuerConnector Interface\nIssueCertificate() | RenewCertificate()\nRevokeCertificate() | GetOrderStatus()"]
        II --> LC["Local CA"]
        II --> ACME["ACME v2"]
        II --> SC["step-ca"]
        II --> OC["OpenSSL / Custom CA"]
        II --> VP["Vault PKI (planned)"]
    end

    subgraph "Target Connectors"
        direction TB
        TI["TargetConnector Interface\nDeployCertificate()\nValidateDeployment()"]
        TI --> NG["NGINX"]
        TI --> AP["Apache httpd"]
        TI --> HP["HAProxy"]
        TI --> F5["F5 BIG-IP (interface only)"]
        TI --> IIS["IIS (interface only)"]
    end

    subgraph "Notifier Connectors"
        direction TB
        NI["NotifierConnector Interface\nSendAlert() | SendEvent()"]
        NI --> EM["Email (SMTP)"]
        NI --> WH["Webhook (HTTP)"]
        NI --> SL["Slack"]
        NI --> TM["Microsoft Teams"]
        NI --> PD["PagerDuty"]
        NI --> OG["OpsGenie"]
    end
```

### IssuerConnectorAdapter (Dependency Inversion)

The service layer defines its own `IssuerConnector` interface (`internal/service/renewal.go`) while the connector layer has its own `issuer.Connector` interface (`internal/connector/issuer/interface.go`). The `IssuerConnectorAdapter` (`internal/service/issuer_adapter.go`) bridges the two, translating between their request/response types. This maintains clean dependency inversion — the service package never imports the connector package directly.

```mermaid
flowchart LR
    SVC["Service Layer<br/>service.IssuerConnector"] --> ADAPT["IssuerConnectorAdapter<br/>(bridges interfaces)"]
    ADAPT --> CONN["Connector Layer<br/>issuer.Connector"]
    CONN --> LC["Local CA"]
    CONN --> ACME["ACME v2"]
```

Registration happens in `cmd/server/main.go`:
```go
localCA := local.New(nil, logger)
issuerRegistry := map[string]service.IssuerConnector{
    "iss-local": service.NewIssuerConnectorAdapter(localCA),
}
```

### Issuer Connector

Handles certificate issuance from CAs.

```go
type Connector interface {
    ValidateConfig(ctx context.Context, config json.RawMessage) error
    IssueCertificate(ctx context.Context, request IssuanceRequest) (*IssuanceResult, error)
    RenewCertificate(ctx context.Context, request RenewalRequest) (*IssuanceResult, error)
    RevokeCertificate(ctx context.Context, request RevocationRequest) error
    GetOrderStatus(ctx context.Context, orderID string) (*OrderStatus, error)
    GenerateCRL(ctx context.Context, revokedCerts []RevokedCertEntry) ([]byte, error)
    SignOCSPResponse(ctx context.Context, req OCSPSignRequest) ([]byte, error)
    GetCACertPEM(ctx context.Context) (string, error)
}
```

Built-in issuers: **Local CA** (self-signed or sub-CA mode using `crypto/x509`), **ACME v2** (HTTP-01, DNS-01, and DNS-PERSIST-01 challenges, compatible with Let's Encrypt, Sectigo, and any ACME-compliant CA), **step-ca** (Smallstep private CA via native /sign API with JWK provisioner auth), and **OpenSSL/Custom CA** (script-based signing delegating to user-provided shell scripts). The ACME connector uses `golang.org/x/crypto/acme`, generates an ECDSA P-256 account key, handles account registration with ToS acceptance, order creation, challenge solving (HTTP-01 via built-in server, DNS-01 via script-based hooks, DNS-PERSIST-01 via standing TXT records with auto-fallback to DNS-01), order finalization, and DER-to-PEM chain conversion. The interface also includes `GetCACertPEM(ctx)` for CA chain distribution (used by the EST server's `/cacerts` endpoint).

### Target Connector

Deploys certificates to infrastructure. The `DeploymentRequest` includes `KeyPEM` because agents generate and hold private keys locally — the key is passed from the agent's local key store into the target connector, never from the control plane.

```go
type Connector interface {
    ValidateConfig(ctx context.Context, config json.RawMessage) error
    DeployCertificate(ctx context.Context, request DeploymentRequest) (*DeploymentResult, error)
    ValidateDeployment(ctx context.Context, request ValidationRequest) (*ValidationResult, error)
}
```

The `DeploymentRequest` struct carries the full material needed by the target system: the signed certificate, the CA chain, the agent-generated private key, target-specific configuration, and arbitrary metadata. The key field is populated by the agent from its local key store (`CERTCTL_KEY_DIR`) — it never originates from the control plane.

Built-in targets: **NGINX** (writes cert/chain/key files, validates with `nginx -t`, reloads), **Apache httpd** (writes cert/chain/key files, validates with `apachectl configtest`, graceful reload), **HAProxy** (combined PEM file with cert+chain+key, validates config, reloads via systemctl/signal), **F5 BIG-IP** (interface only — proxy agent + iControl REST, implementation planned), **IIS** (interface only — dual-mode: agent-local PowerShell primary + proxy agent WinRM for agentless targets, implementation planned).

Additional cloud, network, and Kubernetes target connectors are planned for future releases.

### Notifier Connector

Sends alerts about certificate lifecycle events.

```go
type Connector interface {
    ValidateConfig(ctx context.Context, config json.RawMessage) error
    SendAlert(ctx context.Context, alert Alert) error
    SendEvent(ctx context.Context, event Event) error
}
```

Built-in notifiers: **Email** (SMTP), **Webhook** (HTTP POST), **Slack** (incoming webhook), **Microsoft Teams** (MessageCard), **PagerDuty** (Events API v2), and **OpsGenie** (Alert API v2). Each is enabled by setting its configuration environment variable.

See the [Connector Development Guide](connectors.md) for details on building custom connectors.

### EST Server (RFC 7030)

The EST (Enrollment over Secure Transport) server provides an industry-standard enrollment interface for devices that need certificates without using the REST API. It runs under `/.well-known/est/` per RFC 7030 and supports four operations: CA certificate distribution (`/cacerts`), initial enrollment (`/simpleenroll`), re-enrollment (`/simplereenroll`), and CSR attributes (`/csrattrs`).

**Architecture:** EST is a handler-level protocol that delegates certificate issuance to an existing `IssuerConnector`. This means EST is not a new issuer — it's a new *interface* to the existing issuance infrastructure. The `ESTService` bridges the `ESTHandler` to whichever issuer connector is configured via `CERTCTL_EST_ISSUER_ID`.

```
Client (WiFi AP, MDM, IoT)
    │
    ▼
ESTHandler (handler layer)
    │  CSR parsing, PKCS#7 response encoding
    ▼
ESTService (service layer)
    │  CSR validation, CN/SAN extraction, audit recording
    ▼
IssuerConnector (connector layer via IssuerConnectorAdapter)
    │  Certificate signing (Local CA, step-ca, etc.)
    ▼
Signed certificate returned as PKCS#7 certs-only
```

**Wire format:** EST uses PKCS#7 (RFC 2315) certs-only degenerate SignedData for certificate responses and base64-encoded DER for CSR requests. The handler includes a hand-rolled ASN.1 PKCS#7 builder — no external PKCS#7 dependency. The CSR reader accepts both base64-encoded DER (standard EST wire format) and PEM-encoded PKCS#10 (convenience for debugging).

**Interface:** The `ESTHandler` defines an `ESTService` interface (dependency inversion, same pattern as all other handlers):

```go
type ESTService interface {
    GetCACerts(ctx context.Context) (string, error)
    SimpleEnroll(ctx context.Context, csrPEM string) (*domain.ESTEnrollResult, error)
    SimpleReEnroll(ctx context.Context, csrPEM string) (*domain.ESTEnrollResult, error)
    GetCSRAttrs(ctx context.Context) ([]byte, error)
}
```

**Issuer connector extension:** EST required adding `GetCACertPEM(ctx) (string, error)` to the issuer connector interface so the `/cacerts` endpoint can serve the CA chain. The Local CA connector returns its CA certificate PEM; ACME, step-ca, and OpenSSL connectors return errors (they don't expose a static CA chain — their chains are per-issuance).

**Audit:** Every EST enrollment is recorded in the audit trail with `protocol: "EST"`, the CN, SANs, issuer ID, serial number, and optional profile ID.

## Security Model

### Private Key Management

```mermaid
flowchart LR
    subgraph "Agent (Your Infrastructure)"
        GEN["1. GENERATE\ncrypto/ecdsa P-256"]
        STORE["2. STORE\nFile perms 0600"]
        USE["3. USE\nCSR gen + deployment"]
        ROT["4. ROTATE\nDelete old after renewal"]
    end

    subgraph "Control Plane (certctl-server)"
        CP["Only sees:\n• Certificates (public)\n• Chains (public)\n• CSRs (public key only)"]
    end

    GEN --> STORE --> USE --> ROT
    USE -.->|"CSR (public key only)"| CP
    CP -.->|"Signed cert + chain"| USE

    style CP fill:#fee,stroke:#c33
    style GEN fill:#efe,stroke:#3c3
    style STORE fill:#efe,stroke:#3c3
    style USE fill:#efe,stroke:#3c3
    style ROT fill:#efe,stroke:#3c3
```

**Agent keygen mode (default, `CERTCTL_KEYGEN_MODE=agent`):** Private keys follow a strict lifecycle on agents:

1. **Generated on the agent** — ECDSA P-256, never sent to the control plane
2. **Stored on the agent** — `CERTCTL_KEY_DIR` with file permissions 0600
3. **Used by the agent** — for deployment to targets (via `DeploymentRequest.KeyPEM`)
4. **Rotated by the agent** — old keys overwritten after successful renewal

The control plane only handles public material: certificates, chains, and CSRs.

**Server keygen mode (`CERTCTL_KEYGEN_MODE=server`, demo only):** The control plane generates RSA-2048 keys server-side within `processRenewalServerKeygen`. Private keys are stored in `certificate_versions.csr_pem`. A log warning is emitted at startup. Use only for Local CA development/demo.

### Authentication

- **API clients → Server**: API key in `Authorization: Bearer` header, or `none` for demo mode
- **Agent → Server**: API key registered at agent creation, included in all requests
- **Server → Issuers**: ACME account key, or connector-specific credentials
- **Agent → Targets**: API tokens, WinRM credentials (stored locally on agent or proxy agent — never on server). Credential scope is limited to the agent's network zone.

### Audit Trail

Every action is recorded as an immutable audit event:

```json
{
  "id": "audit-001",
  "actor": "o-alice",
  "actor_type": "User",
  "action": "certificate_created",
  "resource_type": "certificate",
  "resource_id": "mc-api-prod",
  "details": {"environment": "production"},
  "timestamp": "2026-03-14T10:30:00Z"
}
```

Audit events cannot be modified or deleted. They support filtering by actor, action, resource type, resource ID, and time range. All audit operations are logged via structured `slog` logging; if an audit event fails to persist, the error is logged immediately to ensure no gaps in the audit trail go unnoticed.

### API Audit Log

In addition to application-level audit events, certctl records every HTTP API call via middleware. The audit middleware captures method, path, actor (extracted from auth context), SHA-256 request body hash (truncated to 16 characters), response status code, and request latency. Health and readiness probes are excluded to avoid noise.

Audit recording is async (via goroutine) so it never blocks the HTTP response. If audit persistence fails, the error is logged immediately — the API call still succeeds. The middleware sits after the auth middleware in the stack so the actor identity is available from context.

### Logging

All logging throughout the service layer uses Go's `log/slog` package for structured, queryable logs. This replaces ad-hoc `fmt.Printf` statements with consistent key-value logging that includes request context, operation names, and error details. Agents also implement exponential backoff on network failures to gracefully handle temporary connectivity issues with the control plane.

## API Design

All endpoints are under `/api/v1/` and follow consistent patterns:

- **List**: `GET /api/v1/{resources}` — returns `{data: [...], total, page, per_page}`
- **Get**: `GET /api/v1/{resources}/{id}` — returns the resource
- **Create**: `POST /api/v1/{resources}` — returns the created resource with `201`
- **Update**: `PUT /api/v1/{resources}/{id}` — returns the updated resource
- **Delete**: `DELETE /api/v1/{resources}/{id}` — returns `204` (soft delete/archive)
- **Actions**: `POST /api/v1/{resources}/{id}/{action}` — returns `202` for async operations

Resources: certificates, issuers, targets, agents, jobs, policies, profiles, teams, owners, agent-groups, audit, notifications, discovered-certificates, discovery-scans, network-scan-targets, stats, metrics.

The full API is documented in an OpenAPI 3.1 specification at `api/openapi.yaml` with 97 endpoints across 20 resource domains (95 under `/api/v1/` + `/.well-known/est/` plus `/health` and `/ready`; includes auth, 7 discovery endpoints from M18b, 6 network scan endpoints from M21, Prometheus metrics from M22, and 4 EST enrollment endpoints from M23), all request/response schemas, and pagination conventions. See the [OpenAPI Guide](openapi.md) for usage with Swagger UI and SDK generation.

Jobs support additional action endpoints: `POST /api/v1/jobs/{id}/cancel`, `POST /api/v1/jobs/{id}/approve`, `POST /api/v1/jobs/{id}/reject`.

**Enhanced Query Features (M20):** Certificate list endpoints support additional query capabilities beyond basic pagination:

- **Sorting**: `?sort=notAfter` (ascending) or `?sort=-createdAt` (descending). Whitelist: notAfter, expiresAt, createdAt, updatedAt, commonName, name, status, environment.
- **Time-range filters**: `?expires_before=`, `?expires_after=`, `?created_after=`, `?updated_after=` (RFC 3339 format).
- **Cursor pagination**: `?cursor=<token>&page_size=100` for efficient keyset pagination alongside traditional page-based.
- **Sparse fields**: `?fields=id,common_name,status` to reduce response payload.
- **Additional filters**: `?agent_id=`, `?profile_id=` (in addition to existing status, environment, owner_id, team_id, issuer_id).
- **Deployments**: `GET /api/v1/certificates/{id}/deployments` returns deployment targets for a certificate.

Certificate revocation: `POST /api/v1/certificates/{id}/revoke` with optional `{"reason": "keyCompromise"}`. Supports RFC 5280 reason codes (unspecified, keyCompromise, caCompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, privilegeWithdrawn). Returns the updated certificate status. Best-effort issuer notification — the revocation succeeds even if the issuer connector is unavailable. A JSON-formatted CRL is available at `GET /api/v1/crl`, and a DER-encoded X.509 CRL signed by the issuing CA at `GET /api/v1/crl/{issuer_id}`. An embedded OCSP responder serves signed responses at `GET /api/v1/ocsp/{issuer_id}/{serial}`. Short-lived certificates (profile TTL < 1 hour) are exempt from CRL/OCSP — expiry is sufficient revocation.

Health checks live outside the API prefix: `GET /health` and `GET /ready`.

## MCP Server

certctl includes an MCP (Model Context Protocol) server as a separate binary (`cmd/mcp-server/`) that enables AI assistants to interact with the certificate platform. The MCP server uses the official MCP Go SDK (`modelcontextprotocol/go-sdk`) with stdio transport for integration with Claude, Cursor, and other MCP-compatible tools.

```mermaid
flowchart LR
    AI["AI Assistant\n(Claude, Cursor)"] -->|"stdio"| MCP["MCP Server\ncmd/mcp-server/"]
    MCP -->|"HTTP + Bearer token"| API["certctl REST API\n:8443"]

    subgraph "78 MCP Tools"
        T1["Certificate CRUD"]
        T2["Agent Management"]
        T3["Job Operations"]
        T4["Policy/Profile Queries"]
        T5["Audit Trail Access"]
        T6["Stats & Metrics"]
    end

    MCP --> T1 & T2 & T3 & T4 & T5 & T6
```

The MCP server is a stateless HTTP proxy — every MCP tool call translates to an HTTP request to the certctl REST API. It adds no new state, no new dependencies, and no new attack surface beyond what the API already exposes. Configuration is minimal: `CERTCTL_SERVER_URL` and `CERTCTL_API_KEY` environment variables.

The 78 tools are organized across 16 resource domains with typed input structs and `jsonschema` struct tags for automatic LLM-friendly schema generation. Binary response support handles DER CRL and OCSP endpoints.

## CLI Tool

certctl ships with a command-line tool (`certctl-cli`, built from `cmd/cli/main.go`) that wraps the REST API for terminal workflows. The CLI uses Go's standard library only (`flag` + `text/tabwriter`) — no Cobra or other framework dependencies.

12 subcommands organized by resource: `certs list`, `certs get`, `certs renew`, `certs revoke`, `agents list`, `agents get`, `jobs list`, `jobs get`, `jobs cancel`, `import` (bulk PEM import), `status` (health + summary stats), and `version`. Output is available in table (default) or JSON format via `--format`. Connection is configured via `CERTCTL_SERVER_URL` and `CERTCTL_API_KEY` environment variables or CLI flags.

The bulk import command (`certctl-cli import <file.pem>`) parses multi-certificate PEM files and creates certificate records via the API — useful for bootstrapping certctl with existing certificate inventory.

## Deployment Topologies

### Docker Compose (Development / Small Deployments)

```mermaid
flowchart TB
    subgraph "Docker Network (certctl-network)"
        SERVER["certctl-server\n:8443\nAPI + Dashboard"]
        PG[("PostgreSQL\n:5432\nSchema + Seed Data")]
        AGENT["certctl-agent\nHeartbeat + Work Poll\nagent_keys volume"]
    end

    USER["Browser / curl"] -->|"HTTP :8443"| SERVER
    SERVER -->|"SQL"| PG
    AGENT -->|"HTTP (internal)"| SERVER
```

**Credentials & Configuration:**
Database and API credentials are managed via environment variables defined in a `.env` file. Copy `deploy/.env.example` to `deploy/.env` for local development and customize credentials for production. The agent key directory (`CERTCTL_KEY_DIR`) is persisted as a named Docker volume (`agent_keys`) at `/var/lib/certctl/keys` for reliable key storage across container restarts.

### Production (Kubernetes)

```mermaid
flowchart TB
    subgraph "Kubernetes Cluster"
        subgraph "Control Plane"
            DEP["Deployment\ncertctl-server\nreplicas: 2+"]
            CM["ConfigMap\nIssuer/target configs"]
            SEC["Secret\nAPI keys, ACME creds"]
        end

        subgraph "Data"
            SS[("StatefulSet\nPostgreSQL\nprimary + replica")]
        end

        subgraph "Agent Fleet"
            DS["DaemonSet\ncertctl-agent\n(infra nodes)"]
        end
    end

    ING["Ingress\n+ TLS termination"] --> DEP
    DEP --> SS
    DEP --> CM & SEC
    DS --> DEP
```

For production, you would also add an ingress controller, TLS termination for the certctl API itself, and external PostgreSQL (RDS, Cloud SQL, etc.).

## Discovery Data Flow (M18b + M21)

Certificate discovery enables operators to build a complete inventory of existing certificates before managing them with certctl. There are two discovery modes that feed into the same pipeline:

```mermaid
flowchart TB
    subgraph "Discovery Sources"
        AGENT["certctl-agent\n(filesystem discovery)"]
        SCAN["Filesystem Scanner\n(CERTCTL_DISCOVERY_DIRS)"]
        SERVER["certctl-server\n(network discovery)"]
        NETSCAN["TLS Scanner\n(CIDR ranges + ports)"]
    end

    EXTRACT["Extract Metadata\n(CN, SANs, serial, issuer, expiry, fingerprint)"]
    SERVICE["Discovery Service\n(ProcessDiscoveryReport)"]
    REPO["Discovery Repository\n(upsert with fingerprint dedup)"]
    DB["PostgreSQL\ndiscovered_certificates\ndiscovery_scans tables"]
    AUDIT["Audit Service\n(RecordDiscoveryScanCompleted)"]
    API_LIST["GET /api/v1/discovered-certificates\n(list for triage)"]
    API_CLAIM["POST /discovered-certificates/{id}/claim"]
    API_DISMISS["POST /discovered-certificates/{id}/dismiss"]

    AGENT -->|"Scan loop\n(startup + 6h)"| SCAN
    SCAN --> EXTRACT
    SERVER -->|"Scheduler loop\n(every 6h)"| NETSCAN
    NETSCAN -->|"crypto/tls.Dial\n50 goroutines"| EXTRACT
    EXTRACT --> SERVICE
    SERVICE --> REPO
    REPO -->|"Dedup by fingerprint\n+ agent_id + source_path"| DB
    SERVICE --> AUDIT
    AUDIT --> DB
    DB --> API_LIST
    API_LIST --> API_CLAIM
    API_LIST --> API_DISMISS
```

**Filesystem Discovery (M18b):**

1. **Agent-side discovery** — Agent scans `CERTCTL_DISCOVERY_DIRS` on startup and every 6 hours, walking directories recursively and parsing PEM/DER files
2. **Metadata extraction** — For each certificate found, extract: common name, SANs, serial number, issuer DN, subject DN, expiration date, key algorithm, key size, is_ca flag, SHA-256 fingerprint (used as dedup key)
3. **Server submission** — Agent POSTs scan results as `DiscoveryReport` to `POST /api/v1/agents/{id}/discoveries`
4. **Deduplication** — Server uses fingerprint + agent ID + filesystem path as unique key; prevents duplicate records of the same cert on the same agent

**Network Discovery (M21):**

1. **Target configuration** — Operator creates network scan targets via `POST /api/v1/network-scan-targets` with CIDR ranges, ports, and scan interval
2. **CIDR expansion** — Ranges expanded to individual IPs with /20 safety cap (4096 IPs max)
3. **TLS probing** — Server uses `crypto/tls.DialWithDialer` with `InsecureSkipVerify=true` to connect to each endpoint; 50 concurrent goroutines with configurable timeout
4. **Certificate extraction** — Full X.509 metadata extracted from TLS handshake peer certificates
5. **Sentinel agent** — Results submitted using `server-scanner` as virtual agent ID, with `source_path` set to `ip:port` and `source_format` set to `network`
6. **Same pipeline** — Feeds into the same `DiscoveryService.ProcessDiscoveryReport()` as filesystem discovery — same dedup, same audit trail, same triage workflow

**Common triage workflow (both sources):**

1. **Storage** — Records stored in `discovered_certificates` table with status = "Unmanaged"
2. **Audit** — `discovery_scan_completed` event logged with agent ID, cert count, scan timestamp
3. **Operator triage** — Operator queries `GET /api/v1/discovered-certificates?status=Unmanaged` to see new findings
4. **Claim or dismiss** — For each unmanaged cert, operator either:
   - **Claims it** via `POST /discovered-certificates/{id}/claim` — links to existing managed cert or creates new enrollment
   - **Dismisses it** via `POST /discovered-certificates/{id}/dismiss` — removes from triage, marked as "Dismissed"
9. **Status tracking** — `discovery_cert_claimed` and `discovery_cert_dismissed` events audit the operator's decision
10. **Summary** — `GET /api/v1/discovery-summary` returns count of Unmanaged, Managed, and Dismissed certs (useful for compliance reporting)

This data flow is pull-based and non-blocking. Agents discover at their own pace; the server stores results for later review. There's no pressure to claim or dismiss; operators can leave certificates in "Unmanaged" status indefinitely.

## Testing Strategy

certctl uses a layered testing approach aligned with the handler → service → repository architecture, with 900+ tests across five layers (service, handler, integration, connector, and frontend). The goal is high-confidence regression prevention at the service and handler layers, where the most complex business logic lives, combined with integration tests that exercise the full request path from HTTP to database.

**Service layer unit tests** (`internal/service/*_test.go`) — ~238 test functions across 15 files with mock repositories. These test all business logic in isolation: certificate CRUD with validation, certificate revocation (success, already-revoked, archived, invalid reason, all RFC 5280 reason codes, issuer notification, notification service integration, OCSP/CRL generation), agent lifecycle (registration, heartbeat, CSR submission with both keygen modes), job state machine (creation, processing, cancellation, retry logic), policy evaluation (all 5 rule types, violation creation), renewal and issuance flow (server-side and agent-side keygen paths), notification deduplication (threshold tag matching, channel routing), team/owner/agent group CRUD with pagination and audit recording, issuer service CRUD with connection testing, and the issuer connector adapter (type translation between connector and service layers including revocation). Mock repositories are simple structs with function fields, avoiding heavy mocking frameworks — this keeps tests readable and avoids coupling to mock library APIs.

**Handler layer tests** (`internal/api/handler/*_test.go`) — ~257 test functions across 11 files using Go's `httptest` package. Every handler file has a corresponding test file: certificates (50 tests including revocation, DER CRL, and OCSP), agents (28 tests), jobs (21 tests including approve/reject), notifications (11 tests), policies (19 tests), profiles (18 tests), issuers (17 tests), targets (17 tests), agent groups (12 tests), teams (26 tests), and owners (21 tests). Each test file follows the same pattern: a mock service struct with function fields, `httptest.NewRecorder` for capturing responses, and a shared `contextWithRequestID()` helper. Tests cover the happy path, input validation (missing fields, invalid JSON, empty IDs, name length limits), error propagation from the service layer, method-not-allowed responses, and pagination parameters.

**Integration tests** (`internal/integration/`) — Two test files exercising the full stack from HTTP request through router, handler, service, and postgres repository layers. `lifecycle_test.go` has 11 subtests covering the complete certificate lifecycle: team/owner creation, certificate creation, issuer verification, renewal trigger, job verification, agent registration, CSR submission, deployment, and status reporting. `negative_test.go` has 14 subtests covering error paths, 19 M11b endpoint tests, and 8 revocation endpoint tests (M15a+M15b): nonexistent resource lookups (404s), invalid request bodies (malformed JSON, missing required fields), invalid CSR submission, heartbeat for nonexistent agents, wrong HTTP methods on list endpoints, empty list responses, renewal on nonexistent certificates, expired certificate lifecycle, team/owner/agent group CRUD validation, revocation success, already-revoked rejection, not-found revocation, JSON CRL retrieval, DER CRL retrieval, OCSP response retrieval, and short-lived cert exemption. Both use a shared `setupTestServer()` that builds a fully-wired server with real postgres repositories and the Local CA issuer connector. A third file, `e2e_test.go`, contains 8 cross-milestone test functions with 48+ subtests that exercise features across milestones end-to-end: M10 agent metadata via heartbeat, M11 profiles/teams/owners/agent-groups CRUD, M12 issuer registry verification, M13 GUI operation endpoints, M14 stats and metrics, M15 revocation and CRL, M16 notification channels, and M20 enhanced query API (sorting, cursor pagination, sparse fields, time-range filters).

**Frontend tests** (`web/src/api/client.test.ts`, `web/src/api/utils.test.ts`) — 86 Vitest tests covering the API client, stats/metrics endpoints, and utility functions. The API client tests mock `globalThis.fetch` and verify all endpoint functions (certificates, agents, jobs, policies, issuers, targets, notifications, audit, stats, metrics, health) send correct HTTP methods, URLs, headers, and request bodies. They also test API key management (store/retrieve/clear), auth header propagation, 401 event dispatching, and error handling (server messages, error fields, status text fallback). The stats/metrics endpoint tests verify correct query parameter handling and response shape validation. The utility tests use `vi.useFakeTimers()` for deterministic date testing and cover `formatDate`, `formatDateTime`, `timeAgo`, `daysUntil`, and `expiryColor`. The test environment uses jsdom with `@testing-library/jest-dom` matchers.

**CLI tests** (`internal/cli/client_test.go`) — 14 tests covering all 10 CLI subcommands with httptest mock servers, PEM parsing for bulk import, auth header verification, and JSON/table output formatting.

**CI pipeline** (`.github/workflows/ci.yml`) — Two parallel jobs: Go (build, vet, test with coverage, coverage threshold enforcement) and Frontend (TypeScript type check, Vitest test suite, Vite production build). The Go job runs all tests with `-coverprofile`, then enforces coverage thresholds: service layer must be at least 30% (current: ~35%) and handler layer must be at least 50% (current: ~63%). These thresholds act as regression floors — they can only go up. The service layer threshold is deliberately lower because much of the service code depends on postgres repositories and external connectors that require real infrastructure to test meaningfully. Connector tests are included via `./internal/connector/issuer/...` and `./internal/connector/target/...` (covers Local CA, ACME, step-ca, NGINX, Apache, and HAProxy packages with unit tests for certificate signing logic, DNS solver, issuer validation, and deployment flows). The Frontend job runs `npx vitest run` between the TypeScript check and production build steps.

**Connector tests** (`internal/connector/`) — 57 test functions covering issuer, target, and notifier connectors. The Local CA connector has tests for self-signed and sub-CA modes (RSA, ECDSA, config validation, non-CA cert rejection). The ACME DNS solver has 10 tests for script-based DNS-01 and DNS-PERSIST-01 challenges (6 DNS-01 tests + 4 DNS-PERSIST-01 tests covering `PresentPersist` success, no-script error, script failure, and wildcard domain handling). The step-ca connector has tests with a mock HTTP server for issuance, renewal, revocation, and error paths. The OpenSSL/Custom CA connector has 14 tests covering config validation, issuance success/failure/timeout, renewal, revocation, and CRL generation. The NGINX target connector has 13 tests covering config validation, certificate deployment (file writing, permissions, validate/reload commands), and deployment validation. Apache httpd and HAProxy connectors each have 3 tests covering config validation, deployment, and validation flows. Notifier connector tests span 20 tests across Slack (5), Teams (4), PagerDuty (6), and OpsGenie (5) — verifying channel identity, payload formatting, HTTP error handling, connection failures, auth headers, and configuration defaults.

**What's not tested and why:** Postgres repository implementations (`internal/repository/postgres/`) require a real database and are tested only through integration tests, not unit tests. Target connectors for F5 BIG-IP and IIS are interface stubs (implementation planned for a future release). Scheduler loops are time-dependent and tested manually during development. The ACME connector requires a real ACME server (tested manually against Let's Encrypt staging). These are all candidates for future expansion as the test infrastructure matures.

## What's Next

- [Quick Start](quickstart.md) — Get certctl running locally
- [Advanced Demo](demo-advanced.md) — Issue a certificate end-to-end
- [Connector Guide](connectors.md) — Build custom connectors
- [Compliance Mapping](compliance.md) — SOC 2, PCI-DSS 4.0, and NIST SP 800-57 alignment
- [MCP Server Guide](mcp.md) — AI-native access to the API
- [OpenAPI Spec](openapi.md) — Full API reference and SDK generation
