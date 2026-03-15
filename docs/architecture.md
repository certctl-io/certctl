# Architecture Guide

## Overview

Certctl is a certificate management platform with a **decoupled control-plane and agent architecture**. The control plane orchestrates certificate issuance and renewal, while agents deployed across your infrastructure handle key generation, certificate deployment, and local validation — private keys never leave the infrastructure they were generated on.

New to certificates? Read the [Concepts Guide](concepts.md) first.

### Design Principles

1. **Zero Private Key Exposure** — Private keys are generated and managed only on agents, never sent to the control plane
2. **Decoupled Operations** — Agents operate autonomously; the control plane coordinates but doesn't block agent function
3. **Audit-First** — Complete traceability of all issuance, deployment, and rotation events
4. **Connector Architecture** — Pluggable issuers, targets, and notifiers for extensibility
5. **Self-Hosted** — No cloud lock-in; run with Docker Compose, Kubernetes, or bare metal

## System Components

```mermaid
flowchart TB
    subgraph "Control Plane"
        API["REST API\n(Go net/http, :8443)"]
        SVC["Service Layer"]
        REPO["Repository Layer\n(database/sql + lib/pq)"]
        SCHED["Background Scheduler\n4 loops"]
        DASH["Web Dashboard\n(React SPA)"]
    end

    subgraph "Data Store"
        PG[("PostgreSQL 16\n14 tables\nTEXT primary keys")]
    end

    subgraph "Agent Fleet"
        A1["Agent: nginx-prod\n(heartbeat + work poll)"]
        A2["Agent: f5-prod"]
        A3["Agent: iis-prod"]
    end

    subgraph "Issuer Backends"
        CA1["Local CA\n(crypto/x509)"]
        CA2["ACME\n(Let's Encrypt)"]
        CA3["Vault PKI\n(future)"]
    end

    subgraph "Target Systems"
        T1["NGINX\n(SSH + reload)"]
        T2["F5 BIG-IP\n(REST API)"]
        T3["IIS\n(WinRM)"]
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

**Key internals**: The server uses Go 1.22's `net/http` stdlib routing (no external router framework), structured logging via `slog`, and a handler → service → repository layered architecture. Handlers define their own service interfaces for clean dependency inversion.

### Agents

Lightweight Go processes that run on or near your infrastructure. An agent generates private keys locally, creates CSRs, receives signed certificates from the control plane, deploys them to target systems, and reports status back. Agents communicate with the control plane via HTTP and authenticate with API keys.

The agent runs two background loops: a heartbeat (every 60 seconds) to signal it's alive, and a work poll (every 30 seconds) to check for pending jobs.

### Web Dashboard

A single-page React application served as a static HTML file (`web/index.html`). It communicates with the REST API and provides a visual interface for certificate inventory, agent status, job monitoring, audit trail, policy management, and notifications.

The dashboard includes a **demo mode** that activates when the API is unreachable — it renders realistic mock data for screenshots and offline presentations.

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

### 2. Agent Requests Certificate (CSR → Issuance)

```mermaid
sequenceDiagram
    participant A as Agent
    participant API as Control Plane API
    participant ISS as Issuer Connector
    participant DB as PostgreSQL

    A->>A: Generate RSA-2048 key pair
    A->>A: Create CSR (CN + SANs, public key only)
    A->>API: POST /api/v1/agents/{id}/csr<br/>{csr_pem: "-----BEGIN..."}

    API->>API: Validate CSR format
    API->>ISS: IssueCertificate(IssuanceRequest{CSR})
    ISS-->>API: IssuanceResult{cert_pem, chain_pem, serial, not_after}

    API->>DB: INSERT INTO certificate_versions
    API->>DB: UPDATE managed_certificates SET status='Active'
    API->>DB: INSERT INTO audit_events

    API-->>A: {certificate_pem, chain_pem}<br/>(NO private key in response)

    A->>A: Store cert.pem + chain.pem locally
    Note over A: key.pem stays on agent<br/>Never transmitted anywhere
    A->>A: Deploy to target system
```

### 3. Deploy Certificate to Target

The agent deploys certificates using target connectors. Each connector knows how to push certificates to a specific system:

- **NGINX**: Writes cert/chain files to disk, validates config with `nginx -t`, reloads with `nginx -s reload` or `systemctl reload nginx`
- **F5 BIG-IP**: Calls the F5 REST API to upload certificate and update virtual server bindings
- **IIS**: Uses WinRM to import the certificate into the Windows certificate store and bind it to an IIS site

The agent handles both the certificate (public) and the private key (local only). The control plane never sees the private key.

### 4. Automatic Renewal

The control plane runs a scheduler with four background loops:

```mermaid
flowchart LR
    subgraph "Scheduler (Background Goroutines)"
        R["Renewal Checker\n⏱ every 1h"]
        J["Job Processor\n⏱ every 30s"]
        H["Agent Health\n⏱ every 2m"]
        N["Notification Processor\n⏱ every 1m"]
    end

    R -->|"Find expiring certs\nCreate renewal jobs"| DB[("PostgreSQL")]
    J -->|"Process pending jobs\nCoordinate issuance"| DB
    H -->|"Check heartbeat staleness\nMark agents offline"| DB
    N -->|"Send pending notifications\nEmail / Webhook"| DB
```

| Loop | Interval | Purpose |
|------|----------|---------|
| Renewal checker | 1 hour | Finds certificates approaching expiry, creates renewal jobs |
| Job processor | 30 seconds | Processes pending jobs (issuance, renewal, deployment) |
| Agent health check | 2 minutes | Marks agents as offline if heartbeat is stale |
| Notification processor | 1 minute | Sends pending notifications via configured channels |

When the renewal checker finds a certificate within its renewal window (e.g., 30 days before expiry), it creates a renewal job. The job processor picks it up, coordinates with the issuer, and triggers deployment. All steps are logged in the audit trail and generate notifications.

## Connector Architecture

Certctl uses connector interfaces for extensibility. Each connector type has a standard interface that implementations must satisfy.

```mermaid
flowchart TB
    subgraph "Issuer Connectors"
        direction TB
        II["IssuerConnector Interface\nIssueCertificate() | RenewCertificate()\nRevokeCertificate() | GetOrderStatus()"]
        II --> LC["Local CA"]
        II --> ACME["ACME v2"]
        II --> VP["Vault PKI (future)"]
    end

    subgraph "Target Connectors"
        direction TB
        TI["TargetConnector Interface\nDeployCertificate()\nValidateDeployment()"]
        TI --> NG["NGINX"]
        TI --> F5["F5 BIG-IP"]
        TI --> IIS["IIS"]
    end

    subgraph "Notifier Connectors"
        direction TB
        NI["NotifierConnector Interface\nSendAlert() | SendEvent()"]
        NI --> EM["Email (SMTP)"]
        NI --> WH["Webhook (HTTP)"]
        NI --> SL["Slack (future)"]
    end
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
}
```

Built-in issuers: **Local CA** (self-signed, for development/demos) and **ACME** (Let's Encrypt, Sectigo, etc., in progress).

### Target Connector

Deploys certificates to infrastructure. Note: the interface does NOT include private keys — agents handle keys locally.

```go
type Connector interface {
    ValidateConfig(ctx context.Context, config json.RawMessage) error
    DeployCertificate(ctx context.Context, request DeploymentRequest) (*DeploymentResult, error)
    ValidateDeployment(ctx context.Context, request ValidationRequest) (*ValidationResult, error)
}
```

Built-in targets: **NGINX**, **F5 BIG-IP**, **IIS**.

### Notifier Connector

Sends alerts about certificate lifecycle events.

```go
type Connector interface {
    ValidateConfig(ctx context.Context, config json.RawMessage) error
    SendAlert(ctx context.Context, alert Alert) error
    SendEvent(ctx context.Context, event Event) error
}
```

Built-in notifiers: **Email** (SMTP) and **Webhook** (HTTP POST).

See the [Connector Development Guide](connectors.md) for details on building custom connectors.

## Security Model

### Private Key Management

```mermaid
flowchart LR
    subgraph "Agent (Your Infrastructure)"
        GEN["1. GENERATE\ncrypto/rsa 2048-bit"]
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

Private keys follow a strict lifecycle:

1. **Generated on the agent** — never sent to the control plane
2. **Stored on the agent** — file permissions 0600, owned by the agent process user
3. **Used by the agent** — for deployment to targets and CSR generation
4. **Rotated by the agent** — old keys deleted after successful renewal

The control plane only ever handles public material: certificates, chains, and CSRs. This is a deliberate architectural decision — even if the control plane database is compromised, no private keys are exposed.

### Authentication

- **API clients → Server**: API key in `Authorization: Bearer` header, or `none` for demo mode
- **Agent → Server**: API key registered at agent creation, included in all requests
- **Server → Issuers**: ACME account key, or connector-specific credentials
- **Agent → Targets**: SSH keys, API tokens, WinRM credentials (stored locally on agent)

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

Audit events cannot be modified or deleted. They support filtering by actor, action, resource type, resource ID, and time range.

## API Design

All endpoints are under `/api/v1/` and follow consistent patterns:

- **List**: `GET /api/v1/{resources}` — returns `{data: [...], total, page, per_page}`
- **Get**: `GET /api/v1/{resources}/{id}` — returns the resource
- **Create**: `POST /api/v1/{resources}` — returns the created resource with `201`
- **Update**: `PUT /api/v1/{resources}/{id}` — returns the updated resource
- **Delete**: `DELETE /api/v1/{resources}/{id}` — returns `204` (soft delete/archive)
- **Actions**: `POST /api/v1/{resources}/{id}/{action}` — returns `202` for async operations

Resources: certificates, issuers, targets, agents, jobs, policies, teams, owners, audit, notifications.

Health checks live outside the API prefix: `GET /health` and `GET /ready`.

## Deployment Topologies

### Docker Compose (Development / Small Deployments)

```mermaid
flowchart TB
    subgraph "Docker Network (certctl-network)"
        SERVER["certctl-server\n:8443\nAPI + Dashboard"]
        PG[("PostgreSQL\n:5432\nSchema + Seed Data")]
        AGENT["certctl-agent\nHeartbeat + Work Poll"]
    end

    USER["Browser / curl"] -->|"HTTP :8443"| SERVER
    SERVER -->|"SQL"| PG
    AGENT -->|"HTTP (internal)"| SERVER
```

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

## What's Next

- [Quick Start](quickstart.md) — Get certctl running locally
- [Advanced Demo](demo-advanced.md) — Issue a certificate end-to-end
- [Connector Guide](connectors.md) — Build custom connectors
