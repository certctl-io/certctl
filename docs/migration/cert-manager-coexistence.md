# certctl for cert-manager Users

> Last reviewed: 2026-05-05

You run cert-manager inside Kubernetes and it works well for in-cluster certificates. But you also have VMs, bare-metal servers, network appliances, and legacy systems outside the cluster. cert-manager can't reach those. This guide shows how certctl complements cert-manager to give you unified certificate visibility and automation across your entire infrastructure.

## Not a Replacement

cert-manager is the right tool for in-cluster certs. It's tightly integrated with Kubernetes:
- Native CRDs (Certificate, ClusterIssuer, Issuer)
- Automatic cert injection into Ingress and Service objects
- Controller-driven renewal within the cluster

**certctl does not replace this.** Instead, it extends your certificate management to everything outside Kubernetes: VMs, bare metal, network appliances, Windows servers, and legacy systems.

## The Problem

Your setup:
- **cert-manager**: handles all certs in Kubernetes (TLS for Ingress, service-to-service, internal services)
- **Everything else**: NGINX/Apache on VMs, HAProxy load balancers on bare metal, network appliances, Windows servers with IIS — these are managed inconsistently. Maybe Certbot cron jobs, maybe manual renewal, maybe deprecated cert files sitting around.

Result:
- No unified visibility — you don't know when non-Kubernetes certs expire
- Renewal failures go unnoticed until the cert is already expired
- Audit trail fragmented across multiple tools
- Scaling to hundreds of machines becomes impossible

## The Solution

Deploy certctl control plane once (Docker Compose, Kubernetes Helm chart, or self-hosted). Deploy agents on your VMs, bare metal, and network appliances. One dashboard shows:
- **All cert-manager certs** via discovery scanning (agents find cert-manager-issued certs copied to target machines, or scan the cluster directly)
- **All certctl-managed certs** issued by shared issuers (ACME, step-ca, Vault PKI (planned), private CA)
- **Unified renewal and deployment** across both worlds
- **Single pane of glass** with expiration timeline, renewal status, deployment verification, audit trail

## How to Set Up

### 1. Install certctl Control Plane

**Option A: Docker Compose** (quickest for evaluation)
```bash
cd /opt/certctl
docker compose up -d
# Dashboard & API: https://localhost:8443 (self-signed cert — pin with --cacert ./deploy/test/certs/ca.crt)
```

**Option B: Kubernetes** (recommended for prod)
```bash
helm install certctl deploy/helm/certctl/ \
  --set auth.apiKey=YOUR_SECURE_KEY
```

### 2. Deploy Agents to Non-Kubernetes Infrastructure

On each VM, bare-metal server, or appliance (via proxy agent):
```bash
# Linux amd64
curl -sSL https://github.com/certctl-io/certctl/releases/download/v2.1.0/certctl-agent-linux-amd64 \
  -o /usr/local/bin/certctl-agent
chmod +x /usr/local/bin/certctl-agent

# Config
sudo tee /etc/certctl/agent.env > /dev/null <<EOF
CERTCTL_SERVER_URL=https://certctl-control-plane:8443
CERTCTL_SERVER_CA_BUNDLE_PATH=/etc/certctl/tls/ca.crt
CERTCTL_API_KEY=your-api-key
CERTCTL_DISCOVERY_DIRS=/etc/nginx/certs,/etc/ssl,/etc/letsencrypt/live
CERTCTL_KEY_DIR=/var/lib/certctl/keys
EOF
sudo chmod 600 /etc/certctl/agent.env

# Start
sudo systemctl start certctl-agent
```

### 3. Enable Discovery Scanning

Agents scan configured directories and report back all existing certs. In the dashboard:
- **Discovery** page: all found certs grouped by agent
- Claim cert-manager certs to link them with Kubernetes metadata
- Dismiss obsolete certs

### 4. Configure Shared Issuers

Set up the same issuer certctl uses for non-Kubernetes certs:
- **ACME** (Let's Encrypt, for public certs)
- **step-ca** (Smallstep, for internal certs)
- **Vault PKI** (HashiCorp Vault, for enterprise PKI)
- **Private CA** (your own internal root CA)

No new CA infrastructure needed. If cert-manager already uses your CA, certctl points to the same one.

### 5. Create Policies for Non-Kubernetes Certs

Go to **Policies** → **+ New Policy** to create enforcement rules:
- **Name:** e.g., "VM Certificate Policy"
- **Type:** `expiration_window` or `key_algorithm` (enforce renewal thresholds or crypto requirements)
- **Severity:** `high`
- **Config:** set your enforcement parameters

Certificates are linked to issuers and profiles when created or claimed from discovery. Policies add guardrails — enforcing key algorithm requirements, expiration windows, and other compliance rules across your fleet.

### 6. View Unified Inventory

**Dashboard** shows:
- Certificate status heatmap (all 1000 certs: cert-manager + certctl)
- Renewal job trends (both types)
- Expiration timeline (30/60/90 days)
- Agent fleet status (all infrastructure)

**Certificates** page filters by issuer (show me all ACME certs, or all step-ca certs):
- cert-manager certs discovered from Kubernetes nodes
- certctl-managed certs on VMs
- Network appliance certs auto-discovered

## Shared Infrastructure

If cert-manager and certctl both use the same CA:
- **ACME**: cert-manager uses ClusterIssuer + certctl uses ACME connector → same Let's Encrypt account, transparent coexistence
- **step-ca**: cert-manager uses external issuer CRD + certctl uses step-ca connector → same provisioner, shared certificate inventory
- **Vault PKI**: cert-manager uses external issuer CRD + certctl uses Vault connector → same mount, same audit trail

No conflict. They just issue certs through the same CA. certctl's discovery scanning finds cert-manager-issued certs and shows them alongside certctl-managed ones.

## Key Differences from cert-manager

| Feature | cert-manager | certctl |
|---------|--------------|---------|
| Target | In-cluster (Kubernetes) | Out-of-cluster (VMs, bare metal, appliances) |
| Configuration | CRDs (Certificate, ClusterIssuer, Issuer) | API + Dashboard (JSON REST) |
| Deployment | Injected into Secret objects, mounted by pods | Agent pulls work, deploys via target-specific API (file, service restart, proxy agent) |
| Renewal | Controller watches Certificate CRDs, triggers renewal when needed | Scheduler checks thresholds, agents poll for work |
| Audit | Kubernetes event log | Immutable append-only audit trail |
| Visibility | Per-namespace, per-resource | Fleet-wide, unified inventory |

## Future Integration

On the roadmap (V4): **cert-manager external issuer** — certctl acts as a ClusterIssuer backend for Kubernetes. This would allow cert-manager to request certificates from certctl, which could issue them via any of its connectors (step-ca, Vault, private CA, etc.). Pure integration play; no breaking changes.

For now: cert-manager handles Kubernetes, certctl handles everything else. They coexist seamlessly.

## Next Steps

1. Run through the [Quick Start](../getting-started/quickstart.md) for a 5-minute demo
2. Try the [Multi-Issuer example](../examples/multi-issuer/multi-issuer.md) — manages public and internal certs from one dashboard
3. Explore [Architecture](../reference/architecture.md#agents) for deployment patterns
4. Check the [Helm Chart](../deploy/helm/certctl/) for production Kubernetes deployment
