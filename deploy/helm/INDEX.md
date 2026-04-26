# Certctl Helm Chart - Complete File Index

## Navigation Guide

### Getting Started

1. **Start here**: `INSTALLATION.md` - Quick installation guide with one-liners
2. **Full reference**: `README.md` - Complete Helm chart documentation
3. **Detailed guide**: `DEPLOYMENT_GUIDE.md` - Step-by-step deployment walkthrough
4. **Architecture**: `CHART_SUMMARY.md` - Technical overview and design

### Chart Directory Structure

```
deploy/helm/
│
├── README.md                           Main documentation (15 KB)
├── DEPLOYMENT_GUIDE.md                 Step-by-step guide (12 KB)
├── CHART_SUMMARY.md                    Architecture & design (13 KB)
├── INSTALLATION.md                     Quick start (2.2 KB)
├── INDEX.md                            This file
│
├── certctl/                            Helm chart package
│   ├── Chart.yaml                      Chart metadata
│   ├── values.yaml                     Default configuration (11 KB)
│   ├── .helmignore                     Build ignore patterns
│   │
│   └── templates/                      15 Kubernetes resource templates
│       ├── _helpers.tpl                Helper functions
│       ├── NOTES.txt                   Post-install notes
│       ├── server-deployment.yaml      API server
│       ├── server-service.yaml         Server networking
│       ├── server-configmap.yaml       Server configuration
│       ├── server-secret.yaml          Server secrets
│       ├── postgres-statefulset.yaml   Database
│       ├── postgres-service.yaml       Database networking
│       ├── postgres-secret.yaml        Database secrets
│       ├── agent-daemonset.yaml        Agents (DaemonSet/Deployment)
│       ├── agent-configmap.yaml        Agent configuration
│       ├── ingress.yaml                Optional HTTPS ingress
│       └── serviceaccount.yaml         RBAC resources
│
└── examples/                           Example configurations
    ├── values-dev.yaml                 Development setup
    ├── values-prod-ha.yaml             Production HA setup
    ├── values-external-db.yaml         External PostgreSQL
    └── values-acme-dns01.yaml          ACME DNS-01 configuration
```

## File Descriptions

### Documentation Files

| File | Purpose | Size |
|------|---------|------|
| `README.md` | Complete Helm chart documentation, configuration reference, security considerations | 15 KB |
| `DEPLOYMENT_GUIDE.md` | Step-by-step installation instructions, production setup, troubleshooting | 12 KB |
| `CHART_SUMMARY.md` | Technical overview, architecture, features, best practices | 13 KB |
| `INSTALLATION.md` | Quick start guide, one-liner commands, verification steps | 2.2 KB |
| `INDEX.md` | This file - complete file index and navigation | - |

### Chart Files

| File | Purpose |
|------|---------|
| `Chart.yaml` | Helm chart metadata (name, version, appVersion, license) |
| `values.yaml` | Default configuration values with comprehensive comments |
| `.helmignore` | Files to ignore when building the chart |

### Template Files

| File | Components Created |
|------|-------------------|
| `_helpers.tpl` | 14 Helm template helper functions |
| `NOTES.txt` | Post-installation notes and instructions |
| `server-deployment.yaml` | Certctl API server deployment (1-N replicas) |
| `server-service.yaml` | Service exposing the server |
| `server-configmap.yaml` | Non-secret server configuration |
| `server-secret.yaml` | Secrets (API key, DB password, SMTP) |
| `postgres-statefulset.yaml` | PostgreSQL database with persistent storage |
| `postgres-service.yaml` | Headless service for PostgreSQL |
| `postgres-secret.yaml` | Database credentials |
| `agent-daemonset.yaml` | Certctl agents (DaemonSet or Deployment) |
| `agent-configmap.yaml` | Agent configuration |
| `ingress.yaml` | Optional HTTPS ingress resource |
| `serviceaccount.yaml` | ServiceAccount and RBAC resources |

### Example Configuration Files

| File | Use Case | Features |
|------|----------|----------|
| `values-dev.yaml` | Development/testing | Single replica, debug logging, LoadBalancer, no auth |
| `values-prod-ha.yaml` | Production HA | 3 replicas, pod anti-affinity, monitoring, large storage |
| `values-external-db.yaml` | External PostgreSQL | AWS RDS, Cloud SQL, Azure Database, self-managed |
| `values-acme-dns01.yaml` | Let's Encrypt | DNS-01 challenges, wildcard certs, custom DNS scripts |

## Quick Links

### Installation Commands

#### Development
```bash
helm install certctl certctl/ \
  --set server.auth.type=none \
  --set postgresql.auth.password=dev
```

#### Production HA
```bash
helm install certctl certctl/ \
  --values examples/values-prod-ha.yaml \
  --set server.auth.apiKey="$(openssl rand -base64 32)" \
  --set postgresql.auth.password="$(openssl rand -base64 32)"
```

#### External Database
```bash
helm install certctl certctl/ \
  --values examples/values-external-db.yaml \
  --set postgresql.enabled=false \
  --set 'server.env.CERTCTL_DATABASE_URL=postgres://...'
```

### Verification Commands

```bash
# Check chart syntax
helm lint certctl/
helm template certctl certctl/

# Install in cluster
helm install certctl certctl/
helm status certctl

# Check pod status
kubectl get pods -l app.kubernetes.io/instance=certctl

# View logs
kubectl logs -l app.kubernetes.io/component=server -f
```

## Documentation Organization

### By User Role

**DevOps/Platform Engineers**
- Start: `INSTALLATION.md`
- Deep dive: `DEPLOYMENT_GUIDE.md`
- Configuration reference: `README.md`

**Kubernetes Developers**
- Architecture: `CHART_SUMMARY.md`
- Configuration: `values.yaml`
- Templates: `templates/`

**Security/SREs**
- Security section: `README.md#security-considerations`
- RBAC: `templates/serviceaccount.yaml`
- Network policies: `DEPLOYMENT_GUIDE.md#network-policies`

**Database Administrators**
- PostgreSQL config: `values.yaml` (postgresql section)
- External DB setup: `examples/values-external-db.yaml`
- Backup/restore: `DEPLOYMENT_GUIDE.md#backup-and-restore`

### By Task

**Getting Started**
1. Read: `INSTALLATION.md`
2. Install: `helm install certctl certctl/`
3. Verify: Run commands in `INSTALLATION.md`

**Production Deployment**
1. Read: `DEPLOYMENT_GUIDE.md`
2. Choose: `examples/values-prod-ha.yaml`
3. Deploy: Follow step-by-step guide
4. Reference: `README.md` for detailed options

**Troubleshooting**
- Common issues: `README.md#troubleshooting`
- Detailed guide: `DEPLOYMENT_GUIDE.md#troubleshooting`
- Error messages: kubectl logs and events

**Configuration**
- All options: `values.yaml`
- Examples: `examples/values-*.yaml`
- Detailed docs: `README.md#configuration`

## Key Features

### High Availability
- Multi-replica server deployment
- Pod anti-affinity
- StatefulSet for database
- Pod disruption budgets

### Security
- Non-root containers
- Read-only filesystems
- RBAC support
- Kubernetes Secrets
- Network policies

### Flexibility
- Multiple issuers (Local CA, ACME, step-ca, OpenSSL)
- Internal or external PostgreSQL
- DaemonSet or Deployment agents
- Optional Ingress with TLS
- Email notifications

### Observability
- Health checks
- Structured logging
- Prometheus metrics
- ServiceMonitor support

## Support

- **GitHub**: https://github.com/shankar0123/certctl
- **Issues**: Report on GitHub issues
- **Documentation**: All docs are in `deploy/helm/`

## File Statistics

- **Total files**: 24
- **Documentation**: 4 files (42 KB)
- **Chart files**: 3 files
- **Templates**: 13 files
- **Examples**: 4 files
- **Total size**: 144 KB

## License

All files are covered under the BSL-1.1 license.
