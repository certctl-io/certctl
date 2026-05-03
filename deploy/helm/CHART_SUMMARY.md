# Certctl Helm Chart - Complete Summary

## Overview

A production-ready Helm chart for deploying certctl (self-hosted certificate lifecycle management platform) on Kubernetes. The chart provides:

- High availability support with multi-replica deployments
- Persistent PostgreSQL database with automatic schema migration
- DaemonSet or Deployment-based agent deployment
- Comprehensive security contexts and RBAC
- Multiple deployment scenarios (dev, prod, HA, external DB)
- Full documentation and examples

## Chart Metadata

- **Name**: certctl
- **Chart Version**: 0.1.0
- **App Version**: 2.1.0
- **Type**: application
- **License**: BSL-1.1

## File Structure

```
deploy/helm/
├── README.md                              # Main Helm chart documentation
├── DEPLOYMENT_GUIDE.md                    # Step-by-step deployment guide
├── CHART_SUMMARY.md                       # This file
│
├── certctl/
│   ├── Chart.yaml                         # Chart metadata
│   ├── values.yaml                        # Default configuration values
│   ├── .helmignore                        # Files to ignore when building chart
│   │
│   └── templates/
│       ├── _helpers.tpl                   # Helm template helper functions
│       ├── NOTES.txt                      # Post-deployment notes
│       │
│       ├── server-deployment.yaml         # Certctl API server deployment
│       ├── server-service.yaml            # Server Kubernetes service
│       ├── server-configmap.yaml          # Server configuration
│       ├── server-secret.yaml             # Server secrets (API key, DB password, etc)
│       │
│       ├── postgres-statefulset.yaml      # PostgreSQL database statefulset
│       ├── postgres-service.yaml          # PostgreSQL headless service
│       ├── postgres-secret.yaml           # Database credentials secret
│       │
│       ├── agent-daemonset.yaml           # Certctl agent daemonset/deployment
│       ├── agent-configmap.yaml           # Agent configuration
│       │
│       ├── ingress.yaml                   # Optional ingress resource
│       └── serviceaccount.yaml            # ServiceAccount and RBAC
│
└── examples/
    ├── values-dev.yaml                    # Development/testing configuration
    ├── values-prod-ha.yaml                # Production HA configuration
    ├── values-external-db.yaml            # External PostgreSQL (RDS, Cloud SQL)
    └── values-acme-dns01.yaml             # ACME with DNS-01 (Let's Encrypt)
```

## Key Components

### 1. Server Deployment

**File**: `templates/server-deployment.yaml`

- Manages certctl API server instances
- Configurable replicas (default: 1)
- Health checks (liveness & readiness probes)
- Security context: non-root user, read-only filesystem
- Resource limits (default: 500m CPU, 512Mi memory)
- Automatic restart on failure

**Values**:
```yaml
server:
  replicas: 1
  port: 8443
  auth:
    type: api-key
    apiKey: "REQUIRED"
  resources:
    requests: {cpu: 100m, memory: 128Mi}
    limits: {cpu: 500m, memory: 512Mi}
```

### 2. PostgreSQL StatefulSet

**File**: `templates/postgres-statefulset.yaml`

- Persistent database storage
- Automatic schema migrations on startup
- Single replica (can be extended with external HA tools)
- Health checks via pg_isready
- Configurable storage size and class
- Security context: non-root user (UID 999)

**Values**:
```yaml
postgresql:
  enabled: true
  storage:
    size: 10Gi
    storageClass: ""  # Use default
  auth:
    database: certctl
    username: certctl
    password: "REQUIRED"
```

### 3. Agent DaemonSet/Deployment

**File**: `templates/agent-daemonset.yaml`

- DaemonSet mode: one agent per Kubernetes node
- Deployment mode: custom number of agent replicas
- Local key storage with secure permissions (0600)
- Health checks and automatic restart
- Optional certificate discovery from filesystem

**Values**:
```yaml
agent:
  enabled: true
  kind: DaemonSet  # or Deployment
  replicas: 1      # for Deployment only
  keyDir: /var/lib/certctl/keys
  discoveryDirs: "/etc/ssl/certs"  # optional
```

### 4. Ingress (Optional)

**File**: `templates/ingress.yaml`

- Optional HTTPS ingress
- cert-manager integration for automatic TLS
- Multiple host support
- Path-based routing

**Values**:
```yaml
ingress:
  enabled: false
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: certctl.example.com
      paths:
        - path: /
          pathType: Prefix
```

### 5. ConfigMaps and Secrets

**Files**:
- `server-configmap.yaml` - Non-secret server configuration
- `server-secret.yaml` - API key, database URL, SMTP password
- `postgres-secret.yaml` - Database credentials
- `agent-configmap.yaml` - Agent configuration

All secrets are base64-encoded and stored in Kubernetes Secrets.

### 6. ServiceAccount and RBAC

**File**: `templates/serviceaccount.yaml`

- Optional ServiceAccount creation
- Optional RBAC (ClusterRole, ClusterRoleBinding)
- Namespace-scoped by default

## Deployment Scenarios

### Development Setup

Use `examples/values-dev.yaml`:

```bash
helm install certctl certctl/ \
  --values examples/values-dev.yaml \
  --set server.auth.apiKey="dev-key" \
  --set postgresql.auth.password="dev-password"
```

**Features**:
- Single server replica
- Demo auth (no API key required)
- Small database (5Gi)
- LoadBalancer service for easy access
- Debug logging level

### Production HA Setup

Use `examples/values-prod-ha.yaml`:

```bash
helm install certctl certctl/ \
  --values examples/values-prod-ha.yaml \
  --set server.auth.apiKey="$(openssl rand -base64 32)" \
  --set postgresql.auth.password="$(openssl rand -base64 32)"
```

**Features**:
- 3 server replicas with pod anti-affinity
- Large database storage (100Gi)
- Pod disruption budgets
- Prometheus monitoring enabled
- Production resource limits

### External PostgreSQL

Use `examples/values-external-db.yaml`:

```bash
helm install certctl certctl/ \
  --values examples/values-external-db.yaml \
  --set postgresql.enabled=false \
  --set 'server.env.CERTCTL_DATABASE_URL=postgres://...'
```

**Use cases**:
- AWS RDS
- Google Cloud SQL
- Azure Database for PostgreSQL
- External self-managed PostgreSQL

### ACME with DNS-01

Use `examples/values-acme-dns01.yaml`:

```bash
helm install certctl certctl/ \
  --values examples/values-acme-dns01.yaml
```

**Enables**:
- Automatic certificate issuance from Let's Encrypt
- DNS-01 challenge (wildcard support)
- Custom DNS provider scripts

## Configuration Options

### Server Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `server.replicas` | 1 | Number of server replicas |
| `server.port` | 8443 | Server port |
| `server.auth.type` | api-key | Authentication type — `api-key` or `none` (G-1: `jwt` removed; for JWT/OIDC use a fronting authenticating gateway, see `docs/architecture.md` and `docs/upgrade-to-v2-jwt-removal.md`) |
| `server.auth.apiKey` | "" | API key (REQUIRED when `auth.type=api-key`) |
| `server.logging.level` | info | Log level |
| `server.logging.format` | json | Log format |

### PostgreSQL Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `postgresql.enabled` | true | Enable internal PostgreSQL |
| `postgresql.storage.size` | 10Gi | Database storage size |
| `postgresql.storage.storageClass` | "" | Storage class name |
| `postgresql.auth.password` | "" | Database password (REQUIRED) |

### Agent Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `agent.enabled` | true | Deploy agents |
| `agent.kind` | DaemonSet | DaemonSet or Deployment |
| `agent.replicas` | 1 | Replicas (Deployment only) |
| `agent.keyDir` | /var/lib/certctl/keys | Key storage directory |

### Issuer Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `server.issuer.local.enabled` | true | Enable Local CA |
| `server.issuer.acme.enabled` | false | Enable ACME |
| `server.issuer.acme.directoryURL` | "" | ACME directory URL |
| `server.issuer.acme.email` | "" | ACME email |
| `server.issuer.acme.challengeType` | http-01 | Challenge type |

See `values.yaml` for complete configuration options.

## Helm Template Functions

Defined in `templates/_helpers.tpl`:

| Function | Purpose |
|----------|---------|
| `certctl.name` | Chart name |
| `certctl.fullname` | Full release name |
| `certctl.chart` | Chart name and version |
| `certctl.labels` | Common labels |
| `certctl.selectorLabels` | Selector labels |
| `certctl.serverSelectorLabels` | Server selector labels |
| `certctl.agentSelectorLabels` | Agent selector labels |
| `certctl.postgresSelectorLabels` | PostgreSQL selector labels |
| `certctl.serviceAccountName` | ServiceAccount name |
| `certctl.serverImage` | Server image URI |
| `certctl.agentImage` | Agent image URI |
| `certctl.postgresImage` | PostgreSQL image URI |
| `certctl.databaseURL` | Database connection string |
| `certctl.serverURL` | Server URL for agents |

## Security Features

### Pod Security

- Non-root users (UID 1000 for app, UID 999 for PostgreSQL)
- Read-only root filesystems
- No privilege escalation
- Dropped capabilities (ALL)
- Resource limits to prevent DoS

### Secrets Management

- All sensitive data in Kubernetes Secrets
- Base64 encoded at rest
- Can be integrated with:
  - sealed-secrets
  - external-secrets
  - Vault
  - AWS Secrets Manager

### RBAC

- ServiceAccount per release
- Optional ClusterRole/ClusterRoleBinding
- Extensible for custom permissions

### Network Security

- Support for Kubernetes NetworkPolicies
- Service-to-service communication via internal DNS
- Optional Ingress with TLS

## Monitoring and Observability

### Health Checks

- Liveness probes (detect dead containers)
- Readiness probes (detect not-ready services)
- HTTP endpoints: `/health`, `/readyz`

### Logging

- Structured JSON logging
- Request ID propagation
- Configurable log levels (debug, info, warn, error)

### Metrics

- Prometheus metrics endpoint: `/api/v1/metrics/prometheus`
- Optional ServiceMonitor for Prometheus Operator
- Built-in metrics:
  - Certificate counts by status
  - Agent counts and status
  - Job completion/failure rates
  - Server uptime

## Installation Quick Reference

```bash
# Development
helm install certctl certctl/ \
  --set server.auth.apiKey=dev \
  --set postgresql.auth.password=dev

# Production HA
helm install certctl certctl/ \
  --values examples/values-prod-ha.yaml \
  --set server.auth.apiKey="$(openssl rand -base64 32)" \
  --set postgresql.auth.password="$(openssl rand -base64 32)"

# External database
helm install certctl certctl/ \
  --values examples/values-external-db.yaml \
  --set postgresql.enabled=false \
  --set 'server.env.CERTCTL_DATABASE_URL=postgres://...'

# ACME with Let's Encrypt
helm install certctl certctl/ \
  --set server.issuer.acme.enabled=true \
  --set server.issuer.acme.directoryURL=https://acme-v02.api.letsencrypt.org/directory

# Check status
kubectl get pods -l app.kubernetes.io/instance=certctl
kubectl logs -l app.kubernetes.io/component=server -f

# Upgrade
helm upgrade certctl certctl/ -f new-values.yaml

# Uninstall
helm uninstall certctl
```

## Best Practices

### 1. Use Secrets Management

```bash
# Use sealed-secrets
kubectl create secret generic certctl-secrets \
  --from-literal=api-key="$(openssl rand -base64 32)" \
  --dry-run=client -o yaml | kubeseal -f - | kubectl apply -f -
```

### 2. Configure Resource Limits

Match limits to your cluster capacity:

```yaml
server:
  resources:
    requests: {cpu: 250m, memory: 256Mi}
    limits: {cpu: 1000m, memory: 512Mi}
```

### 3. Enable HA for Production

```yaml
server:
  replicas: 3
podAntiAffinity:
  requiredDuringSchedulingIgnoredDuringExecution: [...]
```

### 4. Use Persistent Storage

```yaml
postgresql:
  storage:
    size: 100Gi
    storageClass: fast-ssd
```

### 5. Enable Monitoring

```yaml
monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
```

## Documentation

- **README.md** - Complete Helm chart documentation
- **DEPLOYMENT_GUIDE.md** - Step-by-step deployment instructions
- **values.yaml** - Commented configuration reference

## Support

For issues, questions, or contributions:
- GitHub: https://github.com/certctl-io/certctl
- Documentation: https://github.com/certctl-io/certctl/tree/main/docs

## License

BSL-1.1 (Business Source License)
