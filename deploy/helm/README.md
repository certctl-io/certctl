# Certctl Helm Chart

Production-ready Helm chart for deploying certctl (self-hosted certificate lifecycle management platform) on Kubernetes.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Chart Features](#chart-features)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Usage Examples](#usage-examples)
7. [Upgrading](#upgrading)
8. [Uninstalling](#uninstalling)
9. [Architecture](#architecture)
10. [Security Considerations](#security-considerations)
11. [Troubleshooting](#troubleshooting)

## Quick Start

```bash
# Add the chart repository (when available)
helm repo add certctl https://charts.example.com
helm repo update

# Install with default values
helm install certctl certctl/certctl \
  --set server.auth.apiKey="your-secure-api-key" \
  --set postgresql.auth.password="your-secure-password"

# Check installation status
kubectl get pods -l app.kubernetes.io/instance=certctl
```

## Chart Features

- **Server Deployment** — certctl control plane with configurable replicas
- **PostgreSQL StatefulSet** — Persistent database with automatic schema migration
- **Agent DaemonSet or Deployment** — Flexible agent deployment (per-node or custom replicas)
- **Ingress Support** — Optional HTTPS ingress with cert-manager integration
- **Security Contexts** — Non-root containers, read-only filesystems, minimal capabilities
- **Resource Limits** — Configurable CPU and memory requests/limits
- **Health Checks** — Liveness and readiness probes on all containers
- **ConfigMaps and Secrets** — Centralized configuration management
- **Service Account and RBAC** — Optional cluster role bindings
- **Pod Disruption Budgets** — HA-ready with configurable disruption budgets
- **Monitoring** — Optional Prometheus ServiceMonitor support

## Prerequisites

- Kubernetes 1.19 or later
- Helm 3.0 or later
- Optional: cert-manager (for automatic TLS certificate provisioning)
- Optional: Prometheus (for metrics scraping)

## Installation

### 1. Using Chart from Repository

```bash
helm repo add certctl https://charts.example.com
helm repo update
helm install certctl certctl/certctl -f my-values.yaml
```

### 2. Using Local Chart

```bash
cd deploy/helm
helm install certctl certctl/ \
  --set server.auth.apiKey="$(openssl rand -base64 32)" \
  --set postgresql.auth.password="$(openssl rand -base64 32)"
```

### 3. Minimal Production Installation

```bash
helm install certctl certctl/certctl \
  --namespace certctl \
  --create-namespace \
  --set server.auth.apiKey="change-me" \
  --set postgresql.auth.password="change-me" \
  --set server.replicas=2 \
  --set server.resources.requests.cpu=200m \
  --set server.resources.requests.memory=256Mi \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set ingress.hosts[0].host=certctl.example.com
```

## Configuration

### Server Configuration

```yaml
server:
  replicas: 1                    # Number of server replicas
  port: 8443                     # Service port
  auth:
    type: api-key               # Authentication type
    apiKey: "your-api-key"      # REQUIRED for production
  logging:
    level: info                 # Log level (debug, info, warn, error)
    format: json                # Output format
  issuer:
    local:
      enabled: true             # Enable local CA issuer
    acme:
      enabled: false            # Enable ACME issuer
      directoryURL: ""          # ACME directory URL
      email: ""                 # ACME registration email
      challengeType: "http-01"  # Challenge type (http-01, dns-01, dns-persist-01)
```

### PostgreSQL Configuration

```yaml
postgresql:
  enabled: true                 # Use managed PostgreSQL
  auth:
    database: certctl
    username: certctl
    password: "your-password"   # REQUIRED
  storage:
    size: 10Gi                  # PVC size
    storageClass: ""            # Use default StorageClass
```

### Agent Configuration

```yaml
agent:
  enabled: true                 # Deploy agents
  kind: DaemonSet              # DaemonSet (one per node) or Deployment
  replicas: 1                  # For Deployment kind only
  discoveryDirs: ""            # Comma-separated cert discovery paths
  nodeSelector: {}             # Node affinity for DaemonSet
```

### Ingress Configuration

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
  tls:
    - secretName: certctl-tls
      hosts:
        - certctl.example.com
```

See `values.yaml` for all available configuration options.

## Usage Examples

### Example 1: High Availability Setup

```yaml
# ha-values.yaml
server:
  replicas: 3
  resources:
    requests:
      cpu: 250m
      memory: 256Mi
    limits:
      cpu: 1000m
      memory: 512Mi

postgresql:
  storage:
    size: 50Gi

podAntiAffinity:
  requiredDuringSchedulingIgnoredDuringExecution:
    - labelSelector:
        matchExpressions:
          - key: app.kubernetes.io/component
            operator: In
            values: [server]
      topologyKey: kubernetes.io/hostname
```

Deploy with:
```bash
helm install certctl certctl/certctl -f ha-values.yaml
```

### Example 2: External PostgreSQL Database

```yaml
# external-db-values.yaml
postgresql:
  enabled: false

server:
  env:
    CERTCTL_DATABASE_URL: "postgres://user:password@rds.example.com:5432/certctl?sslmode=require"
```

Deploy with:
```bash
helm install certctl certctl/certctl -f external-db-values.yaml
```

### Example 3: ACME + Let's Encrypt

```yaml
# acme-values.yaml
server:
  issuer:
    acme:
      enabled: true
      directoryURL: https://acme-v02.api.letsencrypt.org/directory
      email: admin@example.com
      challengeType: dns-01
      dnsPresentScript: /scripts/dns-present.sh
      dnsCleanupScript: /scripts/dns-cleanup.sh
      dnsPropagationWait: 30s
```

### Example 4: Email Notifications via Slack + SMTP

```yaml
# notifications-values.yaml
server:
  smtp:
    enabled: true
    host: smtp.example.com
    port: 587
    username: certctl@example.com
    password: "smtp-password"
    fromAddress: certctl@example.com
    useTLS: true

  notifiers:
    slack:
      enabled: true
      webhookUrl: https://hooks.slack.com/services/YOUR/WEBHOOK/URL
      channel: "#certificates"
```

## Upgrading

```bash
# Update chart repository
helm repo update

# Upgrade release
helm upgrade certctl certctl/certctl -f values.yaml

# View upgrade history
helm history certctl

# Rollback to previous version
helm rollback certctl 1
```

## Uninstalling

```bash
# Delete the release (keeps data by default)
helm uninstall certctl

# Also delete persistent data
kubectl delete pvc --all -l app.kubernetes.io/instance=certctl

# Delete namespace
kubectl delete namespace certctl
```

## Architecture

### Components

```
┌──────────────────────────────────────────────────────────────┐
│ Kubernetes Cluster                                           │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────┐                 ┌──────────────────┐  │
│  │ Ingress/LB      │                 │  Agent Pod 1     │  │
│  │ (optional)      │                 │  (DaemonSet)     │  │
│  └────────┬────────┘                 └──────────────────┘  │
│           │                                                  │
│           ▼                           ┌──────────────────┐  │
│  ┌─────────────────────────┐          │  Agent Pod 2     │  │
│  │ Server Deployment       │          │  (DaemonSet)     │  │
│  │ (1 to N replicas)       │          └──────────────────┘  │
│  │ - REST API              │                                 │
│  │ - Scheduler             │          ┌──────────────────┐  │
│  │ - UI Dashboard          │          │  Agent Pod N     │  │
│  └────────┬────────────────┘          │  (DaemonSet)     │  │
│           │                           └──────────────────┘  │
│           │                                                  │
│           ▼                                                  │
│  ┌──────────────────────────┐                               │
│  │ PostgreSQL StatefulSet   │                               │
│  │ - Database               │                               │
│  │ - PVC (persistent)       │                               │
│  └──────────────────────────┘                               │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Network Communication

- **Server → PostgreSQL**: Internal cluster DNS (`certctl-postgres:5432`)
- **Agent → Server**: Internal cluster DNS (`certctl-server:8443`)
- **External → Server**: Via Ingress or Service (ClusterIP/LoadBalancer/NodePort)

## Security Considerations

### 1. Secrets Management

All sensitive data is stored in Kubernetes Secrets:
- PostgreSQL credentials
- API keys
- SMTP passwords
- ACME account secrets

**Best Practices:**
- Use sealed-secrets or external-secrets operator
- Enable encryption at rest in etcd
- Rotate secrets regularly

```bash
# Example: Using sealed-secrets
kubectl create secret generic certctl-api-key --from-literal=api-key="$(openssl rand -base64 32)" --dry-run=client -o yaml | kubeseal -f - | kubectl apply -f -
```

### 2. RBAC

The chart creates minimal RBAC by default:
- ServiceAccount per release
- ClusterRole (empty, extensible)
- ClusterRoleBinding

**To restrict further:**
```yaml
rbac:
  create: true
  # Add specific rules here
```

### 3. Pod Security

All containers run with:
- Non-root user (UID 1000)
- Read-only root filesystem
- No privilege escalation
- Dropped capabilities (ALL)

### 4. Network Policies

Restrict pod-to-pod communication:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: certctl-default-deny
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/instance: certctl
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: certctl
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: certctl
    - to:
        - podSelector: {}
      ports:
        - protocol: TCP
          port: 53  # DNS
        - protocol: UDP
          port: 53
```

### 5. TLS/HTTPS

Enable HTTPS with cert-manager:

```bash
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set installCRDs=true
```

Then configure Ingress with TLS.

### 6. API Key Security

For production:
1. Generate a strong API key: `openssl rand -base64 32`
2. Store securely (Vault, sealed-secrets, etc.)
3. Never commit to Git
4. Rotate periodically

```bash
# Generate and deploy API key
NEW_KEY=$(openssl rand -base64 32)
kubectl patch secret certctl-server -p "{\"data\":{\"api-key\":\"$(echo -n $NEW_KEY | base64)\"}}"
```

## Troubleshooting

### 1. Pods Not Starting

```bash
# Check pod status
kubectl get pods -l app.kubernetes.io/instance=certctl
kubectl describe pod <pod-name>
kubectl logs <pod-name>
```

### 2. Database Connection Issues

```bash
# Verify PostgreSQL is running
kubectl get pods -l app.kubernetes.io/component=postgres
kubectl logs -l app.kubernetes.io/component=postgres

# Test connection from server pod
kubectl exec -it <server-pod> -- \
  psql postgres://certctl:password@certctl-postgres:5432/certctl
```

### 3. Agent Not Connecting

```bash
# Check agent logs
kubectl logs -l app.kubernetes.io/component=agent

# Verify server is reachable
kubectl exec -it <agent-pod> -- \
  wget -q -O - http://certctl-server:8443/health
```

### 4. Persistent Data Loss

```bash
# Check PVC status
kubectl get pvc

# Verify data is being stored
kubectl exec -it <postgres-pod> -- \
  ls -lah /var/lib/postgresql/data/postgres
```

### 5. Permission Denied Errors

The chart runs containers as non-root (UID 1000). If you see permission errors:

```yaml
# Temporarily allow root for debugging
server:
  securityContext:
    runAsUser: 0  # NOT FOR PRODUCTION
```

### 6. Out of Memory

Increase resource limits:

```bash
helm upgrade certctl certctl/certctl \
  --set server.resources.limits.memory=1Gi \
  --set postgresql.resources.limits.memory=2Gi
```

### 7. Certificate Validation Issues

For self-signed certificates:

```bash
kubectl exec -it <pod> -- \
  CERTCTL_TLS_INSECURE_SKIP_VERIFY=true <command>
```

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| `ImagePullBackOff` | Update `server.image.repository` to your registry |
| `CrashLoopBackOff` | Check logs with `kubectl logs <pod>` |
| `Pending` PVC | Check storage class availability |
| Connection timeout | Verify network policies and service DNS |
| High memory usage | Adjust `postgresql.resources.limits` and `server.resources.limits` |

## Support and Contributing

For issues, questions, or contributions, visit:
- GitHub: https://github.com/certctl-io/certctl
- Documentation: https://github.com/certctl-io/certctl/tree/main/docs

## License

BSL-1.1
