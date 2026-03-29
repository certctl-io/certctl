# Certctl Helm Deployment Guide

Complete guide for deploying certctl on Kubernetes with Helm.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation Methods](#installation-methods)
3. [Production Deployment](#production-deployment)
4. [Configuration Examples](#configuration-examples)
5. [Post-Deployment Setup](#post-deployment-setup)
6. [Monitoring and Logging](#monitoring-and-logging)
7. [Maintenance](#maintenance)

## Prerequisites

### Required Tools

```bash
# Verify Kubernetes cluster access
kubectl cluster-info
kubectl get nodes

# Install Helm (if not already installed)
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
helm version

# Verify Helm installation
helm repo list
```

### Kubernetes Requirements

- Kubernetes 1.19 or later
- At least 2GB available memory
- At least 10GB available storage (for PostgreSQL)
- Network policies support (optional, for security)
- Ingress controller (nginx, istio, etc.) - optional

### Create Namespace

```bash
# Create isolated namespace
kubectl create namespace certctl

# Set as default namespace
kubectl config set-context --current --namespace=certctl

# Label for network policies (optional)
kubectl label namespace certctl certctl-ns=true
```

## Installation Methods

### Method 1: Minimal Development Setup

Perfect for testing and development:

```bash
# Install with minimal configuration
helm install certctl certctl/certctl \
  --namespace certctl \
  --set server.auth.apiKey="dev-key-change-in-production" \
  --set postgresql.auth.password="dev-password-change-in-production"

# Wait for deployment
kubectl rollout status deployment/certctl-server
kubectl rollout status statefulset/certctl-postgres
```

### Method 2: Production HA Setup

For production workloads:

```bash
# Generate secure credentials
API_KEY=$(openssl rand -base64 32)
DB_PASSWORD=$(openssl rand -base64 32)

# Install with HA configuration
helm install certctl certctl/certctl \
  --namespace certctl \
  --values deploy/helm/examples/values-prod-ha.yaml \
  --set server.auth.apiKey="$API_KEY" \
  --set postgresql.auth.password="$DB_PASSWORD"
```

### Method 3: External PostgreSQL

Using managed database service:

```bash
# Install with external database
helm install certctl certctl/certctl \
  --namespace certctl \
  --values deploy/helm/examples/values-external-db.yaml \
  --set server.auth.apiKey="$API_KEY" \
  --set 'server.env.CERTCTL_DATABASE_URL=postgres://user:pass@db.example.com:5432/certctl?sslmode=require'
```

### Method 4: Using Custom values.yaml

Recommended for GitOps workflows:

```bash
# Create values file with secrets management
cat > /tmp/certctl-values.yaml <<EOF
server:
  auth:
    apiKey: "$API_KEY"
  logging:
    level: info

postgresql:
  auth:
    password: "$DB_PASSWORD"
  storage:
    size: 50Gi

agent:
  enabled: true
  kind: DaemonSet

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: certctl.example.com
      paths:
        - path: /
          pathType: Prefix
EOF

# Install using values file
helm install certctl certctl/certctl \
  --namespace certctl \
  --values /tmp/certctl-values.yaml
```

## Production Deployment

### Step 1: Prepare Environment

```bash
# Create namespace
kubectl create namespace certctl
cd deploy/helm

# Generate credentials
API_KEY=$(openssl rand -base64 32)
DB_PASSWORD=$(openssl rand -base64 32)

echo "API Key: $API_KEY"
echo "DB Password: $DB_PASSWORD"

# Save credentials in secure location (e.g., 1Password, Vault, AWS Secrets Manager)
```

### Step 2: Prepare Storage

```bash
# List available storage classes
kubectl get storageclass

# If needed, create a high-performance storage class for production
cat <<EOF | kubectl apply -f -
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast-ssd
provisioner: ebs.csi.aws.com  # For AWS, adjust for your cloud provider
parameters:
  type: gp3
  iops: "3000"
  throughput: "125"
EOF
```

### Step 3: Set Up TLS with cert-manager

```bash
# Install cert-manager (if not already installed)
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set installCRDs=true

# Create ClusterIssuer for Let's Encrypt
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF
```

### Step 4: Install Certctl

```bash
# Install using HA values
helm install certctl certctl/ \
  --namespace certctl \
  --values examples/values-prod-ha.yaml \
  --set server.auth.apiKey="$API_KEY" \
  --set postgresql.auth.password="$DB_PASSWORD" \
  --set ingress.annotations."cert-manager\.io/cluster-issuer"=letsencrypt-prod \
  --set ingress.hosts[0].host=certctl.example.com

# Verify installation
kubectl get all -l app.kubernetes.io/instance=certctl
```

### Step 5: Verify Deployment

```bash
# Check pod status
kubectl get pods -l app.kubernetes.io/instance=certctl
kubectl describe pods -l app.kubernetes.io/instance=certctl

# Check service status
kubectl get svc -l app.kubernetes.io/instance=certctl

# Check ingress status
kubectl get ingress
kubectl describe ingress certctl

# Test API connectivity
POD=$(kubectl get pods -l app.kubernetes.io/component=server -o jsonpath='{.items[0].metadata.name}')
kubectl port-forward $POD 8443:8443 &
curl -H "Authorization: Bearer $API_KEY" http://localhost:8443/health
```

### Step 6: Access the Dashboard

```bash
# Port forward to local machine
kubectl port-forward svc/certctl-server 8443:8443 &

# Or if using Ingress:
# Open browser: https://certctl.example.com
# Login with API key: $API_KEY
```

## Configuration Examples

### Example 1: ACME (Let's Encrypt)

```bash
helm install certctl certctl/ \
  --set server.issuer.acme.enabled=true \
  --set server.issuer.acme.directoryURL=https://acme-v02.api.letsencrypt.org/directory \
  --set server.issuer.acme.email=admin@example.com \
  --set server.issuer.acme.challengeType=http-01
```

### Example 2: DNS-01 (Wildcard Certs)

Requires DNS scripts ConfigMap:

```bash
# Create DNS scripts ConfigMap
kubectl create configmap dns-scripts \
  --from-file=dns-present.sh=./scripts/dns-present.sh \
  --from-file=dns-cleanup.sh=./scripts/dns-cleanup.sh

# Install with DNS-01
helm install certctl certctl/ \
  --set server.issuer.acme.enabled=true \
  --set server.issuer.acme.challengeType=dns-01 \
  --values examples/values-acme-dns01.yaml
```

### Example 3: AWS RDS Database

```bash
helm install certctl certctl/ \
  --set postgresql.enabled=false \
  --set 'server.env.CERTCTL_DATABASE_URL=postgres://user:password@mydb.c9akciq32.us-east-1.rds.amazonaws.com:5432/certctl?sslmode=require'
```

### Example 4: Multiple Issuers

```bash
helm install certctl certctl/ \
  --set server.issuer.local.enabled=true \
  --set server.issuer.acme.enabled=true \
  --set server.issuer.acme.directoryURL=https://acme-v02.api.letsencrypt.org/directory
```

### Example 5: Email Notifications

```bash
helm install certctl certctl/ \
  --set server.smtp.enabled=true \
  --set server.smtp.host=smtp.example.com \
  --set server.smtp.port=587 \
  --set server.smtp.username=alerts@example.com \
  --set server.smtp.password="$SMTP_PASSWORD" \
  --set server.smtp.fromAddress=certctl@example.com
```

## Post-Deployment Setup

### 1. Initial Database Setup

```bash
# Check database connection
POD=$(kubectl get pods -l app.kubernetes.io/component=postgres -o jsonpath='{.items[0].metadata.name}')

# Execute psql commands
kubectl exec -it $POD -- \
  psql -U certctl -d certctl -c '\dt'

# View database status
kubectl logs $POD | tail -20
```

### 2. Create Default Certificates

```bash
# Port forward to API
kubectl port-forward svc/certctl-server 8443:8443 &

# Create a test certificate
API_KEY="your-api-key"
curl -X POST http://localhost:8443/api/v1/certificates \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "common_name": "test.example.com",
    "sans": ["test.example.com", "*.example.com"],
    "owner": "admin@example.com"
  }'
```

### 3. Configure Agents

```bash
# Get agent names
kubectl get pods -l app.kubernetes.io/component=agent -o wide

# Check agent connectivity
POD=$(kubectl get pods -l app.kubernetes.io/component=agent -o jsonpath='{.items[0].metadata.name}')
kubectl logs $POD | grep -i heartbeat
```

### 4. Set Up HTTPS for Web Dashboard

The Ingress will handle TLS if configured properly:

```bash
# Verify ingress is ready
kubectl get ingress
kubectl describe ingress certctl

# Test HTTPS
curl https://certctl.example.com/health
```

## Monitoring and Logging

### 1. View Logs

```bash
# Server logs
kubectl logs -l app.kubernetes.io/component=server -f --all-containers=true

# PostgreSQL logs
kubectl logs -l app.kubernetes.io/component=postgres -f

# Agent logs
kubectl logs -l app.kubernetes.io/component=agent -f --all-containers=true

# Logs from all components
kubectl logs -l app.kubernetes.io/instance=certctl -f --all-containers=true
```

### 2. Install Prometheus Monitoring

```bash
# Install Prometheus operator (if not already installed)
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace

# Certctl will automatically expose metrics if monitoring.enabled=true
helm install certctl certctl/ \
  --set monitoring.enabled=true \
  --set monitoring.serviceMonitor.enabled=true
```

### 3. Set Up Alerts

```bash
# Create Prometheus alerts
cat <<EOF | kubectl apply -f -
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: certctl-alerts
spec:
  groups:
  - name: certctl
    interval: 30s
    rules:
    - alert: CertctlServerDown
      expr: up{job="certctl-server"} == 0
      for: 5m
      annotations:
        summary: "Certctl server is down"

    - alert: CertificateExpiringSoon
      expr: certctl_certificate_expiring_soon > 0
      for: 1h
      annotations:
        summary: "{{ \$value }} certificates expiring soon"
EOF
```

## Maintenance

### Scaling

```bash
# Scale server replicas
helm upgrade certctl certctl/ \
  --set server.replicas=5

# Scale agents (Deployment kind only)
helm upgrade certctl certctl/ \
  --set agent.kind=Deployment \
  --set agent.replicas=10
```

### Updating

```bash
# Update chart version
helm repo update
helm upgrade certctl certctl/certctl \
  --namespace certctl \
  -f values.yaml

# Verify update
kubectl rollout status deployment/certctl-server
kubectl rollout status statefulset/certctl-postgres
```

### Backup and Restore

```bash
# Backup PostgreSQL data
kubectl exec -i $(kubectl get pods -l app.kubernetes.io/component=postgres -o jsonpath='{.items[0].metadata.name}') \
  pg_dump -U certctl certctl | gzip > certctl-backup.sql.gz

# Restore from backup
zcat certctl-backup.sql.gz | kubectl exec -i $(kubectl get pods -l app.kubernetes.io/component=postgres -o jsonpath='{.items[0].metadata.name}') \
  psql -U certctl certctl

# Backup PVC data
kubectl get pvc
kubectl exec -i $(kubectl get pods -l app.kubernetes.io/component=postgres -o jsonpath='{.items[0].metadata.name}') \
  tar czf - /var/lib/postgresql/data | gzip > certctl-data-backup.tar.gz
```

### Uninstall

```bash
# Remove Helm release (keeps PVCs by default)
helm uninstall certctl --namespace certctl

# Delete PVCs if needed
kubectl delete pvc --all -n certctl

# Delete namespace
kubectl delete namespace certctl
```

## Troubleshooting

See [README.md](README.md#troubleshooting) for detailed troubleshooting steps.

Common commands:

```bash
# Get all resources
kubectl get all -n certctl

# Describe pod for events
kubectl describe pod <pod-name> -n certctl

# Stream logs
kubectl logs -f <pod-name> -n certctl

# Execute commands in pod
kubectl exec -it <pod-name> -n certctl -- /bin/sh

# Check events
kubectl get events -n certctl --sort-by='.lastTimestamp'
```
