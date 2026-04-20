# Quick Installation Guide

## One-Liner Installation

### Development (no auth)
```bash
helm install certctl certctl/ \
  --set server.auth.type=none \
  --set postgresql.auth.password=dev
```

### Production (with API key)
```bash
API_KEY=$(openssl rand -base64 32)
DB_PASSWORD=$(openssl rand -base64 32)

helm install certctl certctl/ \
  --values examples/values-prod-ha.yaml \
  --set server.auth.apiKey="$API_KEY" \
  --set postgresql.auth.password="$DB_PASSWORD"
```

## Verify Installation

```bash
# Wait for pods to be ready
kubectl rollout status deployment/certctl-server
kubectl rollout status statefulset/certctl-postgres

# Check all components
kubectl get pods -l app.kubernetes.io/instance=certctl

# View server logs
kubectl logs -l app.kubernetes.io/component=server -f

# Access the API (HTTPS-only as of v2.2; use --cacert or -k depending on your cert provisioning)
kubectl port-forward svc/certctl-server 8443:8443 &
# If the chart provisioned a self-signed cert, fetch the CA bundle from the secret first:
#   kubectl get secret certctl-server-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > /tmp/certctl-ca.crt
curl --cacert /tmp/certctl-ca.crt https://localhost:8443/health
```

## Next Steps

1. **Read Documentation**
   - `README.md` - Complete reference
   - `DEPLOYMENT_GUIDE.md` - Step-by-step guide
   - `CHART_SUMMARY.md` - Architecture overview

2. **Configure for Your Environment**
   - Review `examples/` for your deployment scenario
   - Customize `values.yaml` as needed
   - Use `helm upgrade` to apply changes

3. **Set Up Monitoring**
   - Install Prometheus (optional)
   - Enable Ingress with HTTPS
   - Configure email notifications

4. **Deploy Agents**
   - Agents deploy automatically as DaemonSet
   - Verify with: `kubectl get pods -l app.kubernetes.io/component=agent`

5. **Create Certificates**
   - Configure issuer connectors (Local CA, ACME, etc.)
   - Access web dashboard at ingress or port-forward

## Common Commands

```bash
# List installations
helm list

# View chart values
helm values certctl

# Upgrade chart
helm upgrade certctl certctl/ -f new-values.yaml

# Rollback to previous version
helm rollback certctl 1

# Uninstall chart
helm uninstall certctl

# View deployment history
helm history certctl

# Dry-run installation to see generated YAML
helm install certctl certctl/ --dry-run --debug
```

## Support

- Full documentation in `README.md`
- Troubleshooting in `DEPLOYMENT_GUIDE.md`
- Issues: https://github.com/shankar0123/certctl
