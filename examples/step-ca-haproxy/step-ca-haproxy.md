# step-ca + HAProxy Example

This example demonstrates certctl managing certificates issued by **Smallstep step-ca** and deploying them to **HAProxy**.

> **Operational notes** shared by every example (postgres password rotation trap, TLS provisioning, teardown semantics) live in [`../README.md`](../README.md). Read it first if you plan to change `DB_PASSWORD` after the initial `docker compose up` — the postgres volume binds the password on first boot only.

## Scenario

You're a Smallstep user running step-ca as your internal PKI. You have HAProxy load balancers that need certificates. This setup:

1. **step-ca** issues certificates (via JWK provisioner, no challenge solving)
2. **certctl** manages the certificate lifecycle (renewal policies, deployment, audit)
3. **HAProxy** serves HTTPS with certificates managed by certctl

This is the natural choice if you're already invested in step-ca and want to consolidate certificate lifecycle management without learning Let's Encrypt, DNS-01 challenges, or external integrations.

## What's Included

| Service | Image | Purpose |
|---------|-------|---------|
| **step-ca** | `smallstep/step-ca:latest` | Private internal CA |
| **certctl-server** | `ghcr.io/shankar0123/certctl-server:latest` | Certificate management control plane |
| **certctl-agent** | `ghcr.io/shankar0123/certctl-agent:latest` | Agent running on HAProxy server |
| **haproxy** | `haproxy:2.9-alpine` | Reverse proxy / load balancer |
| **postgres** | `postgres:16-alpine` | certctl audit trail + config storage |

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Curl (to interact with APIs)

### 1. Start Everything

```bash
docker compose up -d
```

This will:
- Initialize step-ca with a self-signed root CA
- Create a JWK provisioner named `certctl` (pre-configured credentials)
- Start certctl-server (connected to step-ca)
- Start the certctl-agent (ready to deploy certs to HAProxy)
- Start HAProxy with a placeholder config

Monitor logs:

```bash
docker compose logs -f certctl-server
```

## TLS Security

certctl is HTTPS-only as of v2.2. The demo compose stack provisions a self-signed certificate. When accessing `https://localhost:8443`, you can either:
- Use `curl --cacert ./deploy/test/certs/ca.crt ...` to pin the CA certificate
- Use `curl -k ...` for quick smoke tests (never in production)
- Import the CA at `./deploy/test/certs/ca.crt` into your OS trust store for browser visits

Wait for all services to reach healthy state:

```bash
docker compose ps
```

Expected output:
```
NAME                              STATUS
certctl-postgres-...              healthy
certctl-server-...                healthy
step-ca-...                       healthy
certctl-agent-...                 running
certctl-haproxy-...               healthy
```

### 2. Access certctl Dashboard

Open your browser to:

```
https://localhost:8443
```

You should see an empty dashboard. This is expected — no certificates issued yet.

### 3. Create a Certificate Profile

This defines what certificates certctl can issue (key algorithm, max TTL, allowed names).

```bash
curl -X POST https://localhost:8443/api/v1/profiles \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "internal-web",
    "key_type": "rsa-2048",
    "max_ttl_days": 90,
    "description": "Internal web services"
  }'
```

### 4. Create an HAProxy Deployment Target

This tells certctl where to deploy certificates on the HAProxy server.

```bash
curl -X POST https://localhost:8443/api/v1/targets \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "haproxy-01",
    "type": "haproxy",
    "enabled": true,
    "config": {
      "pem_path": "/etc/haproxy/ssl/cert.pem",
      "reload_command": "systemctl reload haproxy",
      "validate_command": "haproxy -c -f /etc/haproxy/haproxy.cfg"
    }
  }'
```

Note: In the Docker Compose environment, reload command can be `kill -HUP $(pidof haproxy)` instead of `systemctl reload haproxy`.

### 5. Create a Renewal Policy

This ties a certificate profile to a deployment target and sets renewal thresholds.

```bash
curl -X POST https://localhost:8443/api/v1/renewal-policies \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "haproxy-internal-web",
    "profile_id": "<profile_id_from_step_3>",
    "issuer_id": "iss-stepca",
    "enabled": true,
    "renewal_days_before_expiry": 30,
    "alert_thresholds_days": [30, 14, 7, 0]
  }'
```

Get the issuer ID:

```bash
curl https://localhost:8443/api/v1/issuers | jq '.'
```

You should see `iss-stepca` in the list.

### 6. Issue a Certificate

Request a certificate via the API. The server will sign it via step-ca.

```bash
curl -X POST https://localhost:8443/api/v1/certificates \
  -H 'Content-Type: application/json' \
  -d '{
    "common_name": "api.internal.example.com",
    "sans": ["api.internal.example.com", "api.staging.example.com"],
    "issuer_id": "iss-stepca",
    "profile_id": "<profile_id_from_step_3>"
  }'
```

### 7. Deploy to HAProxy

Get the certificate ID and trigger deployment:

```bash
curl -X POST https://localhost:8443/api/v1/certificates/<cert_id>/deploy \
  -H 'Content-Type: application/json' \
  -d '{
    "target_id": "<target_id_from_step_4>"
  }'
```

The agent will:
1. Fetch the deployment job
2. Generate a combined PEM (cert + chain + key) locally
3. Write it to `/etc/haproxy/ssl/cert.pem` on HAProxy
4. Reload HAProxy
5. Report status back to certctl

### 8. Verify in Dashboard

Refresh https://localhost:8443 and you should see:
- 1 certificate (status: Active, expiry in 90 days)
- 1 deployment job (status: Completed)
- 1 agent (heartbeat: recent)

## Configuration Details

### step-ca Integration

step-ca is configured with:

- **Root CA Name**: `certctl-demo-ca`
- **Provisioner**: `certctl` (JWK type)
- **Default Password**: `certctl-provisioner-demo` (override with `STEP_CA_PROVISIONER_PASSWORD`)

To inspect step-ca:

```bash
docker compose exec step-ca step ca provisioner list
docker compose exec step-ca step ca health --insecure
```

### HAProxy Combined PEM Format

HAProxy requires a single file with certificate, chain, and key concatenated:

```
-----BEGIN CERTIFICATE-----
[leaf certificate]
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
[intermediate CA]
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
[private key]
-----END RSA PRIVATE KEY-----
```

The agent automatically constructs this file from the issued certificate and step-ca-provided chain.

**Security**: The combined PEM is written with `0600` permissions (owner-readable only) because it contains the private key.

### Environment Variables

Customize behavior with:

| Variable | Default | Purpose |
|----------|---------|---------|
| `DB_PASSWORD` | `certctl-dev-password` | PostgreSQL password |
| `STEP_CA_PASSWORD` | `stepca-demo-password` | step-ca root key password |
| `STEP_CA_PROVISIONER_PASSWORD` | `certctl-provisioner-demo` | certctl JWK provisioner password |
| `AGENT_API_KEY` | `agent-demo-key` | Agent authentication token |
| `SERVER_PORT` | `8443` | certctl server external port |

Example:

```bash
STEP_CA_PASSWORD=myca-password AGENT_API_KEY=secret-key docker compose up -d
```

## Integrating with an Existing step-ca Instance

If you already run step-ca elsewhere (not in this Compose file):

1. **Extract the root certificate** from your step-ca:

   ```bash
   step ca root /tmp/step-ca-root.crt --ca-url https://ca.internal:9000 --insecure
   ```

2. **Create or retrieve the certctl JWK provisioner key**:

   ```bash
   step ca provisioner list --ca-url https://ca.internal:9000 --insecure
   step ca provisioner describe certctl --ca-url https://ca.internal:9000 --insecure
   ```

3. **Update docker-compose.yml**:

   ```yaml
   certctl-server:
     environment:
       CERTCTL_STEPCA_URL: https://ca.internal:9000
       CERTCTL_STEPCA_ROOT_CERT_PATH: /etc/certctl/step-ca-root.crt
       CERTCTL_STEPCA_PROVISIONER_NAME: certctl
       CERTCTL_STEPCA_PROVISIONER_KEY_PATH: /etc/certctl/step-ca-provisioner.json
       CERTCTL_STEPCA_PROVISIONER_PASSWORD: <your-password>
   ```

4. **Mount the cert and key**:

   ```yaml
   volumes:
     - /path/to/step-ca-root.crt:/etc/certctl/step-ca-root.crt:ro
     - /path/to/provisioner.json:/etc/certctl/step-ca-provisioner.json:ro
   ```

## Cleanup

```bash
docker compose down -v
```

This removes all containers and volumes (step-ca config, certificates, database).

## Next Steps

### Production Deployment

- Replace image tags (`latest` → specific version)
- Use real TLS certificates for step-ca (self-signed is fine internally, but use proper roots for verification)
- Configure persistent storage for step-ca keys (HSM or encrypted filesystem)
- Set `CERTCTL_AUTH_TYPE: api-key` and rotate API keys regularly
- Enable audit trail export for compliance
- Configure renewal alerts (Slack, email, PagerDuty)
- Run agents on separate machines (not in Compose)

### Advanced Features

- **Multiple HAProxy instances**: Create additional targets and agents
- **Policy-based renewal**: Set different renewal windows per environment (staging vs. production)
- **Approval workflows**: Require manual approval before deploying to production
- **Discovery**: Scan existing HAProxy certs and bring them under management
- **Network scanning**: Discover TLS endpoints in your network and inventory them

## Troubleshooting

### step-ca fails to initialize

Check logs:

```bash
docker compose logs step-ca
```

Common issues:
- Permissions on `/home/step/step-ca` volume
- Port 9000 already in use

### Agent can't reach server

Verify network:

```bash
docker compose exec certctl-agent curl http://certctl-server:8443/health
```

### HAProxy config validation fails

Check HAProxy config syntax:

```bash
docker compose exec haproxy haproxy -c -f /etc/haproxy/haproxy.cfg
```

### Deployment job stays in "Running" state

Check agent logs:

```bash
docker compose logs certctl-agent
```

Likely causes:
- Agent can't write to `/etc/haproxy/ssl/cert.pem` (permissions)
- Reload command is misconfigured
- HAProxy container is not accessible

## Documentation

- [certctl Architecture](../../docs/architecture.md)
- [step-ca Connector Docs](../../docs/connectors.md#step-ca)
- [HAProxy Target Docs](../../docs/connectors.md#haproxy)
- [API Reference](../../api/openapi.yaml)

## Support

For issues or questions:

1. Check the [troubleshooting guide](../../docs/troubleshooting.md)
2. Review service logs: `docker compose logs <service>`
3. Open an issue on GitHub
