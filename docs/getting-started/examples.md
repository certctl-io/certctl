# Deployment Examples

> Last reviewed: 2026-05-05

Five turnkey docker-compose scenarios, each runnable in under 5 minutes. Pick the one closest to your setup.

## Which Example Should I Use?

| I need to... | Example | Issuer | Target |
|--------------|---------|--------|--------|
| Get Let's Encrypt certs for NGINX on a public server | [ACME + NGINX](#acme--nginx) | ACME (HTTP-01) | NGINX |
| Issue wildcard certs without opening port 80 | [Wildcard DNS-01](#wildcard-dns-01) | ACME (DNS-01) | Any |
| Run an internal CA for services behind a firewall | [Private CA + Traefik](#private-ca--traefik) | Local CA | Traefik |
| Use Smallstep step-ca as my PKI backend | [step-ca + HAProxy](#step-ca--haproxy) | step-ca | HAProxy |
| Manage both public and internal certs from one dashboard | [Multi-Issuer](#multi-issuer) | ACME + Local CA | Mixed |

**Already using another tool?** See the migration sections below each example for Certbot, acme.sh, and cert-manager users.

---

## ACME + NGINX

**Scenario:** You have one or more public-facing domains, NGINX as the reverse proxy, and want automated Let's Encrypt certificates with HTTP-01 challenges.

**What it deploys:** certctl server + PostgreSQL + certctl agent + NGINX, all on one Docker network. The agent generates keys locally (ECDSA P-256), submits CSRs to the server, receives signed certs from Let's Encrypt, and deploys them to NGINX with automatic reload.

**Prerequisites:** A domain pointing to your server, ports 80 and 443 open, Docker Compose v20.10+.

```bash
cd examples/acme-nginx
cp .env.example .env   # Edit with your domain and email
docker compose up -d
```

The full walkthrough — including how HTTP-01 challenges work, adding multiple domains, switching to staging for testing, and a production checklist — is in the [example README](../../examples/acme-nginx/acme-nginx.md).

**Migrating from Certbot?** certctl discovers your existing `/etc/letsencrypt/live/` certificates automatically. You keep your ACME account, disable the Certbot cron, and certctl takes over renewal with centralized visibility and deployment verification. The step-by-step process is in [Migrating from Certbot](../migration/from-certbot.md).

---

## Wildcard DNS-01

**Scenario:** You need wildcard certificates (`*.example.com`) or your servers aren't reachable from the internet (no port 80). DNS-01 validates ownership by creating a TXT record at your DNS provider.

**What it deploys:** certctl server + PostgreSQL + certctl agent. Includes a Cloudflare DNS hook script as a working reference — swap in your own DNS provider (Route53, Azure DNS, Google Cloud DNS, or any provider with an API).

**Prerequisites:** A domain, API credentials for your DNS provider, Docker Compose.

```bash
cd examples/acme-wildcard-dns01
cp .env.example .env   # Edit with domain, email, DNS provider credentials
docker compose up -d
```

The full walkthrough — including DNS-PERSIST-01 (set a TXT record once, never touch DNS again on renewals), adapting scripts for other providers, and propagation troubleshooting — is in the [example README](../../examples/acme-wildcard-dns01/acme-wildcard-dns01.md).

**Migrating from acme.sh?** Your existing `dns_*` hook scripts are compatible with certctl's DNS-01 — they use the same pattern (shell scripts creating TXT records). The migration guide covers script adaptation, discovery of existing acme.sh certificates, and phasing out the acme.sh cron. See [Migrating from acme.sh](../migration/from-acmesh.md).

---

## Private CA + Traefik

**Scenario:** Internal services that don't need public CA validation. You run your own certificate authority — either a self-signed root for development, or a subordinate CA chained to your enterprise root (e.g., Active Directory Certificate Services).

**What it deploys:** certctl server + PostgreSQL + certctl agent + Traefik. The Local CA issuer signs certificates directly. Traefik watches a cert directory and auto-reloads when new files appear.

**Prerequisites:** Docker Compose. For sub-CA mode, you'll need a CA certificate and key signed by your enterprise root.

```bash
cd examples/private-ca-traefik
docker compose up -d    # Self-signed mode (no .env needed for demo)
```

The full walkthrough — including sub-CA setup with `CERTCTL_CA_CERT_PATH` and `CERTCTL_CA_KEY_PATH`, creating certificates via the API, monitoring deployments, and production hardening — is in the [example README](../../examples/private-ca-traefik/private-ca-traefik.md).

---

## step-ca + HAProxy

**Scenario:** You use Smallstep's step-ca as your private PKI and want automated lifecycle management for certificates deployed to HAProxy load balancers.

**What it deploys:** certctl server + PostgreSQL + certctl agent + step-ca (with JWK provisioner) + HAProxy. certctl issues certs via step-ca's native `/sign` API, combines them into HAProxy's expected PEM format (cert + chain + key in one file), and reloads HAProxy.

**Prerequisites:** Docker Compose.

```bash
cd examples/step-ca-haproxy
docker compose up -d
```

The full walkthrough — including step-ca provisioner configuration, integrating with an existing step-ca instance, HAProxy PEM format details, and advanced features (approval workflows, policy-based renewal, multi-instance HAProxy) — is in the [example README](../../examples/step-ca-haproxy/step-ca-haproxy.md).

---

## Multi-Issuer

**Scenario:** You manage both public-facing services (needing Let's Encrypt or another public CA) and internal services (using a private CA) and want a single dashboard for everything.

**What it deploys:** certctl server + PostgreSQL + certctl agent configured with both an ACME issuer and a Local CA issuer. Demonstrates issuer assignment via profiles — public services get ACME certs, internal services get Local CA certs, all visible in one inventory.

**Prerequisites:** Docker Compose. For real ACME certs, a public domain and port 80 access.

```bash
cd examples/multi-issuer
docker compose up -d
```

The full walkthrough — including profile-based issuer assignment, testing with ACME staging, Local CA enterprise sub-CA mode, and scaling beyond Docker Compose — is in the [example README](../../examples/multi-issuer/multi-issuer.md).

**Using cert-manager for Kubernetes?** certctl complements cert-manager — cert-manager handles in-cluster certs, certctl handles everything outside: VMs, bare metal, network appliances, Windows servers. They can share the same CA (ACME, step-ca, Vault PKI). See [certctl for cert-manager Users](../migration/cert-manager-coexistence.md).

---

## Beyond These Examples

These 5 scenarios cover the most common deployment patterns, but certctl supports a broader set of issuer and target backends — see `docs/features.md`'s Issuer Connectors and Target Connectors sections for the live catalogs (rebuild via `ls -d internal/connector/issuer/*/ | wc -l` and `ls -d internal/connector/target/*/ | wc -l`). Once you have the basics running, you can mix and match:

**Issuers:** ACME (Let's Encrypt, ZeroSSL, Buypass, Google Trust Services), Local CA (self-signed or sub-CA), step-ca, Vault PKI, DigiCert CertCentral, OpenSSL/Custom CA script, Sectigo (coming soon).

**Targets:** NGINX, Apache, HAProxy, Traefik, Caddy, Envoy, IIS (local PowerShell or WinRM proxy), Postfix, Dovecot, F5 BIG-IP (coming soon).

See [Connector Reference](../reference/connectors/index.md) for configuration details on every issuer and target.
