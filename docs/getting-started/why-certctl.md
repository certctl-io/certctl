# Why certctl?

> Last reviewed: 2026-05-05

Certificate management is broken at every scale between "one domain on Let's Encrypt" and "Fortune 500 budget for Venafi." certctl fills that gap: a self-hosted platform that automates the entire certificate lifecycle, works with any CA, deploys to any server, and keeps private keys on your infrastructure. It's free, source-available, and you own everything.

## The Math That Forces the Decision

The CA/Browser Forum passed [Ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/) in April 2025, mandating a phased reduction in TLS certificate lifetimes: **200 days** as of March 2026, **100 days** by March 2027, and **47 days** by March 2029.

At 47-day lifespans, a team managing 100 certificates is processing **7+ renewals per week**, every week, forever. At 200 certificates, it's two per day. Manual processes, calendar reminders, and certbot cron jobs don't scale to this — a single missed renewal becomes a production outage at 3 AM. Certificate lifecycle automation is no longer optional; the only question is what tool runs it.

## The Landscape Today

If you're evaluating your options, here's what you'll find:

**ACME clients** (certbot, lego, acme.sh) handle issuance and renewal for Let's Encrypt and similar CAs, but they don't deploy to target servers, don't track inventory, don't support private CAs, and give you no audit trail or policy enforcement. You end up writing glue scripts and hoping they don't break.

**Kubernetes-native tools** (cert-manager) work well inside the cluster, but most organizations run mixed infrastructure — NGINX on VMs, HAProxy at the edge, IIS on Windows, maybe an F5. You need a separate solution for everything outside Kubernetes.

**Commercial SaaS platforms** handle more of the lifecycle but are proprietary, cloud-dependent, and priced per certificate. At 100 certs and 20 agents, SaaS pricing runs $3,000-5,000/year and scales linearly. You're paying rent on your own infrastructure's security.

**Enterprise platforms** (Venafi, Keyfactor, AppViewX) are comprehensive but start at $75K/year and require dedicated teams to operate. If you have a 50-server environment, the licensing costs more than the servers.

## What certctl Does Differently

certctl handles issuance, renewal, deployment, revocation, discovery, and monitoring — with three design decisions that no other tool at any price point combines:

### 1. Private Keys Never Leave Your Infrastructure

certctl agents generate ECDSA P-256 private keys locally. The agent creates a CSR and submits it to the control plane. The signed certificate comes back. The private key stays on the agent's filesystem with 0600 permissions — it never crosses the network.

This isn't a premium feature. It's the default behavior, free. Most alternatives either generate keys on the server (creating a single point of compromise) or gate key isolation behind paid tiers.

### 2. CA-Agnostic Issuer Architecture

certctl works with any certificate authority, not just ACME providers. Twelve issuer connectors ship today, all free:

- **ACME v2** (Let's Encrypt, ZeroSSL, Google Trust Services, Buypass) — HTTP-01, DNS-01, DNS-PERSIST-01 challenges, External Account Binding, ACME Renewal Information (RFC 9773), certificate profile selection
- **HashiCorp Vault PKI** — `/v1/{mount}/sign/{role}` API, token auth
- **DigiCert CertCentral** — async order model, OV/EV support
- **Sectigo SCM** — async order model, DV/OV/EV support, 3-header auth
- **Google Cloud CAS** — Certificate Authority Service, OAuth2 service account auth, CA pool selection
- **AWS ACM Private CA** — managed private CA on AWS, IAM-authenticated, SDK-waiter for issuance
- **Entrust Certificate Services** — Entrust CA Gateway with mTLS auth, approval-pending support
- **GlobalSign Atlas HVCA** — region-pinned commercial CA with dual mTLS + API key/secret auth
- **EJBCA / Keyfactor** — self-hosted open-source / Keyfactor enterprise CA, mTLS or OAuth2
- **step-ca** (Smallstep) — native /sign API with JWK provisioner auth
- **Local CA** — self-signed or sub-CA mode (chain to ADCS or any enterprise root); supports multi-level CA tree mode
- **OpenSSL / Custom CA** — delegate signing to any shell script

EST (RFC 7030) and SCEP (RFC 8894) are protocol surfaces, not separate issuers — they dispatch to whichever issuer above is configured for the EST/SCEP profile.

Every connector implements the same interface. Running multiple CAs in parallel — Let's Encrypt for public certs, Vault for internal services, your enterprise CA for legacy systems — is configuration, not code.

### 3. Post-Deployment Verification

Every other tool in this space stops at "the deployment command succeeded." certctl goes further: after deploying a certificate, the agent connects back to the live TLS endpoint and compares the SHA-256 fingerprint of the served certificate against what was deployed.

A reload command can exit 0 while the certificate doesn't take effect — wrong virtual host, stale cache, config that validates but doesn't apply. certctl catches this automatically.

## What Else Ships Free

The three differentiators above get the headlines, but the feature surface is wider than most paid platforms:

**15 deployment targets** — NGINX, Apache, HAProxy, Traefik, Caddy, Envoy, IIS (local PowerShell + remote WinRM), F5 BIG-IP (proxy agent + iControl REST), Postfix/Dovecot (dual-mode), SSH (agentless), Windows Certificate Store, Java Keystore, Kubernetes Secrets, AWS Certificate Manager, and Azure Key Vault. All use a pluggable connector model. The control plane never initiates outbound connections — agents poll for work, meaning certctl works behind firewalls, across network zones, and in air-gapped environments.

**Network certificate discovery** — active TLS scanning of CIDR ranges finds certificates you didn't know existed. Agents also scan local filesystems for PEM/DER files. Everything feeds into a triage workflow where you claim, dismiss, or import discovered certs into management.

**Immutable audit trail** — every API call recorded (method, path, actor, body hash, status, latency). Every certificate lifecycle event tracked. Append-only, no update or delete.

**Policy engine** — 5 rule types (allowed issuers, allowed domains, required metadata, allowed environments, renewal lead time) with violation tracking and severity levels.

**Revocation infrastructure** — DER-encoded X.509 CRL signed by issuing CA, embedded OCSP responder, RFC 5280 revocation with all reason codes, short-lived certificate exemption.

**Prometheus metrics** — `/api/v1/metrics/prometheus` in standard exposition format. Works with Prometheus, Grafana Agent, Datadog Agent, Victoria Metrics.

**MCP server** — the entire REST API is exposed via MCP for AI-assisted certificate management via Claude, Cursor, or any MCP-compatible client. No other certificate platform offers this.

**Full REST API** — OpenAPI 3.1-documented operations covering the entire platform. CLI tool with 10 subcommands. Helm chart for Kubernetes deployment. Scheduled certificate digest emails. Certificate export in PEM and PKCS#12. S/MIME support with EKU-aware issuance.

**Extensively tested** — Go backend with race detection, static analysis (golangci-lint), and vulnerability scanning (govulncheck) on every commit. CI-enforced per-layer coverage thresholds. Frontend test suite. Every push is gated.

## How certctl Compares

### vs. ACME Clients

ACME clients solve one slice of the problem — issuance and renewal from ACME CAs. certctl replaces the ACME client, adds 6 more CA integrations, deploys the cert to the right server, verifies it's live, tracks it in an inventory, alerts on expiry, logs everything to an audit trail, and enforces policy. If you're currently running certbot behind a cron job and a prayer, certctl replaces all of it.

### vs. Agent-Based SaaS

The closest architectural competitors use the same agent model — local key generation, CSR submission, push-based deployment. Where certctl differs: it supports 12 issuer types (not just ACME), provides CRL/OCSP/revocation infrastructure (not just issuance), includes a policy engine and network discovery, and is source-available with no certificate limit. SaaS alternatives are typically proprietary, priced per certificate ($2+/cert/month), and cap their free tiers at 3-5 certificates. certctl is free for any number of certificates, forever.

### vs. Commercial PKI Platforms

On-prem or hosted commercial platforms offer broader cert type coverage (VPN certs, device auth, SCEP) and deeper CA integrations. The trade-off: no free tier, opaque pricing (often €13K+/year for 1,500 certs), proprietary codebases, and no public API documentation. certctl trades breadth of exotic cert types for full transparency — source-available code, fully documented OpenAPI spec, and a free community edition with no artificial limits.

### vs. Enterprise Platforms

Venafi and Keyfactor offer decades of features at $75K-$250K+/year. certctl targets organizations that need 80% of those capabilities at a fraction of the cost. What certctl doesn't have yet: SSO/RBAC (coming in certctl Pro), vendor SLA-backed support. What certctl does have that enterprise platforms don't: an MCP server for AI-assisted management, ACME ARI (RFC 9773) for CA-directed renewal timing, and a deployment model that works in 5 minutes instead of 5 months.

## Who Should Look Elsewhere

certctl isn't the right tool for everyone:

- **Single-domain sites** — if you have one certificate on one server, certbot is fine. certctl is designed for managing tens to hundreds of certificates across multiple servers and CAs.
- **Pure Kubernetes environments** — if every workload runs in-cluster and you're happy with cert-manager, there's no reason to add another tool. certctl shines when your infrastructure extends beyond Kubernetes.
- **Organizations that need a vendor SLA today** — certctl is source-available software maintained by a small team. If you need contractual uptime guarantees and a support hotline, an enterprise platform is the right choice (for now).

## See It Running

The demo seeds certificates across multiple issuers, agents, and deployment targets with 180 days of realistic history — jobs, audit events, discovery scans, approval workflows — so you can explore every feature immediately.

```bash
git clone https://github.com/certctl-io/certctl.git
cd certctl/deploy && docker compose up -d
# Dashboard at https://localhost:8443 (self-signed cert — pin deploy/test/certs/ca.crt)
```

See the [Quickstart Guide](quickstart.md) for a full walkthrough, or explore the [5 turnkey examples](../examples/) for specific scenarios (ACME+NGINX, wildcard DNS-01, private CA+Traefik, step-ca+HAProxy, multi-issuer).

## License

certctl is source-available under the [Business Source License 1.1](../LICENSE). Free for any use except offering a competing managed service.

You own your data, your keys, and your deployment.
