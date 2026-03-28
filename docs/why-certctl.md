# Why certctl?

Certificate management is broken at every scale between "one domain on Let's Encrypt" and "Fortune 500 budget for Venafi."

If you run a personal blog, Certbot works fine. If your company spends $200K/year on Keyfactor, you're covered. But if you're an ops engineer managing 20-500 certificates across NGINX, Apache, HAProxy, and maybe a private CA — the tools available today either don't do enough or cost too much.

certctl fills that gap.

## The Problem

The CA/Browser Forum passed [Ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/) in April 2025, mandating a phased reduction in TLS certificate lifetimes: 200 days as of March 2026, 100 days by March 2027, and 47 days by March 2029. That means every organization needs automated certificate renewal — not eventually, but now.

The existing options for automation are:

- **ACME clients** (Certbot, Lego, CertWarden): Handle issuance and renewal for ACME-compatible CAs, but don't manage deployment to target servers, don't provide inventory visibility, don't support non-ACME CAs, and don't offer audit trails or policy enforcement.
- **Kubernetes-native** (cert-manager): Works well inside Kubernetes, but if your infrastructure includes bare-metal servers, VMs, or network appliances alongside Kubernetes, you need a separate solution for everything cert-manager can't reach.
- **Commercial SaaS** (CertKit, Sectigo CLM): Handle more of the lifecycle but are proprietary, cloud-dependent, and priced per certificate — costs scale linearly with your infrastructure.
- **Enterprise platforms** (Venafi, Keyfactor, AppViewX): Comprehensive but start at $75K/year and require dedicated teams to operate.

## What certctl Does Differently

certctl is a self-hosted certificate lifecycle platform. It handles issuance, renewal, deployment, revocation, discovery, and monitoring — with three design decisions that no other tool at any price point combines:

### 1. Private Keys Never Leave Your Infrastructure

certctl agents generate private keys locally using ECDSA P-256. The agent creates a CSR and submits it to the control plane. The signed certificate comes back. The private key stays on the agent's filesystem with 0600 permissions.

This isn't a premium feature — it's the default behavior in the free tier. Most competitors either generate keys server-side (creating a single point of compromise) or gate key isolation behind paid tiers.

### 2. CA-Agnostic Issuer Architecture

certctl works with any certificate authority, not just ACME providers:

- **ACME** (Let's Encrypt, ZeroSSL, Google Trust Services, Buypass) — HTTP-01 and DNS-01 challenges, DNS-PERSIST-01 for zero-touch renewals, External Account Binding
- **step-ca** (Smallstep) — native /sign API with JWK provisioner authentication
- **Local CA** — self-signed or sub-CA mode (chain to your enterprise root CA, e.g. ADCS)
- **OpenSSL / Custom CA** — delegate signing to any shell script with configurable timeout
- **EST enrollment** (RFC 7030) — device certificate enrollment for WiFi/802.1X, MDM, and IoT

Every issuer connector implements the same interface. Switching CAs or running multiple CAs in parallel requires zero code changes — just configuration.

### 3. Post-Deployment Verification (coming in v2.0.6)

Every other tool in this space stops at "the deployment command succeeded." certctl is adding a step nobody else has: after deploying a certificate to a target, the agent connects back to the target's TLS endpoint and verifies the served certificate matches what was deployed, using SHA-256 fingerprint comparison.

A reload command can exit 0 while the certificate doesn't take effect — wrong virtual host, stale cache, config that validates but doesn't apply. certctl will catch this.

## How certctl Compares

### vs. ACME Clients (Certbot, Lego, CertWarden)

ACME clients solve issuance. certctl solves the lifecycle. The difference: issuing a certificate is step 1 of 5. You also need to deploy it to the right server, verify it's being served, monitor expiration across your fleet, audit who renewed what and when, and enforce policy (minimum key sizes, maximum TTLs, approved algorithms).

certctl does all of this. ACME clients do step 1.

CertWarden is the most capable ACME client — it's centralized, has an API for clients to fetch certs, and handles renewals autonomously. But it's ACME-only (no private CAs, no step-ca, no EST enrollment), has no deployment automation (clients pull certs but must handle installation themselves), no policy engine, no audit trail, and no network discovery.

### vs. CertKit

CertKit is the closest competitor in architecture: agent-based deployment, private key isolation (via their Keystore component), multi-platform support. The differences:

- **Issuer coverage**: CertKit is ACME-only. certctl supports ACME, step-ca, Local CA (sub-CA mode), OpenSSL/custom scripts, and EST enrollment. If you have an internal CA or need device enrollment, CertKit can't help today — their private CA and audit log are still on their roadmap.
- **PKI compliance**: certctl ships CRL endpoints (DER-encoded, CA-signed), an embedded OCSP responder, revocation with all RFC 5280 reason codes, and an immutable API audit trail that records every API call. CertKit doesn't have CRL, OCSP, or audit logging today.
- **Policy engine**: certctl enforces 5 rule types with violation tracking and severity levels. CertKit has no policy engine.
- **Network discovery**: certctl actively scans CIDR ranges for TLS certificates, finding unmanaged certs on your network. CertKit doesn't offer network scanning.
- **Licensing**: certctl is source-available under BSL 1.1 (converts to Apache 2.0 in 2033). CertKit's platform is proprietary; only the agent source is available.
- **Pricing**: certctl's V2 community edition is free with no certificate limit. CertKit's free tier is limited to 3 certificates.

Where CertKit leads: their agent supports more deployment targets today (NGINX, Apache, HAProxy, LiteSpeed, IIS, with auto-detection), runs on Windows and Linux, and has Kubernetes support. CertKit also has a polished onboarding experience as a managed SaaS product.

### vs. Certimate

Certimate is an open-source (MIT) lightweight certificate automation tool focused on ACME issuance and cloud deployment. It advertises 110+ deployment targets — but the bulk of those are cloud CDN, WAF, and load balancer integrations (Alibaba Cloud, Tencent Cloud, Huawei Cloud, Volcengine, etc.), not traditional server deployments like NGINX or Apache on your own infrastructure.

- **Architecture**: Certimate is a centralized single-binary tool with no agent model. All operations run from the Certimate instance — it connects outbound to cloud APIs to deploy certificates. certctl uses a pull-based agent model where agents poll the control plane, keeping the server firewalled off and working across network zones.
- **CA support**: Both support multiple ACME CAs. certctl also supports private CAs (step-ca, Local CA with sub-CA mode, OpenSSL/custom scripts) and EST enrollment — Certimate is ACME-only.
- **Key isolation**: Certimate generates and stores keys centrally. certctl generates keys on the agent (ECDSA P-256) — private keys never touch the control plane.
- **Lifecycle depth**: Certimate handles issuance, renewal, and deployment. certctl adds revocation (RFC 5280, CRL, OCSP), policy enforcement, an immutable audit trail, certificate discovery (filesystem + network), approval workflows, and observability (Prometheus metrics, dashboard charts).
- **Best fit**: Certimate is a good choice for teams that primarily need ACME automation to cloud infrastructure (especially Chinese cloud providers). certctl is a better fit for mixed on-prem/cloud environments that need full lifecycle management, private CA support, and compliance tooling.

### vs. CZERTAINLY

CZERTAINLY is an open-source (MIT + commercial support) cloud-native certificate and key lifecycle management platform built on a microservices architecture. It's the most architecturally ambitious open-source competitor.

- **Architecture**: CZERTAINLY is designed for Kubernetes — it runs as a set of microservices (Core, Auth, Scheduler, plus connector containers). This gives it extensibility but makes deployment significantly heavier than certctl's single Go binary + PostgreSQL. If you don't run Kubernetes, CZERTAINLY isn't a practical option.
- **Connector model**: Both tools use pluggable connectors. CZERTAINLY's connector system is more formally defined (separate containerized services with a connector API framework), while certctl's connectors are compiled-in Go interfaces. CZERTAINLY's approach is more extensible in theory; certctl's is simpler to deploy and operate.
- **Discovery**: Both offer certificate discovery. CZERTAINLY uses pluggable discovery providers (IP discovery, EJBCA NG discovery). certctl has built-in filesystem scanning (agent-side) and network TLS scanning (CIDR ranges) — no additional connector deployment needed.
- **Policy**: CZERTAINLY uses RA (Registration Authority) profiles for enrollment rules. certctl has a broader policy engine (5 rule types with violation tracking, severity levels, and interactive approval workflows).
- **Revocation**: certctl ships DER-encoded CRL, embedded OCSP responder, and full RFC 5280 reason codes. CZERTAINLY supports revocation through its CA connectors but doesn't embed its own CRL/OCSP endpoints.
- **Maturity**: CZERTAINLY has a broader vision (cryptographic key management, post-quantum readiness) but a smaller community. certctl has a narrower scope (certificate lifecycle specifically) with deeper implementation in that scope — 95 API endpoints, 950+ tests, 22 GUI pages.
- **Best fit**: CZERTAINLY is a strong choice for Kubernetes-native organizations that want a modular, extensible platform and are willing to operate microservices. certctl is a better fit for teams that want full lifecycle management without the Kubernetes prerequisite.

### vs. KeyTalk

KeyTalk is a commercial (proprietary) PKI Certificate Key Management System from a Dutch company. It's sold as an on-premises appliance, cloud instance, or managed service.

- **Scope**: KeyTalk covers TLS/SSL, S/MIME email certificates, device authentication, and VPN certificates — broader certificate type coverage than certctl today (though certctl's S/MIME support is planned for v2.2.x).
- **CA support**: Both support multiple CAs. KeyTalk integrates with DigiCert and supports ACME, SCEP, and native CA APIs. certctl supports ACME, step-ca, Local CA, OpenSSL/custom scripts, and EST enrollment.
- **Agent model**: KeyTalk offers agent software for distributed deployment, similar to certctl's agent architecture.
- **Transparency**: KeyTalk's detailed technical documentation (connector list, policy engine capabilities, API surface, audit trail depth) is not publicly available — it's behind enterprise sales. certctl's entire codebase, API spec (OpenAPI 3.1), and documentation are public.
- **Pricing**: KeyTalk is commercial with no public pricing or free tier. certctl's V2 community edition is free with no certificate limit.
- **Best fit**: KeyTalk is positioned for enterprises that want a vendor-supported PKI platform covering multiple certificate types (TLS, S/MIME, device) and are willing to pay for proprietary software. certctl is a better fit for teams that want source-available software they can self-host, audit, and extend without vendor dependency.

### vs. Kubernetes cert-manager

cert-manager is the right choice if your entire infrastructure is Kubernetes. It's mature, well-maintained, and deeply integrated with the Kubernetes ecosystem.

certctl is the right choice if your infrastructure extends beyond Kubernetes — bare-metal servers, VMs, network appliances, Docker hosts, or any mix. certctl deploys to NGINX, Apache, and HAProxy directly, with Traefik and Caddy support planned. The agent model means certctl can reach any server you can SSH into.

certctl also provides features cert-manager doesn't: network certificate discovery (find all TLS certs on your network), a policy engine, an immutable audit trail, OCSP/CRL endpoints, and an MCP server for AI-assisted management.

### vs. Enterprise Platforms (Venafi, Keyfactor)

If your organization has the budget for Venafi or Keyfactor, they're comprehensive solutions with decades of enterprise features.

certctl targets the organizations that need 60% of those capabilities at 1% of the cost. Self-hosted, no per-certificate pricing, no vendor lock-in. The trade-off: no SSO/RBAC (yet — coming in certctl Pro), no F5/IIS target connectors (yet), no SLA-backed support.

## Getting Started

```bash
# Clone and start with Docker Compose (includes demo data)
git clone https://github.com/shankar0123/certctl.git
cd certctl/deploy
docker compose up -d

# Open the dashboard
open http://localhost:8443
```

The demo seeds 15 certificates, 5 agents, 5 deployment targets, discovery data, network scan targets, and pending approval jobs so you can explore every feature immediately.

See the [Quickstart Guide](quickstart.md) for a full walkthrough.

## License

certctl is licensed under the [Business Source License 1.1](../LICENSE). The licensed work is free to use for any purpose other than offering a competing managed service. The license converts to Apache 2.0 on March 1, 2033.

The source is available, auditable, and self-hostable. You own your data, your keys, and your deployment.
