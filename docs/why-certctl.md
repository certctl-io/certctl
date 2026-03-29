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

### 3. Post-Deployment Verification

Every other tool in this space stops at "the deployment command succeeded." certctl goes further: after deploying a certificate to a target, the agent connects back to the target's TLS endpoint and verifies the served certificate matches what was deployed, using SHA-256 fingerprint comparison.

A reload command can exit 0 while the certificate doesn't take effect — wrong virtual host, stale cache, config that validates but doesn't apply. certctl catches this.

## How certctl Compares

### vs. CertKit

Closest competitor architecturally — agent-based, private key isolation (Keystore), multi-platform. certctl leads on issuer coverage (ACME + step-ca + Local CA + OpenSSL + EST vs. ACME-only), PKI compliance (CRL, OCSP, RFC 5280 revocation, immutable audit trail — all missing from CertKit today), policy engine (5 rule types vs. none), and network discovery (CIDR TLS scanning vs. none). certctl is source-available (BSL 1.1 → Apache 2.0) with no cert limit; CertKit is proprietary SaaS with a 3-cert free tier. Where CertKit leads: more deployment targets today (adds LiteSpeed, IIS, auto-detection), Windows support, Kubernetes, and polished SaaS onboarding.

### vs. KeyTalk

Commercial (proprietary) PKI platform from a Dutch company — on-prem appliance, cloud, or managed service. Broader cert type coverage (TLS, S/MIME, device auth, VPN) and DigiCert + SCEP integrations. No public documentation on policy engine, API surface, or audit capabilities. No free tier, no public pricing. certctl trades breadth of cert types for full transparency — source-available, public API spec, free community edition with no limits.

### vs. Enterprise Platforms (Venafi, Keyfactor)

Comprehensive solutions with decades of features — at $75K-$250K+/yr. certctl targets organizations that need 80% of those capabilities at 1% of the cost. The trade-off: no SSO/RBAC yet (coming in certctl Pro), no F5/IIS target connectors yet, no SLA-backed support.

## Getting Started

```bash
# Clone and start with Docker Compose (includes demo data)
git clone https://github.com/shankar0123/certctl.git
cd certctl/deploy
docker compose up -d

# Open the dashboard
open http://localhost:8443
```

The demo seeds 35 certificates across 5 issuers, 8 agents, 8 deployment targets, 90 days of job history, discovery scan data, network scan targets, and pending approval jobs so you can explore every feature immediately.

See the [Quickstart Guide](quickstart.md) for a full walkthrough.

## License

certctl is licensed under the [Business Source License 1.1](../LICENSE). The licensed work is free to use for any purpose other than offering a competing managed service. The license converts to Apache 2.0 on March 1, 2033.

The source is available, auditable, and self-hostable. You own your data, your keys, and your deployment.
