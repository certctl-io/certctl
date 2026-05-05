# certctl Documentation

> Last reviewed: 2026-05-05

The full docs index, organized by audience. Pick the section that matches what you need to do; each link below opens a focused doc rather than a wall of text.

For the elevator pitch and quickstart commands, see the repo `README.md` at the root. For the marketing site, see [certctl.io](https://certctl.io).

---

## Getting Started

You're new to certctl, just cloned the repo, or want to understand what it does before installing.

| Doc | What it covers |
|---|---|
| [Concepts](getting-started/concepts.md) | TLS certificates explained for beginners — CAs, ACME, EST, private keys, the full glossary |
| [Quickstart](getting-started/quickstart.md) | Five-minute setup with Docker Compose, dashboard tour, API tour |
| [Examples](getting-started/examples.md) | Five turnkey scenarios — ACME+NGINX, wildcard DNS-01, private CA+Traefik, step-ca+HAProxy, multi-issuer |
| [Advanced demo](getting-started/advanced-demo.md) | End-to-end certificate lifecycle with technical depth at each step |
| [Why certctl](getting-started/why-certctl.md) | Positioning vs ACME clients, agent-based SaaS, enterprise platforms; when to look elsewhere |

## Reference

You're operating certctl in production or building integrations and need authoritative technical detail.

| Doc | What it covers |
|---|---|
| [Architecture](reference/architecture.md) | System design, data flow, security model, deployment topologies |
| [API](reference/api.md) | OpenAPI 3.1 spec, integration patterns, client SDK generation |
| [CLI](reference/cli.md) | certctl-cli command reference and CI/CD integration patterns |
| [MCP server](reference/mcp.md) | Model Context Protocol integration for AI assistants |
| [Release verification](reference/release-verification.md) | Cosign / SLSA / SBOM verification procedure |
| [Intermediate CA hierarchy](reference/intermediate-ca-hierarchy.md) | Multi-level CA tree management — RFC 5280 §3.2/§4.2.1.9/§4.2.1.10 enforcement |
| [Deployment model](reference/deployment-model.md) | Atomic write, post-deploy verify, rollback semantics across all targets |
| [Vendor matrix](reference/vendor-matrix.md) | Tested vendor versions per target connector |

### Connectors

The [connector index](reference/connectors/index.md) is the canonical catalog (interfaces, registry, scanners, plus an inline reference per built-in). Per-connector deep-dive siblings cover operator-grade material — vendor edges, troubleshooting, rotation playbooks, when-to-use vs alternatives.

**Issuers** (13 deep-dives): [ACME](reference/connectors/acme.md) · [ADCS](reference/connectors/adcs.md) · [AWS ACM Private CA](reference/connectors/aws-acm-pca.md) · [DigiCert](reference/connectors/digicert.md) · [EJBCA / Keyfactor](reference/connectors/ejbca.md) · [Entrust](reference/connectors/entrust.md) · [GlobalSign Atlas HVCA](reference/connectors/globalsign.md) · [Google CAS](reference/connectors/google-cas.md) · [Local CA](reference/connectors/local-ca.md) · [OpenSSL / Custom CA](reference/connectors/openssl.md) · [Sectigo SCM](reference/connectors/sectigo.md) · [step-ca / Smallstep](reference/connectors/step-ca.md) · [Vault PKI](reference/connectors/vault.md)

**Targets** (15 deep-dives): [Apache](reference/connectors/apache.md) · [AWS Certificate Manager](reference/connectors/aws-acm.md) · [Azure Key Vault](reference/connectors/azure-kv.md) · [Caddy](reference/connectors/caddy.md) · [Envoy](reference/connectors/envoy.md) · [F5 BIG-IP](reference/connectors/f5.md) · [HAProxy](reference/connectors/haproxy.md) · [IIS](reference/connectors/iis.md) · [Java Keystore](reference/connectors/jks.md) · [Kubernetes Secrets](reference/connectors/k8s.md) · [NGINX](reference/connectors/nginx.md) · [Postfix / Dovecot](reference/connectors/postfix.md) · [SSH (agentless)](reference/connectors/ssh.md) · [Traefik](reference/connectors/traefik.md) · [Windows Certificate Store](reference/connectors/wincertstore.md)

### Protocols

| Doc | What it covers |
|---|---|
| [ACME server](reference/protocols/acme-server.md) | Run certctl as an RFC 8555 + RFC 9773 ARI ACME server |
| [ACME server threat model](reference/protocols/acme-server-threat-model.md) | Security posture for the ACME server endpoint |
| [SCEP server](reference/protocols/scep-server.md) | RFC 8894 native SCEP server — RA cert config, multi-profile dispatch, must-staple, mTLS sibling route |
| [SCEP for Microsoft Intune](reference/protocols/scep-intune.md) | Intune-specific deployment guide — NDES replacement playbook |
| [EST server](reference/protocols/est.md) | RFC 7030 EST server — 802.1X / Wi-Fi enrollment, IoT bootstrap, channel binding |
| [CRL & OCSP](reference/protocols/crl-ocsp.md) | RFC 5280 CRL + RFC 6960 OCSP responder for relying parties |
| [Async CA polling](reference/protocols/async-ca-polling.md) | Bounded polling for async-CA issuer connectors |

## Operator

You're running certctl in production and need operational guidance.

| Doc | What it covers |
|---|---|
| [Security posture](operator/security.md) | Auth, rate limits, encryption at rest, key rotation |
| [Control plane TLS](operator/tls.md) | Self-signed bootstrap, operator-supplied Secret, cert-manager Certificate CR |
| [Database TLS](operator/database-tls.md) | PostgreSQL transport encryption |
| [Approval workflow](operator/approval-workflow.md) | Two-person integrity gate for high-stakes issuance |
| [Helm deployment](operator/helm-deployment.md) | Kubernetes installation via the bundled chart |
| [Performance baselines](operator/performance-baselines.md) | Operator-runnable benchmarks for regression spot checks |
| [Legacy clients (TLS 1.2)](operator/legacy-clients-tls-1.2.md) | Reverse-proxy runbook for embedded EST/SCEP clients on TLS 1.2 |

### Runbooks

| Runbook | When |
|---|---|
| [Cloud targets](operator/runbooks/cloud-targets.md) | AWS ACM + Azure Key Vault deployment, debugging, rollback |
| [Expiry alerts](operator/runbooks/expiry-alerts.md) | Per-policy multi-channel routing matrix, severity tiers |
| [Disaster recovery](operator/runbooks/disaster-recovery.md) | CRL cache, OCSP responder cert, CA private-key rotation, Postgres restore |

## Migration

You're moving from another cert-management tool to certctl, or running both in parallel.

| From | Doc |
|---|---|
| Certbot | [migration/from-certbot.md](migration/from-certbot.md) |
| acme.sh | [migration/from-acmesh.md](migration/from-acmesh.md) |
| cert-manager (coexistence, not replacement) | [migration/cert-manager-coexistence.md](migration/cert-manager-coexistence.md) |
| Caddy ACME (point Caddy at certctl) | [migration/acme-from-caddy.md](migration/acme-from-caddy.md) |
| cert-manager ACME (point cert-manager at certctl) | [migration/acme-from-cert-manager.md](migration/acme-from-cert-manager.md) |
| Traefik ACME (point Traefik at certctl) | [migration/acme-from-traefik.md](migration/acme-from-traefik.md) |

## Compliance

You're working through a SOC 2, PCI, or NIST audit and need to map certctl's capabilities to control objectives.

| Doc | What it covers |
|---|---|
| [Compliance overview](compliance/index.md) | What these guides cover and what they don't |
| [SOC 2 Type II](compliance/soc2.md) | Trust Service Criteria mapping (CC6, CC7, CC8, A1) |
| [PCI-DSS 4.0](compliance/pci-dss.md) | Requirements 3, 4, 6, 7, 8, 10 |
| [NIST SP 800-57](compliance/nist-sp-800-57.md) | Key management alignment with NIST guidance |

## Contributor

You're contributing to certctl, running tests locally, or trying to understand the CI pipeline.

| Doc | What it covers |
|---|---|
| [Testing strategy](contributor/testing-strategy.md) | What we test and why; per-PR fast gates vs daily deep-scan |
| [Test environment](contributor/test-environment.md) | Local environment with real CAs (Pebble, step-ca, etc.) |
| [QA prerequisites](contributor/qa-prerequisites.md) | Before running QA: stack boot, demo data baseline, env vars |
| [QA test suite](contributor/qa-test-suite.md) | qa_test.go reference for release QA |
| [GUI QA checklist](contributor/gui-qa-checklist.md) | Manual GUI verification pass for release |
| [Release sign-off](contributor/release-sign-off.md) | Release-day checklist — code state, automated gates, manual QA, artefact verification |
| [CI pipeline](contributor/ci-pipeline.md) | CI shape, regression guards, adding new checks |

## Archive

Historical docs preserved for reference. Most operators don't need these.

| Doc | Why archived |
|---|---|
| [Upgrade to TLS (v2.2)](archive/upgrades/to-tls-v2.2.md) | Pre-v2.2 HTTPS-everywhere upgrade procedure |
| [Upgrade past v2 JWT removal](archive/upgrades/to-v2-jwt-removal.md) | G-1 milestone JWT auth removal procedure |

---

## Reading order by role

**First-time operator:** [Concepts](getting-started/concepts.md) → [Quickstart](getting-started/quickstart.md) → [Examples](getting-started/examples.md). About 90 minutes end to end.

**Production operator:** [Architecture](reference/architecture.md) → [Security posture](operator/security.md) → [Control plane TLS](operator/tls.md) → [Disaster recovery runbook](operator/runbooks/disaster-recovery.md). About 4 hours end to end.

**PKI engineer:** [ACME server](reference/protocols/acme-server.md) → [SCEP server](reference/protocols/scep-server.md) → [EST server](reference/protocols/est.md) → [Intermediate CA hierarchy](reference/intermediate-ca-hierarchy.md). About 6 hours end to end.

**Auditor / compliance team:** [Compliance overview](compliance/index.md) → applicable framework doc → [Disaster recovery runbook](operator/runbooks/disaster-recovery.md) → [Approval workflow](operator/approval-workflow.md) → [ACME server threat model](reference/protocols/acme-server-threat-model.md). About 4 hours end to end.

**Contributor:** [Architecture](reference/architecture.md) → [Testing strategy](contributor/testing-strategy.md) → [Test environment](contributor/test-environment.md) → [CI pipeline](contributor/ci-pipeline.md). About 3 hours end to end.
