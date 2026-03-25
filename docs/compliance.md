# Compliance Mapping Guides

certctl is a certificate lifecycle management tool, not a compliance product. It doesn't make you compliant — your organization, policies, and processes do that. What certctl provides is tooling that supports the technical controls auditors and evaluators look for when assessing certificate and key management practices.

These guides map certctl's features to three widely referenced compliance frameworks. They're designed for security engineers, IT auditors, and procurement teams evaluating certctl for environments with regulatory requirements.

## What's Covered

**[SOC 2 Type II](compliance-soc2.md)** — Maps certctl features to AICPA Trust Service Criteria. Covers logical access controls (CC6), system operations and monitoring (CC7), change management (CC8), and availability (A1). Most relevant for organizations undergoing SOC 2 audits where certificate management is in scope.

**[PCI-DSS 4.0](compliance-pci-dss.md)** — Maps certctl features to PCI Data Security Standard version 4.0 requirements. Covers data-in-transit protection (Req 4), cryptographic key management (Req 3), authentication (Req 8), audit logging (Req 10), secure development (Req 6), and access control (Req 7). Most relevant for organizations handling cardholder data where TLS certificates protect transmission channels.

**[NIST SP 800-57](compliance-nist.md)** — Maps certctl's key management practices to NIST Special Publication 800-57 Part 1 Rev 5 (2020). Covers key generation, storage, cryptoperiods, key state lifecycle, algorithm selection, key transport, and revocation. Most relevant for organizations aligning with US federal cryptographic guidance or using NIST as a key management baseline.

## What These Guides Are Not

These are mapping guides, not certification claims. certctl is not SOC 2 certified, PCI-DSS validated, or NIST-assessed. The guides document how certctl's technical implementation supports the controls these frameworks require — they do not replace your auditor's assessment, your organization's policies, or your security team's judgment.

The guides also clearly identify gaps where certctl's current implementation doesn't fully align with a framework's recommendations, features planned for future versions, and areas where operator action is required regardless of what certctl provides.

## How to Use These Guides

If you're evaluating certctl for a regulated environment, start with the framework your auditor cares about. Each guide includes an evidence summary table mapping specific compliance criteria to certctl features, API endpoints, and configuration — the kind of specifics your auditor will ask for.

If you're preparing for an audit and certctl is already deployed, use the "Operator Responsibilities" section of each guide to identify what your organization must manage beyond what certctl provides.

## Quick Reference

| Framework | Primary Concern | Key certctl Features |
|---|---|---|
| SOC 2 Type II | Trust service criteria for SaaS/infrastructure | API audit trail, auth controls, monitoring, change management |
| PCI-DSS 4.0 | Cardholder data protection | TLS lifecycle, key management, immutable logging, access control |
| NIST SP 800-57 | Cryptographic key management | Agent-side keygen, key isolation, algorithm selection, revocation |

## certctl Pro (V3) Enhancements

Several compliance-relevant features are planned for certctl Pro:

- **OIDC/SSO** — Enterprise identity provider integration (SOC 2 CC6.1, PCI-DSS 8.3)
- **RBAC** — Role-based access control with admin/operator/viewer roles (SOC 2 CC6.3, PCI-DSS 7.2)
- **NATS Audit Streaming** — Real-time audit event streaming to SIEM systems (SOC 2 CC7.2, PCI-DSS 10.2)
- **Bulk Revocation** — Fleet-wide incident response capability (NIST SP 800-57 Section 5.4)
- **Health/Compliance Scoring** — Automated compliance posture assessment per certificate
