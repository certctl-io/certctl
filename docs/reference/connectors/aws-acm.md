# AWS Certificate Manager (ACM) Target Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the AWS Certificate Manager
> (ACM) target connector. For the connector-development context
> (interface contract, registry, atomic deploy primitive shared
> across all targets), see the [connector index](index.md).
>
> **Note:** this is the **target** connector that deploys
> certificates *into* ACM for ALB / CloudFront / API Gateway / App
> Runner consumption. The **issuer** connector that pulls certs
> *from* AWS ACM Private CA is documented separately at
> [aws-acm-pca.md](aws-acm-pca.md).

## Overview

The AWS ACM target connector deploys certificates into AWS
Certificate Manager — the public AWS service that ALB /
CloudFront / API Gateway / App Runner consume by ARN. Closes the
"we terminate TLS at AWS, how do we get certctl-issued certs to
ALB?" question for cloud-first deployments. Rank 5 of the
2026-05-03 Infisical deep-research deliverable.

Implementation lives at `internal/connector/target/awsacm/`.

## When to use this connector

Use the AWS ACM target connector when:

- TLS terminates at AWS-managed edges (ALB, CloudFront, API
  Gateway, App Runner) and those services consume certs by ACM
  ARN.
- You want certctl to drive the rotation while Terraform /
  CloudFormation handles the ARN-to-resource attachment.
- You need short-lived IAM credentials (IRSA, instance profiles)
  rather than long-lived access keys.

Look elsewhere when:

- The target is an EC2 instance running NGINX / HAProxy / Apache
  directly — those connectors are simpler than the ACM round-trip.
- You're using ACM Private CA for internal trust — that's the
  [aws-acm-pca.md](aws-acm-pca.md) issuer, a different connector.

## Configuration

```json
{
  "region": "us-east-1",
  "certificate_arn": "arn:aws:acm:us-east-1:123456789012:certificate/abcdef01-2345-6789-abcd-ef0123456789",
  "tags": {"env": "production", "app": "api-gateway"}
}
```

| Field | Default | Description |
|---|---|---|
| `region` | (required) | AWS region for the ACM endpoint (e.g. `us-east-1`). CloudFront-attached certs MUST live in `us-east-1`; ALB / API Gateway use the same region as the load balancer. |
| `certificate_arn` | — | ARN of an existing ACM certificate to rotate in place. Empty on first deploy — the adapter creates a new ACM cert via `ImportCertificate` and the deployment record's Metadata captures the resulting ARN. Operators can also pre-create the ARN out-of-band (Terraform, CloudFormation) and pin it here. |
| `tags` | — | Tags applied to the ACM cert at first import + re-applied via `AddTagsToCertificate` on every subsequent import (ACM strips tags on re-import). The reserved keys `certctl-managed-by` and `certctl-certificate-id` are set automatically and cannot be overridden. |

## IAM policy (minimum permissions)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "acm:ImportCertificate",
      "acm:GetCertificate",
      "acm:DescribeCertificate",
      "acm:ListCertificates",
      "acm:AddTagsToCertificate"
    ],
    "Resource": "arn:aws:acm:*:*:certificate/*"
  }]
}
```

## Auth recipes

- **IRSA (IAM Roles for Service Accounts) — recommended for K8s
  deploys.** Annotate the agent's ServiceAccount with
  `eks.amazonaws.com/role-arn=arn:aws:iam::<account>:role/certctl-acm-deployer`.
  The role's trust policy allows the cluster's OIDC provider;
  permission policy is the JSON above. Short-lived STS
  credentials are auto-rotated by EKS — no long-lived access
  keys.
- **EC2 instance profile — recommended for VM-based agents.**
  Attach an instance profile referencing the same role. SDK's
  `LoadDefaultConfig` picks credentials up via the IMDS metadata
  service.
- **AWS SSO / `aws configure sso` — recommended for operator
  workstations.** SDK reads `~/.aws/config` for the SSO profile
  and refreshes tokens via the existing CLI session.
- **Long-lived access keys are NOT supported in connector
  Config** — the credential chain is configured at the SDK
  level, not the connector level. This is a procurement-
  readability decision: a security reviewer reading the
  `deployment_targets` table should never find an access key.

## Atomic-rollback contract

Every `DeployCertificate` snapshots the existing cert via
`DescribeCertificate` + `GetCertificate` BEFORE calling
`ImportCertificate` with the new bytes. After import, the
connector re-fetches the cert metadata and compares serial
numbers.

On serial-mismatch (post-verify failure), the connector calls
`ImportCertificate` again with the snapshotted bytes to restore
the previous cert. The rollback path emits a `WARN`-level slog
entry; the rollback's own success or failure is exposed via
`certctl_deploy_rollback_total{target_type="AWSACM",outcome="restored"|"also_failed"}`
per the deploy-hardening I Phase 10 metric exposer.

Mirrors the Bundle 5+ pre-deploy-snapshot pattern shipped for
IIS / WinCertStore / JavaKeystore.

## ALB attachment recipe

certctl creates / rotates the ACM cert; the operator (or
Terraform / CloudFormation) attaches it to the ALB listener
separately. For Terraform-driven deployments, look up the ARN by
tag:

```hcl
data "aws_acm_certificate" "certctl_managed" {
  domain      = "api.example.com"
  most_recent = true

  # Filter by certctl provenance tags so an unrelated ACM cert with
  # the same SAN doesn't get picked up.
  tags = {
    "certctl-managed-by"      = "certctl"
    "certctl-certificate-id"  = "mc-api-prod"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.api.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = data.aws_acm_certificate.certctl_managed.arn
  # ...
}
```

The ARN updates in place across renewals (ACM `ImportCertificate`
is upsert-style when given an ARN), so the ALB listener's
`certificate_arn` reference doesn't change. CloudFront / API
Gateway distributions can reference the same ARN via their
respective Terraform resources.

## Threat model carve-outs

- **Cert key bytes never written to disk on the agent.**
  `DeployCertificate` reads `request.KeyPEM` from memory and
  passes it to the SDK's `ImportCertificate` call. No temp file.
  No swap-out window.
- **Provenance tags are mandatory.** The reserved
  `certctl-managed-by=certctl` + `certctl-certificate-id=<mc-id>`
  pair is set automatically on every import. Operators
  identifying a stray ACM cert in their account can match
  against `certctl-managed-by` to confirm it was certctl-issued
  (or NOT — the absence of the tag means a manual import).
- **No long-lived AWS credentials in `Config`.** `Config`
  carries region + ARN + operator tags only. AWS auth is the
  SDK credential chain (IRSA / instance profile / SSO).
- **`ListCertificates` IAM permission is required for the V2
  ARN-discovery dance to work.** Operators who pin
  `Config.CertificateArn` after the first deploy can drop this
  permission; the V2 fallback emits a warning and reverts to
  "always create new ARN" if the operator forgets to update
  `certificate_arn` post-first-deploy.

## Procurement checklist crib

Paste into security review:

- certctl uses short-lived IAM-role credentials via IRSA /
  instance profile, not long-lived access keys.
- The cert key is held only in agent memory during the import
  call; never written to disk.
- Every imported ACM cert is tagged with
  `certctl-managed-by=certctl` +
  `certctl-certificate-id=<mc-id>` for forensic traceability.
- Failed imports trigger automatic rollback to the snapshotted
  previous cert; both outcomes are surfaced via Prometheus.
- The minimum IAM policy is 5 actions on
  `arn:aws:acm:*:*:certificate/*`; CloudTrail captures every
  API call for audit.

## ValidateOnly contract

ACM has no dry-run API for `ImportCertificate`; `ValidateOnly`
returns `target.ErrValidateOnlyNotSupported` per the deploy-
hardening I Phase 3 sentinel contract. Operators preview deploys
via `ValidateConfig` + `aws acm describe-certificate
--certificate-arn <arn>` against the current ARN.

## Related docs

- [Connector index](index.md) — interface contract, registry, deploy primitive
- [Azure Key Vault](azure-kv.md) — Azure equivalent target
- [AWS ACM Private CA issuer](aws-acm-pca.md) — the *issuer* counterpart (same vendor, opposite direction)
- [Cloud targets runbook](../../operator/runbooks/cloud-targets.md) — operator playbook covering both AWS ACM and Azure KV
