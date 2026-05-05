# AWS ACM Private CA Issuer Connector — Operator Deep-Dive

> Last reviewed: 2026-05-05
>
> Operator-grade documentation for the AWS Certificate Manager
> Private Certificate Authority (ACM PCA) issuer connector. For the
> connector-development context (interface contract, registry,
> ports/adapters), see the [connector index](index.md).

## Overview

AWS ACM Private CA is a managed private CA on AWS. The connector
calls `IssueCertificate` (which is asynchronous at the ACM PCA API
level), then runs the SDK's `NewCertificateIssuedWaiter` until the
cert reaches `CERTIFICATE_ISSUED` state, then `GetCertificate` to
retrieve the PEM. Default waiter timeout is 5 minutes; tune by
editing `defaultWaiterTimeout` in
`internal/connector/issuer/awsacmpca/awsacmpca.go`.

Implementation lives at `internal/connector/issuer/awsacmpca/`.

## When to use this connector

Use the AWS ACM PCA connector when:

- Your workloads are AWS-native and you want the CA to live inside
  your AWS account (for blast-radius, IAM, and audit reasons).
- You need ACM PCA's CRL distribution and OCSP responder to serve
  status to relying parties without certctl being in the OCSP path.
- You want IAM-based access control (no API keys to rotate) for
  certctl's signing path.

Look elsewhere when:

- You're not on AWS — Google CAS or Azure Key Vault are the cloud-
  native equivalents on those platforms.
- You need public-trust certificates — ACM PCA is private only.
- You don't already pay for ACM PCA (it has a non-trivial monthly
  cost). Vault, step-ca, or the Local CA issuer are free
  self-hosted alternatives.

## Configuration

| Setting | Required | Default | Description |
|---|---|---|---|
| `CERTCTL_AWS_PCA_REGION` | Yes | — | AWS region (e.g. `us-east-1`) |
| `CERTCTL_AWS_PCA_CA_ARN` | Yes | — | ARN of the ACM Private CA |
| `CERTCTL_AWS_PCA_SIGNING_ALGORITHM` | No | `SHA256WITHRSA` | Signing algorithm |
| `CERTCTL_AWS_PCA_VALIDITY_DAYS` | No | `365` | Certificate validity in days |
| `CERTCTL_AWS_PCA_TEMPLATE_ARN` | No | — | Optional certificate template ARN |

Supported signing algorithms: `SHA256WITHRSA`, `SHA384WITHRSA`,
`SHA512WITHRSA`, `SHA256WITHECDSA`, `SHA384WITHECDSA`,
`SHA512WITHECDSA`.

## Authentication

Standard AWS credential chain via
`aws-sdk-go-v2/config.LoadDefaultConfig()`. Resolves credentials in
this order:

1. Environment variables (`AWS_ACCESS_KEY_ID`,
   `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`).
2. Shared config files (`~/.aws/config`, `~/.aws/credentials`,
   profile via `AWS_PROFILE`).
3. IAM Roles for Service Accounts (IRSA) on EKS.
4. EC2 instance profiles.
5. ECS task roles.
6. SSO.

certctl never stores AWS credentials directly — set them in the
certctl process's environment or via the IAM role attached to the
host.

## Minimal IAM policy

The IAM principal that certctl authenticates as needs the following
actions against the CA's ARN:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "acm-pca:IssueCertificate",
        "acm-pca:GetCertificate",
        "acm-pca:RevokeCertificate",
        "acm-pca:GetCertificateAuthorityCertificate"
      ],
      "Resource": "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012"
    }
  ]
}
```

Replace the `Resource` ARN with your own CA ARN. If you use a
`TemplateArn` (subordinate-CA template), the policy needs no
additional permissions — `IssueCertificate` covers it.

## Worked example: add the issuer via API

```bash
curl -k -X POST https://localhost:8443/api/v1/issuers \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "iss-aws-prod",
    "name": "AWS ACM PCA (prod)",
    "type": "AWSACMPCA",
    "config": {
      "region": "us-east-1",
      "ca_arn": "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
      "signing_algorithm": "SHA256WITHRSA",
      "validity_days": 90
    }
  }'
```

The certctl server process must have AWS credentials available
before the issuer is created (or before any subsequent issuance
call). For a local dev run with shared-config creds:
`export AWS_PROFILE=my-profile` before `docker compose up`. For an
EKS deployment: attach an IRSA-bound IAM role to the certctl pod's
service account.

## Troubleshooting

### `AccessDeniedException: User ... is not authorized to perform: acm-pca:IssueCertificate`

The IAM principal certctl is using lacks the required actions.
Apply the IAM policy above (scoped to your CA ARN) to the
role/user. The principal can be inspected with
`aws sts get-caller-identity` from the certctl host.

### `ResourceNotFoundException: Could not find Certificate Authority`

The `CAArn` doesn't match any CA in the configured region. Common
causes: region mismatch (CA is in `us-west-2`, certctl region is
set to `us-east-1`), CA was deleted, ARN typo. Verify with
`aws acm-pca describe-certificate-authority --certificate-authority-arn <arn> --region <region>`.

### `acmpca waiter (waiting for issuance): exceeded max wait time`

The cert was submitted but didn't reach `CERTIFICATE_ISSUED` state
within 5 minutes. Check the CA's CloudWatch metrics for backlog;
check the CA's audit reports for any policy violations on the
request. If the wait is consistently slow, edit
`defaultWaiterTimeout` in
`internal/connector/issuer/awsacmpca/awsacmpca.go` and rebuild.

## Revocation

CRL and OCSP are managed by AWS ACM PCA directly. certctl records
revocations locally and notifies AWS via the `RevokeCertificate`
API with RFC 5280 reason mapping (e.g. `keyCompromise` →
`KEY_COMPROMISE`). AWS ACM PCA's CRL distribution point and OCSP
responder serve the resulting status to verifying clients —
certctl is **not** in the OCSP path for this connector.

## Related docs

- [Connector index](index.md) — interface contract, registry, port/adapter wiring
- [Async CA polling](../protocols/async-ca-polling.md) — bounded-polling primitive (ACM PCA uses the SDK waiter, not certctl's polling, but the same operator concerns apply)
- [Disaster recovery runbook](../../operator/runbooks/disaster-recovery.md) — what happens to ACM PCA-issued certs if the CA is deleted
