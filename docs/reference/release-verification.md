# Release Verification

> Last reviewed: 2026-05-05

certctl ships signed, attested release artefacts on every `v*` tag. This guide covers verifying those signatures and attestations before deploying.

## What gets signed

Every `v*` tag publishes:

- Binaries: `certctl-agent`, `certctl-server`, `certctl-cli`, `certctl-mcp-server` for `linux|darwin × amd64|arm64`
- A `checksums.txt` covering every binary
- Per-binary SPDX-JSON SBOMs
- Cosign signatures (keyless OIDC, signing identity = the release workflow on a signed tag)
- SLSA Level 3 provenance

Container images on `ghcr.io/certctl-io/certctl-{server,agent}` are built with `docker/build-push-action` `provenance: mode=max` + `sbom: true` and additionally signed with Cosign at the image digest.

## Verification procedure

### 1. Verify SHA-256 checksums

```bash
sha256sum -c checksums.txt
```

### 2. Verify the Cosign signature on `checksums.txt`

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/certctl-io/certctl/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt
```

Every individual binary ships with its own `.sigstore.json` bundle (unified Sigstore bundle containing signature, certificate chain, and Rekor inclusion proof). Swap `checksums.txt` for any binary name and point `--bundle` at the matching `<binary>.sigstore.json` to verify it directly.

### 3. Verify SLSA Level 3 provenance on a binary

```bash
slsa-verifier verify-artifact \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/certctl-io/certctl \
  --source-tag v2.1.0 \
  certctl-agent-linux-amd64
```

Replace `v2.1.0` with the tag you're verifying.

### 4. Verify a container image signature and its SBOM / provenance attestations

```bash
IMAGE=ghcr.io/certctl-io/certctl-server:v2.1.0

cosign verify \
  --certificate-identity-regexp '^https://github\.com/certctl-io/certctl/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "$IMAGE"

# SBOM attestation (SPDX-JSON, emitted by docker/build-push-action)
cosign verify-attestation --type spdxjson \
  --certificate-identity-regexp '^https://github\.com/certctl-io/certctl/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "$IMAGE"

# SLSA provenance attestation (docker/build-push-action `provenance: mode=max`)
cosign verify-attestation --type slsaprovenance \
  --certificate-identity-regexp '^https://github\.com/certctl-io/certctl/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "$IMAGE"
```

## Why this matters

The keyless OIDC signing identity is `https://github.com/certctl-io/certctl/.github/workflows/release.yml@refs/tags/<tag>`. That regex anchor is what lets you trust the binary you're holding came from the certctl-io repo's release workflow on a signed tag, not from a fork or a malicious push.

If any of the verification commands above fail or produce unexpected output, do not deploy the artefact. File a security report per [the security policy](../operator/security.md#reporting-a-vulnerability).

## Related docs

- [Architecture](architecture.md) — overall system design
- [Security posture](../operator/security.md) — operator-facing security guidance
- [CI pipeline](../contributor/ci-pipeline.md) — what runs on every commit (the release pipeline is the same one)
