# Release Sign-Off

> Last reviewed: 2026-05-05

Release-day checklist for tagging a new certctl release. Walks through the gates that must be green before pushing the tag, in the order they should be verified.

## Pre-release: code state

| Gate | How to check | Pass |
|---|---|---|
| `master` is at the commit you intend to tag | `git log -1 --format='%H %s'` | ☐ |
| Working tree clean | `git status -sb` | ☐ |
| Local matches GitHub | `curl -sS https://api.github.com/repos/certctl-io/certctl/commits/master \| grep -oE '"sha": "[a-f0-9]+"' \| head -1` matches local | ☐ |
| `WORKSPACE-CHANGELOG.md` updated with the release's milestones | manual review | ☐ |
| `certctl/CHANGELOG.md` updated (release-facing) | manual review | ☐ |
| Migration ladder ends cleanly | `ls migrations/*.up.sql \| sort \| tail -3` shows the right last migration | ☐ |

## Pre-release: automated gates (CI)

| Gate | How to check | Pass |
|---|---|---|
| CI pipeline green on the tag-target commit | GitHub Actions web UI | ☐ |
| `make verify` clean locally | run from repo root | ☐ |
| `go test -race -count=1 ./...` clean | full race check | ☐ |
| `golangci-lint run ./...` clean | local lint | ☐ |
| `govulncheck ./...` clean | vulnerability scan | ☐ |
| Coverage thresholds met (service ≥55%, handler ≥60%, domain ≥40%, middleware ≥30%) | `go test -coverprofile=cover.out ./... && go tool cover -func=cover.out` | ☐ |
| Frontend type-check + Vitest + Vite build clean | `cd web && npm run typecheck && npm run test && npm run build` | ☐ |

## Pre-release: manual QA passes

| Surface | Checklist | Pass |
|---|---|---|
| Local stack boots clean from scratch | `qa-prerequisites.md` Steps 1-4 green | ☐ |
| GUI QA checklist | `gui-qa-checklist.md` end to end | ☐ |
| End-to-end test environment | `test-environment.md` Steps 1-14 green | ☐ |
| Performance baselines | `performance-baselines.md` four spot checks within bounds | ☐ |
| Helm chart deploys clean | `helm-deployment.md` install + verify | ☐ |
| ACME server interop (cert-manager) | `make acme-cert-manager-test` green | ☐ |
| ACME server RFC conformance (lego) | `make acme-rfc-conformance-test` green | ☐ |

## Release artefact verification

After the release workflow runs (triggered by tag push), verify the published artefacts:

| Artefact | How to verify | Pass |
|---|---|---|
| Cosign keyless OIDC signature on `checksums.txt` | per `docs/reference/release-verification.md` step 2 | ☐ |
| SLSA Level 3 provenance on each binary | step 3 | ☐ |
| Container image signature + SBOM + provenance | step 4 | ☐ |
| Release notes published on GitHub Releases page | manual review | ☐ |
| ghcr.io images at `ghcr.io/certctl-io/certctl-{server,agent}:<tag>` pullable | `docker pull` round-trips | ☐ |

## Branch protection + tag push

| Gate | How to check | Pass |
|---|---|---|
| `master` branch protection rule allows the tag push | Repository Settings → Branches | ☐ |
| Tag pushed | `git tag -s v<version> -m 'Release v<version>'; git push origin v<version>` | ☐ |
| Release workflow kicked off in GitHub Actions | watch the Actions tab | ☐ |

## Post-release

| Gate | How to check | Pass |
|---|---|---|
| Release workflow completed without errors | GitHub Actions | ☐ |
| Sample binary downloaded and Cosign-verified by an operator who is not the release author | another team member | ☐ |
| `WORKSPACE-CHANGELOG.md` notes the tag commit SHA | manual edit | ☐ |
| `cowork/CLAUDE.md` "Active Focus" → "Current tag" updated | manual edit | ☐ |
| `certctl.io/index.html` star count + `data-gh-version` rendering picks up the new tag | open the landing page in 6+ hours (cache TTL) | ☐ |
| Reddit / Hacker News / LinkedIn announcement drafted (if a major release) | per the operator's promotion playbook | ☐ |

## If a gate fails

Revert the tag push immediately:

```bash
git push --delete origin v<version>
git tag -d v<version>
```

Investigate, fix, re-tag.

## Related docs

- [`docs/contributor/qa-prerequisites.md`](qa-prerequisites.md) — local stack prereqs
- [`docs/contributor/test-environment.md`](test-environment.md) — full local environment tutorial
- [`docs/contributor/gui-qa-checklist.md`](gui-qa-checklist.md) — GUI manual QA pass
- [`docs/contributor/testing-strategy.md`](testing-strategy.md) — what we test in CI vs deep-scan vs manual QA
- [`docs/contributor/ci-pipeline.md`](ci-pipeline.md) — CI shape and regression guards
- [`docs/operator/performance-baselines.md`](../operator/performance-baselines.md) — performance regression spot checks
- [`docs/operator/helm-deployment.md`](../operator/helm-deployment.md) — Helm install + verify
- [`docs/reference/release-verification.md`](../reference/release-verification.md) — Cosign / SLSA / SBOM verification procedure
