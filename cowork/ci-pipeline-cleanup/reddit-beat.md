# Reddit / HN announce — ci-pipeline-cleanup

> Don't auto-post. Operator times manually after the tag lands.

## r/devops / r/golang

> **certctl 2.X.0 — CI pipeline cleanup: 19 status checks → 7, ci.yml -71%**
>
> Open-source Go cert lifecycle tool. v2.X.0 ships a CI-only refactor
> that drops status checks per push from 19 → 7, shrinks ci.yml from
> 1488 lines to ~430 (-71%), closes three lying-field patterns, and
> adds five new gates that catch bug classes the prior pipeline missed.
>
> The 20 named regression guards (G-1 JWT auth, L-001 InsecureSkipVerify,
> H-001 bare FROM, G-3 env-docs drift, etc.) extracted from inline
> ci.yml bash to sibling scripts/ci-guards/<id>.sh — each callable
> locally as `bash scripts/ci-guards/<id>.sh`. Adding a new guard:
> drop a new script; CI loop auto-picks it up.
>
> Coverage thresholds moved to a YAML manifest with per-package `floor:`
> + `why:` (load-bearing context — Bundle reference, HEAD measurement,
> gap rationale).
>
> Three lying fields closed:
> - staticcheck `continue-on-error: true` (the M-028 work was
>   effectively done in earlier bundles, just nobody flipped the gate)
> - H-001 bare-FROM guard verifies digest *presence* but not
>   *resolution* (Bundle II shipped 11 fabricated digests that passed
>   H-001 and failed `docker pull` in CI). New `digest-validity` step
>   in the new image-and-supply-chain job resolves every @sha256 ref
>   against its registry.
> - Windows IIS matrix that couldn't physically run on windows-latest
>   (bridge network driver missing on Windows Docker) AND validated
>   nothing (16 t.Log placeholders). Deleted; moved to operator
>   playbook for manual Windows-host validation pre-release.
>
> Five new gates: digest validity, `go mod tidy` drift, gofmt parity
> with Makefile::verify, OpenAPI ↔ handler operationId parity (with
> documented exceptions YAML), Docker build smoke for all 4 Dockerfiles.
>
> Repo: <github>/certctl. Operator guide: docs/ci-pipeline.md.

## Hacker News

> **certctl: CI pipeline cleanup — 19 status checks → 7, ci.yml -71%**
>
> Open-source cert lifecycle tool. v2.X.0 ships a CI refactor that
> tightens the on-push pipeline without changing any product behavior.
>
> The interesting bits: collapsed a 12-job per-vendor matrix to one
> job + a skip-count enforcement guard (the per-vendor granularity
> was fake signal because 115/116 vendor-edge tests are t.Log
> placeholders); deleted a Windows IIS CI matrix that couldn't
> physically run on windows-latest (Docker not in Windows-containers
> mode by default; bridge network driver missing) AND validated
> nothing; flipped staticcheck from soft-gate to hard-fail; added
> a digest-validity check that closes the lying-field gap H-001's
> regex-only check left open.
>
> Coverage thresholds in a YAML manifest with per-package `why:`
> context. 20 regression guards as standalone scripts, each
> callable locally. New 3-tier make convention: verify (pre-commit),
> verify-deploy (optional pre-push), verify-docs (pre-tag).

## Discord (announcement channel template)

> 🚀 v2.X.0 ships ci-pipeline-cleanup — 19 status checks → 7,
> ci.yml -71%, 3 lying fields closed, 5 new gates.
>
> docs/ci-pipeline.md is the new operator guide. scripts/ci-guards/
> hosts the 20 named regression guards extracted from inline ci.yml
> bash. .github/coverage-thresholds.yml is the per-package floor
> manifest. cowork/ci-pipeline-cleanup/ has the bundle artefacts.
