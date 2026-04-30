# CI Pipeline Cleanup — Frozen Decisions

> 14 frozen decisions confirmed at Phase 0. Each subsequent Phase references the decision number it implements.

## 0.1 — Trigger model

Three-tier split, no mixing:
- **On push/PR to master:** blocking, fast, every check earns its keep, target <10 min wall-clock.
- **Daily cron + workflow_dispatch:** `security-deep-scan.yml` as-is; slow scans, best-effort, never blocks.
- **On tag push (`v*`):** `release.yml` as-is; cross-platform binaries, ghcr.io push, SLSA provenance.

## 0.2 — Extracted-script location

`scripts/ci-guards/` at repo root. Operator runs `bash scripts/ci-guards/<id>.sh` locally. Contract documented in `scripts/ci-guards/README.md`.

## 0.3 — Coverage threshold YAML format

`.github/coverage-thresholds.yml`. Top-level keys are package paths; each entry has `floor:` (integer pct) + `why:` (multi-line string for load-bearing context). Bash step uses Python (already on the runner) to read the YAML — no `yq` dependency.

## 0.4 — Vendor matrix collapse policy (REVISES Bundle II decision 0.9)

Single `deploy-vendor-e2e` job replaces 12-job matrix. Bundle II decision 0.9 said "Each vendor e2e gets its own GitHub Actions matrix job" — this revision recognizes that 115/116 vendor-edge tests are `t.Log` placeholders, so per-vendor status-check granularity is fake signal. Skip-detection guard partially restores per-vendor visibility (SKIP messages name the vendor). Documented as deliberate revision in `cowork/ci-pipeline-cleanup/decisions-revised.md`.

## 0.5 — Windows IIS validation deletion (REVISES Bundle II decision 0.4)

Delete `deploy-vendor-e2e-windows` matrix entirely. Bundle II decision 0.4 said "the IIS e2e suite runs on a separate Windows-runner CI matrix job" — this revision recognizes that (a) the matrix can't physically work on `windows-latest` (Docker not started in Windows-containers mode; `bridge` driver missing on Windows Docker), and (b) all 16 IIS + WinCertStore tests are `t.Log` placeholders. Move validation to `docs/connector-iis.md::Operator validation playbook` per Bundle II decision 0.14's third criterion. The `windows-iis-test` sidecar stays in `deploy/docker-compose.test.yml` for operator local use.

## 0.6 — Skip-detection guard semantics + EXPECTED_SKIPS allowlist

After `go test -tags integration -run 'VendorEdge_'`, count `^--- SKIP:` lines. Allowlist: 6 JavaKeystore tests in `vendor_e2e_phase3_to_13_test.go` that legitimately t.Log without sidecar. Allowlist file at `scripts/ci-guards/vendor-e2e-skip-allowlist.txt`, one test name per line.

## 0.7 — SA1019 closure approach

Close each site individually with byte-equivalence tests where the deprecated API was load-bearing. Then flip `continue-on-error: true` → `false` in the SAME commit. Do NOT split — shipping the gate without closing sites would fail CI on master. Live verification: `staticcheck ./... 2>&1 | grep -c SA1019` returns 0 BEFORE flipping the gate.

## 0.8 — Image-and-supply-chain placement

Separate top-level job (not steps in `go-build-and-test`). Two reasons: (a) digest-validity needs network egress to multiple registries (Docker Hub, ghcr.io, mcr.microsoft.com), bundling into go-build blocks Go tests on registry latency. (b) `docker build` is parallel to Go tests; isolating lets it run concurrently.

## 0.9 — Coverage PR-comment provider

Default: lightweight self-hosted action that posts a per-PR comment via `gh pr comment`. Avoids paid SaaS. Operator can swap to Codecov/Coveralls later.

## 0.10 — Docker build smoke scope

Build all 4 Dockerfiles in the repo: `Dockerfile`, `Dockerfile.agent`, `deploy/test/f5-mock-icontrol/Dockerfile`, `deploy/test/libest/Dockerfile`. The test-sidecar Dockerfiles are load-bearing for vendor-e2e — a syntax error there silently breaks the e2e suite. Tagged `:smoke` and discarded.

## 0.11 — OpenAPI ↔ handler parity exception YAML

NEW `api/openapi-handler-exceptions.yaml`. Schema: `documented_exceptions:` list of `{route, why}` entries. The 13-route gap at HEAD is root-caused in Phase 9; most are likely health probes / metrics / SCEP-EST-OCSP wire endpoints that legitimately have no operationId.

## 0.12 — Branch-protection-rule update timing

Operator updates GitHub branch-protection rules in Phase 13 AFTER the new pipeline ships and runs green on a feature branch + on the first push to master. Required-checks list changes from 19 → 7 entries. Operator action only — agent cannot do this.

## 0.13 — Make-target naming for new operator-side scripts

- `make verify` (existing) — required pre-commit; gofmt + vet + lint + tests
- `make verify-deploy` (new) — optional pre-push; digest-validity + OpenAPI parity + docker build smoke (server + agent only — fast subset for local)
- `make verify-docs` (new) — required pre-tag; QA-doc Part-count + seed-count drift

## 0.14 — RAM headroom verification methodology

Phase 0 deliverable. Operator creates `prototype/ci-pipeline-cleanup-vendor-collapse` branch, runs the collapsed `deploy-vendor-e2e` job once, captures peak RSS via `docker stats --no-stream` snapshots every 30 sec, records max in this baseline doc. If max > 12 GB (75% of 16 GB ceiling), fall back to bucketed matrix (3 jobs × ~4 sidecars). If max ≤ 12 GB, single-job collapse is approved.
