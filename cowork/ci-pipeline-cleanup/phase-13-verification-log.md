# Phase 13 Verification Log

> Captured against repo HEAD post-Phase-12 commit `453ba78` on 2026-04-30.

## All 22 ci-guards run on HEAD

```
PASS  B-1-orphan-crud.sh
PASS  D-1-D-2-statusbadge-phantom.sh
PASS  G-1-jwt-auth-literal.sh
PASS  G-2-api-key-hash-json.sh
PASS  G-3-env-docs-drift.sh
PASS  H-001-bare-from.sh
PASS  H-009-readme-jwt.sh
PASS  L-001-insecure-skip-verify.sh
PASS  L-1-bulk-action-loop.sh
PASS  M-012-no-root-user.sh
PASS  P-1-documented-orphan-fns.sh
PASS  S-1-hardcoded-source-counts.sh
PASS  S-2-strings-contains-err.sh
PASS  T-1-frontend-page-coverage.sh
PASS  U-2-plaintext-healthcheck.sh
PASS  U-3-migration-mount.sh
PASS  bundle-8-L-015-target-blank-rel-noopener.sh
PASS  bundle-8-L-019-dangerously-set-inner-html.sh
PASS  bundle-8-M-009-bare-usemutation.sh
PASS  digest-validity.sh
PASS  openapi-handler-parity.sh
PASS  test-naming-convention.sh
```

The two "intentionally-fail-on-bare-invocation" helper scripts:
- `vendor-e2e-skip-check.sh` — needs `test-output.log` argument (CI provides it); naked invocation correctly errors
- `coverage-pr-comment.sh` — no-ops gracefully when `PR_NUMBER` env var is unset

## Make targets pre-tag

```
make verify-docs:
  qa-doc-part-count: clean (56 == 56).
  qa-doc-seed-count: clean.
  verify-docs: PASS — safe to tag
```

`make verify` and `make verify-deploy` require Go + docker; sandbox can't run them. Operator pre-tag verification:

```bash
make verify         # required pre-commit
make verify-deploy  # optional pre-push
make verify-docs    # required pre-tag (verified above)
```

## ci.yml final shape

- Line count: **439** (down from baseline **1488** = -71%)
- Job boundaries verified at lines 13, 232, 278, 345, 409:
  - `go-build-and-test`
  - `frontend-build`
  - `helm-lint`
  - `deploy-vendor-e2e` (single job, was 12-job matrix)
  - `image-and-supply-chain` (NEW)
- Total status checks per push: **7** (5 CI + 2 CodeQL), down from baseline **19**.

## Phase commits (master ahead of v2.0.66)

```
453ba78 ci-pipeline-cleanup Phase 12: docs/ci-pipeline.md + bundle artefacts
ce987cc ci-pipeline-cleanup Phase 11: make verify-docs + verify-deploy targets
3a69600 ci-pipeline-cleanup Phase 10: coverage PR-comment action
19a5e43 ci-pipeline-cleanup Phases 7-9: image-and-supply-chain job
d0bc53b ci-pipeline-cleanup Phase 6 follow-up: IIS operator playbook + matrix doc
6f6de63 ci-pipeline-cleanup Phase 5+6: collapse vendor matrix; delete Windows matrix
71b2245 ci-pipeline-cleanup Phase 4: gofmt parity + go mod tidy drift
af72630 ci-pipeline-cleanup Phase 3: staticcheck hard-fail (SA1019 sites verified closed)
60f368e ci-pipeline-cleanup Phase 2: coverage thresholds → YAML manifest
5b7a022 ci-pipeline-cleanup Phase 1: extract 20 regression guards to scripts/ci-guards/
d57910c ci-pipeline-cleanup Phase 0: baseline + frozen decisions + Bundle II revisions
```

## Operator action items post-merge

1. **GitHub branch protection rule update** — required-checks list changes 19 → 7:
   ```
   Go Build & Test
   Frontend Build
   Helm Chart Validation
   deploy-vendor-e2e
   image-and-supply-chain
   Analyze (go)
   Analyze (javascript-typescript)
   ```
   Old-name checks (`deploy-vendor-e2e (<vendor>)` × 12, `deploy-vendor-e2e-windows (<vendor>)` × 2) won't appear on new PRs after the workflow change. Operator removes them from the required list.

2. **RAM-headroom verification** (frozen decision 0.14) — operator runs the collapsed `deploy-vendor-e2e` job on a one-off branch with `docker stats --no-stream` polling. If peak RSS > 12 GB, fall back to bucketed matrix per `cowork/ci-pipeline-cleanup/decisions-revised.md`. If ≤ 12 GB, current single-job design is the final shape.

3. **Tag** — operator picks the exact `v2.X.0` value (recommended: increment from `v2.0.66`). 11 phase commits land on master after the prior bundle's closing commit.

## Acceptance gate verified

All 19 ☐ items from the prompt's "Final acceptance gate" pass except the operator-only items (3 above). Bundle is shippable pending the operator action.
