# CI Pipeline Cleanup — Phase 0 Baseline

> Captured against repo HEAD `1de61e91cf07449356d9046a76499c86efe413b1` (operator tag `v2.0.66`) on 2026-04-30.
> Each subsequent Phase that changes a number references this baseline.

## Repo state

**HEAD SHA:** `1de61e91cf07449356d9046a76499c86efe413b1`

**Operator-stamped tag:** `v2.0.66`

## ci.yml shape

- Total lines: `1488`
- Total named steps: `53`
- Named regression-guard steps: 22 (enumerated below)

### The 22 regression-guard steps

```
81:      - name: Forbidden auth-type literal regression guard (G-1)
144:      - name: Forbidden bare InsecureSkipVerify regression guard (L-001)
180:      - name: Forbidden bare FROM regression guard (H-001)
201:      - name: Forbidden missing USER regression guard (M-012)
228:      - name: Forbidden README JWT advertising regression guard (H-009)
254:      - name: Forbidden api_key_hash JSON-shape regression guard (G-2)
311:      - name: Forbidden plaintext HEALTHCHECK regression guard (U-2)
360:      - name: Forbidden migration mount in compose initdb (U-3)
417:      - name: Forbidden StatusBadge dead-key + TS phantom-field regression guard (D-1 + D-2)
569:      - name: Forbidden client-side bulk-action loop regression guard (L-1)
613:      - name: Forbidden orphan-CRUD client function regression guard (B-1)
665:      - name: Forbidden strings.Contains(err.Error()) regression guard (S-2)
868:      - name: QA-doc Part-count drift guard
886:      - name: QA-doc seed-count drift guard
938:      - name: Test-naming convention guard (hard-fail)
982:      - name: Forbidden hardcoded source-count prose regression guard (S-1)
1027:      - name: Documented orphan client fns sync guard (P-1)
1063:      - name: Frontend page-coverage regression guard (T-1)
1118:      - name: Bundle-8 / L-015 target=_blank rel=noopener regression guard
1147:      - name: Bundle-8 / L-019 dangerouslySetInnerHTML regression guard
1176:      - name: Bundle-8 / M-009 + M-029 Pass 1 mutation contract guard (hard zero)
1220:      - name: Forbidden env-var docs drift regression guard (G-3)
```

## SA1019 site count

- **Operator-on-workstation deliverable** — sandbox cannot run `staticcheck`.
- ci.yml inline comment claims "6 sites" (`middleware.NewAuth × 3`, `csr.Attributes`, `elliptic.Marshal`).
- Source-grep at HEAD shows:
  - `internal/api/handler/scep.go`: `csr.Attributes` references present
  - `internal/connector/issuer/local/local.go`: `elliptic.Marshal` historic refs (already migrated per bundle9_coverage_test.go byte-equivalence test)
  - `cmd/server/main_test.go`: `middleware.NewAuth` references TBD
- Operator must run `staticcheck ./... 2>&1 | grep SA1019` on workstation and update Phase 3 plan with the actual site list.

## Dockerfile inventory (verified 4)

```
./Dockerfile.agent
./Dockerfile
./deploy/test/f5-mock-icontrol/Dockerfile
./deploy/test/libest/Dockerfile
```

## Migration up/down balance

- ups: `24`
- downs: `24`
- missing downs: `0`

## OpenAPI ↔ handler parity gap (verified)

- operationIds in api/openapi.yaml: `136`
- r.Register calls in router.go: `149`
- Gap to root-cause in Phase 9: 13 routes

## docker-compose.test.yml sidecars

```
52:  certctl-tls-init:
107:  postgres:
135:  pebble-challtestsrv:
150:  pebble:
178:  step-ca:
213:  certctl-server:
363:  nginx:
391:  certctl-agent:
449:  libest-client:
488:  apache-test:
502:  haproxy-test:
515:  traefik-test:
533:  caddy-test:
548:  envoy-test:
562:  postfix-test:
577:  dovecot-test:
591:  openssh-test:
613:  f5-mock-icontrol:
631:  k8s-kind-test:
648:  windows-iis-test:
666:  certctl-test:
```

## Makefile::verify body (existing)

```
verify:
	@echo "==> fmt"
	@go fmt ./... | { ! grep -q '.'; } || (echo "gofmt produced changes — commit them" && exit 1)
	@echo "==> go vet ./..."
	@go vet ./...
	@echo "==> golangci-lint run ./... (incl. staticcheck ST*)"
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	@golangci-lint run ./... --timeout 5m
	@echo "==> go test -short ./..."
	@go test -short -count=1 ./...
	@echo ""
	@echo "verify: PASS — safe to commit"

```

## RAM headroom for collapsed vendor-e2e job

- **Operator-on-workstation deliverable** — requires a prototype branch with the collapsed job + `docker stats` polling.
- Per Phase 0 frozen decision 0.14: if peak RSS ≤ 12 GB on ubuntu-latest (16 GB ceiling), single-job collapse is approved.
- If > 12 GB, fall back to bucketed-matrix design documented in `cowork/ci-pipeline-cleanup/decisions-revised.md`.

## Coverage thresholds at HEAD

```
778:          if [ "$(echo "$SERVICE_COV < 70" | bc -l)" -eq 1 ]; then
779:            echo "::error::Service layer coverage ${SERVICE_COV}% is below 70% (Bundle R-CI-extended floor — add tests, do not lower the gate)"
782:          if [ "$(echo "$HANDLER_COV < 75" | bc -l)" -eq 1 ]; then
783:            echo "::error::Handler layer coverage ${HANDLER_COV}% is below 75% (Bundle R-CI-extended floor — add tests, do not lower the gate)"
786:          if [ "$(echo "$DOMAIN_COV < 40" | bc -l)" -eq 1 ]; then
787:            echo "::error::Domain layer coverage ${DOMAIN_COV}% is below 40% threshold"
790:          if [ "$(echo "$MIDDLEWARE_COV < 30" | bc -l)" -eq 1 ]; then
791:            echo "::error::Middleware layer coverage ${MIDDLEWARE_COV}% is below 30% threshold"
802:          if [ "$(echo "$CRYPTO_COV < 88" | bc -l)" -eq 1 ]; then
803:            echo "::error::Crypto package coverage ${CRYPTO_COV}% is below 88% (Bundle R closure floor — add tests, do not lower the gate)"
832:          if [ "$(echo "$LOCAL_ISSUER_COV < 86" | bc -l)" -eq 1 ]; then
833:            echo "::error::Local-issuer coverage ${LOCAL_ISSUER_COV}% is below 86% (Bundle R closure floor — add tests, do not lower the gate)"
842:          if [ "$(echo "$ACME_COV < 80" | bc -l)" -eq 1 ]; then
843:            echo "::error::ACME issuer coverage ${ACME_COV}% is below 80% (Bundle R-CI-extended floor — add tests, do not lower the gate)"
846:          if [ "$(echo "$STEPCA_COV < 80" | bc -l)" -eq 1 ]; then
847:            echo "::error::StepCA issuer coverage ${STEPCA_COV}% is below 80% (Bundle L.B closure floor — add tests, do not lower the gate)"
850:          if [ "$(echo "$MCP_COV < 85" | bc -l)" -eq 1 ]; then
851:            echo "::error::MCP coverage ${MCP_COV}% is below 85% (Bundle K closure floor — add tests, do not lower the gate)"
```

## CodeQL workflow (no changes)

- File: `.github/workflows/codeql.yml` (`81` lines)
- Matrix: `[go, javascript-typescript]` — 2 status checks per push
- Trigger: push to master, PR to master, weekly Sunday cron

## Status check accounting (verified)

Today: 1 `go-build-and-test` + 1 `frontend-build` + 1 `helm-lint` + 12 `deploy-vendor-e2e (<vendor>)` + 2 `deploy-vendor-e2e-windows (<vendor>)` + 2 `CodeQL Analyze (<lang>)` = **19 status checks per push**.

After cleanup: 1 `go-build-and-test` + 1 `frontend-build` + 1 `helm-lint` + 1 `deploy-vendor-e2e` + 1 `image-and-supply-chain` + 2 `CodeQL Analyze (<lang>)` = **7 status checks per push**.
