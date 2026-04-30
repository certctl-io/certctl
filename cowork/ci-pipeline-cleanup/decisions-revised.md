# CI Pipeline Cleanup — Deliberate Revisions of Bundle II Decisions

This bundle deliberately revises two Bundle II frozen decisions. Both revisions are recorded here for audit trail and acknowledged in the per-Phase commits that implement them.

## Bundle II decision 0.4 → revised by ci-pipeline-cleanup decision 0.5

**Bundle II 0.4 (original):** "IIS e2e strategy — `mcr.microsoft.com/windows/servercore:ltsc2022` Windows containers via Docker Desktop on Windows hosts. Linux CI runners CAN'T run Windows containers, so the IIS e2e suite runs on a separate Windows-runner CI matrix job (or operator's local Windows host for development). Documented limitation."

**ci-pipeline-cleanup 0.5 (revision):** Delete the Windows-runner CI matrix entirely.

**Rationale for revision:**

1. The matrix can't physically work on `windows-latest` GitHub-hosted runners today. Verified via the failure logs from CI run `25183374742` (commit `1de61e9`):
   - `wincertstore` job: `error during connect: ... open //./pipe/docker_engine: The system cannot find the file specified` — Docker daemon not started in Windows-containers mode.
   - `iis` job: image pulled successfully (so the new digest is correct), then died at `failed to create network deploy_certctl-test: could not find plugin bridge in v1 plugin registry: plugin not found` — `bridge` network driver doesn't exist on Windows Docker (uses `nat`).

2. Even if both Docker-daemon and network-driver issues were fixed, the matrix would validate nothing of substance. Verified by source-grep: all 16 functions matching `TestVendorEdge_(IIS|WinCertStore)_*` in `deploy/test/vendor_e2e_phase3_to_13_test.go` are `t.Log` placeholders that exercise no IIS-specific behavior. The real IIS connector validation lives in `internal/connector/target/iis/` unit tests (run on Linux in `go-build-and-test` — already green per push).

3. Bundle II decision 0.14 explicitly required operator manual smoke against a real instance for "verified" status in the vendor matrix. Moving IIS + WinCertStore validation to a documented operator playbook in `docs/connector-iis.md` satisfies that criterion better than a fake CI matrix that passes by skipping.

**Preservation:** the `windows-iis-test` sidecar stays in `deploy/docker-compose.test.yml` under `profiles: [deploy-e2e-windows]` — operators on a Windows host can opt in via `docker compose --profile deploy-e2e-windows up -d windows-iis-test`. Linux CI never activates this profile.

## Bundle II decision 0.9 → revised by ci-pipeline-cleanup decision 0.4

**Bundle II 0.9 (original):** "CI parallelism — Each vendor e2e gets its own GitHub Actions matrix job. Vendor failures surface independently in the CI status check (operator sees 'K8s 1.31 vendor-edge fail' as a discrete check, not a generic 'integration tests failed')."

**ci-pipeline-cleanup 0.4 (revision):** Single `deploy-vendor-e2e` job replaces the 12-job matrix; per-vendor visibility partially restored via skip-detection guard messages.

**Rationale for revision:**

1. The per-vendor granularity Bundle II decision 0.9 was designed to provide is fake signal. Verified by source-analysis at HEAD:
   ```
   $ grep -cE 't\.Log\(' deploy/test/{vendor_e2e_phase3_to_13,nginx_vendor_e2e}_test.go
   deploy/test/nginx_vendor_e2e_test.go:9
   deploy/test/vendor_e2e_phase3_to_13_test.go:106

   $ awk '/^func TestVendorEdge_/{in_test=1; name=$2; has_assert=0; next}
          in_test && /^}$/ {if (has_assert) print name; in_test=0}
          in_test && /t\.(Fatal|Error|Errorf|Fatalf|Fail|Failf)/ {has_assert=1}' \
          deploy/test/vendor_e2e_phase3_to_13_test.go deploy/test/nginx_vendor_e2e_test.go
   TestVendorEdge_NGINX_HighConcurrencyDeployUnderLoad_E2E
   ```
   115 of 116 vendor-edge test functions are `t.Log`-only — they spin up a sidecar, log a one-line description of the vendor quirk, and return. Only 1 has a real assertion.

2. Per-vendor status-check granularity costs ~9 sec setup overhead × 12 jobs = ~108 sec of pure runner waste per push (verified from CI run `25183374742` job timings).

3. The single-job version partially restores per-vendor visibility via the skip-detection guard (decision 0.6): if a sidecar fails to start, the affected tests' SKIP names print in the CI output and the build fails. Operators see "TestVendorEdge_K8s_KubeletSyncWaitContract_DefaultTimeout60s_E2E SKIPPED: vendor sidecar 'k8s-kind' not reachable" — same per-vendor signal, just no longer rendered as a separate status-check row.

**Preservation:** the per-test discoverability via `go test -run 'VendorEdge_<vendor>'` (Bundle II frozen decision 0.6) is unchanged. Only the matrix-jobs-per-vendor part of decision 0.9 is revised; the per-test naming convention stays.

## Forward-looking note

Both revisions are limited in scope to CI execution shape — they do NOT delete the test files, the sidecar definitions, or the documentation that Bundle II shipped. Future work could re-introduce per-vendor matrix jobs if test bodies are filled in with real assertions (transforming the t.Log placeholders into actual contract pins). At that point, decision 0.4 + 0.9 should be re-evaluated.
