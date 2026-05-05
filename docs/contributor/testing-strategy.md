# certctl Testing Strategy & Deep-Scan Operator Runbook

> Last reviewed: 2026-05-05

This doc covers the **testing topology** (per-PR fast gates vs. daily deep-scan
gates), and the **operator runbook** for re-running each deep-scan tool locally
when the CI receipt is ambiguous or when an operator wants to validate a fix
before the next scheduled scan.

For the manual end-to-end QA playbook, see [`testing-guide.md`](../testing-guide.md).
For the security posture / per-finding closure log, see [`security.md`](../operator/security.md).

## CI workflow split

certctl runs two GitHub Actions workflows:

- **`.github/workflows/ci.yml`** — runs on every push/PR. Fast feedback only.
  Includes `gofmt`, `go vet`, `golangci-lint`, `go test -short -count=1`,
  `govulncheck`, the per-layer coverage gates, and the regression-grep guards
  (the M-009 mutation budget, the L-001 InsecureSkipVerify guard, the H-001
  Dockerfile SHA-pin guard, the M-012 USER-directive guard, etc.).
- **`.github/workflows/security-deep-scan.yml`** — runs daily 06:00 UTC and on
  manual dispatch. Heavyweight tools that need docker, network egress to
  scanner registries, or wall-clock budgets the per-PR check can't tolerate.
  Includes `gosec`, `osv-scanner`, the `-race -count=10` full-suite run,
  `trivy` image scan, `syft` SBOM, ZAP baseline DAST, `nuclei`,
  `schemathesis` OpenAPI fuzz, `testssl.sh`, `go-mutesting` mutation testing,
  and `semgrep p/react-security`.

Receipts from each scheduled run are uploaded as a 30-day-retention artefact
named `security-deep-scan-<run-id>`. Audit them via the GitHub Actions UI;
download the artefact zip for any scan that surfaces a finding.

## Operator runbook — local re-run procedures

These are the same commands the workflow runs, intended for an operator with
a workstation that has docker + the Go toolchain installed. The local-run
shape is identical to CI; the difference is wall-clock and the artefact
location (CI uploads; local writes to `$PWD`).

### Mutation testing (D-003)

**Tool:** [`go-mutesting`](https://github.com/zimmski/go-mutesting). Mutates
each AST node in turn (flips comparisons, swaps return values, removes
statements) and re-runs the package's tests. A mutant is **killed** if any
test fails; **surviving** mutants indicate a coverage gap (no test caught
the bug the mutant introduced).

**Targets:** the three security-critical packages whose coverage gate is
**85%** in `ci.yml`:

- `internal/crypto/`
- `internal/pkcs7/`
- `internal/connector/issuer/local/`

**Acceptance threshold:** ≥80% mutation kill ratio per package. Surviving
mutants below that threshold get triaged in
`cowork/comprehensive-audit-2026-04-25/d003-mutation-results.md` — either
ship a targeted unit test that kills the mutant, or document an
equivalent-mutation justification.

**Local run:**

```
go install github.com/zimmski/go-mutesting/cmd/go-mutesting@latest
for pkg in ./internal/crypto/... ./internal/pkcs7/... ./internal/connector/issuer/local/...; do
  echo "=== $pkg ==="
  $(go env GOPATH)/bin/go-mutesting "$pkg"
done
```

The tool prints one line per mutant (`PASS` = killed, `FAIL` = surviving)
plus a per-package summary `The mutation score is X.YZ`. CPU-bound, single
core, takes ~10 minutes on a 2024-era laptop for the three packages combined.

**Sandbox note:** `go-mutesting` writes a mutant copy of the source tree to
`/tmp/go-mutesting/` per run; needs ≥2 GB free disk. Sandboxed CI runners
are sized for this; constrained dev sandboxes are not.

### DAST baseline (D-004)

**Tool:** [OWASP ZAP `baseline`](https://www.zaproxy.org/docs/docker/baseline-scan/).
Spiders the running server's URL surface and runs the OWASP-ZAP active+passive
rule pack. **Baseline** mode skips the destructive active-scan rules; it's safe
against a non-throwaway environment.

**Target:** the live `deploy/docker-compose.yml` stack on `https://localhost:8443`.

**Acceptance:** zero HIGH/CRITICAL alerts. WARN/INFO alerts get triaged in the
ZAP report; some are unavoidable (e.g., HSTS preload-list nag is a deployment
recommendation, not a server defect).

**Local run:**

```
docker compose -f deploy/docker-compose.yml up -d
sleep 20  # wait for /ready to flip OK; check `curl --cacert deploy/test/certs/ca.crt https://localhost:8443/ready`
docker run --rm --network host \
  -v "$PWD":/zap/wrk \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://localhost:8443 \
  -r zap-report.html -J zap-report.json
docker compose -f deploy/docker-compose.yml down
```

The HTML report opens in a browser; the JSON is machine-readable for triage.

### TLS audit (D-005)

**Tool:** [`testssl.sh`](https://testssl.sh/). Probes the TLS handshake and
each enabled cipher suite; reports protocol-version weaknesses, cipher
weaknesses, certificate-chain issues, and known CVE patterns (Heartbleed,
ROBOT, BEAST, etc.).

**Target:** the live stack on `https://localhost:8443`.

**Acceptance:** zero HIGH/CRITICAL findings. certctl pins
`tls.Config.MinVersion = tls.VersionTLS13` (`cmd/server/tls.go`), so anything
that surfaces is either (a) a real defect, (b) a testssl false positive, or
(c) a deployment-config issue worth documenting in the operator runbook.

**Local run:**

```
docker compose -f deploy/docker-compose.yml up -d
sleep 20
docker run --rm --network host \
  -v "$PWD":/data \
  drwetter/testssl.sh:latest \
  --jsonfile /data/testssl.json https://localhost:8443
docker compose -f deploy/docker-compose.yml down

# Filter to actionable severities
jq '[.scanResult[] | select(.severity == "HIGH" or .severity == "CRITICAL")]' testssl.json
```

### Frontend semgrep (D-007)

**Tool:** [`semgrep`](https://semgrep.dev/) with the maintained
[`p/react-security` ruleset](https://semgrep.dev/p/react-security). Catches
React-specific XSS / injection patterns: `dangerouslySetInnerHTML` without
sanitization, `target="_blank"` without `rel="noopener noreferrer"`,
`href={userInput}`, `eval`, `document.write`, etc.

**Target:** the frontend source tree at `web/src/`.

**Acceptance:** zero findings. Bundle 8 already verified
`dangerouslySetInnerHTML` count at zero and the `target="_blank"`
rel-noopener pin via simple grep guards in `ci.yml`; semgrep adds defence
in depth — it catches escape patterns the greps don't see (e.g.,
`href={user_input}`, runtime `eval`, `document.write`).

**Local run:**

```
docker run --rm -v "$PWD":/src returntocorp/semgrep:latest \
  semgrep --config=p/react-security --json /src/web/src \
  > semgrep-react.json

# Count findings
jq '.results | length' semgrep-react.json

# Pretty-print findings
jq '.results[] | {rule_id: .check_id, path, line: .start.line, message: .extra.message}' semgrep-react.json
```

If the count is non-zero, every result has a `check_id` (e.g.
`react.dangerouslySetInnerHTML`) and a `message` describing the escape
pattern. Triage each: either fix the call site, or — for legitimate edge
cases — add a `// nosem: <check_id> — <reason>` directive on the
preceding line.

## Cadence

| Tool                 | Trigger                            | Wall-clock | Owner          |
|----------------------|------------------------------------|------------|----------------|
| go-mutesting         | daily deep-scan + manual dispatch  | ~10 min    | maintainers    |
| ZAP baseline (DAST)  | daily deep-scan + manual dispatch  | ~5 min     | maintainers    |
| testssl.sh           | daily deep-scan + manual dispatch  | ~3 min     | maintainers    |
| semgrep react        | daily deep-scan + manual dispatch  | ~1 min     | maintainers    |
| `make verify`        | every commit (pre-push)            | ~1 min     | every developer |
| ci.yml fast gates    | every push/PR                      | ~3 min     | every developer |

Re-run any of the deep-scan tools locally when:

- A CI receipt surfaces an unexpected finding and you want to bisect against
  a local change before pushing.
- You're cutting a release tag and want belt-and-suspenders evidence beyond
  the most recent scheduled scan.
- You're adding a new feature in the relevant surface (crypto code →
  re-run mutation testing; new HTTP handler → re-run schemathesis + ZAP;
  new TLS-config knob → re-run testssl).

## Related docs

- [`docs/operator/security.md`](../operator/security.md) — security posture, per-finding closure log.
- [`docs/testing-guide.md`](../testing-guide.md) — manual end-to-end QA playbook.
- [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — per-PR fast gates.
- [`.github/workflows/security-deep-scan.yml`](../.github/workflows/security-deep-scan.yml) — daily deep-scan gates.
- [`scripts/install-security-tools.sh`](../scripts/install-security-tools.sh) — Go-host-installed tools (the docker-based tools are not in this script).
