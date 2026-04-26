#!/usr/bin/env bash
# Bundle-7 / Audit D-001:
# Idempotent installer for the §12 mandatory tool suite. Used locally
# during a Bundle-7-style run and by the CI workflows
# (.github/workflows/ci.yml + .github/workflows/security-deep-scan.yml).
#
# Tools installed via go install (host-Go, no docker required):
#   govulncheck    Go module CVE scan
#   staticcheck    Go static-analysis (additive to vet)
#   errcheck       unchecked-error finder
#   ineffassign    dead-assignment finder
#   gosec          Go security static-analysis (best-effort; large download)
#   osv-scanner    multi-ecosystem CVE scan
#
# Tools NOT installed by this script (containerized in CI workflows):
#   semgrep, hadolint, trivy, syft, checkov, kube-score,
#   schemathesis, OWASP ZAP, nuclei, testssl.sh
#
# Usage:
#   bash scripts/install-security-tools.sh                # default GOBIN
#   GOBIN=/tmp/gobin bash scripts/install-security-tools.sh
#
# Exit codes:
#   0  every tool installed
#   1  one or more installs failed (script continues but reports at end)

set -uo pipefail

if ! command -v go >/dev/null 2>&1; then
    echo "ERROR: go toolchain not on PATH" >&2
    exit 1
fi

FAIL=0
install_tool() {
    local pkg="$1"
    local name
    name="$(basename "${pkg%@*}")"
    echo "=> install $name ($pkg)"
    if ! go install "$pkg" 2>&1; then
        echo "WARN: failed to install $name" >&2
        FAIL=$((FAIL + 1))
    fi
}

install_tool golang.org/x/vuln/cmd/govulncheck@latest
install_tool honnef.co/go/tools/cmd/staticcheck@latest
install_tool github.com/kisielk/errcheck@latest
install_tool github.com/gordonklaus/ineffassign@latest
install_tool github.com/securego/gosec/v2/cmd/gosec@latest
install_tool github.com/google/osv-scanner/cmd/osv-scanner@latest

if [ "$FAIL" -ne 0 ]; then
    echo "WARNING: $FAIL tool(s) failed to install — partial coverage only" >&2
    exit 1
fi
echo "OK: all 6 tools installed"
