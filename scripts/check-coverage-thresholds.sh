#!/usr/bin/env bash
# scripts/check-coverage-thresholds.sh
#
# Enforces per-package coverage floors declared in
# .github/coverage-thresholds.yml against the live coverage.out.
#
# Per ci-pipeline-cleanup bundle Phase 2 / frozen decision 0.3.
# Adding a new gated package: one entry in the YAML — this script
# auto-picks it up. Lowering a floor REQUIRES corresponding code-side
# test work — never lower the gate to make CI green.

set -e

if [ ! -f coverage.out ]; then
  echo "::error::coverage.out not found — run 'go test -cover -coverprofile=coverage.out' first"
  exit 1
fi

if [ ! -f .github/coverage-thresholds.yml ]; then
  echo "::error::.github/coverage-thresholds.yml not found"
  exit 1
fi

echo "=== Coverage Report ==="
go tool cover -func=coverage.out | tail -1
echo ""

# Extract the pkg → floor table from the YAML.
python3 - <<'PY' > /tmp/cov-thresholds.tsv
import yaml
d = yaml.safe_load(open('.github/coverage-thresholds.yml'))
for pkg, entry in d.items():
    print(f"{pkg}\t{entry['floor']}")
PY

fail=0
while IFS=$'\t' read -r pkg floor; do
  cov=$(go tool cover -func=coverage.out \
          | grep "$pkg" \
          | awk '{print $NF}' \
          | sed 's/%//' \
          | awk '{sum+=$1; n++} END {if(n>0) printf "%.1f", sum/n; else print "0"}')
  printf "%-50s %5s%% (floor: %s%%)\n" "$pkg" "$cov" "$floor"
  if [ "$(echo "$cov < $floor" | bc -l)" -eq 1 ]; then
    # Pull the why: text out of the YAML for this package.
    why=$(python3 -c "
import yaml, sys
d = yaml.safe_load(open('.github/coverage-thresholds.yml'))
print(d.get(sys.argv[1], {}).get('why', '').strip())
" "$pkg")
    echo "::error::$pkg coverage $cov% is below floor $floor%"
    echo "Why this floor exists:"
    echo "$why" | sed 's/^/  /'
    echo "Add tests; do not lower the gate."
    fail=1
  fi
done < /tmp/cov-thresholds.tsv

[ $fail -eq 0 ] || exit 1
echo ""
echo "All coverage thresholds passed."
