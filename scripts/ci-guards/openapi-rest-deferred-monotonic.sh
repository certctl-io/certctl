#!/usr/bin/env bash
# scripts/ci-guards/openapi-rest-deferred-monotonic.sh
#
# Phase 13 Sprint 13.1 closure (2026-05-14, architecture diligence audit
# ARCH-H1): the `rest-deferred` exception bucket in
# api/openapi-handler-exceptions.yaml MUST monotonically decrease vs
# the checked-in baseline at api/openapi-handler-exceptions-baseline.txt.
#
# Contract:
#   - openapi-handler-exceptions.yaml entries categorized as
#     `category: rest-deferred` are REST-shaped routes whose OpenAPI
#     op was deferred when the handler shipped. They are gaps, not
#     contracts, and must reach zero.
#   - This guard reads the current rest-deferred count via the parity
#     script's --bucket subcommand, reads the baseline from
#     api/openapi-handler-exceptions-baseline.txt, and fails if the
#     current count exceeds the baseline.
#   - Phase 13 Sprints 13.4-13.6 author the OpenAPI ops for the
#     remaining 28 rest-deferred entries; each batch bumps the
#     baseline file downward. Sprint 13.7 lands the baseline at 0
#     AND tightens the sibling openapi-handler-parity.sh guard to a
#     hard zero-exact pin.
#
# Going forward: any PR that adds a new `category: rest-deferred`
# entry without simultaneously bumping the baseline file fails CI.
#
# Operator workflow:
#   1. Land an OpenAPI op for one of the rest-deferred routes.
#   2. Delete the corresponding entry from
#      api/openapi-handler-exceptions.yaml.
#   3. Decrement api/openapi-handler-exceptions-baseline.txt by the
#      number of entries removed.
#   4. Commit all three changes in the same PR — this guard verifies
#      they stay consistent.

set -e

BASELINE_FILE="api/openapi-handler-exceptions-baseline.txt"

if [ ! -f "$BASELINE_FILE" ]; then
    echo "::error::missing $BASELINE_FILE — required by Phase 13 Sprint 13.1 contract."
    echo ""
    echo "Create it with a single integer matching the current rest-deferred count:"
    echo "  bash scripts/ci-guards/openapi-handler-parity.sh --bucket=rest-deferred > $BASELINE_FILE"
    exit 1
fi

# Whitespace-tolerant read of the baseline.
BASELINE=$(tr -d '[:space:]' < "$BASELINE_FILE")
if ! [[ "$BASELINE" =~ ^[0-9]+$ ]]; then
    echo "::error::$BASELINE_FILE must contain a single non-negative integer; got: '$BASELINE'"
    exit 1
fi

CURRENT=$(bash scripts/ci-guards/openapi-handler-parity.sh --bucket=rest-deferred)
if ! [[ "$CURRENT" =~ ^[0-9]+$ ]]; then
    echo "::error::openapi-handler-parity.sh --bucket=rest-deferred returned non-integer: '$CURRENT'"
    exit 1
fi

if [ "$CURRENT" -gt "$BASELINE" ]; then
    echo "::error::rest-deferred bucket grew: $CURRENT > baseline $BASELINE."
    echo ""
    echo "Phase 13 Sprint 13.1 contract: the rest-deferred bucket in"
    echo "api/openapi-handler-exceptions.yaml must monotonically decrease."
    echo ""
    echo "If you added a new REST route that genuinely cannot be authored into"
    echo "openapi.yaml yet (e.g. work-in-progress), surface the rationale in"
    echo "the PR description AND get explicit operator sign-off before"
    echo "bumping $BASELINE_FILE upward. The default answer is 'author"
    echo "the OpenAPI op now instead'."
    exit 1
fi

if [ "$CURRENT" -lt "$BASELINE" ]; then
    echo "::error::rest-deferred bucket shrank below baseline: $CURRENT < $BASELINE."
    echo ""
    echo "Authoring an OpenAPI op is the right move — but the baseline file"
    echo "at $BASELINE_FILE must be bumped down in the SAME commit so this"
    echo "guard's pin tightens automatically. Update it to: $CURRENT"
    exit 1
fi

echo "openapi-rest-deferred-monotonic: clean — rest-deferred = $CURRENT, baseline = $BASELINE."
