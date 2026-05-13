#!/usr/bin/env bash
# deploy/demo-up.sh — boot the certctl demo stack with the fresh
# CERTCTL_DEMO_MODE_ACK_TS the Phase 2 SEC-H3 guard requires.
#
# The demo overlay sets CERTCTL_DEMO_MODE_ACK=true. Phase 2 SEC-H3
# (2026-05-13) pairs that with a fail-closed requirement: the server
# refuses to start unless CERTCTL_DEMO_MODE_ACK_TS=<unix-epoch> is set
# and is within the last 24h (with 1-minute future clock-skew tolerance).
#
# A static value in docker-compose.demo.yml would rot the next day, so
# the overlay passthroughs the value from the shell environment. This
# helper mints a fresh TS at run time and forwards any extra args to
# `docker compose up`, so operators can use it as a drop-in replacement
# for the bare command. Example:
#
#     ./demo-up.sh -d                  # cold boot in detached mode
#     ./demo-up.sh -d --pull always    # forward any flags through
#
# The cold-DB compose smoke in .github/workflows/ci.yml does the same
# thing inline; this script exists so local operators don't have to
# remember the export.

set -euo pipefail

# cd to the deploy/ dir so the relative `-f` paths resolve regardless
# of where the operator invokes this from. The script lives next to
# the compose files it references.
cd "$(dirname "$0")"

export CERTCTL_DEMO_MODE_ACK_TS="$(date +%s)"

echo "[demo-up] minting CERTCTL_DEMO_MODE_ACK_TS=$CERTCTL_DEMO_MODE_ACK_TS"
echo "[demo-up] running: docker compose -f docker-compose.yml -f docker-compose.demo.yml up $*"

exec docker compose \
  -f docker-compose.yml \
  -f docker-compose.demo.yml \
  up "$@"
