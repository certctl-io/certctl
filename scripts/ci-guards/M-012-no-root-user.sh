#!/usr/bin/env bash
# scripts/ci-guards/M-012-no-root-user.sh
#
# Bundle A / Audit M-012 (CWE-250): every Dockerfile in the repo
# MUST end with a `USER <non-root>` directive before the
# ENTRYPOINT/CMD so the container never runs as uid=0. This script
# grep-fails the build if any Dockerfile is missing such a USER.
# `USER root` and `USER 0` are explicitly rejected.

set -e
BAD=""
for df in $(find . -name 'Dockerfile*' -not -path './web/node_modules/*'); do
  # Find the LAST USER directive in the file.
  last_user=$(grep -E '^USER\s+\S+' "$df" | tail -1 | awk '{print $2}')
  if [ -z "$last_user" ]; then
    BAD="$BAD\n$df: no USER directive at all"
    continue
  fi
  if [ "$last_user" = "root" ] || [ "$last_user" = "0" ]; then
    BAD="$BAD\n$df: terminal USER is $last_user (must drop privileges)"
    continue
  fi
done
if [ -n "$BAD" ]; then
  echo "::error::M-012 regression: Dockerfile USER-drop missing:"
  echo -e "$BAD"
  exit 1
fi
echo "M-012 no-root-user: clean."
