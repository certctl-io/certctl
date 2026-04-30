#!/usr/bin/env bash
# scripts/ci-guards/G-1-jwt-auth-literal.sh
#
# G-1 closed the JWT silent auth downgrade by removing "jwt" from the
# accepted CERTCTL_AUTH_TYPE values. This script grep-fails the build
# if "jwt" reappears in any of the *additive* auth-type surfaces:
# the validAuthTypes / ValidAuthTypes() set, the OpenAPI enum, the
# helm chart's allowed-types list, or the .env.example default.
# Comment lines and the dedicated rejection branch in config.go
# (`c.Auth.Type == "jwt"`) are intentionally exempt — those are the
# G-1 fix itself, not a regression.
#
# Connector packages (internal/connector/) are exempt because the
# Google OAuth2 service-account JWT and step-ca provisioner one-
# time-token JWT are external-protocol uses, unrelated to certctl's
# own auth shape. Test files (_test.go) are exempt so negative
# tests can pass the literal.
#
# See docs/upgrade-to-v2-jwt-removal.md for the closure rationale,
# or internal/config/config.go::ValidAuthTypes for the allowed set.

set -e

# Scoped patterns that indicate "jwt" being added back to an
# allowed-set surface. Each catches a regression shape we've
# actually seen in pre-G-1 code:
#   - Go map/slice literal:  "jwt": true   or   "jwt",
#   - Go switch case:        case "jwt"
#   - YAML enum:             enum: [..., jwt, ...]   or   - jwt
#   - .env conditional:      AUTH_TYPE.*"jwt"|=jwt$
BAD=$(grep -rnEH \
    -e '"jwt"\s*:\s*true' \
    -e '"jwt"\s*,' \
    -e 'case\s+"jwt"' \
    -e 'enum:.*\bjwt\b' \
    -e '^\s*-\s*jwt\s*$' \
    -e 'AUTH_TYPE\s*=\s*jwt\s*$' \
    -e 'AUTH_TYPE\s*=\s*jwt\s*#' \
    -e 'auth\.type\s*=\s*jwt\s*$' \
    -e 'AuthType\("jwt"\)' \
    internal/config/ \
    internal/api/ \
    cmd/ \
    api/openapi.yaml \
    .env.example \
    deploy/.env.example \
    deploy/helm/certctl/values.yaml \
    deploy/helm/certctl/templates/ \
    2>/dev/null \
    | grep -v '_test.go' \
    | grep -vE '^\s*[^:]+:[0-9]+:\s*(//|#)' \
    | grep -v 'is no longer accepted' \
    || true)
if [ -n "$BAD" ]; then
  echo "::error::G-1 regression: \"jwt\" reappeared in an allowed-set surface:"
  echo "$BAD"
  echo ""
  echo "Allowed surface for 'jwt' literals: comment lines, the"
  echo "dedicated rejection branch in internal/config/config.go,"
  echo "and connector packages (Google OAuth2, step-ca)."
  echo "See docs/upgrade-to-v2-jwt-removal.md and"
  echo "internal/config/config.go::ValidAuthTypes()."
  exit 1
fi
echo "G-1 jwt-auth-literal: clean."
