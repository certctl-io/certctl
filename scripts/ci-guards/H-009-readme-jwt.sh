#!/usr/bin/env bash
# scripts/ci-guards/H-009-readme-jwt.sh
#
# H-009 closed by Bundle D as verified-already-clean: at audit time
# the README does NOT advertise JWT support (certctl does not ship
# in-process JWT middleware; JWT/OIDC integration is via an
# authenticating gateway, see docs/reference/architecture.md "Authenticating-
# gateway pattern"). This script grep-fails the build if README ever
# re-introduces a sentence advertising JWT as a supported auth mode.
# Pattern: "JWT" within ~6 words of "support|auth|enabled|mode" in
# README.md. The architecture / compliance / connector docs that
# legitimately mention JWT (Google OAuth2 service-account JWT,
# step-ca provisioner JWT, JWT-via-gateway pattern) are out of
# scope — they describe what certctl does NOT do, or external
# protocol uses.

set -e
if grep -inE 'JWT.{0,40}(support|auth|enabled|mode|provider)' README.md \
   | grep -v 'gateway' | grep -v 'pre-G-1'; then
  echo "::error::H-009 regression: README.md appears to advertise JWT auth support."
  echo "certctl does NOT ship in-process JWT middleware. JWT/OIDC"
  echo "integration is via an authenticating gateway — see"
  echo "docs/reference/architecture.md::Authenticating-gateway pattern."
  echo "If you added a sentence about JWT to README, either remove"
  echo "it or rewrite it to point at the gateway pattern."
  exit 1
fi
echo "H-009 readme-jwt: clean."
