#!/usr/bin/env bash
# scripts/ci-guards/bundle-1-compat-regression.sh
#
# Auth Bundle 2 / Phase 6 Bundle-1-only compat regression.
#
# Pre-commit invariant: a deployment with CERTCTL_AUTH_TYPE=api-key,
# zero OIDC providers configured, and zero session cookies on requests
# behaves byte-identically to Bundle 1.
#
# Phase 6 wires session middleware into the chain:
#   RequestID -> Logging -> Recovery -> CORS -> RateLimit ->
#   Auth (session-then-Bearer fallback) -> CSRF -> Audit -> Handler
#
# The session middleware MUST short-circuit cleanly when:
#   - The request has no `certctl_session` cookie.
#   - There are no OIDC providers configured (no IdPs to redirect to).
#   - The CSRFMiddleware MUST be a pass-through for API-key actors
#     (no session row in context => no CSRF check).
#
# This guard checks the static-source invariants that protect the
# Bundle-1 path, since spinning up docker-compose + running the full
# integration test suite is sandbox-infeasible. Concretely:
#
#   1. session.NewSessionMiddleware MUST defer to next on missing OR
#      invalid cookie (not 401). If a future refactor changes that to
#      a 401, the Bearer fallback path breaks and every API-key request
#      fails.
#
#   2. session.NewCSRFMiddleware MUST be a pass-through when the
#      session row is absent from context. A future refactor that
#      checks CSRF on Bearer requests would break every programmatic
#      API client.
#
#   3. session.ChainAuthSessionThenBearer MUST be the entry point
#      authMiddleware refers to in cmd/server/main.go. A regression
#      that drops the chain and goes straight to bearerMiddleware
#      breaks the session login path; a regression that drops the
#      bearer middleware entirely breaks every Bundle-1 client.
#
#   4. The 4 public OIDC routes MUST be in router.AuthExemptRouterRoutes
#      (so /auth/oidc/login etc. don't go through the auth chain on a
#      Bundle-1-only deployment AND don't 401 a user trying to start
#      a login).
#
# Each invariant: a single grep that fails the build on regression.
#
# When the sandbox-feasibility constraint changes (operator gets a
# Linux VM with docker-in-docker for the CI runs), promote this to a
# real `docker compose up` integration test that runs the existing
# test suite + asserts zero new 401s vs the v2.1.0 baseline. Until
# then, the static checks below are the load-bearing pin.

set -e

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

fail=0

# Invariant 1: SessionMiddleware MUST defer-to-next on cookie miss/invalid.
if ! grep -q 'next.ServeHTTP(w, r)' internal/auth/session/middleware.go; then
    echo "::error::SessionMiddleware no longer defers to next on missing cookie"
    fail=1
fi
if grep -q 'http.Error.*StatusUnauthorized' internal/auth/session/middleware.go; then
    echo "::warning::SessionMiddleware appears to write 401 directly — verify Bearer fallback still works"
fi

# Invariant 2: CSRFMiddleware MUST be pass-through on missing session row.
if ! grep -qE 'sessionContextKey\{\}\)\.\(\*sessiondomain\.Session\)' internal/auth/session/middleware.go; then
    echo "::error::CSRFMiddleware no longer reads session row from context"
    fail=1
fi
if ! grep -qE 'if !ok \|\| sess == nil \{$' internal/auth/session/middleware.go; then
    echo "::error::CSRFMiddleware no longer pass-throughs on missing session row (API-key actors must be CSRF-exempt)"
    fail=1
fi

# Invariant 3: chained-auth combinator MUST be the entry point in main.go.
if ! grep -q 'session.ChainAuthSessionThenBearer' cmd/server/main.go; then
    echo "::error::cmd/server/main.go does not wire session.ChainAuthSessionThenBearer"
    fail=1
fi
if ! grep -q 'bearerMiddleware\s*=\s*auth.NewAuthWithKeyStore' cmd/server/main.go; then
    echo "::error::cmd/server/main.go no longer constructs the Bundle-1 Bearer middleware"
    fail=1
fi

# Invariant 4: public OIDC routes are in the auth-exempt allowlist.
for route in 'GET /auth/oidc/login' 'GET /auth/oidc/callback' 'POST /auth/oidc/back-channel-logout' 'POST /auth/logout'; do
    if ! grep -qF "\"$route\"" internal/api/router/router.go; then
        echo "::error::router.AuthExemptRouterRoutes is missing entry: $route"
        fail=1
    fi
done

# Invariant 5: AuthInfo extension MUST gracefully degrade when no
# OIDCProvidersResolver is wired (test-fixture + no-db-deploy paths).
if ! grep -q 'if h.OIDCProvidersResolver != nil' internal/api/handler/health.go; then
    echo "::error::AuthInfo no longer guards on OIDCProvidersResolver != nil"
    fail=1
fi

if [ $fail -eq 0 ]; then
    echo "OK: Bundle-1 compat regression invariants hold."
fi
exit $fail
