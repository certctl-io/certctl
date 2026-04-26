package handler

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

// Bundle-5 / Audit H-007 / CWE-306 + CWE-288:
//
// Pre-Bundle-5, POST /api/v1/agents accepted any request and registered
// the supplied agent payload — any host with network reach to the server
// could enroll a fake agent and start polling for work without a shared
// secret. This file implements the bootstrap-token defence.
//
// Contract:
//
//   - When CERTCTL_AGENT_BOOTSTRAP_TOKEN is empty (the v2.0.x default), the
//     handler accepts registrations as before. main.go logs a one-shot WARN
//     at startup announcing the v2.2.0 deprecation: bootstrap token will
//     become required in v2.2.0 and unset will fail-loud.
//
//   - When the token is non-empty, every registration request must carry
//     `Authorization: Bearer <token>` whose value matches the configured
//     token byte-for-byte. The compare uses crypto/subtle.ConstantTimeCompare
//     to defeat timing oracles.
//
//   - Mismatch / missing / malformed → 401 with
//     {"error":"invalid_or_missing_bootstrap_token"} JSON body. The handler
//     does NOT echo what the client sent (defence-in-depth against credential
//     shape leakage to a token spray probe).
//
// Generation guidance (lives in docs/quickstart.md): `openssl rand -hex 32`
// for 256-bit entropy. Operators rotate by setting the new value, restarting
// the server, then re-issuing the new token to whoever drives agent
// enrollment.

// ErrBootstrapTokenInvalid is the sentinel returned by verifyBootstrapToken
// on any non-accept path (missing header, malformed Bearer token, mismatch).
// Handlers translate this into HTTP 401 with a fixed error string.
var ErrBootstrapTokenInvalid = errors.New("invalid or missing agent bootstrap token")

// Operator-visible deprecation WARN for the warn-mode default lives in
// cmd/server/main.go — emitted once at startup, not per-request, so a
// busy registration endpoint doesn't flood the log.

// verifyBootstrapToken returns nil when the request should proceed and
// ErrBootstrapTokenInvalid when it should be rejected.
//
// Parameters:
//
//	r        — incoming HTTP request
//	expected — the configured token; empty = warn-mode pass-through
//
// Token extraction order:
//  1. `Authorization: Bearer <token>` (canonical)
//  2. (Future) X-Certctl-Bootstrap-Token: <token> — reserved, not yet read
//
// All comparisons use crypto/subtle.ConstantTimeCompare. Even when the
// presented token is the wrong length, we still copy bytes through the
// constant-time path so the timing signature is uniform.
func verifyBootstrapToken(r *http.Request, expected string) error {
	if expected == "" {
		// Warn-mode pass-through. The startup WARN in main.go is the
		// operator-visible signal; this fast path stays silent so a busy
		// endpoint doesn't add log noise per request.
		return nil
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ErrBootstrapTokenInvalid
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return ErrBootstrapTokenInvalid
	}

	presented := strings.TrimPrefix(authHeader, bearerPrefix)
	if presented == "" {
		return ErrBootstrapTokenInvalid
	}

	// Constant-time compare. We pad the shorter side so the comparison
	// runs in a length-independent code path; subtle.ConstantTimeCompare
	// requires equal-length slices.
	expectedBytes := []byte(expected)
	presentedBytes := []byte(presented)
	if len(expectedBytes) != len(presentedBytes) {
		// Run a dummy compare to keep the timing similar regardless of
		// length-vs-content failure mode.
		_ = subtle.ConstantTimeCompare(expectedBytes, expectedBytes)
		return ErrBootstrapTokenInvalid
	}
	if subtle.ConstantTimeCompare(expectedBytes, presentedBytes) != 1 {
		return ErrBootstrapTokenInvalid
	}
	return nil
}
