package auth

import "strings"

// ProtocolEndpointPrefixes lists the URL path prefixes that authenticate
// via the protocol itself rather than via certctl's Bearer / cookie
// stack. Bundle 1 Phase 3 uses this allowlist as the explicit "do NOT
// wrap with RequirePermission" set: the RBAC middleware applies only to
// admin handlers replacing legacy IsAdmin checks plus any new
// permission-gated routes; the endpoints below keep their existing
// protocol-level auth.
//
// Adding a new protocol endpoint that doesn't take a Bearer token MUST
// also add the prefix here and a parallel test in Phase 12 asserting
// the route is unwrapped.
//
// Per the Phase 3 audit:
//
//	ACME server  : /acme/profile/<id>/* + /acme/* (JWS-signed, RFC 8555).
//	SCEP server  : /scep                          (challenge password +
//	                                              signed CSR, RFC 8894).
//	EST server   : /.well-known/est/*             (mTLS client cert,
//	                                              RFC 7030).
//	OCSP responder : /.well-known/pki/ocsp        (RFC 6960, public).
//	CRL distrib. : /.well-known/pki/crl/*         (RFC 5280, public).
//
// Plus the existing public-route bypass list at internal/api/router
// (router.go:69-72): /health, /ready, /api/v1/auth/info. Those bypass
// EVERY middleware stack, not just RBAC, so they're not in this
// allowlist; they're handled in router.go directly.
var ProtocolEndpointPrefixes = []string{
	"/acme",
	"/scep",
	"/.well-known/est",
	"/.well-known/pki/ocsp",
	"/.well-known/pki/crl",
}

// IsProtocolEndpoint reports whether the request path is in the
// "do not gate" allowlist. Phase 3 RequirePermission check bails out
// early for these paths so the protocol surface is preserved.
func IsProtocolEndpoint(path string) bool {
	for _, p := range ProtocolEndpointPrefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}
