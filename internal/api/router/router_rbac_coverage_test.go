package router

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// TestRouterRBACGateCoverage AST-walks router.go and asserts that every
// state-changing handler registration goes through rbacGate or
// rbacGateScoped, excepting (a) protocol endpoints (ACME / SCEP / EST /
// CRL / OCSP) that authenticate via their own protocol primitives,
// (b) the bootstrap endpoint which is auth-exempt by design,
// (c) auth-info / login / logout / break-glass-login / health surfaces
// that establish identity rather than carry it.
//
// This is the ratchet that prevents 2026-05-10 audit CRIT-1 from
// regressing. A developer who registers a new state-changing handler
// (or a list endpoint) without rbacGate / rbacGateScoped fails this
// test. Update authExemptRoutes ONLY when registering a new
// auth-exempt surface, and document the addition in the commit body.
//
// See cowork/auth-bundles-audit-2026-05-10.md CRIT-1 for the closure
// history.
func TestRouterRBACGateCoverage(t *testing.T) {
	// Routes whose handlers MUST stay ungated. Every entry here is a
	// surface that establishes identity or is RFC-mandated unauth.
	// Adding a new entry requires a justification comment.
	authExemptRoutes := map[string]string{
		// Identity-bearing surfaces (the gate would be circular):
		"GET /api/v1/auth/me":          "every caller may read their own identity",
		"GET /api/v1/auth/permissions": "every caller may read the global permission catalogue",
		"GET /api/v1/auth/check":       "identity-probe; gating would be circular",

		// Auth handshake surfaces (no identity at request time):
		"GET /auth/oidc/login":                "OIDC handshake start; no Bearer at this point",
		"GET /auth/oidc/callback":             "IdP redirects here pre-auth; cookie+state validated inside",
		"POST /auth/oidc/back-channel-logout": "IdP-initiated; auth via IdP-signed logout_token in body",
		"POST /auth/logout":                   "caller session-cookie is checked inside the handler",
		"POST /auth/breakglass/login":         "local-password recovery; surface invisible when disabled",
		"GET /api/v1/auth/bootstrap":          "day-0 admin probe; pre-admin by definition",
		"POST /api/v1/auth/bootstrap":         "consumes one-shot bootstrap token from body",

		// Health / version / info:
		"GET /health":           "K8s/Docker liveness probe; cannot carry Bearer",
		"GET /ready":            "K8s/Docker readiness probe; cannot carry Bearer",
		"GET /api/v1/auth/info": "GUI reads before login to detect auth mode",
		"GET /api/v1/version":   "rollout probes; pre-auth allowed",
	}

	// Protocol-endpoint prefixes — every r.Register against one of these
	// is intentionally ungated (protocol-level auth via JWS / mTLS / CSR-
	// embedded credentials). Mirrors AuthExemptDispatchPrefixes plus the
	// in-router ACME paths.
	protocolPrefixes := []string{
		"/acme/",
		"/scep",
		"/.well-known/pki",
		"/.well-known/est",
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "router.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse router.go: %v", err)
	}

	var unguarded []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Register" {
			return true
		}
		// Reject calls that aren't r.Register (e.g. mux.Handle is filtered out
		// by the SelectorExpr.X check below). The router type is `*Router`;
		// we accept any selector since RegisterFunc also wraps Register.
		_ = sel
		if len(call.Args) < 2 {
			return true
		}

		routeLit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || routeLit.Kind != token.STRING {
			return true
		}
		route := strings.Trim(routeLit.Value, `"`)
		// Only inspect routes that should be gated: state-changing
		// (POST/PUT/PATCH/DELETE) or any read endpoint (GET).
		if !isHTTPMethodRoute(route) {
			return true
		}
		// Auth-exempt allowlist?
		if _, ok := authExemptRoutes[route]; ok {
			return true
		}
		// Protocol prefix?
		if hasProtocolPrefix(route, protocolPrefixes) {
			return true
		}

		// Inspect arg 1: must be rbacGate(...) or rbacGateScoped(...).
		wrap, ok := call.Args[1].(*ast.CallExpr)
		if !ok {
			unguarded = append(unguarded, route)
			return true
		}
		wrapName := ""
		switch fn := wrap.Fun.(type) {
		case *ast.Ident:
			wrapName = fn.Name
		case *ast.SelectorExpr:
			wrapName = fn.Sel.Name
		}
		if wrapName != "rbacGate" && wrapName != "rbacGateScoped" {
			unguarded = append(unguarded, route)
		}
		return true
	})

	if len(unguarded) > 0 {
		sort.Strings(unguarded)
		t.Fatalf("router.go: %d routes registered without rbacGate / rbacGateScoped (and not in authExemptRoutes / protocolPrefixes):\n  %s\n\n"+
			"If a new auth-exempt surface is intentional, add it to authExemptRoutes (or protocolPrefixes) "+
			"with a justification comment. Otherwise wrap with rbacGate(reg.Checker, \"<perm>\", <handler>).\n\n"+
			"This test pins the 2026-05-10 audit CRIT-1 closure. Removing an existing rbacGate wrap requires "+
			"either (a) moving the route to authExemptRoutes here, or (b) demonstrating the new approach in "+
			"the commit body.",
			len(unguarded), strings.Join(unguarded, "\n  "))
	}
}

func isHTTPMethodRoute(route string) bool {
	for _, prefix := range []string{"GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD "} {
		if strings.HasPrefix(route, prefix) {
			return true
		}
	}
	return false
}

func hasProtocolPrefix(route string, prefixes []string) bool {
	// Strip the method token to compare against URL prefixes.
	idx := strings.Index(route, " ")
	if idx == -1 {
		return false
	}
	urlPart := route[idx+1:]
	for _, p := range prefixes {
		if strings.HasPrefix(urlPart, p) {
			return true
		}
	}
	return false
}
