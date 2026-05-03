package router

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Bundle D / Audit M-027: pin the router ↔ OpenAPI spec parity.
//
// The audit reported "router 121 vs OpenAPI 125 — 4 op gap" by counting
// r.Register call sites with a regex. That methodology is incomplete: the
// router additionally registers 4 routes via direct r.mux.Handle calls
// (the Bundle B / M-002 AuthExemptRouterRoutes — health/ready/auth-info/
// version). When you count BOTH dispatch shapes the totals match exactly.
//
// This test:
//   1. Walks router.go's AST to enumerate every (method, path) tuple from
//      both r.Register AND r.mux.Handle sites.
//   2. Walks api/openapi.yaml's path/method nesting to enumerate every
//      documented operation.
//   3. Asserts the two sets are identical (modulo a tiny exception list
//      for routes that legitimately don't appear in the spec).
//
// Adding a new route without updating openapi.yaml fails this test.

// SpecParityExceptions is the documented allowlist of (method, path)
// tuples that are intentionally NOT in api/openapi.yaml. Each entry must
// have a justification — typically "internal" or "non-stable surface".
//
// At Bundle D close time, this list is empty. Future entries should be
// rare — the OpenAPI spec is the source of truth for the public API
// surface.
var SpecParityExceptions = map[string]string{
	// SCEP RFC 8894 + Intune master bundle Phase 6.5: the /scep-mtls
	// sibling route is opt-in (gated on per-profile MTLSEnabled). It rides
	// the same SCEP-PKIOperation contract as /scep but with an additional
	// client-cert auth layer at the handler. The OpenAPI spec covers the
	// canonical /scep endpoint; documenting /scep-mtls separately would
	// duplicate every operation row with no information gain — the
	// PKIMessage wire format, query params, and response shapes are
	// identical. The route lives in router.go as literal r.Register calls
	// for the openapi-parity scanner's benefit; it stays out of openapi.yaml
	// by exception. See docs/legacy-est-scep.md::mTLS-sibling-route for the
	// operator-facing description.
	"GET /scep-mtls":  "Phase 6.5 mTLS sibling route — same wire format as /scep with cert-required gate; documented in docs/legacy-est-scep.md",
	"POST /scep-mtls": "Phase 6.5 mTLS sibling route — same wire format as /scep with cert-required gate; documented in docs/legacy-est-scep.md",

	// ACME server (RFC 8555 + RFC 9773 ARI) — Phase 1a foundation.
	// Like SCEP/EST, ACME is a wire-protocol surface (JWS-signed JSON
	// over HTTPS per RFC 7515) whose semantics are dictated by the RFC
	// rather than by an OpenAPI document. Documenting every endpoint
	// in openapi.yaml would duplicate RFC 8555 §7.1 + §7.2 with no
	// information gain. The canonical reference is docs/acme-server.md.
	// Subsequent phases will extend this list with new-account,
	// new-order, finalize, authz, challenge, cert, key-change,
	// revoke-cert, renewal-info — each gets its own exception entry
	// in the same commit that lands the route.
	"GET /acme/profile/{id}/directory":         "RFC 8555 §7.1.1 directory; documented in docs/acme-server.md",
	"HEAD /acme/profile/{id}/new-nonce":        "RFC 8555 §7.2 new-nonce; documented in docs/acme-server.md",
	"GET /acme/profile/{id}/new-nonce":         "RFC 8555 §7.2 new-nonce (GET form); documented in docs/acme-server.md",
	"POST /acme/profile/{id}/new-account":      "RFC 8555 §7.3 new-account; documented in docs/acme-server.md",
	"POST /acme/profile/{id}/account/{acc_id}": "RFC 8555 §7.3.2 account update + §7.3.6 deactivation; documented in docs/acme-server.md",
	"GET /acme/directory":                      "RFC 8555 §7.1.1 directory (default-profile shorthand); documented in docs/acme-server.md",
	"HEAD /acme/new-nonce":                     "RFC 8555 §7.2 new-nonce (default-profile shorthand); documented in docs/acme-server.md",
	"GET /acme/new-nonce":                      "RFC 8555 §7.2 new-nonce GET (default-profile shorthand); documented in docs/acme-server.md",
	"POST /acme/new-account":                   "RFC 8555 §7.3 new-account (default-profile shorthand); documented in docs/acme-server.md",
	"POST /acme/account/{acc_id}":              "RFC 8555 §7.3.2 + §7.3.6 (default-profile shorthand); documented in docs/acme-server.md",

	// Phase 2 — orders + finalize + authz + cert.
	"POST /acme/profile/{id}/new-order":               "RFC 8555 §7.4 new-order; documented in docs/acme-server.md",
	"POST /acme/profile/{id}/order/{ord_id}":          "RFC 8555 §7.4 order POST-as-GET; documented in docs/acme-server.md",
	"POST /acme/profile/{id}/order/{ord_id}/finalize": "RFC 8555 §7.4 finalize; documented in docs/acme-server.md",
	"POST /acme/profile/{id}/authz/{authz_id}":        "RFC 8555 §7.5 authz POST-as-GET; documented in docs/acme-server.md",
	"POST /acme/profile/{id}/cert/{cert_id}":          "RFC 8555 §7.4.2 cert download; documented in docs/acme-server.md",
	"POST /acme/new-order":                            "Phase 2 default-profile shorthand for new-order.",
	"POST /acme/order/{ord_id}":                       "Phase 2 default-profile shorthand for order POST-as-GET.",
	"POST /acme/order/{ord_id}/finalize":              "Phase 2 default-profile shorthand for finalize.",
	"POST /acme/authz/{authz_id}":                     "Phase 2 default-profile shorthand for authz POST-as-GET.",
	"POST /acme/cert/{cert_id}":                       "Phase 2 default-profile shorthand for cert download.",
}

func TestRouter_OpenAPIParity(t *testing.T) {
	routes, err := scanRouterRoutes("router.go")
	if err != nil {
		t.Fatalf("scan router.go: %v", err)
	}
	specOps, err := scanOpenAPIOperations("../../../api/openapi.yaml")
	if err != nil {
		t.Fatalf("scan openapi.yaml: %v", err)
	}

	routeSet := make(map[string]bool, len(routes))
	for _, r := range routes {
		routeSet[r] = true
	}
	specSet := make(map[string]bool, len(specOps))
	for _, o := range specOps {
		specSet[o] = true
	}

	var inRouterNotSpec, inSpecNotRouter []string
	for r := range routeSet {
		if !specSet[r] {
			if _, allow := SpecParityExceptions[r]; !allow {
				inRouterNotSpec = append(inRouterNotSpec, r)
			}
		}
	}
	for s := range specSet {
		if !routeSet[s] {
			inSpecNotRouter = append(inSpecNotRouter, s)
		}
	}

	sort.Strings(inRouterNotSpec)
	sort.Strings(inSpecNotRouter)

	if len(inRouterNotSpec) > 0 {
		t.Errorf("routes in router.go but missing from api/openapi.yaml (%d):\n  %s\n\n"+
			"Add the operation to openapi.yaml OR add an explicit exception to "+
			"SpecParityExceptions with a justification.",
			len(inRouterNotSpec), strings.Join(inRouterNotSpec, "\n  "))
	}
	if len(inSpecNotRouter) > 0 {
		t.Errorf("operations in api/openapi.yaml but missing from router.go (%d):\n  %s\n\n"+
			"Either implement the endpoint or remove it from openapi.yaml.",
			len(inSpecNotRouter), strings.Join(inSpecNotRouter, "\n  "))
	}
}

// --- helpers --------------------------------------------------------------

func scanRouterRoutes(name string) ([]string, error) {
	fset := token.NewFileSet()
	src, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []string
	ast.Inspect(src, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		// We care about r.mux.Handle("METHOD /path", ...) and
		// r.Register("METHOD /path", ...). Both have a string literal as
		// arg[0].
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		isMuxHandle := false
		isRegister := sel.Sel.Name == "Register"
		if sel.Sel.Name == "Handle" {
			if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "mux" {
				isMuxHandle = true
			}
		}
		if !isMuxHandle && !isRegister {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		v := strings.Trim(lit.Value, "\"`")
		// Skip the generic Register helper itself (line 38: r.mux.Handle(pattern,...)
		// — pattern is a func arg, not a literal, so it would not be a BasicLit).
		// Skip non-METHOD-prefixed strings (defensive).
		if !looksLikeMethodPath(v) {
			return true
		}
		out = append(out, v)
		return true
	})
	return out, nil
}

var methodPathRe = regexp.MustCompile(`^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD) /`)

func looksLikeMethodPath(s string) bool {
	return methodPathRe.MatchString(s)
}

// scanOpenAPIOperations walks openapi.yaml's paths block and returns
// every (METHOD, PATH) tuple in the same "METHOD /path" string shape the
// router uses. Naive but sufficient: the spec is hand-maintained YAML
// with consistent 2-space-then-4-space indentation.
func scanOpenAPIOperations(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	inPaths := false
	currentPath := ""
	pathRe := regexp.MustCompile(`^  (/[^:]+):\s*$`)
	methodRe := regexp.MustCompile(`^    (get|post|put|delete|patch|options|head):\s*$`)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "paths:") {
			inPaths = true
			continue
		}
		if inPaths && line != "" && !strings.HasPrefix(line, " ") {
			inPaths = false
			continue
		}
		if !inPaths {
			continue
		}
		if m := pathRe.FindStringSubmatch(line); m != nil {
			currentPath = m[1]
			continue
		}
		if m := methodRe.FindStringSubmatch(line); m != nil && currentPath != "" {
			out = append(out, strings.ToUpper(m[1])+" "+currentPath)
		}
	}
	return out, nil
}
