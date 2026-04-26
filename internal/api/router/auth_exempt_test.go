package router

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// osReadFile is a thin wrapper that the test functions use; aliased so the
// file's helper section reads cleanly without importing "os" repeatedly in
// the body.
var osReadFile = os.ReadFile

// Bundle B / Audit M-002 (CWE-862 Authorization Bypass).
//
// The certctl router has TWO layers where a route can be made auth-exempt:
//
//  1. internal/api/router/router.go::RegisterHandlers calls r.mux.Handle
//     directly (instead of r.Register), bypassing the router-level
//     middleware.Chain wrap. The 4 routes that do this today are pinned
//     in AuthExemptRouterRoutes.
//
//  2. cmd/server/main.go::buildFinalHandler dispatches by URL prefix,
//     routing some prefixes through the noAuthHandler chain. Those are
//     pinned in AuthExemptDispatchPrefixes.
//
// This file pins layer 1: it parses router.go's AST, finds every
// r.mux.Handle string-literal arg, and asserts that set equals
// AuthExemptRouterRoutes exactly. Adding a new mux.Handle without
// updating the allowlist constant fails CI; updating the constant
// requires a code reviewer to read the new entry's justification
// comment. Layer 2's pin lives in cmd/server/main_test.go for symmetry
// with the dispatch logic itself.

func TestRouter_AuthExemptAllowlist_PinsActualRegistrations(t *testing.T) {
	actual, err := extractRouterDirectMuxHandles("router.go")
	if err != nil {
		t.Fatalf("scan router.go: %v", err)
	}
	expected := append([]string(nil), AuthExemptRouterRoutes...)
	sort.Strings(actual)
	sort.Strings(expected)

	if !slicesEqual(actual, expected) {
		t.Errorf("AuthExemptRouterRoutes drift detected.\n"+
			"  Direct r.mux.Handle calls in router.go: %v\n"+
			"  AuthExemptRouterRoutes constant:        %v\n"+
			"\n"+
			"If you added a new mux.Handle, you MUST also add the route to\n"+
			"AuthExemptRouterRoutes WITH a justification comment explaining\n"+
			"why it is safe-without-auth. Adding a new auth-bypass without\n"+
			"updating the allowlist is the M-002 regression this test guards.\n",
			actual, expected)
	}
}

func TestRouter_AllRegisterCallsGoThroughMiddlewareChain(t *testing.T) {
	// Every r.Register / r.RegisterFunc call in router.go pipes through
	// middleware.Chain(handler, r.middleware...). Any future change to
	// the Register / RegisterFunc body that drops the middleware wrap
	// silently exempts every "authenticated" route from auth — fail fast.
	//
	// We read router.go as raw bytes and check for the load-bearing
	// strings inside each function body. AST stringification is overkill
	// for a substring check.
	raw, err := readFileBytes("router.go")
	if err != nil {
		t.Fatalf("read router.go: %v", err)
	}
	registerBody := extractFuncSourceByName(raw, "Register")
	registerFuncBody := extractFuncSourceByName(raw, "RegisterFunc")

	if !strings.Contains(registerBody, "middleware.Chain") {
		t.Errorf("Router.Register no longer pipes through middleware.Chain — auth bypass risk. Body:\n%s", registerBody)
	}
	// RegisterFunc is allowed to either chain directly or delegate to Register.
	if !strings.Contains(registerFuncBody, "r.Register") && !strings.Contains(registerFuncBody, "middleware.Chain") {
		t.Errorf("Router.RegisterFunc no longer delegates to Register / middleware.Chain — auth bypass risk. Body:\n%s", registerFuncBody)
	}
}

// --- helpers --------------------------------------------------------------

func parseRouterFile(name string) (*ast.File, error) {
	fset := token.NewFileSet()
	return parser.ParseFile(fset, name, nil, parser.ParseComments)
}

// extractRouterDirectMuxHandles returns every "<METHOD> <PATH>" string
// literal passed as the first argument to r.mux.Handle in the file.
func extractRouterDirectMuxHandles(name string) ([]string, error) {
	src, err := parseRouterFile(name)
	if err != nil {
		return nil, err
	}
	var out []string
	ast.Inspect(src, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		// Looking for r.mux.Handle(...) — selector chain Sel="Handle",
		// X is itself a SelectorExpr Sel="mux".
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Handle" {
			return true
		}
		inner, ok := sel.X.(*ast.SelectorExpr)
		if !ok || inner.Sel.Name != "mux" {
			return true
		}
		if len(call.Args) == 0 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		// Skip the generic Register helper itself (line 38: r.mux.Handle(pattern, ...))
		// — pattern there is a func parameter, not a string literal.
		// Trim quotes on the literal value.
		v := strings.Trim(lit.Value, "\"`")
		if v == "" {
			return true
		}
		out = append(out, v)
		return true
	})
	return out, nil
}

func readFileBytes(name string) ([]byte, error) {
	return osReadFile(name)
}

// extractFuncSourceByName returns the raw source body (between the opening
// and matching closing brace) of the named func defined in src.
func extractFuncSourceByName(src []byte, name string) string {
	needle := []byte("func (r *Router) " + name + "(")
	idx := indexOfBytes(src, needle)
	if idx < 0 {
		return ""
	}
	// Find first '{' after the signature, then walk to the matching '}'.
	openIdx := idx + indexOfBytes(src[idx:], []byte("{"))
	if openIdx < 0 {
		return ""
	}
	depth := 0
	for i := openIdx; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return string(src[openIdx : i+1])
			}
		}
	}
	return ""
}

func indexOfBytes(haystack, needle []byte) int {
	return strings.Index(string(haystack), string(needle))
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
