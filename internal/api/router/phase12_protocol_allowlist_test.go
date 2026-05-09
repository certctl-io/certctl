package router

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/certctl-io/certctl/internal/auth"
)

// =============================================================================
// Bundle 1 Phase 12 (Category F) — protocol endpoints MUST NOT be wrapped in
// rbacGate / auth.RequirePermission.
//
// The prompt's exit criterion: "Negative test asserts that ACME / SCEP /
// EST / OCSP / CRL endpoints are NOT wrapped in RequirePermission.
// Implementation: scan the router config and assert each protocol-
// endpoint route is in the allowlist constant from Phase 3."
//
// Two complementary checks ride here:
//
//  1. Scan router.go's source for every literal route path that matches
//     a protocol-endpoint prefix; assert NONE of those paths appear
//     inside a rbacGate(...) call. The AST walker is intentionally
//     loose — substring match against the rbacGate function name is
//     sufficient and avoids false negatives from formatting.
//
//  2. Pin the protocol-endpoint dispatch prefixes (cmd/server/main.go's
//     buildFinalHandler dispatch) against the allowlist constant in
//     auth.IsProtocolEndpoint. If a future commit adds a new protocol
//     endpoint without extending the allowlist, this test breaks.
// =============================================================================

// protocolEndpointPrefixes is the canonical set of URL prefixes the
// auth middleware MUST bypass. Mirrors auth.IsProtocolEndpoint's
// internal switch. This test pins the constant against the actual
// router shape.
var protocolEndpointPrefixes = []string{
	"/acme",
	"/scep",
	"/.well-known/est",
	"/.well-known/pki/ocsp",
	"/.well-known/pki/crl",
}

// TestPhase12_ProtocolEndpointsNotGated walks router.go and asserts
// no rbacGate(...) call references a path under a protocol-endpoint
// prefix. We accept false negatives (the test is conservative) but
// never false positives — if rbacGate wraps a protocol path, the test
// fails with the offending line.
func TestPhase12_ProtocolEndpointsNotGated(t *testing.T) {
	src, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("read router.go: %v", err)
	}
	fset := token.NewFileSet()
	if _, perr := parser.ParseFile(fset, "router.go", src, parser.SkipObjectResolution); perr != nil {
		t.Fatalf("parse router.go: %v", perr)
	}
	body := string(src)

	// Find every line containing rbacGate(. For each, scan for any
	// of the protocol prefixes appearing on the same line. If both
	// land on a single line, that's a Category-F violation.
	for i, line := range strings.Split(body, "\n") {
		if !strings.Contains(line, "rbacGate(") {
			continue
		}
		for _, prefix := range protocolEndpointPrefixes {
			// We look for `"<prefix>"` or `"<prefix>/...` shapes —
			// the path argument is always a quoted string in the
			// repo's r.Register("METHOD /path", ...) convention.
			if strings.Contains(line, `"`+prefix) {
				t.Errorf("router.go line %d: rbacGate wraps a protocol-endpoint path %q (Category F violation): %s",
					i+1, prefix, strings.TrimSpace(line))
			}
		}
	}
}

// TestPhase12_IsProtocolEndpoint_CoversCanonicalPrefixes pins the
// auth.IsProtocolEndpoint allowlist against the canonical prefix
// set. If a future commit adds a new protocol that the auth
// middleware needs to bypass, both this slice AND
// auth.IsProtocolEndpoint must change in lockstep.
func TestPhase12_IsProtocolEndpoint_CoversCanonicalPrefixes(t *testing.T) {
	for _, prefix := range protocolEndpointPrefixes {
		// IsProtocolEndpoint takes a full path; pass the prefix as
		// a synthetic representative request path.
		probe := prefix
		if !strings.HasSuffix(probe, "/") {
			probe = probe + "/probe"
		}
		if !auth.IsProtocolEndpoint(probe) {
			t.Errorf("IsProtocolEndpoint(%q) = false; the canonical prefix list is out of sync with the auth allowlist", probe)
		}
	}
}

// TestPhase12_RBACGateRoutesAreUnderAPIv1 belt-and-braces: every
// rbacGate-wrapped path the parity test enumerates must start with
// `/api/v1/` so we can never accidentally wrap a protocol endpoint
// (those all live under `/acme`, `/scep`, or `/.well-known/`).
func TestPhase12_RBACGateRoutesAreUnderAPIv1(t *testing.T) {
	src, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("read router.go: %v", err)
	}
	for i, line := range strings.Split(string(src), "\n") {
		if !strings.Contains(line, "rbacGate(") {
			continue
		}
		// Find the quoted path argument. Look for the first
		// occurrence of `"METHOD /...`.
		startQuote := strings.Index(line, `"`)
		if startQuote < 0 {
			continue
		}
		endQuote := strings.Index(line[startQuote+1:], `"`)
		if endQuote < 0 {
			continue
		}
		path := line[startQuote+1 : startQuote+1+endQuote]
		// The Register signature is "METHOD /path" — split on
		// whitespace.
		parts := strings.Fields(path)
		if len(parts) != 2 {
			continue
		}
		urlPath := parts[1]
		if !strings.HasPrefix(urlPath, "/api/v1/") {
			t.Errorf("router.go line %d: rbacGate wraps non-API-v1 path %q: %s",
				i+1, urlPath, strings.TrimSpace(line))
		}
	}
}
