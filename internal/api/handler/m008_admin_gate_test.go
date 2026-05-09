package handler

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Bundle C / Audit M-008: pin the admin-gated handler set.
//
// The audit's request is "Admin-gated operation role-gate test coverage
// needs verification". Verified-already-clean recon: only one handler
// in internal/api/handler/ calls auth.IsAdmin to gate access:
// bulk_revocation.go — which has 3 dedicated tests
// (NonAdmin_Returns403, AdminExplicitFalse_Returns403,
// AdminPermitted_ForwardsActor) covering all three branches.
//
// This test enforces the invariant going forward by walking every
// .go file in this package, finding every auth.IsAdmin call
// site, and asserting the file appears in AdminGatedHandlers below.
// Adding a new auth.IsAdmin call without updating the constant
// AND adding a parallel test triplet fails CI.

// AdminGatedHandlers is the documented allowlist of handler files that
// gate access on auth.IsAdmin. Every entry MUST have:
//   - a non-admin-rejection test ("_NonAdmin_Returns403")
//   - an explicit-false-admin-rejection test ("_AdminExplicitFalse_Returns403")
//   - an admin-allowed actor-attribution test ("_AdminPermitted_ForwardsActor")
//
// Keys are the handler filenames; values are short descriptions of why
// the gate exists. health.go is an INFORMATIONAL caller of IsAdmin (it
// surfaces the flag to the GUI but does not gate) — explicitly excluded.
// Bundle 1 Phase 3.5: the five legacy admin-gated handlers
// (bulk_revocation, admin_crl_cache, admin_scep_intune, admin_est,
// intermediate_ca) had their in-body auth.IsAdmin checks removed and
// the gate moved to router.go via auth.RequirePermission middleware.
// AdminGatedHandlers is now empty; the only legitimate auth.IsAdmin
// call site in this package is health.go (informational, surfaces the
// admin flag to the GUI but doesn't gate). New routes should not add
// in-handler auth.IsAdmin checks; gate at the router level instead.
var AdminGatedHandlers = map[string]string{}

// InformationalIsAdminCallers is the documented allowlist of files that
// call auth.IsAdmin without using the result to gate access. The
// only legitimate use of an informational call is reporting the flag to
// a downstream consumer (e.g. health.go::AuthCheck reports admin to the
// GUI so it can hide admin-only buttons).
var InformationalIsAdminCallers = map[string]string{
	"health.go": "informational: reports admin flag to GUI for affordance gating, no server-side gate",
}

func TestM008_AdminGatedHandlers_PinExpectedSet(t *testing.T) {
	actual, err := scanIsAdminCallers(".")
	if err != nil {
		t.Fatalf("scan handler dir: %v", err)
	}

	expected := append([]string(nil), keys(AdminGatedHandlers)...)
	expected = append(expected, keys(InformationalIsAdminCallers)...)
	sort.Strings(actual)
	sort.Strings(expected)

	if !slicesEqual008(actual, expected) {
		t.Errorf(
			"auth.IsAdmin call sites changed:\n"+
				"  actual:   %v\n"+
				"  expected: %v\n"+
				"\n"+
				"Bundle 1 Phase 3.5 removed in-handler auth.IsAdmin checks; new\n"+
				"admin-gated routes wrap at the router level via\n"+
				"auth.RequirePermission middleware (see router.go::rbacGate).\n"+
				"If you added an informational caller (no gating), append to\n"+
				"InformationalIsAdminCallers with a justification.",
			actual, expected)
	}
}

func TestM008_AdminGatedHandlers_HaveTripletTests(t *testing.T) {
	for handlerFile := range AdminGatedHandlers {
		base := strings.TrimSuffix(handlerFile, ".go")
		// Look for the 3-test triplet in the corresponding _test.go file
		// or in any test file in the package — bulk_revocation_handler_test.go
		// follows a slightly different naming convention.
		matches, err := filepath.Glob("*_test.go")
		if err != nil {
			t.Fatalf("glob: %v", err)
		}
		var foundNonAdmin, foundExplicitFalse, foundAdminPermitted bool
		for _, m := range matches {
			body, err := os.ReadFile(m)
			if err != nil {
				continue
			}
			s := string(body)
			// Look for tests that mention the handler base name + the
			// expected suffix. Loose match because some test files use
			// _Handler_NonAdmin and others use _NonAdmin.
			if strings.Contains(s, "NonAdmin_Returns403") {
				foundNonAdmin = true
			}
			if strings.Contains(s, "AdminExplicitFalse_Returns403") {
				foundExplicitFalse = true
			}
			if strings.Contains(s, "AdminPermitted_ForwardsActor") {
				foundAdminPermitted = true
			}
		}
		if !foundNonAdmin {
			t.Errorf("admin-gated handler %s lacks a *_NonAdmin_Returns403 test", base)
		}
		if !foundExplicitFalse {
			t.Errorf("admin-gated handler %s lacks a *_AdminExplicitFalse_Returns403 test", base)
		}
		if !foundAdminPermitted {
			t.Errorf("admin-gated handler %s lacks a *_AdminPermitted_ForwardsActor test", base)
		}
	}
}

// --- helpers --------------------------------------------------------------

func scanIsAdminCallers(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		_, parseErr := parser.ParseFile(fset, filepath.Join(dir, name), body, parser.SkipObjectResolution)
		if parseErr != nil {
			continue
		}
		// Substring-match auth.IsAdmin — cheap and sufficient
		// because the import path is fixed and there's no aliasing
		// shenanigans elsewhere in this package.
		if strings.Contains(string(body), "auth.IsAdmin(") {
			out = append(out, name)
		}
	}
	return out, nil
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func slicesEqual008(a, b []string) bool {
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
