package ciparity

// surface_parity_test.go — per post-v2.1.0 anti-rot item 2 (Auditable
// Codebase Bundle).
//
// Three tests, all stdlib-only:
//
//   1. TestSurfaceParity_MCPToolCatalogue (HARD GATE)
//      Every MCP tool name matches the `certctl_<word>(_<word>)*`
//      convention; no duplicates across files; total count ≥
//      mcpBaselineFloor. Catches accidental tool deletions + naming-
//      convention drift.
//
//   2. TestSurfaceParity_CLICommandCatalogue (INFORMATIONAL — t.Log only)
//      Walks cmd/cli/main.go's switch-case dispatcher. Per frozen
//      decision 0.9, warn-only until the CLI surface stabilizes.
//
//   3. TestSurfaceParity_OpenAPI_MCPHeuristicCoverage (INFORMATIONAL)
//      Reports the fraction of OpenAPI operations whose path tokens
//      overlap with any MCP tool name token. Trend metric, not a gate.
//
//   4. TestSurfaceParity_Summary (INFORMATIONAL)
//      One-glance summary of the four surface counts.
//
// All file paths are resolved relative to the repo root, which this
// test discovers by walking up from $PWD until it finds go.mod. Keeps
// the test runnable from any working directory.

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// mcpBaselineFloor — see header doc. Bump when a deletion is
// deliberate; the diff captures the change.
//
// Phase 3 ARCH-H3 reconciliation (2026-05-13): the audit framing
// "121 vs floor 150 — doc/code drift" was a measurement scoping error
// — the audit counted only internal/mcp/tools.go (which has 121
// AddTool calls) and missed the four sibling files listed in
// mcpToolFiles() below (tools_audit_fix.go + tools_auth.go +
// tools_auth_bundle2.go + tools_est.go) that add another 34 unique
// names. Live total: 155 unique `Name: "certctl_*"` declarations
// across the 5 files, ≥ 150. This test therefore passes today.
//
// Bumping the floor: when the catalogue legitimately grows, raise
// this constant in the same commit that adds the new tools so the
// floor tracks the ratchet. Lower only when a deletion is intentional
// and documented in surface-parity-mcp-exemptions.yaml.
const mcpBaselineFloor = 150

var (
	mcpToolNameRe = regexp.MustCompile(`^certctl_[a-z][a-z0-9_]*[a-z0-9]$`)
	mcpNameDeclRe = regexp.MustCompile(`Name:\s*"(certctl_[a-z0-9_]+)"`)
	openapiPathRe = regexp.MustCompile(`^  (/[^:]+):\s*$`)
	openapiVerbRe = regexp.MustCompile(`^    (get|post|put|delete|patch|options|head):\s*$`)
	caseLiteralRe = regexp.MustCompile(`case\s+"([a-z\-]+)":`)
)

// mcpToolFiles lists the (non-test) Go files expected to register
// MCP tools.
//
// Phase 9 Sprint 10 (commit fbe053aa, 2026-05-14): tools.go was split
// into six tool-domain sibling files in the same `mcp` package
// (tools_certificates.go + tools_agents.go + tools_resources.go +
// tools_jobs.go + tools_discovery.go + tools_admin.go). Original
// tools.go now holds only the RegisterTools dispatcher + Bundle-3
// fence wrappers + paginationQuery helper — zero mcp.AddTool calls.
// This list is the union of pre-Sprint-10 + Sprint-10 sibling files.
func mcpToolFiles(repo string) []string {
	base := filepath.Join(repo, "internal", "mcp")
	return []string{
		// Pre-Sprint-10 catalogue.
		filepath.Join(base, "tools.go"),
		filepath.Join(base, "tools_audit_fix.go"),
		filepath.Join(base, "tools_auth.go"),
		filepath.Join(base, "tools_auth_bundle2.go"),
		filepath.Join(base, "tools_est.go"),
		// Phase 9 Sprint 10 sibling files.
		filepath.Join(base, "tools_certificates.go"),
		filepath.Join(base, "tools_agents.go"),
		filepath.Join(base, "tools_resources.go"),
		filepath.Join(base, "tools_jobs.go"),
		filepath.Join(base, "tools_discovery.go"),
		filepath.Join(base, "tools_admin.go"),
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	cur := wd
	for {
		if _, err := os.Stat(filepath.Join(cur, "go.mod")); err == nil {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			t.Fatalf("no go.mod found from %s upward", wd)
		}
		cur = parent
	}
}

// readFileOrSkip reads a file; on ENOENT, calls t.Skipf rather than
// failing — useful for files that may be renamed during refactors.
func readFileOrFail(t *testing.T, p string) []byte {
	t.Helper()
	body, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected file missing: %s (refactor? — update the test)", p)
		}
		t.Fatalf("read %s: %v", p, err)
	}
	return body
}

// TestSurfaceParity_MCPToolCatalogue is a HARD gate.
//
// Asserts:
//
//   - Every MCP tool name conforms to certctl_<word>(_<word>)*.
//   - No tool name is registered in more than one tools*.go file.
//   - Total tools ≥ mcpBaselineFloor.
func TestSurfaceParity_MCPToolCatalogue(t *testing.T) {
	repo := findRepoRoot(t)
	names := map[string]string{}
	for _, path := range mcpToolFiles(repo) {
		body := readFileOrFail(t, path)
		base := filepath.Base(path)
		for _, m := range mcpNameDeclRe.FindAllStringSubmatch(string(body), -1) {
			name := m[1]
			if !mcpToolNameRe.MatchString(name) {
				t.Errorf("MCP tool name %q in %s does not match certctl_<word>(_<word>)* — fix the name or relax the convention deliberately",
					name, base)
				continue
			}
			if other, dup := names[name]; dup {
				t.Errorf("MCP tool name %q duplicated: first in %s, again in %s — pick a unique name",
					name, filepath.Base(other), base)
				continue
			}
			names[name] = path
		}
	}
	if len(names) < mcpBaselineFloor {
		t.Errorf("MCP tool count regressed: %d found, baseline floor %d. "+
			"If the deletion is intentional, lower mcpBaselineFloor in this test in the SAME commit. "+
			"If accidental, restore the deleted tools.",
			len(names), mcpBaselineFloor)
	}
	t.Logf("MCP tool catalogue: %d tools (baseline floor %d)", len(names), mcpBaselineFloor)
}

// TestSurfaceParity_CLICommandCatalogue — informational only.
//
// Walks cmd/cli/main.go's switch-case dispatcher and reports the
// distinct verbs handled. Returns success regardless of contents.
// Promoted to fail-on-miss when the CLI surface stabilizes.
func TestSurfaceParity_CLICommandCatalogue(t *testing.T) {
	repo := findRepoRoot(t)
	body := readFileOrFail(t, filepath.Join(repo, "cmd", "cli", "main.go"))
	verbs := map[string]struct{}{}
	for _, m := range caseLiteralRe.FindAllStringSubmatch(string(body), -1) {
		verbs[m[1]] = struct{}{}
	}
	if len(verbs) == 0 {
		t.Fatal("CLI scanner found zero verbs — likely a refactor; update the test")
	}
	out := make([]string, 0, len(verbs))
	for v := range verbs {
		out = append(out, v)
	}
	sort.Strings(out)
	t.Logf("CLI verb catalogue (%d distinct case literals; informational only per frozen decision 0.9):\n  %s",
		len(out), strings.Join(out, ", "))
}

// scanOpenAPIOps walks openapi.yaml's paths block and returns every
// (METHOD, PATH) tuple. Mirrors the parser used by
// internal/api/router/openapi_parity_test.go::scanOpenAPIOperations.
func scanOpenAPIOps(t *testing.T, path string) []string {
	t.Helper()
	body := readFileOrFail(t, path)
	var out []string
	inPaths := false
	currentPath := ""
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
		if m := openapiPathRe.FindStringSubmatch(line); m != nil {
			currentPath = m[1]
			continue
		}
		if m := openapiVerbRe.FindStringSubmatch(line); m != nil && currentPath != "" {
			out = append(out, strings.ToUpper(m[1])+" "+currentPath)
		}
	}
	return out
}

// scanRouterRoutes scans internal/api/router/router.go for route
// registrations. Uses a regex (not go/ast) to keep this package
// stdlib-only; the router.go file is large but the patterns we care
// about are stable enough that regex is sufficient.
func scanRouterRoutes(t *testing.T, path string) []string {
	t.Helper()
	body := readFileOrFail(t, path)
	// Match r.Register("METHOD /path", ...) and r.mux.Handle("METHOD /path", ...).
	registerRe := regexp.MustCompile(`r\.Register\(\s*"([A-Z]+ /[^"]+)"`)
	muxHandleRe := regexp.MustCompile(`r\.mux\.Handle\(\s*"([A-Z]+ /[^"]+)"`)
	seen := map[string]struct{}{}
	for _, m := range registerRe.FindAllStringSubmatch(string(body), -1) {
		seen[m[1]] = struct{}{}
	}
	for _, m := range muxHandleRe.FindAllStringSubmatch(string(body), -1) {
		seen[m[1]] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out
}

// TestSurfaceParity_OpenAPI_MCPHeuristicCoverage — informational.
//
// For each OpenAPI operation, splits the path into tokens; if any
// token appears in any MCP tool name's token set, the op is "covered."
// This is a heuristic — the actual semantic map (operationId →
// MCP tool) is not declared in the source, so we approximate.
func TestSurfaceParity_OpenAPI_MCPHeuristicCoverage(t *testing.T) {
	repo := findRepoRoot(t)
	specOps := scanOpenAPIOps(t, filepath.Join(repo, "api", "openapi.yaml"))
	mcpTokens := map[string]struct{}{}
	for _, path := range mcpToolFiles(repo) {
		body := readFileOrFail(t, path)
		for _, m := range mcpNameDeclRe.FindAllStringSubmatch(string(body), -1) {
			for _, tok := range strings.Split(strings.TrimPrefix(m[1], "certctl_"), "_") {
				mcpTokens[tok] = struct{}{}
			}
		}
	}
	covered := 0
	for _, op := range specOps {
		parts := strings.Split(op, " ")
		if len(parts) != 2 {
			continue
		}
		segs := strings.FieldsFunc(parts[1], func(r rune) bool {
			return r == '/' || r == '{' || r == '}' || r == '-'
		})
		hit := false
		for _, s := range segs {
			if _, ok := mcpTokens[strings.ToLower(s)]; ok {
				hit = true
				break
			}
		}
		if hit {
			covered++
		}
	}
	if len(specOps) == 0 {
		t.Fatal("openapi.yaml scan returned zero operations — fix the test")
	}
	pct := (covered * 100) / len(specOps)
	t.Logf("OpenAPI↔MCP heuristic coverage (informational): %d of %d ops (%d%%) share at least one path token with an MCP tool name",
		covered, len(specOps), pct)
}

// TestSurfaceParity_Summary prints the four surface counts side-by-side.
func TestSurfaceParity_Summary(t *testing.T) {
	repo := findRepoRoot(t)
	routes := scanRouterRoutes(t, filepath.Join(repo, "internal", "api", "router", "router.go"))
	specOps := scanOpenAPIOps(t, filepath.Join(repo, "api", "openapi.yaml"))
	mcpCount := 0
	for _, path := range mcpToolFiles(repo) {
		body := readFileOrFail(t, path)
		mcpCount += len(mcpNameDeclRe.FindAllStringSubmatch(string(body), -1))
	}
	cliBody := readFileOrFail(t, filepath.Join(repo, "cmd", "cli", "main.go"))
	cliCount := len(caseLiteralRe.FindAllStringSubmatch(string(cliBody), -1))
	t.Logf("Surface parity summary (informational):\n"+
		"  router routes : %d\n"+
		"  OpenAPI ops   : %d\n"+
		"  MCP tools     : %d  (floor %d)\n"+
		"  CLI verbs     : %d  (warn-only — frozen decision 0.9)",
		len(routes), len(specOps), mcpCount, mcpBaselineFloor, cliCount)
}
