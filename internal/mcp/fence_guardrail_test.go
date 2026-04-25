package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFenceGuardrail_NoBareCallToolResult is the regression guardrail for
// Bundle-3 / Audit H-002, H-003, M-003, M-004, M-005 / CWE-1039 (LLM Prompt
// Injection).
//
// The wrapper-layer fencing strategy (textResult / errorResult in tools.go)
// only provides defense-in-depth if EVERY MCP tool routes its response
// through those wrappers. A new tool that constructs its own
// `gomcp.CallToolResult{...}` literal — or returns a bare `fmt.Errorf` from
// the tool handler signature — would silently bypass the fence and re-open
// every finding in this bundle.
//
// This guardrail walks every .go file in the mcp package and fails CI if it
// finds a `gomcp.CallToolResult{` literal outside `tools.go` (which defines
// textResult). It is intentionally cheap and string-based — a real Go AST
// scan would be more precise but would also be more brittle to refactor.
//
// To add a new MCP tool: route through textResult / errorResult and this
// test stays green. To deliberately bypass: explicitly add the file to the
// allowlist below with a comment explaining why.
func TestFenceGuardrail_NoBareCallToolResult(t *testing.T) {
	// Files allowed to construct CallToolResult directly.
	// tools.go defines the textResult wrapper and is the ONLY legitimate
	// site. Tests are also allowed (they exercise the wrapper output).
	allow := map[string]bool{
		"tools.go": true,
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	violations := []string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		if allow[name] {
			continue
		}
		body, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(body)
		if strings.Contains(text, "gomcp.CallToolResult{") ||
			strings.Contains(text, "mcp.CallToolResult{") {
			violations = append(violations, name+": constructs CallToolResult literal — must route through textResult/errorResult (Bundle-3 fence)")
		}
	}
	if len(violations) > 0 {
		t.Errorf("Bundle-3 fence guardrail violated. Add allowlist entry only with security review.\n  - %s",
			strings.Join(violations, "\n  - "))
	}
}
