// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package mcp

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// RegisterTools registers all certctl API endpoints as MCP tools on the server.
func RegisterTools(s *gomcp.Server, client *Client) {
	registerCertificateTools(s, client)
	registerCRLOCSPTools(s, client)
	registerIssuerTools(s, client)
	registerTargetTools(s, client)
	registerAgentTools(s, client)
	registerJobTools(s, client)
	registerPolicyTools(s, client)
	registerProfileTools(s, client)
	registerTeamTools(s, client)
	registerOwnerTools(s, client)
	registerAgentGroupTools(s, client)
	registerAuditTools(s, client)
	registerNotificationTools(s, client)
	registerStatsTools(s, client)
	registerMetricsTools(s, client)
	registerDigestTools(s, client)
	registerHealthTools(s, client)
	registerESTTools(s, client)
	// 2026-05-05 CLI/API/MCP↔GUI parity audit closure (35 P1 findings).
	// Each register function below maps to one phase of
	// cowork/mcp-coverage-expansion-prompt.md.
	registerApprovalTools(s, client)       // Phase A — P1-28..P1-31
	registerHealthCheckTools(s, client)    // Phase B — P1-20..P1-27
	registerRenewalPolicyTools(s, client)  // Phase C — P1-1..P1-5
	registerNetworkScanTools(s, client)    // Phase D — P1-14..P1-19
	registerDiscoveryReadTools(s, client)  // Phase E — P1-10..P1-13
	registerIntermediateCATools(s, client) // Phase F — P1-6..P1-9
	registerVerificationTools(s, client)   // Phase G — P1-32, P1-34, P1-35
	// Bundle 1 Phase 11 — RBAC management tools (12 tools).
	// auth_me + role lifecycle + permission grants + key→role grants.
	// All route through the existing HTTP client; permission gates fire
	// server-side. See internal/mcp/tools_auth.go.
	registerAuthTools(s, client)
	// Bundle 2 Phase 9 — OIDC + session management tools (11 tools).
	// list/get/create/update/delete/refresh OIDC provider, list/add/remove
	// group→role mapping, list/revoke session. All route through the
	// existing HTTP client; permission gates fire server-side via the
	// Phase-5 rbacGate wrappers. See internal/mcp/tools_auth_bundle2.go.
	registerAuthBundle2Tools(s, client)
	// Audit 2026-05-10 MED-13 — 11 tools rounding out the operator
	// surface: approvals (4) + break-glass admin (4) + bootstrap
	// status/consume (2) + audit category filter (1). See
	// internal/mcp/tools_audit_fix.go for the per-tool wiring + the
	// security comment on certctl_bootstrap_consume (never wire to
	// autonomous operation; one-shot token-minting primitive).
	registerAuditFixTools(s, client)
	// Phase G P1-33 (POST /api/v1/agents/{id}/discoveries) is
	// intentionally NOT exposed via MCP — it is a machine-to-machine
	// channel for agents to push filesystem-scan reports, not an
	// operator-driven flow. See registerAgentTools for context.
}

// ── Helpers ─────────────────────────────────────────────────────────

// textResult is the success-path wrapper used by every MCP tool. Bundle-3
// (Audit H-002, H-003, M-003, M-004, M-005, CWE-1039 LLM Prompt Injection):
// the response body returned to the LLM consumer may contain attacker-
// controllable text — cert subject DN/SANs (CSR submitter controls), agent
// hostname/OS/arch/IP (agent self-reports), upstream CA error strings (CA
// controls), audit details + notification bodies (downstream actors). To
// make the trust boundary explicit, we wrap every body in `--- UNTRUSTED
// MCP_RESPONSE START ... END ---` fences. LLM consumers that fence
// untrusted data correctly will see the attack as data, not instructions.
//
// See internal/mcp/fence.go for the strategy doc + per-finding rationale.
func textResult(data json.RawMessage) (*gomcp.CallToolResult, any, error) {
	return &gomcp.CallToolResult{
		Content: []gomcp.Content{
			&gomcp.TextContent{Text: fenceMCPResponse(string(data))},
		},
	}, nil, nil
}

// errorResult is the failure-path wrapper used by every MCP tool. Bundle-3
// (M-004 in particular): the wrapped error often originates from an upstream
// CA whose error string the attacker may control. We fence the error message
// via fenceMCPError before returning to the LLM consumer. The third return
// value is what the gomcp framework surfaces; gomcp formats it into a
// CallToolResult.IsError content automatically.
func errorResult(err error) (*gomcp.CallToolResult, any, error) {
	return nil, nil, fmt.Errorf("%s", fenceMCPError(err.Error()))
}

func paginationQuery(page, perPage int) url.Values {
	q := url.Values{}
	if page > 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if perPage > 0 {
		q.Set("per_page", strconv.Itoa(perPage))
	}
	return q
}
