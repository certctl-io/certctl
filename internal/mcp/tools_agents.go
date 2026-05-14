// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package mcp

import (
	"context"
	"fmt"
	"net/url"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Phase 9 ARCH-M2 closure Sprint 10 (2026-05-14): extracted from
// internal/mcp/tools.go via the Option B sibling-file pattern.
//
// This file groups the agent-management MCP tool domain: per-agent
// CRUD + lifecycle (registerAgentTools — register / list / get /
// retire / heartbeat / poll / claim / verify / discoveries) and the
// agent-group surface (registerAgentGroupTools — group CRUD +
// membership). Phase G P1-33 (POST /api/v1/agents/{id}/discoveries)
// stays intentionally absent from the MCP surface per the comment
// in tools.go::RegisterTools — that endpoint is the
// machine-to-machine path agents use to push filesystem-scan
// reports, not an operator-driven flow worth exposing to LLM
// consumers.

// ── Agents ──────────────────────────────────────────────────────────

func registerAgentTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_agents",
		Description: "List all registered agents with status, OS, architecture, and version info.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListParams) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/agents", paginationQuery(input.Page, input.PerPage))
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_agent",
		Description: "Get agent details including status, last heartbeat, OS, architecture, IP, and version.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/agents/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_register_agent",
		Description: "Register a new agent. Requires name and hostname. Returns 409 if an agent with the same name already exists.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input RegisterAgentInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/agents", input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_agent_heartbeat",
		Description: "Send agent heartbeat with optional metadata (OS, architecture, IP, version). Returns 404 if agent not found.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input struct {
		ID           string `json:"id" jsonschema:"Agent ID"`
		Version      string `json:"version,omitempty" jsonschema:"Agent version"`
		Hostname     string `json:"hostname,omitempty" jsonschema:"Hostname"`
		OS           string `json:"os,omitempty" jsonschema:"Operating system"`
		Architecture string `json:"architecture,omitempty" jsonschema:"CPU architecture"`
		IPAddress    string `json:"ip_address,omitempty" jsonschema:"IP address"`
	}) (*gomcp.CallToolResult, any, error) {
		body := map[string]string{}
		if input.Version != "" {
			body["version"] = input.Version
		}
		if input.Hostname != "" {
			body["hostname"] = input.Hostname
		}
		if input.OS != "" {
			body["os"] = input.OS
		}
		if input.Architecture != "" {
			body["architecture"] = input.Architecture
		}
		if input.IPAddress != "" {
			body["ip_address"] = input.IPAddress
		}
		data, err := c.Post("/api/v1/agents/"+input.ID+"/heartbeat", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_agent_submit_csr",
		Description: "Submit a PEM-encoded CSR from an agent for signing.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AgentCSRInput) (*gomcp.CallToolResult, any, error) {
		body := map[string]string{"csr_pem": input.CSRPEM}
		if input.CertificateID != "" {
			body["certificate_id"] = input.CertificateID
		}
		data, err := c.Post("/api/v1/agents/"+input.AgentID+"/csr", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_agent_pickup_certificate",
		Description: "Agent picks up a signed certificate after CSR has been processed.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AgentPickupInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/agents/"+input.AgentID+"/certificates/"+input.CertID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_agent_get_work",
		Description: "Get pending work items (deployment jobs, AwaitingCSR jobs) for an agent.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/agents/"+input.ID+"/work", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_agent_report_job_status",
		Description: "Agent reports completion or failure of an assigned job.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AgentJobStatusInput) (*gomcp.CallToolResult, any, error) {
		body := map[string]string{"status": input.Status}
		if input.Error != "" {
			body["error"] = input.Error
		}
		data, err := c.Post("/api/v1/agents/"+input.AgentID+"/jobs/"+input.JobID+"/status", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	// I-004: soft-retirement. DELETE /api/v1/agents/{id} returns 200 on a
	// fresh retire (body echoes retired_at/already_retired/cascade/counts),
	// 204 on an idempotent retire of an already-retired agent (do() in
	// client.go normalizes that to {"status":"deleted"}), 409 when downstream
	// dependencies block the retire and force wasn't set, 403 on sentinel
	// agents, or 400 when force=true was sent without a reason. The tool
	// forwards the raw handler response so the LLM operator sees the
	// dependency counts and can decide whether to retry with force=true.
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_retire_agent",
		Description: "Soft-retire an agent (DELETE /api/v1/agents/{id}). Sets retired_at + retired_reason on the row; the agent is filtered from the default listing and surfaces only via certctl_list_retired_agents. Default is a safety-gated soft-retire that returns 409 blocked_by_dependencies if the agent has active targets, active certificates, or pending jobs — the returned counts tell you what would be orphaned. Pass force=true to cascade through and retire those dependents too; force=true requires a non-empty reason (captured in the audit trail). Sentinel discovery agents (server-scanner, cloud-aws-sm, cloud-azure-kv, cloud-gcp-sm) cannot be retired — the handler returns 403 unconditionally. Idempotent: retrying on an already-retired agent returns 204 without side effects.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input RetireAgentInput) (*gomcp.CallToolResult, any, error) {
		// Client-side mirror of the handler's ErrForceReasonRequired contract
		// (see internal/api/handler/agents.go) so the LLM gets an immediate,
		// actionable error instead of a round-trip 400. Whitespace-only
		// reasons are treated as empty — matches handler's TrimSpace check.
		if input.Force && input.Reason == "" {
			return errorResult(fmt.Errorf("reason is required when force=true"))
		}
		query := url.Values{}
		if input.Force {
			query.Set("force", "true")
		}
		if input.Reason != "" {
			query.Set("reason", input.Reason)
		}
		data, err := c.DeleteWithQuery("/api/v1/agents/"+input.ID, query)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	// I-004: retired agents are filtered out of GET /api/v1/agents by default.
	// The /agents/retired endpoint is the opt-in view — same pagination shape
	// as the default listing, but filters to rows where retired_at IS NOT NULL.
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_retired_agents",
		Description: "List soft-retired agents (GET /api/v1/agents/retired). These are agents that have been retired via certctl_retire_agent; retired_at and retired_reason are populated. Returned separately from certctl_list_agents so the default listing stays focused on operational agents.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListParams) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/agents/retired", paginationQuery(input.Page, input.PerPage))
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Agent Groups ────────────────────────────────────────────────────

func registerAgentGroupTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_agent_groups",
		Description: "List agent groups with dynamic matching criteria (OS, architecture, IP CIDR, version).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListParams) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/agent-groups", paginationQuery(input.Page, input.PerPage))
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_agent_group",
		Description: "Get agent group details including matching criteria.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/agent-groups/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_create_agent_group",
		Description: "Create a new agent group with dynamic matching criteria. Requires name.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input CreateAgentGroupInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/agent-groups", input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_update_agent_group",
		Description: "Update an agent group's name, description, or matching criteria.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input UpdateAgentGroupInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Put("/api/v1/agent-groups/"+input.ID, input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_delete_agent_group",
		Description: "Delete an agent group.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Delete("/api/v1/agent-groups/" + input.ID)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_agent_group_members",
		Description: "List agents that are members of a group (by dynamic criteria and manual membership).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/agent-groups/"+input.ID+"/members", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}
