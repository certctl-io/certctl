// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package mcp

import (
	"context"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Phase 9 ARCH-M2 closure Sprint 10 (2026-05-14): extracted from
// internal/mcp/tools.go via the Option B sibling-file pattern.
//
// This file groups the workflow MCP tool domain: jobs (the renewal
// + deployment work queue — registerJobTools) and approvals (the
// human-in-the-loop gate that fronts every CertificateProfile with
// RequiresApproval=true — registerApprovalTools, Phase A P1-28..P1-31).
//
// The approvalDecisionPayload struct sits alongside its callers
// (approve + reject MCP tools) so consumers reading the JSON shape
// don't have to chase across the file. It's intentionally unexported
// — the only public surface is the approve / reject tool args
// rendered by gomcp.AddTool.

// ── Jobs ────────────────────────────────────────────────────────────

func registerJobTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_jobs",
		Description: "List jobs with optional status and type filters. Job types: Issuance, Renewal, Deployment, Validation.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListJobsInput) (*gomcp.CallToolResult, any, error) {
		q := paginationQuery(input.Page, input.PerPage)
		if input.Status != "" {
			q.Set("status", input.Status)
		}
		if input.Type != "" {
			q.Set("type", input.Type)
		}
		data, err := c.Get("/api/v1/jobs", q)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_job",
		Description: "Get job details including type, status, attempts, errors, and timestamps.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/jobs/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_cancel_job",
		Description: "Cancel a pending or running job.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/jobs/"+input.ID+"/cancel", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_approve_job",
		Description: "Approve a job that is in AwaitingApproval state.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/jobs/"+input.ID+"/approve", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_reject_job",
		Description: "Reject a job in AwaitingApproval state with an optional reason.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input RejectJobInput) (*gomcp.CallToolResult, any, error) {
		body := map[string]string{}
		if input.Reason != "" {
			body["reason"] = input.Reason
		}
		data, err := c.Post("/api/v1/jobs/"+input.ID+"/reject", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Approvals (Phase A — P1-28..P1-31) ──────────────────────────────
//
// 2026-05-05 CLI/API/MCP↔GUI parity audit closure. Operators using AI
// assistants for cert-renewal in regulated environments need natural-language
// approve/reject. The service layer enforces ErrApproveBySameActor (the
// requesting actor cannot self-approve) and the handler extracts the
// decided_by actor from auth.UserKey — so the MCP server's API key
// identity becomes the audit-trail actor automatically. Two-person integrity
// is preserved as long as the MCP server's key is distinct from the
// requesting actor's; the tool inputs deliberately omit any actor_id field
// to prevent client-side spoofing.

func registerApprovalTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_approvals",
		Description: "List issuance approval requests (GET /api/v1/approvals). Optional state/certificate_id/requested_by filters narrow the returned set. Use state=pending to surface the operator-action queue.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListApprovalsInput) (*gomcp.CallToolResult, any, error) {
		q := paginationQuery(input.Page, input.PerPage)
		if input.State != "" {
			q.Set("state", input.State)
		}
		if input.CertificateID != "" {
			q.Set("certificate_id", input.CertificateID)
		}
		if input.RequestedBy != "" {
			q.Set("requested_by", input.RequestedBy)
		}
		data, err := c.Get("/api/v1/approvals", q)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_approval",
		Description: "Get a single approval request (GET /api/v1/approvals/{id}). Returns the full ApprovalRequest row — state, requesting actor, linked job, linked certificate.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/approvals/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_approve_request",
		Description: "Approve an issuance request (POST /api/v1/approvals/{id}/approve). The decided_by actor is derived server-side from the authenticated API-key name; the two-person-integrity contract (ErrApproveBySameActor → HTTP 403) is enforced unconditionally. Optional `note` is captured in the audit row.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ApprovalDecisionInput) (*gomcp.CallToolResult, any, error) {
		body := approvalDecisionPayload{Note: input.Note}
		data, err := c.Post("/api/v1/approvals/"+input.ID+"/approve", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_reject_request",
		Description: "Reject an issuance request (POST /api/v1/approvals/{id}/reject). Same RBAC contract as approve. Optional `note` is captured in the audit row.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ApprovalDecisionInput) (*gomcp.CallToolResult, any, error) {
		body := approvalDecisionPayload{Note: input.Note}
		data, err := c.Post("/api/v1/approvals/"+input.ID+"/reject", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// approvalDecisionPayload mirrors the handler-side approvalDecisionBody.
type approvalDecisionPayload struct {
	Note string `json:"note,omitempty"`
}
