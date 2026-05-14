// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package mcp

import (
	"context"
	"net/url"
	"strconv"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Phase 9 ARCH-M2 closure Sprint 10 (2026-05-14): extracted from
// internal/mcp/tools.go via the Option B sibling-file pattern.
//
// This file groups the observability / admin MCP tool domain — the
// read-mostly surface an LLM consumer uses to assess fleet state:
//
//   - registerAuditTools — audit-log read.
//   - registerStatsTools — aggregated counters (certs by
//     status / source / issuer; agents by state; jobs by status).
//   - registerDigestTools — point-in-time fleet digest snapshot.
//   - registerMetricsTools — raw Prometheus exposition pass-through.
//   - registerHealthTools — service health probes + a handful of
//     historical-placement claim/dismiss subtools (see
//     tools_discovery.go for the duplicate-by-design comment).
//   - registerHealthCheckTools — Phase B P1-20..P1-27 — health-check
//     CRUD + the certificate-health-monitor surface.
//
// paginationQuery (in tools.go) is consumed by some of these
// register functions via net/url + strconv (Itoa); the imports
// stay local to this file.

// ── Audit ───────────────────────────────────────────────────────────

func registerAuditTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_audit_events",
		Description: "List immutable audit trail events. Shows actor, action, resource, and timestamp for all lifecycle operations.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListParams) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/audit", paginationQuery(input.Page, input.PerPage))
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_audit_event",
		Description: "Get a specific audit event by ID.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/audit/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Stats ───────────────────────────────────────────────────────────

func registerStatsTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_dashboard_summary",
		Description: "Get high-level dashboard metrics: total/expiring/expired/revoked certs, active/offline agents, pending/failed/completed jobs.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input EmptyInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/stats/summary", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_certificates_by_status",
		Description: "Get certificate counts grouped by status (Active, Expiring, Expired, Revoked, etc.).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input EmptyInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/stats/certificates-by-status", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_expiration_timeline",
		Description: "Get certificates expiring per day for the next N days (default 30, max 365).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input TimelineInput) (*gomcp.CallToolResult, any, error) {
		q := url.Values{}
		if input.Days > 0 {
			q.Set("days", strconv.Itoa(input.Days))
		}
		data, err := c.Get("/api/v1/stats/expiration-timeline", q)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_job_trends",
		Description: "Get job success/failure trends per day for the past N days (default 30, max 365).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input TimelineInput) (*gomcp.CallToolResult, any, error) {
		q := url.Values{}
		if input.Days > 0 {
			q.Set("days", strconv.Itoa(input.Days))
		}
		data, err := c.Get("/api/v1/stats/job-trends", q)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_issuance_rate",
		Description: "Get new certificate issuance count per day for the past N days (default 30, max 365).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input TimelineInput) (*gomcp.CallToolResult, any, error) {
		q := url.Values{}
		if input.Days > 0 {
			q.Set("days", strconv.Itoa(input.Days))
		}
		data, err := c.Get("/api/v1/stats/issuance-rate", q)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Digest ──────────────────────────────────────────────────────────

func registerDigestTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_preview_digest",
		Description: "Preview the scheduled certificate digest email in HTML format. Shows summary of certificate status, pending jobs, and expiring certificates.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input EmptyInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/digest/preview", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_send_digest",
		Description: "Trigger immediate sending of the certificate digest email to configured recipients. If no explicit recipients are configured, sends to certificate owners.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input EmptyInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/digest/send", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Metrics ─────────────────────────────────────────────────────────

func registerMetricsTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_metrics",
		Description: "Get system metrics snapshot: gauge metrics (cert/agent/job counts), counters (completed/failed totals), and server uptime.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input EmptyInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/metrics", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Health ──────────────────────────────────────────────────────────

func registerHealthTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_health",
		Description: "Check certctl server health status.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input EmptyInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/health", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_ready",
		Description: "Check certctl server readiness (database connectivity, etc.).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input EmptyInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/ready", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_info",
		Description: "Get auth configuration (auth type and whether auth is required).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input EmptyInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/auth/info", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_check",
		Description: "Validate that the configured API key is accepted by the server.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input EmptyInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/auth/check", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	// I-2 closure (cat-i-b0924b6675f8): pre-I-2 the README claimed "all
	// API endpoints are exposed via MCP" but the discovered-certificate
	// lifecycle (claim + dismiss) was never wrapped — operators using
	// MCP clients had no path to bring an
	// out-of-band cert under management or to mark a benign discovery
	// as not-of-interest without dropping to the REST API directly.
	// These two tools wrap the existing HTTP handlers
	// (DiscoveryHandler.ClaimDiscovered + DismissDiscovered).

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_claim_discovered_certificate",
		Description: "Link a discovered certificate (dc-*) to an existing managed certificate (mc-*) via POST /api/v1/discovered-certificates/{id}/claim. Use this to bring an out-of-band cert (e.g. one found by an agent filesystem scan or a network scan) under certctl management without re-issuing — the discovered row is marked Managed and its managed_certificate_id is set so subsequent renewals/revocations on the managed cert update both rows.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ClaimDiscoveredCertificateInput) (*gomcp.CallToolResult, any, error) {
		body := map[string]string{"managed_certificate_id": input.ManagedCertificateID}
		data, err := c.Post("/api/v1/discovered-certificates/"+input.ID+"/claim", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_dismiss_discovered_certificate",
		Description: "Dismiss a discovered certificate (POST /api/v1/discovered-certificates/{id}/dismiss). Use this to mark a discovery as not-of-interest (e.g. expired self-signed test certs found by a network scan) — the row stops appearing in the unmanaged-list view but is preserved in the DB for audit history.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input DismissDiscoveredCertificateInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/discovered-certificates/"+input.ID+"/dismiss", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Health Checks (Phase B — P1-20..P1-27) ──────────────────────────
//
// 2026-05-05 CLI/API/MCP↔GUI parity audit closure. AI-assistant queries like
// "are any health checks failing?" / "ack the prod nginx incident" had no
// MCP path — operators had to drop to curl. Mirrors the existing target
// resource shape (CRUD + history + summary + acknowledge).

func registerHealthCheckTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_health_checks",
		Description: "List monitored TLS endpoint health checks (GET /api/v1/health-checks). Optional filters: status, certificate_id, network_scan_target_id, enabled.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListHealthChecksInput) (*gomcp.CallToolResult, any, error) {
		q := paginationQuery(input.Page, input.PerPage)
		if input.Status != "" {
			q.Set("status", input.Status)
		}
		if input.CertificateID != "" {
			q.Set("certificate_id", input.CertificateID)
		}
		if input.NetworkScanTargetID != "" {
			q.Set("network_scan_target_id", input.NetworkScanTargetID)
		}
		if input.Enabled != "" {
			q.Set("enabled", input.Enabled)
		}
		data, err := c.Get("/api/v1/health-checks", q)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_health_check_summary",
		Description: "Return aggregate counts of TLS health-check states (GET /api/v1/health-checks/summary). Useful for dashboard-style queries about endpoint posture.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input EmptyInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/health-checks/summary", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_health_check",
		Description: "Get a single TLS endpoint health check (GET /api/v1/health-checks/{id}).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/health-checks/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_create_health_check",
		Description: "Create a TLS endpoint health check (POST /api/v1/health-checks). Required: endpoint (host:port). Server-side defaults: check_interval_seconds=300, degraded_threshold=2, down_threshold=5.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input CreateHealthCheckInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/health-checks", input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_update_health_check",
		Description: "Update a TLS endpoint health check (PUT /api/v1/health-checks/{id}). The handler performs a merge update: non-zero numeric fields and non-empty strings overwrite, zero values preserve existing.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input UpdateHealthCheckInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Put("/api/v1/health-checks/"+input.ID, input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_delete_health_check",
		Description: "Delete a TLS endpoint health check (DELETE /api/v1/health-checks/{id}).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Delete("/api/v1/health-checks/" + input.ID)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_health_check_history",
		Description: "Get probe history for a TLS endpoint health check (GET /api/v1/health-checks/{id}/history). Default limit 100; max 1000 (clamped server-side).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input HealthCheckHistoryInput) (*gomcp.CallToolResult, any, error) {
		q := url.Values{}
		if input.Limit > 0 {
			q.Set("limit", strconv.Itoa(input.Limit))
		}
		data, err := c.Get("/api/v1/health-checks/"+input.ID+"/history", q)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_acknowledge_health_check",
		Description: "Acknowledge a TLS health-check incident (POST /api/v1/health-checks/{id}/acknowledge). Marks the check Acknowledged=true; the handler records the actor (defaults to 'unknown' if absent) for the audit trail.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AcknowledgeHealthCheckInput) (*gomcp.CallToolResult, any, error) {
		body := struct {
			Actor string `json:"actor,omitempty"`
		}{Actor: input.Actor}
		data, err := c.Post("/api/v1/health-checks/"+input.ID+"/acknowledge", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}
