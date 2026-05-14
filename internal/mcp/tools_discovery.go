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
// This file groups the discovery MCP tool domain:
//
//   - registerNetworkScanTools — Phase D P1-14..P1-19 — network-scan
//     target CRUD + manual-scan trigger. Drives the inbound side of
//     the discovery pipeline (the server-initiated scans against
//     CIDRs / hostnames the operator declared).
//   - registerDiscoveryReadTools — Phase E P1-10..P1-13 — read-side
//     surface for discovered certificates (list / get / claim /
//     dismiss). The claim + dismiss subtools also exist under
//     registerHealthTools for historical-placement reasons
//     (pre-2026-05-05 I-2 closure parked them with the health
//     surface); those duplicate registrations are intentional and
//     documented in the pre-extract comments at the Discovery
//     read-side banner.

// ── Network-Scan Targets (Phase D — P1-14..P1-19) ───────────────────
//
// 2026-05-05 CLI/API/MCP↔GUI parity audit closure. AI-assistant queries like
// "what new certs did the scanner find on my fleet?" or "trigger a scan of
// the DC1 web tier" had no MCP path. trigger_network_scan returns the
// scan-row body so the AI can subsequently call list_discovered_certificates.

func registerNetworkScanTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_network_scan_targets",
		Description: "List network-scan targets (GET /api/v1/network-scan-targets). Each target is a (CIDR, ports) tuple the scheduler probes for TLS certificates.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input EmptyInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/network-scan-targets", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_network_scan_target",
		Description: "Get a single network-scan target (GET /api/v1/network-scan-targets/{id}).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/network-scan-targets/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_create_network_scan_target",
		Description: "Create a network-scan target (POST /api/v1/network-scan-targets). Provide cidrs and ports for the scanner to probe (e.g. cidrs=['10.0.0.0/24'], ports=[443,8443]).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input CreateNetworkScanTargetInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/network-scan-targets", input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_update_network_scan_target",
		Description: "Update a network-scan target (PUT /api/v1/network-scan-targets/{id}).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input UpdateNetworkScanTargetInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Put("/api/v1/network-scan-targets/"+input.ID, input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_delete_network_scan_target",
		Description: "Delete a network-scan target (DELETE /api/v1/network-scan-targets/{id}).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Delete("/api/v1/network-scan-targets/" + input.ID)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_trigger_network_scan",
		Description: "Trigger an immediate network scan of a target (POST /api/v1/network-scan-targets/{id}/scan). Returns the discovery-scan body when certs are found; the AI can then call certctl_list_discovered_certificates filtered by agent_id to view results.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/network-scan-targets/"+input.ID+"/scan", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Discovery read-side (Phase E — P1-10..P1-13) ────────────────────
//
// 2026-05-05 CLI/API/MCP↔GUI parity audit closure. The MCP server already
// has certctl_claim_discovered_certificate + certctl_dismiss_discovered_certificate
// (registered by registerHealthTools — historical placement; see I-2 closure).
// This phase adds the read-side so operators can ask "what's in the triage
// queue?" and "what did the scanner pick up overnight?".

func registerDiscoveryReadTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_discovered_certificates",
		Description: "List discovered certificates (GET /api/v1/discovered-certificates). These are TLS certs found by agent filesystem scans + network scans that are not yet under management. Filter by agent_id and/or status (Unmanaged, Managed, Dismissed).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListDiscoveredCertificatesInput) (*gomcp.CallToolResult, any, error) {
		q := paginationQuery(input.Page, input.PerPage)
		if input.AgentID != "" {
			q.Set("agent_id", input.AgentID)
		}
		if input.Status != "" {
			q.Set("status", input.Status)
		}
		data, err := c.Get("/api/v1/discovered-certificates", q)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_discovered_certificate",
		Description: "Get a single discovered certificate (GET /api/v1/discovered-certificates/{id}). Returns the dc-* row including subject DN, SANs, fingerprint, observed-at endpoint, and managed_certificate_id (set if claimed).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/discovered-certificates/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_discovery_scans",
		Description: "List discovery-scan rows (GET /api/v1/discovery-scans). Each row records one agent filesystem scan or network scan run with timing + cert-count.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListDiscoveryScansInput) (*gomcp.CallToolResult, any, error) {
		q := paginationQuery(input.Page, input.PerPage)
		if input.AgentID != "" {
			q.Set("agent_id", input.AgentID)
		}
		data, err := c.Get("/api/v1/discovery-scans", q)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_discovery_summary",
		Description: "Return aggregate counts of discovered-certificate states (GET /api/v1/discovery-summary). Useful for triage-queue dashboard queries.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input EmptyInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/discovery-summary", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}
