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
// This file groups the resource-management MCP tool domain — the
// configuration surface an operator builds out once and then
// references throughout cert issuance:
//
//   - registerIssuerTools — issuer CRUD across the 12 issuer
//     connectors (local CA, ACME upstream, ADCS / NDES, GlobalSign,
//     Sectigo, DigiCert, Let's Encrypt, etc.).
//   - registerTargetTools — deployment target CRUD across the 13
//     target connectors (nginx / apache / haproxy / F5 / Palo Alto /
//     IIS / WinCertStore / JavaKeystore / etc.).
//   - registerPolicyTools — policy / policy-rule CRUD (issuance
//     policies, key-strength rules, validity caps, EKU constraints).
//   - registerProfileTools — certificate-profile CRUD (named
//     bundles of "issuer + policy + targets + renewal cadence").
//   - registerTeamTools / registerOwnerTools — ownership + RBAC
//     scoping primitives (assign profiles to teams / owners).
//   - registerNotificationTools — notification-channel CRUD across
//     the 6 notifier connectors (email + webhook + chat + paging).
//   - registerIntermediateCATools — Phase F P1-6..P1-9 (signed
//     intermediate CA lifecycle: issue / sign / renew / list under
//     the local issuer).
//
// Co-located because they're the "configure once, reference
// everywhere" half of the API surface; an LLM consumer reasoning
// about "what objects can the operator create + edit" sees them
// here together.

// ── Issuers ─────────────────────────────────────────────────────────

func registerIssuerTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_issuers",
		Description: "List all configured issuer connectors (Local CA, ACME, step-ca).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListParams) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/issuers", paginationQuery(input.Page, input.PerPage))
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_issuer",
		Description: "Get issuer details including type, configuration, and enabled status.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/issuers/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_create_issuer",
		Description: "Register a new issuer connector. Requires name and type (ACME, GenericCA, or StepCA).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input CreateIssuerInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/issuers", input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_update_issuer",
		Description: "Update an issuer connector's configuration.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input UpdateIssuerInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Put("/api/v1/issuers/"+input.ID, input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_delete_issuer",
		Description: "Delete an issuer connector.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Delete("/api/v1/issuers/" + input.ID)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_test_issuer",
		Description: "Test connectivity to an issuer connector. Returns success or error details.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/issuers/"+input.ID+"/test", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Targets ─────────────────────────────────────────────────────────

func registerTargetTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_targets",
		Description: "List all deployment targets (NGINX, Apache, HAProxy, F5, IIS).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListParams) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/targets", paginationQuery(input.Page, input.PerPage))
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_target",
		Description: "Get deployment target details including type, agent, and configuration.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/targets/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_create_target",
		Description: "Create a new deployment target. Requires name and type (NGINX, Apache, HAProxy, F5, IIS).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input CreateTargetInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/targets", input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_update_target",
		Description: "Update a deployment target's configuration.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input UpdateTargetInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Put("/api/v1/targets/"+input.ID, input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_delete_target",
		Description: "Delete a deployment target.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Delete("/api/v1/targets/" + input.ID)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Policies ────────────────────────────────────────────────────────

func registerPolicyTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_policies",
		Description: "List all policy rules. Policy types: AllowedIssuers, AllowedDomains, RequiredMetadata, AllowedEnvironments, RenewalLeadTime.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListParams) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/policies", paginationQuery(input.Page, input.PerPage))
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_policy",
		Description: "Get policy rule details including type, configuration, and enabled status.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/policies/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_create_policy",
		Description: "Create a new policy rule. Requires name and type. Optional severity (Warning, Error, Critical) defaults to Warning.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input CreatePolicyInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/policies", input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_update_policy",
		Description: "Update a policy rule's name, type, configuration, enabled status, or severity.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input UpdatePolicyInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Put("/api/v1/policies/"+input.ID, input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_delete_policy",
		Description: "Delete a policy rule.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Delete("/api/v1/policies/" + input.ID)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_policy_violations",
		Description: "List violations for a specific policy. Shows affected certificates and severity (Warning, Error, Critical).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListViolationsInput) (*gomcp.CallToolResult, any, error) {
		q := paginationQuery(input.Page, input.PerPage)
		data, err := c.Get("/api/v1/policies/"+input.ID+"/violations", q)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Profiles ────────────────────────────────────────────────────────

func registerProfileTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_profiles",
		Description: "List certificate enrollment profiles defining allowed key types, max TTL, and crypto constraints.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListParams) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/profiles", paginationQuery(input.Page, input.PerPage))
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_profile",
		Description: "Get certificate profile details including allowed algorithms, max TTL, EKUs, and SAN patterns.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/profiles/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_create_profile",
		Description: "Create a certificate enrollment profile. Requires name.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input CreateProfileInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/profiles", input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_update_profile",
		Description: "Update a certificate profile's constraints.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input UpdateProfileInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Put("/api/v1/profiles/"+input.ID, input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_delete_profile",
		Description: "Delete a certificate profile.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Delete("/api/v1/profiles/" + input.ID)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Teams ───────────────────────────────────────────────────────────

func registerTeamTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_teams",
		Description: "List all teams for certificate ownership grouping.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListParams) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/teams", paginationQuery(input.Page, input.PerPage))
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_team",
		Description: "Get team details.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/teams/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_create_team",
		Description: "Create a new team. Requires name.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input CreateTeamInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/teams", input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_update_team",
		Description: "Update a team's name or description.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input UpdateTeamInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Put("/api/v1/teams/"+input.ID, input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_delete_team",
		Description: "Delete a team.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Delete("/api/v1/teams/" + input.ID)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Owners ──────────────────────────────────────────────────────────

func registerOwnerTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_owners",
		Description: "List all certificate owners with email and team assignment.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListParams) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/owners", paginationQuery(input.Page, input.PerPage))
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_owner",
		Description: "Get owner details including email and team.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/owners/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_create_owner",
		Description: "Create a new certificate owner. Requires name.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input CreateOwnerInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/owners", input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_update_owner",
		Description: "Update an owner's name, email, or team assignment.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input UpdateOwnerInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Put("/api/v1/owners/"+input.ID, input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_delete_owner",
		Description: "Delete a certificate owner.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Delete("/api/v1/owners/" + input.ID)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Notifications ───────────────────────────────────────────────────

func registerNotificationTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_notifications",
		Description: "List notification events (expiration warnings, renewal/deployment results, policy violations, revocations). Optional status filter supports the I-005 Dead letter tab (status=dead).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListNotificationsInput) (*gomcp.CallToolResult, any, error) {
		q := paginationQuery(input.Page, input.PerPage)
		if input.Status != "" {
			q.Set("status", input.Status)
		}
		data, err := c.Get("/api/v1/notifications", q)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_notification",
		Description: "Get notification event details.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/notifications/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_mark_notification_read",
		Description: "Mark a notification as read.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/notifications/"+input.ID+"/read", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	// I-005: requeue a dead-letter notification. Flips status from 'dead'
	// back to 'pending' and clears next_retry_at so the retry sweep picks
	// the notification up on its next tick. Operator-triggered; the tool
	// is the MCP counterpart of the GUI's Dead letter tab "Requeue" button.
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_requeue_notification",
		Description: "Requeue a dead notification back to pending so the retry sweep can deliver it again. Used to recover from persistent delivery failures after the underlying issue (SMTP config, webhook endpoint, etc.) has been fixed.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/notifications/"+input.ID+"/requeue", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Intermediate CAs (Phase F — P1-6..P1-9) ─────────────────────────
//
// 2026-05-05 CLI/API/MCP↔GUI parity audit closure. Rank 8 primitive
// (multi-level CA hierarchy management). The handlers are admin-gated via
// auth.IsAdmin — non-admin callers see HTTP 403 regardless of MCP
// surface. We expose the full management API rather than carving it off
// because the operator ran the original Rank 8 deliverable to make this
// a first-class managed primitive; gating by API key role at the handler
// layer is the correct least-privilege boundary, not by transport.

func registerIntermediateCATools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_intermediate_cas",
		Description: "List the intermediate-CA hierarchy under a parent issuer (GET /api/v1/issuers/{id}/intermediates). Admin-gated route. Returns flat rows; callers render the tree from each row's parent_ca_id.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListIntermediateCAsInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/issuers/"+input.IssuerID+"/intermediates", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_create_intermediate_ca",
		Description: "Create an intermediate CA under a parent issuer (POST /api/v1/issuers/{id}/intermediates). Admin-gated. Discriminator: when parent_ca_id is empty AND root_cert_pem + key_driver_id are present, registers an operator-supplied root CA; otherwise signs a child under the named parent.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input CreateIntermediateCAInput) (*gomcp.CallToolResult, any, error) {
		body := map[string]any{"name": input.Name}
		if input.ParentCAID != "" {
			body["parent_ca_id"] = input.ParentCAID
		}
		if input.RootCertPEM != "" {
			body["root_cert_pem"] = input.RootCertPEM
		}
		if input.KeyDriverID != "" {
			body["key_driver_id"] = input.KeyDriverID
		}
		if len(input.Subject) > 0 {
			body["subject"] = input.Subject
		}
		if input.Algorithm != "" {
			body["algorithm"] = input.Algorithm
		}
		if input.TTLDays > 0 {
			body["ttl_days"] = input.TTLDays
		}
		if input.PathLenConstraint != nil {
			body["path_len_constraint"] = *input.PathLenConstraint
		}
		if len(input.NameConstraints) > 0 {
			body["name_constraints"] = input.NameConstraints
		}
		if input.OCSPResponderURL != "" {
			body["ocsp_responder_url"] = input.OCSPResponderURL
		}
		if len(input.Metadata) > 0 {
			body["metadata"] = input.Metadata
		}
		data, err := c.Post("/api/v1/issuers/"+input.IssuerID+"/intermediates", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_intermediate_ca",
		Description: "Get a single intermediate CA (GET /api/v1/intermediates/{id}). Admin-gated.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/intermediates/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_retire_intermediate_ca",
		Description: "Retire an intermediate CA (POST /api/v1/intermediates/{id}/retire). Admin-gated. Two-phase: first call (confirm=false) transitions active→retiring; second call (confirm=true) transitions retiring→retired. Refuses retired transition while active children remain (drain-first semantics).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input RetireIntermediateCAInput) (*gomcp.CallToolResult, any, error) {
		body := struct {
			Note    string `json:"note,omitempty"`
			Confirm bool   `json:"confirm,omitempty"`
		}{Note: input.Note, Confirm: input.Confirm}
		data, err := c.Post("/api/v1/intermediates/"+input.ID+"/retire", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}
