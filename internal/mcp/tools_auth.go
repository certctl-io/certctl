// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package mcp

import (
	"context"
	"net/url"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// =============================================================================
// Bundle 1 Phase 11 — RBAC MCP tools.
//
// 12 tools mirroring the Phase-4 + Phase-7 HTTP surface so operators
// driving certctl from Claude / VS Code / any MCP client get the same
// management capability the GUI + CLI already expose. Every tool routes
// through the existing HTTP client (no parallel business logic), so
// permission gates fire server-side: a non-admin caller's MCP tool
// invocation returns whatever 403 the underlying HTTP handler emits.
//
// Coverage map (each tool → HTTP endpoint → permission):
//
//   certctl_auth_me                        GET    /v1/auth/me                          (no perm; own data)
//   certctl_auth_list_roles                GET    /v1/auth/roles                       auth.role.list
//   certctl_auth_get_role                  GET    /v1/auth/roles/{id}                  auth.role.list
//   certctl_auth_create_role               POST   /v1/auth/roles                       auth.role.create
//   certctl_auth_update_role               PUT    /v1/auth/roles/{id}                  auth.role.edit
//   certctl_auth_delete_role               DELETE /v1/auth/roles/{id}                  auth.role.delete
//   certctl_auth_list_permissions          GET    /v1/auth/permissions                 auth.role.list
//   certctl_auth_add_permission_to_role    POST   /v1/auth/roles/{id}/permissions      auth.role.edit
//   certctl_auth_remove_permission_from_role DELETE /v1/auth/roles/{id}/permissions/{perm} auth.role.edit
//   certctl_auth_list_keys                 GET    /v1/auth/keys                        auth.role.list
//   certctl_auth_assign_role_to_key        POST   /v1/auth/keys/{id}/roles             auth.role.assign
//   certctl_auth_revoke_role_from_key      DELETE /v1/auth/keys/{id}/roles/{role_id}   auth.role.assign
//
// CLAUDE.md asks for a re-derive after each MCP-tool addition:
//   grep -cE 'mcp\.AddTool\(' internal/mcp/tools*.go
// =============================================================================

func registerAuthTools(s *gomcp.Server, c *Client) {
	// ── Identity probe ────────────────────────────────────────────────
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_me",
		Description: "Return the current actor's identity, roles, and effective permissions (GET /v1/auth/me). Useful for verifying which API key the MCP server is calling under and what operations it can perform without 403.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, _ struct{}) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/auth/me", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	// ── Roles ─────────────────────────────────────────────────────────
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_list_roles",
		Description: "List every role in the active tenant (GET /v1/auth/roles). Permission: auth.role.list.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, _ struct{}) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/auth/roles", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_get_role",
		Description: "Get a single role by id, including its current permission grants (GET /v1/auth/roles/{id}). Permission: auth.role.list.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthRoleIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/auth/roles/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_create_role",
		Description: "Create a new custom role (POST /v1/auth/roles). The 7 default roles (admin / operator / viewer / agent / mcp / cli / auditor) are seeded by migration; this tool is for tenant-specific custom roles. Permission: auth.role.create.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthCreateRoleInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/auth/roles", input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_update_role",
		Description: "Update a custom role's name or description (PUT /v1/auth/roles/{id}). Default roles cannot be renamed. Permission: auth.role.edit.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthUpdateRoleInput) (*gomcp.CallToolResult, any, error) {
		body := map[string]string{}
		if input.Name != "" {
			body["name"] = input.Name
		}
		if input.Description != "" {
			body["description"] = input.Description
		}
		data, err := c.Put("/api/v1/auth/roles/"+input.ID, body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_delete_role",
		Description: "Delete a custom role (DELETE /v1/auth/roles/{id}). Fails with 409 when actors still hold the role; revoke their assignments first via certctl_auth_revoke_role_from_key. Permission: auth.role.delete.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthRoleIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Delete("/api/v1/auth/roles/" + input.ID)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	// ── Permissions ───────────────────────────────────────────────────
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_list_permissions",
		Description: "List the canonical permission catalogue (GET /v1/auth/permissions). Used by the role editor to populate the grant picker. Permission: auth.role.list.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, _ struct{}) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/auth/permissions", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_add_permission_to_role",
		Description: "Grant a permission to a role at a scope (POST /v1/auth/roles/{id}/permissions). Body: permission name (must be in canonical catalogue), scope_type (global|profile|issuer), and scope_id (required for non-global). Permission: auth.role.edit.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthRolePermissionGrantInput) (*gomcp.CallToolResult, any, error) {
		body := map[string]any{"permission": input.Permission}
		if input.ScopeType != "" {
			body["scope_type"] = input.ScopeType
		}
		if input.ScopeID != "" {
			body["scope_id"] = input.ScopeID
		}
		data, err := c.Post("/api/v1/auth/roles/"+input.RoleID+"/permissions", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_remove_permission_from_role",
		Description: "Revoke a permission from a role (DELETE /v1/auth/roles/{id}/permissions/{perm}?scope_type=&scope_id=). The scope_type + scope_id query params disambiguate when a permission is granted at multiple scopes. Permission: auth.role.edit.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthRolePermissionRevokeInput) (*gomcp.CallToolResult, any, error) {
		path := "/api/v1/auth/roles/" + input.RoleID + "/permissions/" + input.Permission
		q := url.Values{}
		if input.ScopeType != "" {
			q.Set("scope_type", input.ScopeType)
		}
		if input.ScopeID != "" {
			q.Set("scope_id", input.ScopeID)
		}
		if encoded := q.Encode(); encoded != "" {
			path += "?" + encoded
		}
		data, err := c.Delete(path)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	// ── Keys ──────────────────────────────────────────────────────────
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_list_keys",
		Description: "List every actor in the active tenant with at least one role grant (GET /v1/auth/keys). Includes the synthetic actor-demo-anon row when CERTCTL_AUTH_TYPE=none is configured; that row is system-managed and cannot be mutated. Permission: auth.role.list.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, _ struct{}) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/auth/keys", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_assign_role_to_key",
		Description: "Assign a role to an API key actor (POST /v1/auth/keys/{id}/roles). Body: role_id. Privilege-escalation guard: the caller must hold auth.role.assign globally (admin role or equivalent). Permission: auth.role.assign.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthAssignKeyRoleInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/auth/keys/"+input.KeyID+"/roles",
			map[string]string{"role_id": input.RoleID})
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_revoke_role_from_key",
		Description: "Revoke a role from an API key actor (DELETE /v1/auth/keys/{id}/roles/{role_id}). Rejects revocations against the reserved actor-demo-anon (HTTP 409). Audit 2026-05-11 A-4: pass scope_type=global / profile / issuer (with scope_id for the latter two) to selectively revoke ONE variant when the actor holds the same role at multiple scopes; omit both for the legacy 'revoke every variant' behaviour. Permission: auth.role.assign.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthRevokeKeyRoleInput) (*gomcp.CallToolResult, any, error) {
		// Audit 2026-05-11 A-4 — append the optional scope filter when
		// the caller supplied scope_type. The handler validates the
		// pair shape (scope_id required vs forbidden) so we don't
		// duplicate that here.
		path := "/api/v1/auth/keys/" + input.KeyID + "/roles/" + input.RoleID
		if input.ScopeType != "" {
			q := "?scope_type=" + url.QueryEscape(input.ScopeType)
			if input.ScopeID != "" {
				q += "&scope_id=" + url.QueryEscape(input.ScopeID)
			}
			path += q
		}
		data, err := c.Delete(path)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}
