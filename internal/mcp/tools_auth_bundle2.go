// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// =============================================================================
// Bundle 2 Phase 9 — OIDC + session MCP tools.
//
// 11 tools mirroring the Phase-5 HTTP surface so operators driving certctl
// from Claude / VS Code / any MCP client get the same OIDC-provider +
// group-mapping + session management capability the GUI + CLI already
// expose. Every tool routes through the existing HTTP client (no parallel
// business logic), so permission gates fire server-side: a non-admin
// caller's MCP tool invocation returns whatever 403 / 404 the underlying
// HTTP handler emits.
//
// Coverage map (each tool → HTTP endpoint → permission):
//
//   certctl_auth_list_oidc_providers      GET    /v1/auth/oidc/providers                   auth.oidc.list
//   certctl_auth_get_oidc_provider        GET    /v1/auth/oidc/providers (filtered)        auth.oidc.list
//   certctl_auth_create_oidc_provider     POST   /v1/auth/oidc/providers                   auth.oidc.create
//   certctl_auth_update_oidc_provider     PUT    /v1/auth/oidc/providers/{id}              auth.oidc.edit
//   certctl_auth_delete_oidc_provider     DELETE /v1/auth/oidc/providers/{id}              auth.oidc.delete
//   certctl_auth_refresh_oidc_provider    POST   /v1/auth/oidc/providers/{id}/refresh      auth.oidc.edit
//   certctl_auth_list_group_mappings      GET    /v1/auth/oidc/group-mappings?provider_id  auth.oidc.list
//   certctl_auth_add_group_mapping        POST   /v1/auth/oidc/group-mappings              auth.oidc.edit
//   certctl_auth_remove_group_mapping     DELETE /v1/auth/oidc/group-mappings/{id}         auth.oidc.edit
//   certctl_auth_list_sessions            GET    /v1/auth/sessions[?actor_id=&actor_type=] auth.session.list (own) | auth.session.list.all (other)
//   certctl_auth_revoke_session           DELETE /v1/auth/sessions/{id}                    auth.session.revoke (or own-bypass)
//
// auth_get_oidc_provider note: the Phase-5 server does NOT expose a
// singular GET /v1/auth/oidc/providers/{id} endpoint — the GUI's
// OIDCProviderDetailPage (web/src/pages/auth/OIDCProviderDetailPage.tsx)
// fetches the full list and filters in-process. The MCP tool mirrors
// that pattern exactly: fetch the list, filter by id, return the
// matching provider object as JSON or an explicit "not found" error.
// This keeps the MCP surface in lockstep with the GUI's permission
// boundary (auth.oidc.list grants "see any provider", as it does on
// the GUI) without inventing a new HTTP endpoint.
//
// CLAUDE.md asks for a re-derive after each MCP-tool addition:
//   grep -cE 'mcp\.AddTool\(' internal/mcp/tools*.go
// =============================================================================

// providersListEnvelope mirrors the wire shape of GET /v1/auth/oidc/providers,
// used by certctl_auth_get_oidc_provider to filter list-by-id.
type providersListEnvelope struct {
	Providers []json.RawMessage `json:"providers"`
}

func registerAuthBundle2Tools(s *gomcp.Server, c *Client) {
	registerAuthOIDCProviderTools(s, c)
	registerAuthGroupMappingTools(s, c)
	registerAuthSessionTools(s, c)
}

// ── OIDC provider tools ─────────────────────────────────────────────

func registerAuthOIDCProviderTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_list_oidc_providers",
		Description: "List every OIDC identity provider configured in the active tenant (GET /v1/auth/oidc/providers). Returns a JSON envelope {providers:[...]} where each provider exposes id, name, issuer_url, client_id, redirect_uri, groups_claim_path/format, scopes, iat_window_seconds, jwks_cache_ttl_seconds, created/updated timestamps. Encrypted client_secret is NEVER returned. Permission: auth.oidc.list.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, _ struct{}) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/auth/oidc/providers", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_get_oidc_provider",
		Description: "Fetch a single OIDC provider by id. The Phase-5 HTTP API ships only a list endpoint (no GET /v1/auth/oidc/providers/{id}); this tool calls the list endpoint and filters in-process, mirroring the GUI's OIDCProviderDetailPage. Returns the matching provider object on hit or an explicit \"oidc provider not found\" error on miss. Permission: auth.oidc.list.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthOIDCProviderIDInput) (*gomcp.CallToolResult, any, error) {
		id := strings.TrimSpace(input.ID)
		if id == "" {
			return errorResult(fmt.Errorf("id is required"))
		}
		data, err := c.Get("/api/v1/auth/oidc/providers", nil)
		if err != nil {
			return errorResult(err)
		}
		var env providersListEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			return errorResult(fmt.Errorf("decoding providers list: %w", err))
		}
		for _, raw := range env.Providers {
			var probe struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(raw, &probe); err != nil {
				continue
			}
			if probe.ID == id {
				return textResult(raw)
			}
		}
		return errorResult(fmt.Errorf("oidc provider not found: %s", id))
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_create_oidc_provider",
		Description: "Configure a new OIDC identity provider (POST /v1/auth/oidc/providers). The server fetches the IdP's discovery document at create time, runs the IdP-downgrade-attack defense (rejects HS256/HS384/HS512/none in id_token_signing_alg_values_supported), encrypts client_secret at rest via AES-256-GCM, and seeds the JWKS cache. Tenant-unique on name. Permission: auth.oidc.create.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthCreateOIDCProviderInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/auth/oidc/providers", input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_update_oidc_provider",
		Description: "Update an existing OIDC provider's configuration (PUT /v1/auth/oidc/providers/{id}). Pass the full provider shape; client_secret may be omitted to preserve the existing ciphertext (no rotate). Provide a new client_secret value to rotate. Issuer-URL changes re-run the IdP-downgrade-attack defense + re-fetch JWKS. Permission: auth.oidc.edit.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthUpdateOIDCProviderInput) (*gomcp.CallToolResult, any, error) {
		id := strings.TrimSpace(input.ID)
		if id == "" {
			return errorResult(fmt.Errorf("id is required"))
		}
		// The handler binds against oidcProviderRequest (no `id` field on
		// the wire); strip the path-only id from the body before sending.
		body := struct {
			Name                string   `json:"name"`
			IssuerURL           string   `json:"issuer_url"`
			ClientID            string   `json:"client_id"`
			ClientSecret        string   `json:"client_secret,omitempty"`
			RedirectURI         string   `json:"redirect_uri"`
			GroupsClaimPath     string   `json:"groups_claim_path,omitempty"`
			GroupsClaimFormat   string   `json:"groups_claim_format,omitempty"`
			FetchUserinfo       bool     `json:"fetch_userinfo,omitempty"`
			Scopes              []string `json:"scopes,omitempty"`
			AllowedEmailDomains []string `json:"allowed_email_domains,omitempty"`
			IATWindowSeconds    int      `json:"iat_window_seconds,omitempty"`
			JWKSCacheTTLSeconds int      `json:"jwks_cache_ttl_seconds,omitempty"`
		}{
			Name:                input.Name,
			IssuerURL:           input.IssuerURL,
			ClientID:            input.ClientID,
			ClientSecret:        input.ClientSecret,
			RedirectURI:         input.RedirectURI,
			GroupsClaimPath:     input.GroupsClaimPath,
			GroupsClaimFormat:   input.GroupsClaimFormat,
			FetchUserinfo:       input.FetchUserinfo,
			Scopes:              input.Scopes,
			AllowedEmailDomains: input.AllowedEmailDomains,
			IATWindowSeconds:    input.IATWindowSeconds,
			JWKSCacheTTLSeconds: input.JWKSCacheTTLSeconds,
		}
		data, err := c.Put("/api/v1/auth/oidc/providers/"+url.PathEscape(id), body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_delete_oidc_provider",
		Description: "Delete an OIDC provider (DELETE /v1/auth/oidc/providers/{id}). The server returns HTTP 409 (ErrOIDCProviderInUse) when any user has an authenticated session minted via this provider; revoke those sessions first via certctl_auth_list_sessions + certctl_auth_revoke_session, then retry. Cascades all group-role mappings on success. Permission: auth.oidc.delete.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthOIDCProviderIDInput) (*gomcp.CallToolResult, any, error) {
		id := strings.TrimSpace(input.ID)
		if id == "" {
			return errorResult(fmt.Errorf("id is required"))
		}
		data, err := c.Delete("/api/v1/auth/oidc/providers/" + url.PathEscape(id))
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_refresh_oidc_provider",
		Description: "Re-fetch the IdP's discovery document + JWKS keys (POST /v1/auth/oidc/providers/{id}/refresh). Run after the IdP rotates signing keys mid-day so the next OIDC login picks up the new keys without waiting for jwks_cache_ttl_seconds. Re-runs the IdP-downgrade-attack defense as a side effect. Permission: auth.oidc.edit.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthOIDCProviderIDInput) (*gomcp.CallToolResult, any, error) {
		id := strings.TrimSpace(input.ID)
		if id == "" {
			return errorResult(fmt.Errorf("id is required"))
		}
		data, err := c.Post("/api/v1/auth/oidc/providers/"+url.PathEscape(id)+"/refresh", struct{}{})
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Group-mapping tools ─────────────────────────────────────────────

func registerAuthGroupMappingTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_list_group_mappings",
		Description: "List the group→role mappings for a single OIDC provider (GET /v1/auth/oidc/group-mappings?provider_id=<id>). The server returns 400 when provider_id is omitted. Empty list is fail-closed: until at least one mapping exists, OIDC logins via that provider 401 with \"no roles assigned\". Permission: auth.oidc.list.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthListGroupMappingsInput) (*gomcp.CallToolResult, any, error) {
		providerID := strings.TrimSpace(input.ProviderID)
		if providerID == "" {
			return errorResult(fmt.Errorf("provider_id is required"))
		}
		q := url.Values{}
		q.Set("provider_id", providerID)
		data, err := c.Get("/api/v1/auth/oidc/group-mappings", q)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_add_group_mapping",
		Description: "Add a group→role mapping for an OIDC provider (POST /v1/auth/oidc/group-mappings). Body: {provider_id, group_name, role_id}. role_id must already exist; the server returns 409 on duplicate (provider_id, group_name) pairs. Mappings take effect on the NEXT login via the provider — existing sessions keep their original role assignments. Permission: auth.oidc.edit.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthAddGroupMappingInput) (*gomcp.CallToolResult, any, error) {
		body := map[string]string{
			"provider_id": strings.TrimSpace(input.ProviderID),
			"group_name":  strings.TrimSpace(input.GroupName),
			"role_id":     strings.TrimSpace(input.RoleID),
		}
		data, err := c.Post("/api/v1/auth/oidc/group-mappings", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_remove_group_mapping",
		Description: "Remove a group→role mapping (DELETE /v1/auth/oidc/group-mappings/{id}). Effective on the NEXT login; existing sessions are unaffected. Removing the last mapping for a provider makes that provider effectively offline (logins fail closed with \"no roles assigned\"). Permission: auth.oidc.edit.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthRemoveGroupMappingInput) (*gomcp.CallToolResult, any, error) {
		id := strings.TrimSpace(input.ID)
		if id == "" {
			return errorResult(fmt.Errorf("id is required"))
		}
		data, err := c.Delete("/api/v1/auth/oidc/group-mappings/" + url.PathEscape(id))
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Session tools ───────────────────────────────────────────────────

func registerAuthSessionTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_list_sessions",
		Description: "List active sessions (GET /v1/auth/sessions). With actor_id empty, returns the caller's own sessions (auth.session.list). With actor_id set to a different actor, returns that actor's sessions (auth.session.list.all required — the server-side handler 403s otherwise). actor_type defaults to User on the server when actor_id is provided. Each row exposes id, actor_id, actor_type, ip_address, user_agent, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked. Permission: auth.session.list (own) or auth.session.list.all (other).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthListSessionsInput) (*gomcp.CallToolResult, any, error) {
		q := url.Values{}
		if actorID := strings.TrimSpace(input.ActorID); actorID != "" {
			q.Set("actor_id", actorID)
		}
		if actorType := strings.TrimSpace(input.ActorType); actorType != "" {
			q.Set("actor_type", actorType)
		}
		data, err := c.Get("/api/v1/auth/sessions", q)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_auth_revoke_session",
		Description: "Revoke an active session (DELETE /v1/auth/sessions/{id}). The handler enforces an own-bypass: a caller may revoke their OWN sessions even without auth.session.revoke (use case: \"sign me out of my old laptop from my new laptop\"). Revoking another actor's session requires auth.session.revoke. Idempotent — second call against the same id returns 204. Permission: auth.session.revoke (with own-bypass).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuthRevokeSessionInput) (*gomcp.CallToolResult, any, error) {
		id := strings.TrimSpace(input.ID)
		if id == "" {
			return errorResult(fmt.Errorf("id is required"))
		}
		data, err := c.Delete("/api/v1/auth/sessions/" + url.PathEscape(id))
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}
