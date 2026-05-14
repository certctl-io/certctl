// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package mcp

import (
	"context"
	"fmt"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Phase 9 ARCH-M2 closure Sprint 10 (2026-05-14): extracted from
// internal/mcp/tools.go via the Option B sibling-file pattern. Package
// stays `mcp`; every external caller of RegisterTools(...) resolves
// the same way — pure mechanical relocation. The dispatcher in
// tools.go still calls registerCertificateTools / registerCRLOCSPTools
// / registerRenewalPolicyTools / registerVerificationTools in the
// same order, just from this file.
//
// This file groups the certificate-lifecycle MCP tool domain:
// certificate CRUD + revocation (registerCertificateTools), CRL/OCSP
// surface (registerCRLOCSPTools), renewal-policy management
// (registerRenewalPolicyTools — Phase C of the 2026-05-05 parity
// audit), and certificate-verification tooling (registerVerificationTools
// — Phase G P1-32/P1-34/P1-35 of the same audit). Co-locating these
// four register-functions matches the operator-mental-model boundary
// (everything a certificate-administrator touches in one file) and
// pre-dates the Sprint 10 split — tools_audit_fix.go + tools_auth.go +
// tools_auth_bundle2.go + tools_est.go already follow the same
// sibling-file convention.

// ── Certificates ────────────────────────────────────────────────────

func registerCertificateTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_certificates",
		Description: "List managed certificates with optional filters for status, environment, owner, team, and issuer. Returns paginated results.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListCertificatesInput) (*gomcp.CallToolResult, any, error) {
		q := paginationQuery(input.Page, input.PerPage)
		if input.Status != "" {
			q.Set("status", input.Status)
		}
		if input.Environment != "" {
			q.Set("environment", input.Environment)
		}
		if input.OwnerID != "" {
			q.Set("owner_id", input.OwnerID)
		}
		if input.TeamID != "" {
			q.Set("team_id", input.TeamID)
		}
		if input.IssuerID != "" {
			q.Set("issuer_id", input.IssuerID)
		}
		data, err := c.Get("/api/v1/certificates", q)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_certificate",
		Description: "Get a specific certificate by ID. Returns full certificate details including status, expiry, owner, and tags.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/certificates/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_create_certificate",
		Description: "Create a new managed certificate. Requires name, common_name, renewal_policy_id, issuer_id, owner_id, and team_id.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input CreateCertificateInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/certificates", input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_update_certificate",
		Description: "Update an existing certificate's metadata (name, environment, owner, tags, etc.).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input UpdateCertificateInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Put("/api/v1/certificates/"+input.ID, input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_archive_certificate",
		Description: "Archive (soft-delete) a certificate by ID.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Delete("/api/v1/certificates/" + input.ID)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_certificate_versions",
		Description: "List all versions (renewals) of a certificate. Shows serial numbers, validity periods, and fingerprints.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListVersionsInput) (*gomcp.CallToolResult, any, error) {
		q := paginationQuery(input.Page, input.PerPage)
		data, err := c.Get("/api/v1/certificates/"+input.ID+"/versions", q)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_trigger_renewal",
		Description: "Trigger immediate renewal of a certificate. Creates a renewal job (async, returns 202). Returns 404 if certificate not found, 400 if certificate is archived/expired, 409 if renewal already in progress.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/certificates/"+input.ID+"/renew", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_trigger_deployment",
		Description: "Trigger deployment of a certificate to its targets. Optionally specify a single target.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input TriggerDeploymentInput) (*gomcp.CallToolResult, any, error) {
		body := map[string]string{}
		if input.TargetID != "" {
			body["target_id"] = input.TargetID
		}
		data, err := c.Post("/api/v1/certificates/"+input.ID+"/deploy", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_revoke_certificate",
		Description: "Revoke a certificate with an optional RFC 5280 reason code. Records in audit trail and notifies the issuer.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input RevokeCertificateInput) (*gomcp.CallToolResult, any, error) {
		body := map[string]string{}
		if input.Reason != "" {
			body["reason"] = input.Reason
		}
		data, err := c.Post("/api/v1/certificates/"+input.ID+"/revoke", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_bulk_revoke_certificates",
		Description: "Bulk revoke certificates matching filter criteria. At least one criterion (profile_id, owner_id, agent_id, issuer_id, team_id, or certificate_ids) is required. Returns counts of matched, revoked, skipped, and failed certificates.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input BulkRevokeCertificatesInput) (*gomcp.CallToolResult, any, error) {
		body := map[string]interface{}{
			"reason": input.Reason,
		}
		if input.ProfileID != "" {
			body["profile_id"] = input.ProfileID
		}
		if input.OwnerID != "" {
			body["owner_id"] = input.OwnerID
		}
		if input.AgentID != "" {
			body["agent_id"] = input.AgentID
		}
		if input.IssuerID != "" {
			body["issuer_id"] = input.IssuerID
		}
		if input.TeamID != "" {
			body["team_id"] = input.TeamID
		}
		if len(input.CertificateIDs) > 0 {
			body["certificate_ids"] = input.CertificateIDs
		}
		data, err := c.Post("/api/v1/certificates/bulk-revoke", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	// L-1 master closure (cat-l-fa0c1ac07ab5): bulk-renew MCP tool.
	// Mirrors certctl_bulk_revoke_certificates shape sans the Reason
	// field. Server returns total_matched / total_enqueued /
	// total_skipped / total_failed plus per-cert {certificate_id,
	// job_id} pairs in enqueued_jobs.
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_bulk_renew_certificates",
		Description: "Bulk renew certificates matching filter criteria (profile_id, owner_id, agent_id, issuer_id, team_id) or an explicit certificate_ids list. At least one selector required. Returns counts of matched, enqueued, skipped, and failed certificates plus per-cert {certificate_id, job_id} pairs.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input BulkRenewCertificatesInput) (*gomcp.CallToolResult, any, error) {
		body := map[string]interface{}{}
		if input.ProfileID != "" {
			body["profile_id"] = input.ProfileID
		}
		if input.OwnerID != "" {
			body["owner_id"] = input.OwnerID
		}
		if input.AgentID != "" {
			body["agent_id"] = input.AgentID
		}
		if input.IssuerID != "" {
			body["issuer_id"] = input.IssuerID
		}
		if input.TeamID != "" {
			body["team_id"] = input.TeamID
		}
		if len(input.CertificateIDs) > 0 {
			body["certificate_ids"] = input.CertificateIDs
		}
		data, err := c.Post("/api/v1/certificates/bulk-renew", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	// L-2 closure (cat-l-8a1fb258a38a): bulk-reassign MCP tool.
	// Narrower than bulk-renew/revoke — IDs-only, no criteria-mode.
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_bulk_reassign_certificates",
		Description: "Bulk reassign owner (and optionally team) for a set of certificates. owner_id is required. team_id is optional and updates only when non-empty. Returns counts of matched, reassigned, skipped (already-owned-by-target), and failed certificates.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input BulkReassignCertificatesInput) (*gomcp.CallToolResult, any, error) {
		body := map[string]interface{}{
			"certificate_ids": input.CertificateIDs,
			"owner_id":        input.OwnerID,
		}
		if input.TeamID != "" {
			body["team_id"] = input.TeamID
		}
		data, err := c.Post("/api/v1/certificates/bulk-reassign", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── CRL & OCSP ──────────────────────────────────────────────────────
//
// M-006 relocation: CRL and OCSP are served unauthenticated under the
// RFC 8615 `.well-known/pki/*` namespace (RFC 5280 §5 for CRL, RFC 6960
// §2.1 for OCSP) so relying parties can retrieve them without a certctl
// API key. The non-standard JSON CRL tool (`certctl_get_crl`) has been
// removed — RFC 5280 defines only the DER wire format.

func registerCRLOCSPTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_der_crl",
		Description: "Get DER-encoded X.509 CRL for a specific issuer (RFC 5280). Served unauthenticated at /.well-known/pki/crl/{issuer_id}. Returns binary CRL data signed by the issuing CA.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetDERCRLInput) (*gomcp.CallToolResult, any, error) {
		raw, contentType, err := c.GetRaw("/.well-known/pki/crl/" + input.IssuerID)
		if err != nil {
			return errorResult(err)
		}
		return &gomcp.CallToolResult{
			Content: []gomcp.Content{
				&gomcp.TextContent{Text: fmt.Sprintf("DER CRL retrieved (%d bytes, content-type: %s)", len(raw), contentType)},
			},
		}, nil, nil
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_ocsp_check",
		Description: "Check OCSP status for a certificate by issuer ID and hex serial number (RFC 6960). Served unauthenticated at /.well-known/pki/ocsp/{issuer_id}/{serial}. Returns good, revoked, or unknown.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input OCSPInput) (*gomcp.CallToolResult, any, error) {
		raw, contentType, err := c.GetRaw("/.well-known/pki/ocsp/" + input.IssuerID + "/" + input.Serial)
		if err != nil {
			return errorResult(err)
		}
		return &gomcp.CallToolResult{
			Content: []gomcp.Content{
				&gomcp.TextContent{Text: fmt.Sprintf("OCSP response retrieved (%d bytes, content-type: %s)", len(raw), contentType)},
			},
		}, nil, nil
	})
}

// ── Renewal Policies (Phase C — P1-1..P1-5) ─────────────────────────
//
// 2026-05-05 CLI/API/MCP↔GUI parity audit closure. The G-1 milestone shipped
// renewal_policies as a separate resource from the policy engine; the GUI
// has the page and the API has full CRUD, but MCP previously had zero
// coverage. Note: the MCP "policy" tools registered by registerPolicyTools
// already point at /api/v1/renewal-policies (legacy alias) — these new tools
// expose the renewal-policy domain directly with explicit naming.

func registerRenewalPolicyTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_renewal_policies",
		Description: "List renewal policies (GET /api/v1/renewal-policies). Each policy controls renewal-window, retry, and alert-threshold/severity matrix for managed certificates.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ListParams) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/renewal-policies", paginationQuery(input.Page, input.PerPage))
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_renewal_policy",
		Description: "Get a single renewal policy (GET /api/v1/renewal-policies/{id}).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/renewal-policies/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_create_renewal_policy",
		Description: "Create a renewal policy (POST /api/v1/renewal-policies). Required: name. Reasonable defaults exist server-side for renewal_window_days, retries, and alert thresholds.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input CreateRenewalPolicyInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/renewal-policies", input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_update_renewal_policy",
		Description: "Update a renewal policy (PUT /api/v1/renewal-policies/{id}).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input UpdateRenewalPolicyInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Put("/api/v1/renewal-policies/"+input.ID, input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_delete_renewal_policy",
		Description: "Delete a renewal policy (DELETE /api/v1/renewal-policies/{id}). Returns HTTP 409 if any managed_certificates still reference the policy (FK-RESTRICT via ErrRenewalPolicyInUse).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Delete("/api/v1/renewal-policies/" + input.ID)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// ── Verification (Phase G — P1-32, P1-34, P1-35) ────────────────────
//
// 2026-05-05 CLI/API/MCP↔GUI parity audit closure. P1-33 (POST
// /api/v1/agents/{id}/discoveries) is intentionally excluded — it is a
// machine-to-machine push channel for agents reporting filesystem-scan
// results, not an operator-driven flow. The remaining three round out
// MCP coverage of certificate-deployment and job-verification surfaces.

func registerVerificationTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_list_certificate_deployments",
		Description: "List deployments for a managed certificate (GET /api/v1/certificates/{id}/deployments). Returns the per-target deployment status rows for the named cert.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/certificates/"+input.ID+"/deployments", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_verify_job",
		Description: "Record post-deployment verification for a job (POST /api/v1/jobs/{id}/verify). Required: target_id, expected_fingerprint, actual_fingerprint. Typically called by agents after probing the live TLS endpoint, but exposed here for operator-driven manual verification.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input VerifyJobInput) (*gomcp.CallToolResult, any, error) {
		body := map[string]any{
			"target_id":            input.TargetID,
			"expected_fingerprint": input.ExpectedFingerprint,
			"actual_fingerprint":   input.ActualFingerprint,
			"verified":             input.Verified,
		}
		if input.Error != "" {
			body["error"] = input.Error
		}
		data, err := c.Post("/api/v1/jobs/"+input.ID+"/verify", body)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_get_job_verification",
		Description: "Get the recorded verification status for a job (GET /api/v1/jobs/{id}/verification). Returns the latest VerificationResult row (expected/actual fingerprint, verified bool, timestamp).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input GetByIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/jobs/"+input.ID+"/verification", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}
