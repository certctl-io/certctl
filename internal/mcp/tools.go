package mcp

import (
	"context"
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
	// MCP clients (Claude, Cursor, etc.) had no path to bring an
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
