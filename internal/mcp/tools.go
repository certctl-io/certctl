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

// ── Approvals (Phase A — P1-28..P1-31) ──────────────────────────────
//
// 2026-05-05 CLI/API/MCP↔GUI parity audit closure. Operators using AI
// assistants for cert-renewal in regulated environments need natural-language
// approve/reject. The service layer enforces ErrApproveBySameActor (the
// requesting actor cannot self-approve) and the handler extracts the
// decided_by actor from middleware.UserKey — so the MCP server's API key
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

// ── Intermediate CAs (Phase F — P1-6..P1-9) ─────────────────────────
//
// 2026-05-05 CLI/API/MCP↔GUI parity audit closure. Rank 8 primitive
// (multi-level CA hierarchy management). The handlers are admin-gated via
// middleware.IsAdmin — non-admin callers see HTTP 403 regardless of MCP
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
