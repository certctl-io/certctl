package mcp

// Audit 2026-05-10 MED-13 closure — 11 new MCP tools that round out
// the MCP surface for the operator workflows that previously had GUI +
// CLI coverage but no MCP equivalent: approval workflow (4),
// break-glass credential admin (4), bootstrap-status/consume (2),
// audit list with category filter (1).
//
// Coverage map (each tool → HTTP endpoint → permission):
//
//   certctl_approval_list                    GET    /v1/approvals                       approval.read
//   certctl_approval_get                     GET    /v1/approvals/{id}                  approval.read
//   certctl_approval_approve                 POST   /v1/approvals/{id}/approve          approval.approve
//   certctl_approval_reject                  POST   /v1/approvals/{id}/reject           approval.reject
//   certctl_breakglass_list                  GET    /v1/auth/breakglass/credentials                     auth.breakglass.admin
//   certctl_breakglass_set_password          POST   /v1/auth/breakglass/credentials                     auth.breakglass.admin
//   certctl_breakglass_unlock                POST   /v1/auth/breakglass/credentials/{actor_id}/unlock   auth.breakglass.admin
//   certctl_breakglass_remove                DELETE /v1/auth/breakglass/credentials/{actor_id}          auth.breakglass.admin
//   certctl_bootstrap_status                 GET    /v1/auth/bootstrap                  (token; auth-exempt)
//   certctl_bootstrap_consume                POST   /v1/auth/bootstrap                  (token; auth-exempt)
//   certctl_audit_list_with_category         GET    /v1/audit?category=<cat>            audit.read
//
// Hygiene notes carried into the audit row by the server-side handler:
//   - approval reject + breakglass set/remove are PERMANENTLY operator-
//     consequential. MCP tools simply pass the call through; the
//     server-side endpoint emits the audit row.
//   - bootstrap_consume is the load-bearing one-shot token-exchange
//     primitive. Tool description carries an explicit cautious-wording
//     comment: "never wire this to autonomous operation — a leaked
//     bootstrap token mints a fresh admin API key."

import (
	"context"
	"net/url"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerAuditFixTools(s *gomcp.Server, c *Client) {
	// ── Approvals (4) ───────────────────────────────────────────────────
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_approval_list",
		Description: "List pending approval requests (GET /v1/approvals). Approval workflow primitive: certificate issuance + profile-edit operations gated on `CertificateProfile.RequiresApproval=true` materialize an `issuance_approval_requests` row that one approver of a different actor than the requester must approve before the request actually executes. Permission: approval.read.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, _ struct{}) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/approvals", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_approval_get",
		Description: "Get a single approval request by id (GET /v1/approvals/{id}). The response carries the approval payload — a JSON envelope with `before`+`after` for profile edits, or the full `IssuanceRequest` for certificate issuance. Permission: approval.read.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ApprovalIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/approvals/"+input.ID, nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_approval_approve",
		Description: "Approve a pending approval request (POST /v1/approvals/{id}/approve). The server-side service-layer rejects with ErrApproveBySameActor if the caller is the same actor who originated the request (same-actor self-approve is forbidden — the security primitive requires a SECOND human/key/actor sign-off). On success, the approval executes the requested operation. Permission: approval.approve.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ApprovalIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/approvals/"+input.ID+"/approve", map[string]string{})
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_approval_reject",
		Description: "Reject a pending approval request (POST /v1/approvals/{id}/reject). The originating request is permanently denied; a new request must be created if the requester still wants the operation. Permission: approval.reject.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ApprovalIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/approvals/"+input.ID+"/reject", map[string]string{})
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	// ── Break-glass (4) ─────────────────────────────────────────────────
	//
	// Break-glass is a deliberate bypass of the SSO security boundary.
	// The whole feature is invisible (404 NOT 403) when
	// CERTCTL_BREAKGLASS_ENABLED=false. Operators turn it on during SSO
	// incidents and OFF after recovery.
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_breakglass_list",
		Description: "List configured break-glass credentials (GET /v1/auth/breakglass/credentials). Each row carries the actor_id + role + lockout-counter state. Break-glass is a deliberate SSO-bypass: it lets a designated admin log in via username+password when the OIDC IdP is down. Permission: auth.breakglass.admin. Returns 404 when CERTCTL_BREAKGLASS_ENABLED is false.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, _ struct{}) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/auth/breakglass/credentials", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_breakglass_set_password",
		Description: "Set or update a break-glass credential password (POST /v1/auth/breakglass/credentials). Body: {actor_id, password, role_id}. The server-side handler hashes the password with Argon2id (RFC 9106, m=64MiB, t=3, p=4) before persisting. Returns 404 when CERTCTL_BREAKGLASS_ENABLED is false. NEVER log the password — the MCP transport sees plaintext; the server-side audit row redacts. Permission: auth.breakglass.admin.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input BreakglassSetPasswordInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/auth/breakglass/credentials", input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_breakglass_unlock",
		Description: "Reset the lockout counter on a break-glass credential (POST /v1/auth/breakglass/credentials/{actor_id}/unlock). Use after a failed-attempts lockout: the credential is locked for CERTCTL_BREAKGLASS_LOCKOUT_DURATION after CERTCTL_BREAKGLASS_LOCKOUT_THRESHOLD bad attempts; this tool clears the counter ahead of the natural expiry. Permission: auth.breakglass.admin.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input BreakglassActorIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/auth/breakglass/credentials/"+input.ActorID+"/unlock", map[string]string{})
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_breakglass_remove",
		Description: "Permanently remove a break-glass credential (DELETE /v1/auth/breakglass/credentials/{actor_id}). Operator-consequential — once removed, the actor can no longer log in via break-glass; a new credential must be set via certctl_breakglass_set_password. Permission: auth.breakglass.admin.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input BreakglassActorIDInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Delete("/api/v1/auth/breakglass/credentials/" + input.ActorID)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	// ── Bootstrap (2) ───────────────────────────────────────────────────
	//
	// The bootstrap endpoints (GET probe + POST consume) are
	// AUTH-EXEMPT — they authenticate via the
	// CERTCTL_BOOTSTRAP_TOKEN pre-shared secret, not via the
	// caller's API key. The probe is safe; the consume is the
	// load-bearing one-shot that mints an admin API key on a fresh
	// server. NEVER WIRE certctl_bootstrap_consume INTO AUTONOMOUS
	// OPERATION — a leaked bootstrap token from any log/telemetry/
	// chat-transcript surface would let a downstream caller mint a
	// fresh admin key.
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_bootstrap_status",
		Description: "Probe whether the day-0 bootstrap endpoint is currently callable (GET /v1/auth/bootstrap). Returns 200 with `{available: bool, reason: <string>}` — `available=true` only on a fresh server with no admin-roled actors AND with CERTCTL_BOOTSTRAP_TOKEN set. This tool is safe — read-only, no credentials, no audit row.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, _ struct{}) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/auth/bootstrap", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_bootstrap_consume",
		Description: "Consume the day-0 bootstrap token to mint a fresh admin API key (POST /v1/auth/bootstrap). Body: {token, key_name}. This is the load-bearing one-shot primitive that creates the FIRST admin key on a fresh certctl server. CAUTION: NEVER WIRE THIS TO AUTONOMOUS OPERATION. A leaked bootstrap token from any log, telemetry, or chat-transcript surface lets a downstream caller mint a fresh admin key bypassing every other access-control gate. Run this manually, exactly once, from a trusted shell. The server-side audit row redacts the token but preserves the resulting key_id. AUTH-EXEMPT (the token IS the auth).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input BootstrapConsumeInput) (*gomcp.CallToolResult, any, error) {
		data, err := c.Post("/api/v1/auth/bootstrap", input)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	// ── Audit category filter (1) ───────────────────────────────────────
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "certctl_audit_list_with_category",
		Description: "List audit events filtered by category (GET /v1/audit?category=<cat>). Categories: auth (login/logout/role changes), pki (issuance/renew/revoke), config (provider/profile/issuer edits), system (startup/shutdown/scheduler events), security (alerts, intrusion-detection). Pass `category` to narrow. Other query params (limit, since, until, actor_id) accepted verbatim. Permission: audit.read. Use this when investigating a specific class of operation; for full unfiltered access use the underlying GET /v1/audit directly.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input AuditListWithCategoryInput) (*gomcp.CallToolResult, any, error) {
		q := url.Values{}
		if input.Category != "" {
			q.Set("category", input.Category)
		}
		if input.Limit > 0 {
			q.Set("limit", intToString(input.Limit))
		}
		if input.Since != "" {
			q.Set("since", input.Since)
		}
		if input.Until != "" {
			q.Set("until", input.Until)
		}
		if input.ActorID != "" {
			q.Set("actor_id", input.ActorID)
		}
		data, err := c.Get("/api/v1/audit", q)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})
}

// intToString is a tiny stdlib-free int formatter used by the
// audit category tool to encode int Limit into the query string
// without dragging in strconv at the call site (keeps the tool
// definitions compact).
func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
