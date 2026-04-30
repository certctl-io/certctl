package mcp

// EST RFC 7030 hardening master bundle Phase 9.2 — MCP tools.
//
// 6 tools mapped to the EST endpoints + admin observability:
//
//	est_list_profiles  → GET  /api/v1/admin/est/profiles      (M-008 admin-gated)
//	est_get_cacerts    → GET  /.well-known/est/[<PathID>/]cacerts
//	est_get_csrattrs   → GET  /.well-known/est/[<PathID>/]csrattrs
//	est_enroll         → POST /.well-known/est/[<PathID>/]simpleenroll
//	est_reenroll       → POST /.well-known/est/[<PathID>/]simplereenroll
//	est_admin_stats    → alias of est_list_profiles for parity with the
//	                     SCEP admin tool naming (admin GUI uses both
//	                     names interchangeably; we expose both for
//	                     LLM-friendly discovery).
//
// Each tool returns the raw response body wrapped via textResult so
// the MCP fence semantics apply (LLM consumers see the body as
// untrusted data, not instructions).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── Input types ─────────────────────────────────────────────────────

type ESTProfileInput struct {
	Profile string `json:"profile,omitempty" jsonschema:"EST profile PathID (empty = legacy /.well-known/est root)"`
}

type ESTEnrollInput struct {
	Profile string `json:"profile,omitempty" jsonschema:"EST profile PathID (empty = legacy /.well-known/est root)"`
	CSR     string `json:"csr" jsonschema:"PKCS#10 CSR — PEM-encoded or base64-DER. Required."`
}

// ── Tool registration ──────────────────────────────────────────────

func registerESTTools(s *gomcp.Server, c *Client) {
	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "est_list_profiles",
		Description: "List per-profile EST observability snapshot (counters + mTLS trust-anchor expiries + auth-mode posture). Admin-gated. Returns one snapshot per configured EST profile.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input struct{}) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/admin/est/profiles", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "est_admin_stats",
		Description: "Alias of est_list_profiles — returns the same per-profile EST stats snapshot. Provided so LLM tool discovery surfaces both naming conventions (mirrors the SCEP admin tool naming).",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input struct{}) (*gomcp.CallToolResult, any, error) {
		data, err := c.Get("/api/v1/admin/est/profiles", nil)
		if err != nil {
			return errorResult(err)
		}
		return textResult(data)
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "est_get_cacerts",
		Description: "EST GET /.well-known/est/[<profile>/]cacerts (RFC 7030 §4.1). Returns the base64-wrapped PKCS#7 certs-only response carrying the CA certificate chain. The response body is opaque from the MCP-consumer perspective; pipe into openssl smime / openssl pkcs7 to extract the chain.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ESTProfileInput) (*gomcp.CallToolResult, any, error) {
		body, contentType, err := c.GetRaw(estPathFor(input.Profile, "cacerts"))
		if err != nil {
			return errorResult(err)
		}
		return textResult(estRawResultJSON(body, contentType))
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "est_get_csrattrs",
		Description: "EST GET /.well-known/est/[<profile>/]csrattrs (RFC 7030 §4.5). Returns the base64-encoded ASN.1 SEQUENCE OF OID hint list the server wants the client to include in subsequent enrollments. Empty body (HTTP 204) when no profile-derived hints are configured.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ESTProfileInput) (*gomcp.CallToolResult, any, error) {
		body, contentType, err := c.GetRaw(estPathFor(input.Profile, "csrattrs"))
		if err != nil {
			return errorResult(err)
		}
		return textResult(estRawResultJSON(body, contentType))
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "est_enroll",
		Description: "EST POST /.well-known/est/[<profile>/]simpleenroll (RFC 7030 §4.2). Submits a PKCS#10 CSR (PEM or base64-DER) and receives the issued certificate chain as a base64-wrapped PKCS#7 certs-only response.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ESTEnrollInput) (*gomcp.CallToolResult, any, error) {
		if strings.TrimSpace(input.CSR) == "" {
			return errorResult(fmt.Errorf("csr is required (PEM-encoded or base64-DER PKCS#10)"))
		}
		body, contentType, err := c.PostRaw(estPathFor(input.Profile, "simpleenroll"),
			"application/pkcs10", []byte(input.CSR))
		if err != nil {
			return errorResult(err)
		}
		return textResult(estRawResultJSON(body, contentType))
	})

	gomcp.AddTool(s, &gomcp.Tool{
		Name:        "est_reenroll",
		Description: "EST POST /.well-known/est/[<profile>/]simplereenroll (RFC 7030 §4.2.2). Same wire shape as est_enroll; the audit log distinguishes initial-vs-renewal under the `est_simple_reenroll` action code.",
	}, func(ctx context.Context, req *gomcp.CallToolRequest, input ESTEnrollInput) (*gomcp.CallToolResult, any, error) {
		if strings.TrimSpace(input.CSR) == "" {
			return errorResult(fmt.Errorf("csr is required"))
		}
		body, contentType, err := c.PostRaw(estPathFor(input.Profile, "simplereenroll"),
			"application/pkcs10", []byte(input.CSR))
		if err != nil {
			return errorResult(err)
		}
		return textResult(estRawResultJSON(body, contentType))
	})
}

// estPathFor builds the per-profile EST URL path. Empty profile maps
// to the legacy root for backward compat with v2.0.x deploys.
func estPathFor(profile, op string) string {
	if profile == "" {
		return "/.well-known/est/" + op
	}
	return "/.well-known/est/" + profile + "/" + op
}

// estRawResultJSON wraps the raw EST response body in a JSON envelope
// the MCP consumer can structurally consume. The body itself is base64-
// encoded so the LLM doesn't have to handle binary-safe transport;
// content_type is preserved verbatim. Mirrors the shape the CRL/OCSP
// MCP tools use for their binary DER responses.
func estRawResultJSON(body []byte, contentType string) json.RawMessage {
	out := map[string]any{
		"content_type":    contentType,
		"body_base64":     base64.StdEncoding.EncodeToString(body),
		"body_size_bytes": len(body),
	}
	raw, _ := json.Marshal(out)
	return raw
}
