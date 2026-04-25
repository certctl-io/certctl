package mcp

// Input types for MCP tool arguments.
// The jsonschema struct tags provide descriptions for LLM tool discovery.

// ── Pagination ──────────────────────────────────────────────────────

type ListParams struct {
	Page    int `json:"page,omitempty" jsonschema:"Page number (default 1)"`
	PerPage int `json:"per_page,omitempty" jsonschema:"Results per page (default 50, max 500)"`
}

// ── Certificates ────────────────────────────────────────────────────

type ListCertificatesInput struct {
	ListParams
	Status      string `json:"status,omitempty" jsonschema:"Filter by status: Pending, Active, Expiring, Expired, RenewalInProgress, Failed, Revoked, Archived"`
	Environment string `json:"environment,omitempty" jsonschema:"Filter by environment"`
	OwnerID     string `json:"owner_id,omitempty" jsonschema:"Filter by owner ID"`
	TeamID      string `json:"team_id,omitempty" jsonschema:"Filter by team ID"`
	IssuerID    string `json:"issuer_id,omitempty" jsonschema:"Filter by issuer ID"`
}

type GetByIDInput struct {
	ID string `json:"id" jsonschema:"Resource ID (e.g. mc-api-prod, t-platform)"`
}

type CreateCertificateInput struct {
	ID              string            `json:"id,omitempty" jsonschema:"Certificate ID (auto-generated if empty)"`
	Name            string            `json:"name" jsonschema:"Display name"`
	CommonName      string            `json:"common_name" jsonschema:"Certificate common name (e.g. api.example.com)"`
	SANs            []string          `json:"sans,omitempty" jsonschema:"Subject Alternative Names"`
	Environment     string            `json:"environment,omitempty" jsonschema:"Environment (e.g. production, staging)"`
	OwnerID         string            `json:"owner_id" jsonschema:"Owner ID (required)"`
	TeamID          string            `json:"team_id" jsonschema:"Team ID (required)"`
	IssuerID        string            `json:"issuer_id" jsonschema:"Issuer connector ID"`
	TargetIDs       []string          `json:"target_ids,omitempty" jsonschema:"Deployment target IDs"`
	RenewalPolicyID string            `json:"renewal_policy_id" jsonschema:"Renewal policy ID (required)"`
	ProfileID       string            `json:"certificate_profile_id,omitempty" jsonschema:"Certificate profile ID"`
	Tags            map[string]string `json:"tags,omitempty" jsonschema:"Key-value tags"`
}

type UpdateCertificateInput struct {
	ID              string            `json:"id" jsonschema:"Certificate ID to update"`
	Name            string            `json:"name,omitempty" jsonschema:"Display name"`
	Environment     string            `json:"environment,omitempty" jsonschema:"Environment"`
	OwnerID         string            `json:"owner_id,omitempty" jsonschema:"Owner ID"`
	TeamID          string            `json:"team_id,omitempty" jsonschema:"Team ID"`
	TargetIDs       []string          `json:"target_ids,omitempty" jsonschema:"Deployment target IDs"`
	RenewalPolicyID string            `json:"renewal_policy_id,omitempty" jsonschema:"Renewal policy ID"`
	ProfileID       string            `json:"certificate_profile_id,omitempty" jsonschema:"Certificate profile ID"`
	Tags            map[string]string `json:"tags,omitempty" jsonschema:"Key-value tags"`
}

type TriggerDeploymentInput struct {
	ID       string `json:"id" jsonschema:"Certificate ID"`
	TargetID string `json:"target_id,omitempty" jsonschema:"Optional specific target ID"`
}

type RevokeCertificateInput struct {
	ID     string `json:"id" jsonschema:"Certificate ID to revoke"`
	Reason string `json:"reason,omitempty" jsonschema:"RFC 5280 reason: unspecified, keyCompromise, caCompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, privilegeWithdrawn"`
}

type BulkRevokeCertificatesInput struct {
	Reason         string   `json:"reason" jsonschema:"RFC 5280 reason: unspecified, keyCompromise, caCompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, privilegeWithdrawn"`
	ProfileID      string   `json:"profile_id,omitempty" jsonschema:"Revoke all certs matching this profile ID"`
	OwnerID        string   `json:"owner_id,omitempty" jsonschema:"Revoke all certs owned by this owner"`
	AgentID        string   `json:"agent_id,omitempty" jsonschema:"Revoke all certs deployed via this agent"`
	IssuerID       string   `json:"issuer_id,omitempty" jsonschema:"Revoke all certs issued by this issuer"`
	TeamID         string   `json:"team_id,omitempty" jsonschema:"Revoke all certs owned by members of this team"`
	CertificateIDs []string `json:"certificate_ids,omitempty" jsonschema:"Explicit list of certificate IDs to revoke"`
}

// BulkRenewCertificatesInput is the MCP tool input for bulk-renew (L-1
// master closure, cat-l-fa0c1ac07ab5). Mirrors BulkRevokeCertificatesInput
// field-for-field minus Reason.
type BulkRenewCertificatesInput struct {
	ProfileID      string   `json:"profile_id,omitempty" jsonschema:"Renew all certs matching this profile ID"`
	OwnerID        string   `json:"owner_id,omitempty" jsonschema:"Renew all certs owned by this owner"`
	AgentID        string   `json:"agent_id,omitempty" jsonschema:"Renew all certs deployed via this agent"`
	IssuerID       string   `json:"issuer_id,omitempty" jsonschema:"Renew all certs issued by this issuer"`
	TeamID         string   `json:"team_id,omitempty" jsonschema:"Renew all certs owned by members of this team"`
	CertificateIDs []string `json:"certificate_ids,omitempty" jsonschema:"Explicit list of certificate IDs to renew"`
}

// BulkReassignCertificatesInput is the MCP tool input for bulk-reassign
// (L-2 closure, cat-l-8a1fb258a38a). IDs-only — no criteria-mode.
type BulkReassignCertificatesInput struct {
	CertificateIDs []string `json:"certificate_ids" jsonschema:"Explicit list of certificate IDs to reassign"`
	OwnerID        string   `json:"owner_id" jsonschema:"Required. New owner_id for every cert in certificate_ids"`
	TeamID         string   `json:"team_id,omitempty" jsonschema:"Optional. When non-empty, also updates team_id on every cert"`
}

type ListVersionsInput struct {
	ID string `json:"id" jsonschema:"Certificate ID"`
	ListParams
}

// ── CRL & OCSP ──────────────────────────────────────────────────────

type GetDERCRLInput struct {
	IssuerID string `json:"issuer_id" jsonschema:"Issuer ID for DER-encoded CRL"`
}

type OCSPInput struct {
	IssuerID string `json:"issuer_id" jsonschema:"Issuer ID"`
	Serial   string `json:"serial" jsonschema:"Hex-encoded certificate serial number"`
}

// ── Issuers ─────────────────────────────────────────────────────────

type CreateIssuerInput struct {
	ID      string      `json:"id,omitempty" jsonschema:"Issuer ID"`
	Name    string      `json:"name" jsonschema:"Issuer display name"`
	Type    string      `json:"type" jsonschema:"Issuer type: ACME, GenericCA, StepCA"`
	Config  interface{} `json:"config,omitempty" jsonschema:"Issuer-specific configuration"`
	Enabled bool        `json:"enabled,omitempty" jsonschema:"Whether the issuer is enabled"`
}

type UpdateIssuerInput struct {
	ID      string      `json:"id" jsonschema:"Issuer ID to update"`
	Name    string      `json:"name,omitempty" jsonschema:"Issuer display name"`
	Type    string      `json:"type,omitempty" jsonschema:"Issuer type"`
	Config  interface{} `json:"config,omitempty" jsonschema:"Issuer-specific configuration"`
	Enabled *bool       `json:"enabled,omitempty" jsonschema:"Whether the issuer is enabled"`
}

// ── Targets ─────────────────────────────────────────────────────────

type CreateTargetInput struct {
	ID      string      `json:"id,omitempty" jsonschema:"Target ID"`
	Name    string      `json:"name" jsonschema:"Target display name"`
	Type    string      `json:"type" jsonschema:"Target type: NGINX, Apache, HAProxy, F5, IIS"`
	AgentID string      `json:"agent_id" jsonschema:"Agent ID that manages this target (required)"`
	Config  interface{} `json:"config,omitempty" jsonschema:"Target-specific configuration"`
	Enabled bool        `json:"enabled,omitempty" jsonschema:"Whether the target is enabled"`
}

type UpdateTargetInput struct {
	ID      string      `json:"id" jsonschema:"Target ID to update"`
	Name    string      `json:"name,omitempty" jsonschema:"Target display name"`
	Type    string      `json:"type,omitempty" jsonschema:"Target type"`
	AgentID string      `json:"agent_id,omitempty" jsonschema:"Agent ID"`
	Config  interface{} `json:"config,omitempty" jsonschema:"Target-specific configuration"`
	Enabled *bool       `json:"enabled,omitempty" jsonschema:"Whether the target is enabled"`
}

// ── Agents ──────────────────────────────────────────────────────────

type RegisterAgentInput struct {
	ID       string `json:"id,omitempty" jsonschema:"Agent ID"`
	Name     string `json:"name" jsonschema:"Agent display name"`
	Hostname string `json:"hostname" jsonschema:"Agent hostname"`
}

type AgentCSRInput struct {
	AgentID       string `json:"agent_id" jsonschema:"Agent ID"`
	CSRPEM        string `json:"csr_pem" jsonschema:"PEM-encoded certificate signing request"`
	CertificateID string `json:"certificate_id,omitempty" jsonschema:"Certificate ID for the CSR"`
}

type AgentPickupInput struct {
	AgentID string `json:"agent_id" jsonschema:"Agent ID"`
	CertID  string `json:"cert_id" jsonschema:"Certificate ID to pick up"`
}

type AgentJobStatusInput struct {
	AgentID string `json:"agent_id" jsonschema:"Agent ID"`
	JobID   string `json:"job_id" jsonschema:"Job ID"`
	Status  string `json:"status" jsonschema:"Job status to report"`
	Error   string `json:"error,omitempty" jsonschema:"Error message if job failed"`
}

// RetireAgentInput pins the MCP tool surface for certctl_retire_agent. I-004
// introduces a soft-retirement flow that the handler exposes on DELETE
// /api/v1/agents/{id} with two optional query flags: force=true cascades
// through dependent active targets/certs/jobs, and reason is the human-readable
// string captured in the audit trail. The handler enforces
// ErrForceReasonRequired when force=true is sent without a reason; we surface
// both as separate fields so the LLM can populate them independently and so
// the retire_agent_test shape assertion stays aligned with the JSON-wire
// contract. ID is always emitted (no omitempty) because a retire call without
// a target agent is meaningless; Force and Reason are omitempty so the default
// soft-retire path sends no query suffix at all.
type RetireAgentInput struct {
	ID     string `json:"id" jsonschema:"Agent ID to soft-retire"`
	Force  bool   `json:"force,omitempty" jsonschema:"Cascade-retire downstream active targets, certs, and jobs (requires reason)"`
	Reason string `json:"reason,omitempty" jsonschema:"Human-readable reason (required when force=true)"`
}

// ── Jobs ────────────────────────────────────────────────────────────

type ListJobsInput struct {
	ListParams
	Status string `json:"status,omitempty" jsonschema:"Filter by status: Pending, AwaitingCSR, AwaitingApproval, Running, Completed, Failed, Cancelled"`
	Type   string `json:"type,omitempty" jsonschema:"Filter by type: Issuance, Renewal, Deployment, Validation"`
}

type RejectJobInput struct {
	ID     string `json:"id" jsonschema:"Job ID to reject"`
	Reason string `json:"reason,omitempty" jsonschema:"Reason for rejection"`
}

// ── Notifications ───────────────────────────────────────────────────

// ListNotificationsInput adds the I-005 status filter on top of the standard
// pagination params. Status="dead" drives the Dead letter tab use case;
// empty status preserves the pre-I-005 list-all behavior.
type ListNotificationsInput struct {
	ListParams
	Status string `json:"status,omitempty" jsonschema:"Filter by status: pending, sent, failed, dead, read"`
}

// ── Policies ────────────────────────────────────────────────────────

type CreatePolicyInput struct {
	ID       string      `json:"id,omitempty" jsonschema:"Policy ID"`
	Name     string      `json:"name" jsonschema:"Policy display name"`
	Type     string      `json:"type" jsonschema:"Policy type: AllowedIssuers, AllowedDomains, RequiredMetadata, AllowedEnvironments, RenewalLeadTime"`
	Config   interface{} `json:"config,omitempty" jsonschema:"Policy-specific configuration"`
	Enabled  bool        `json:"enabled,omitempty" jsonschema:"Whether the policy is enabled"`
	Severity string      `json:"severity,omitempty" jsonschema:"Violation severity: Warning, Error, or Critical (default: Warning)"`
}

type UpdatePolicyInput struct {
	ID       string      `json:"id" jsonschema:"Policy ID to update"`
	Name     string      `json:"name,omitempty" jsonschema:"Policy display name"`
	Type     string      `json:"type,omitempty" jsonschema:"Policy type"`
	Config   interface{} `json:"config,omitempty" jsonschema:"Policy-specific configuration"`
	Enabled  *bool       `json:"enabled,omitempty" jsonschema:"Whether the policy is enabled"`
	Severity string      `json:"severity,omitempty" jsonschema:"Violation severity: Warning, Error, or Critical"`
}

type ListViolationsInput struct {
	ID string `json:"id" jsonschema:"Policy ID"`
	ListParams
}

// ── Profiles ────────────────────────────────────────────────────────

type CreateProfileInput struct {
	ID                   string      `json:"id,omitempty" jsonschema:"Profile ID"`
	Name                 string      `json:"name" jsonschema:"Profile display name"`
	Description          string      `json:"description,omitempty" jsonschema:"Profile description"`
	AllowedKeyAlgorithms interface{} `json:"allowed_key_algorithms,omitempty" jsonschema:"Allowed key algorithms and minimum sizes"`
	MaxTTLSeconds        int         `json:"max_ttl_seconds,omitempty" jsonschema:"Maximum certificate TTL in seconds"`
	AllowedEKUs          []string    `json:"allowed_ekus,omitempty" jsonschema:"Allowed Extended Key Usages"`
	RequiredSANPatterns  []string    `json:"required_san_patterns,omitempty" jsonschema:"Required SAN patterns"`
	AllowShortLived      bool        `json:"allow_short_lived,omitempty" jsonschema:"Allow short-lived certificates (TTL < 1 hour)"`
	Enabled              bool        `json:"enabled,omitempty" jsonschema:"Whether the profile is enabled"`
}

type UpdateProfileInput struct {
	ID                   string      `json:"id" jsonschema:"Profile ID to update"`
	Name                 string      `json:"name,omitempty" jsonschema:"Profile display name"`
	Description          string      `json:"description,omitempty" jsonschema:"Profile description"`
	AllowedKeyAlgorithms interface{} `json:"allowed_key_algorithms,omitempty" jsonschema:"Allowed key algorithms and minimum sizes"`
	MaxTTLSeconds        *int        `json:"max_ttl_seconds,omitempty" jsonschema:"Maximum certificate TTL in seconds"`
	AllowedEKUs          []string    `json:"allowed_ekus,omitempty" jsonschema:"Allowed Extended Key Usages"`
	RequiredSANPatterns  []string    `json:"required_san_patterns,omitempty" jsonschema:"Required SAN patterns"`
	AllowShortLived      *bool       `json:"allow_short_lived,omitempty" jsonschema:"Allow short-lived certificates"`
	Enabled              *bool       `json:"enabled,omitempty" jsonschema:"Whether the profile is enabled"`
}

// ── Teams ───────────────────────────────────────────────────────────

type CreateTeamInput struct {
	ID          string `json:"id,omitempty" jsonschema:"Team ID"`
	Name        string `json:"name" jsonschema:"Team name"`
	Description string `json:"description,omitempty" jsonschema:"Team description"`
}

type UpdateTeamInput struct {
	ID          string `json:"id" jsonschema:"Team ID to update"`
	Name        string `json:"name,omitempty" jsonschema:"Team name"`
	Description string `json:"description,omitempty" jsonschema:"Team description"`
}

// ── Owners ──────────────────────────────────────────────────────────

type CreateOwnerInput struct {
	ID     string `json:"id,omitempty" jsonschema:"Owner ID"`
	Name   string `json:"name" jsonschema:"Owner display name"`
	Email  string `json:"email,omitempty" jsonschema:"Owner email for notifications"`
	TeamID string `json:"team_id,omitempty" jsonschema:"Team ID the owner belongs to"`
}

type UpdateOwnerInput struct {
	ID     string `json:"id" jsonschema:"Owner ID to update"`
	Name   string `json:"name,omitempty" jsonschema:"Owner display name"`
	Email  string `json:"email,omitempty" jsonschema:"Owner email"`
	TeamID string `json:"team_id,omitempty" jsonschema:"Team ID"`
}

// ── Agent Groups ────────────────────────────────────────────────────

type CreateAgentGroupInput struct {
	ID                string `json:"id,omitempty" jsonschema:"Agent group ID"`
	Name              string `json:"name" jsonschema:"Group display name"`
	Description       string `json:"description,omitempty" jsonschema:"Group description"`
	MatchOS           string `json:"match_os,omitempty" jsonschema:"Match agents by OS (e.g. linux, darwin, windows)"`
	MatchArchitecture string `json:"match_architecture,omitempty" jsonschema:"Match agents by architecture (e.g. amd64, arm64)"`
	MatchIPCIDR       string `json:"match_ip_cidr,omitempty" jsonschema:"Match agents by IP CIDR range"`
	MatchVersion      string `json:"match_version,omitempty" jsonschema:"Match agents by version"`
	Enabled           bool   `json:"enabled,omitempty" jsonschema:"Whether the group is enabled"`
}

type UpdateAgentGroupInput struct {
	ID                string `json:"id" jsonschema:"Agent group ID to update"`
	Name              string `json:"name,omitempty" jsonschema:"Group display name"`
	Description       string `json:"description,omitempty" jsonschema:"Group description"`
	MatchOS           string `json:"match_os,omitempty" jsonschema:"Match agents by OS"`
	MatchArchitecture string `json:"match_architecture,omitempty" jsonschema:"Match agents by architecture"`
	MatchIPCIDR       string `json:"match_ip_cidr,omitempty" jsonschema:"Match agents by IP CIDR range"`
	MatchVersion      string `json:"match_version,omitempty" jsonschema:"Match agents by version"`
	Enabled           *bool  `json:"enabled,omitempty" jsonschema:"Whether the group is enabled"`
}

// ── Stats ───────────────────────────────────────────────────────────

type TimelineInput struct {
	Days int `json:"days,omitempty" jsonschema:"Number of days to look back (default 30, max 365)"`
}

// ── Discovered Certificates (I-2 closure) ──────────────────────────

// ClaimDiscoveredCertificateInput is the MCP tool input for claiming a
// discovered certificate (POST /api/v1/discovered-certificates/{id}/claim).
// I-2 closure (cat-i-b0924b6675f8). The HTTP handler at
// internal/api/handler/discovery.go::ClaimDiscovered links the discovered
// row (DC-*) to a managed certificate (mc-*); operators use this to
// bring an out-of-band cert under management without re-issuing.
type ClaimDiscoveredCertificateInput struct {
	ID                   string `json:"id" jsonschema:"Discovered certificate ID (dc-*)"`
	ManagedCertificateID string `json:"managed_certificate_id" jsonschema:"Existing managed certificate ID (mc-*) to link to"`
}

// DismissDiscoveredCertificateInput is the MCP tool input for dismissing
// a discovered certificate (POST /api/v1/discovered-certificates/{id}/dismiss).
// I-2 closure (cat-i-b0924b6675f8). Marks the row as not-of-interest
// (e.g. expired self-signed test certs found by a network scan); the row
// stops appearing in the unmanaged-list view but is preserved in the DB
// for audit history.
type DismissDiscoveredCertificateInput struct {
	ID string `json:"id" jsonschema:"Discovered certificate ID (dc-*)"`
}

// ── Empty ───────────────────────────────────────────────────────────

type EmptyInput struct{}
