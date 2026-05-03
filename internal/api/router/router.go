package router

import (
	"net/http"

	"github.com/shankar0123/certctl/internal/api/handler"
	"github.com/shankar0123/certctl/internal/api/middleware"
)

// Router wraps http.ServeMux and manages route registration with middleware.
type Router struct {
	mux        *http.ServeMux
	middleware []func(http.Handler) http.Handler
}

// New creates a new Router instance.
func New() *Router {
	return &Router{
		mux:        http.NewServeMux(),
		middleware: []func(http.Handler) http.Handler{},
	}
}

// NewWithMiddleware creates a Router with initial middleware stack.
func NewWithMiddleware(middlewares ...func(http.Handler) http.Handler) *Router {
	r := New()
	r.middleware = middlewares
	return r
}

// ServeHTTP implements http.Handler interface.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

// Register registers a handler for a given path with the middleware chain applied.
func (r *Router) Register(pattern string, handler http.Handler) {
	r.mux.Handle(pattern, middleware.Chain(handler, r.middleware...))
}

// RegisterFunc registers a handler function for a given path.
func (r *Router) RegisterFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	r.Register(pattern, http.HandlerFunc(handler))
}

// AuthExemptRouterRoutes is the documented allowlist of routes that the
// router itself registers via direct r.mux.Handle calls (NOT via r.Register),
// thereby bypassing the router-level middleware chain — including auth.
//
// Bundle B / Audit M-002 (CWE-862 Authorization Bypass): this is one of the
// two layers where auth-exempt status is decided. The complete picture:
//
//  1. Router layer (this constant) — direct mux.Handle registrations in
//     RegisterHandlers below. Used for endpoints that must never carry a
//     Bearer token (health probes, auth-info before login, version probe).
//
//  2. Dispatch layer (cmd/server/main.go::buildFinalHandler) — URL-prefix
//     dispatch that routes /.well-known/pki/*, /.well-known/est/*, and
//     /scep[/...]* through the no-auth handler chain. Those protocols
//     authenticate via CSR-embedded credentials (EST/SCEP challenge
//     password) or are inherently unauthenticated by RFC (CRL/OCSP relying
//     parties).
//
// Every entry in this slice has a justification. Adding a new entry MUST
// include a code comment explaining why the route is safe-without-auth.
// The TestRouter_AuthExemptAllowlist regression test below pins the slice
// to the actual mux.Handle calls — adding an undocumented bypass fails CI.
var AuthExemptRouterRoutes = []string{
	"GET /health",           // K8s/Docker liveness probe; cannot carry Bearer
	"GET /ready",            // K8s/Docker readiness probe; cannot carry Bearer
	"GET /api/v1/auth/info", // GUI calls before login to detect auth mode
	"GET /api/v1/version",   // Rollout probes need build identity without key
}

// AuthExemptDispatchPrefixes is the documented allowlist of URL prefixes
// that cmd/server/main.go::buildFinalHandler routes through the no-auth
// handler chain. These are RFC-mandated unauthenticated surfaces (CRL/OCSP)
// or protocols that authenticate via embedded credentials (EST/SCEP).
//
// Bundle B / Audit M-002: complement to AuthExemptRouterRoutes. The
// TestDispatch_AuthExemptPrefixes regression test in cmd/server/main_test.go
// pins this slice to buildFinalHandler's actual dispatch logic.
var AuthExemptDispatchPrefixes = []string{
	"/.well-known/pki",      // RFC 5280 CRL + RFC 6960 OCSP — relying-party-unauth
	"/.well-known/est",      // RFC 7030 EST — auth via mTLS or CSR-embedded creds
	"/.well-known/est-mtls", // EST + mTLS sibling route (EST hardening Phase 2) — auth is client cert
	"/scep",                 // RFC 8894 SCEP — auth via challengePassword in CSR
	"/scep-mtls",            // SCEP + mTLS sibling route (Phase 6.5) — auth is client cert + challengePassword
}

// HandlerRegistry groups all API handler dependencies for router registration.
type HandlerRegistry struct {
	Certificates   handler.CertificateHandler
	Issuers        handler.IssuerHandler
	Targets        handler.TargetHandler
	Agents         handler.AgentHandler
	Jobs           handler.JobHandler
	Policies       handler.PolicyHandler
	Profiles       handler.ProfileHandler
	Teams          handler.TeamHandler
	Owners         handler.OwnerHandler
	AgentGroups    handler.AgentGroupHandler
	Audit          handler.AuditHandler
	Notifications  handler.NotificationHandler
	Stats          handler.StatsHandler
	Metrics        handler.MetricsHandler
	Health         handler.HealthHandler
	Discovery      handler.DiscoveryHandler
	NetworkScan    handler.NetworkScanHandler
	Verification   handler.VerificationHandler
	Export         handler.ExportHandler
	Digest         handler.DigestHandler
	HealthChecks   *handler.HealthCheckHandler
	BulkRevocation handler.BulkRevocationHandler
	// L-1 master closure (cat-l-fa0c1ac07ab5 + cat-l-8a1fb258a38a):
	// server-side bulk endpoints replace pre-L-1 client-side N×HTTP
	// loops in CertificatesPage.tsx. See handler/bulk_renewal.go and
	// handler/bulk_reassignment.go.
	BulkRenewal      handler.BulkRenewalHandler
	BulkReassignment handler.BulkReassignmentHandler
	RenewalPolicies  handler.RenewalPolicyHandler
	// Version handles GET /api/v1/version (U-3 ride-along,
	// cat-u-no_version_endpoint). Wired through the no-auth dispatch in
	// cmd/server/main.go so probes and rollout systems can read build
	// identity without Bearer credentials. See handler/version.go.
	Version handler.VersionHandler
	// AdminCRLCache handles GET /api/v1/admin/crl/cache. Bundle CRL/OCSP-
	// Responder Phase 5 — admin-gated ops surface for the
	// scheduler-driven CRL pre-generation pipeline.
	AdminCRLCache handler.AdminCRLCacheHandler
	// AdminSCEPIntune handles the per-profile Microsoft Intune Connector
	// observability + reload endpoints. SCEP RFC 8894 + Intune master
	// bundle Phase 9.2.
	//   GET  /api/v1/admin/scep/intune/stats         → per-profile snapshot
	//   POST /api/v1/admin/scep/intune/reload-trust  → SIGHUP-equivalent
	// Both endpoints are admin-gated (M-008 pin updated to include
	// admin_scep_intune.go).
	AdminSCEPIntune handler.AdminSCEPIntuneHandler
	// AdminEST handles the per-profile EST observability + trust-anchor
	// reload endpoints. EST RFC 7030 hardening master bundle Phase 7.2.
	//   GET  /api/v1/admin/est/profiles      → per-profile snapshot
	//   POST /api/v1/admin/est/reload-trust  → SIGHUP-equivalent
	// Both endpoints are admin-gated (M-008 pin updated to include
	// admin_est.go).
	AdminEST handler.AdminESTHandler
	// ACME handles RFC 8555 ACME server endpoints under
	// /acme/profile/<id>/* and the optional /acme/* shorthand.
	// Phase 1a wires:
	//   GET  /acme/profile/{id}/directory
	//   HEAD /acme/profile/{id}/new-nonce
	//   GET  /acme/profile/{id}/new-nonce
	//   GET  /acme/directory     (shorthand)
	//   HEAD /acme/new-nonce     (shorthand)
	//   GET  /acme/new-nonce     (shorthand)
	// Subsequent phases add new-account + account/<id>, orders,
	// authzs, challenges, key-change, revoke-cert, ARI. See
	// docs/acme-server.md for the configuration reference.
	ACME handler.ACMEHandler
}

// RegisterHandlers sets up all API routes with their handlers.
func (r *Router) RegisterHandlers(reg HandlerRegistry) {
	// Health endpoints (no auth middleware — must always be accessible)
	r.mux.Handle("GET /health", middleware.Chain(
		http.HandlerFunc(reg.Health.Health),
		middleware.CORS,
		middleware.ContentType,
	))
	r.mux.Handle("GET /ready", middleware.Chain(
		http.HandlerFunc(reg.Health.Ready),
		middleware.CORS,
		middleware.ContentType,
	))
	// Auth info endpoint (no auth middleware — GUI needs this before login)
	r.mux.Handle("GET /api/v1/auth/info", middleware.Chain(
		http.HandlerFunc(reg.Health.AuthInfo),
		middleware.CORS,
		middleware.ContentType,
	))
	// Version endpoint (no auth middleware — used by rollout probes that
	// don't carry Bearer tokens; the dispatch layer in cmd/server/main.go
	// also routes /api/v1/version through the no-auth chain). U-3 ride-along
	// (cat-u-no_version_endpoint, P2). The handler reads
	// runtime/debug.BuildInfo for VCS attribution; ldflags-supplied Version
	// is preferred when present.
	r.mux.Handle("GET /api/v1/version", middleware.Chain(
		reg.Version,
		middleware.CORS,
		middleware.ContentType,
	))
	// Auth check endpoint (uses full middleware chain via r.Register)
	r.Register("GET /api/v1/auth/check", http.HandlerFunc(reg.Health.AuthCheck))

	// Certificates routes: /api/v1/certificates
	// Bulk operations MUST register before {id} routes — Go 1.22 ServeMux
	// gives literal segments precedence over pattern-var segments, but
	// listing the bulk paths first makes the precedence operator-visible
	// and prevents a future refactor from accidentally inverting it. All
	// three bulk endpoints share the same envelope shape (criteria/IDs
	// in, {total_matched, total_<verb>, total_skipped, total_failed,
	// errors[]} out). L-1 master added bulk-renew + bulk-reassign
	// alongside the pre-existing bulk-revoke.
	r.Register("POST /api/v1/certificates/bulk-revoke", http.HandlerFunc(reg.BulkRevocation.BulkRevoke))
	// EST RFC 7030 hardening Phase 11.2 — Source-scoped EST bulk-revoke.
	// Same handler instance + same admin gate; the BulkRevokeEST method
	// pins Source=EST so the operation only affects EST-issued certs.
	r.Register("POST /api/v1/est/certificates/bulk-revoke", http.HandlerFunc(reg.BulkRevocation.BulkRevokeEST))
	r.Register("POST /api/v1/certificates/bulk-renew", http.HandlerFunc(reg.BulkRenewal.BulkRenew))
	r.Register("POST /api/v1/certificates/bulk-reassign", http.HandlerFunc(reg.BulkReassignment.BulkReassign))
	r.Register("GET /api/v1/certificates", http.HandlerFunc(reg.Certificates.ListCertificates))
	r.Register("POST /api/v1/certificates", http.HandlerFunc(reg.Certificates.CreateCertificate))
	r.Register("GET /api/v1/certificates/{id}", http.HandlerFunc(reg.Certificates.GetCertificate))
	r.Register("PUT /api/v1/certificates/{id}", http.HandlerFunc(reg.Certificates.UpdateCertificate))
	r.Register("DELETE /api/v1/certificates/{id}", http.HandlerFunc(reg.Certificates.ArchiveCertificate))
	r.Register("GET /api/v1/certificates/{id}/versions", http.HandlerFunc(reg.Certificates.GetCertificateVersions))
	r.Register("GET /api/v1/certificates/{id}/deployments", http.HandlerFunc(reg.Certificates.GetCertificateDeployments))
	r.Register("POST /api/v1/certificates/{id}/renew", http.HandlerFunc(reg.Certificates.TriggerRenewal))
	r.Register("POST /api/v1/certificates/{id}/deploy", http.HandlerFunc(reg.Certificates.TriggerDeployment))
	r.Register("POST /api/v1/certificates/{id}/revoke", http.HandlerFunc(reg.Certificates.RevokeCertificate))

	// Export endpoints: /api/v1/certificates/{id}/export/{format}
	r.Register("GET /api/v1/certificates/{id}/export/pem", http.HandlerFunc(reg.Export.ExportPEM))
	r.Register("POST /api/v1/certificates/{id}/export/pkcs12", http.HandlerFunc(reg.Export.ExportPKCS12))

	// NOTE: RFC 5280 CRL and RFC 6960 OCSP endpoints are registered separately
	// via RegisterPKIHandlers under /.well-known/pki/ so relying parties can
	// fetch them without presenting certctl API credentials. The legacy
	// /api/v1/crl and /api/v1/ocsp paths have been retired (see M-006).

	// Issuers routes: /api/v1/issuers
	r.Register("GET /api/v1/issuers", http.HandlerFunc(reg.Issuers.ListIssuers))
	r.Register("POST /api/v1/issuers", http.HandlerFunc(reg.Issuers.CreateIssuer))
	r.Register("GET /api/v1/issuers/{id}", http.HandlerFunc(reg.Issuers.GetIssuer))
	r.Register("PUT /api/v1/issuers/{id}", http.HandlerFunc(reg.Issuers.UpdateIssuer))
	r.Register("DELETE /api/v1/issuers/{id}", http.HandlerFunc(reg.Issuers.DeleteIssuer))
	r.Register("POST /api/v1/issuers/{id}/test", http.HandlerFunc(reg.Issuers.TestConnection))

	// Targets routes: /api/v1/targets
	r.Register("GET /api/v1/targets", http.HandlerFunc(reg.Targets.ListTargets))
	r.Register("POST /api/v1/targets", http.HandlerFunc(reg.Targets.CreateTarget))
	r.Register("GET /api/v1/targets/{id}", http.HandlerFunc(reg.Targets.GetTarget))
	r.Register("PUT /api/v1/targets/{id}", http.HandlerFunc(reg.Targets.UpdateTarget))
	r.Register("DELETE /api/v1/targets/{id}", http.HandlerFunc(reg.Targets.DeleteTarget))
	r.Register("POST /api/v1/targets/{id}/test", http.HandlerFunc(reg.Targets.TestTargetConnection))

	// Agents routes: /api/v1/agents
	//
	// I-004 soft-retirement surface:
	//   * GET /api/v1/agents/retired — opt-in listing of retired agents.
	//     MUST be registered before /agents/{id} so Go 1.22 ServeMux's
	//     literal-beats-pattern-var precedence routes the `retired` literal
	//     to ListRetiredAgents instead of treating "retired" as a {id}
	//     parameter value against GetAgent.
	//   * DELETE /api/v1/agents/{id} — RetireAgent. Replaces the pre-I-004
	//     hard-delete; the underlying repo does a soft-retire with
	//     optional cascade.
	r.Register("GET /api/v1/agents", http.HandlerFunc(reg.Agents.ListAgents))
	r.Register("POST /api/v1/agents", http.HandlerFunc(reg.Agents.RegisterAgent))
	r.Register("GET /api/v1/agents/retired", http.HandlerFunc(reg.Agents.ListRetiredAgents))
	r.Register("GET /api/v1/agents/{id}", http.HandlerFunc(reg.Agents.GetAgent))
	r.Register("DELETE /api/v1/agents/{id}", http.HandlerFunc(reg.Agents.RetireAgent))
	r.Register("POST /api/v1/agents/{id}/heartbeat", http.HandlerFunc(reg.Agents.Heartbeat))
	r.Register("POST /api/v1/agents/{id}/csr", http.HandlerFunc(reg.Agents.AgentCSRSubmit))
	r.Register("GET /api/v1/agents/{id}/certificates/{cert_id}", http.HandlerFunc(reg.Agents.AgentCertificatePickup))
	r.Register("GET /api/v1/agents/{id}/work", http.HandlerFunc(reg.Agents.AgentGetWork))
	r.Register("POST /api/v1/agents/{id}/jobs/{job_id}/status", http.HandlerFunc(reg.Agents.AgentReportJobStatus))

	// Jobs routes: /api/v1/jobs
	r.Register("GET /api/v1/jobs", http.HandlerFunc(reg.Jobs.ListJobs))
	r.Register("GET /api/v1/jobs/{id}", http.HandlerFunc(reg.Jobs.GetJob))
	r.Register("POST /api/v1/jobs/{id}/cancel", http.HandlerFunc(reg.Jobs.CancelJob))
	r.Register("POST /api/v1/jobs/{id}/approve", http.HandlerFunc(reg.Jobs.ApproveJob))
	r.Register("POST /api/v1/jobs/{id}/reject", http.HandlerFunc(reg.Jobs.RejectJob))

	// Policies routes: /api/v1/policies
	r.Register("GET /api/v1/policies", http.HandlerFunc(reg.Policies.ListPolicies))
	r.Register("POST /api/v1/policies", http.HandlerFunc(reg.Policies.CreatePolicy))
	r.Register("GET /api/v1/policies/{id}", http.HandlerFunc(reg.Policies.GetPolicy))
	r.Register("PUT /api/v1/policies/{id}", http.HandlerFunc(reg.Policies.UpdatePolicy))
	r.Register("DELETE /api/v1/policies/{id}", http.HandlerFunc(reg.Policies.DeletePolicy))
	r.Register("GET /api/v1/policies/{id}/violations", http.HandlerFunc(reg.Policies.ListViolations))

	// Renewal Policies routes: /api/v1/renewal-policies
	// G-1: fixes frontend FK drift — OnboardingWizard + CertificatesPage dropdowns
	// were previously populating renewal_policy_id from /api/v1/policies (compliance
	// rules, pol-* IDs), violating FK managed_certificates.renewal_policy_id →
	// renewal_policies(id) ON DELETE RESTRICT. This block is the backend half; the
	// frontend half swaps getPolicies → getRenewalPolicies at 3 call sites.
	r.Register("GET /api/v1/renewal-policies", http.HandlerFunc(reg.RenewalPolicies.ListRenewalPolicies))
	r.Register("POST /api/v1/renewal-policies", http.HandlerFunc(reg.RenewalPolicies.CreateRenewalPolicy))
	r.Register("GET /api/v1/renewal-policies/{id}", http.HandlerFunc(reg.RenewalPolicies.GetRenewalPolicy))
	r.Register("PUT /api/v1/renewal-policies/{id}", http.HandlerFunc(reg.RenewalPolicies.UpdateRenewalPolicy))
	r.Register("DELETE /api/v1/renewal-policies/{id}", http.HandlerFunc(reg.RenewalPolicies.DeleteRenewalPolicy))

	// Profiles routes: /api/v1/profiles
	r.Register("GET /api/v1/profiles", http.HandlerFunc(reg.Profiles.ListProfiles))
	r.Register("POST /api/v1/profiles", http.HandlerFunc(reg.Profiles.CreateProfile))
	r.Register("GET /api/v1/profiles/{id}", http.HandlerFunc(reg.Profiles.GetProfile))
	r.Register("PUT /api/v1/profiles/{id}", http.HandlerFunc(reg.Profiles.UpdateProfile))
	r.Register("DELETE /api/v1/profiles/{id}", http.HandlerFunc(reg.Profiles.DeleteProfile))

	// Teams routes: /api/v1/teams
	r.Register("GET /api/v1/teams", http.HandlerFunc(reg.Teams.ListTeams))
	r.Register("POST /api/v1/teams", http.HandlerFunc(reg.Teams.CreateTeam))
	r.Register("GET /api/v1/teams/{id}", http.HandlerFunc(reg.Teams.GetTeam))
	r.Register("PUT /api/v1/teams/{id}", http.HandlerFunc(reg.Teams.UpdateTeam))
	r.Register("DELETE /api/v1/teams/{id}", http.HandlerFunc(reg.Teams.DeleteTeam))

	// Owners routes: /api/v1/owners
	r.Register("GET /api/v1/owners", http.HandlerFunc(reg.Owners.ListOwners))
	r.Register("POST /api/v1/owners", http.HandlerFunc(reg.Owners.CreateOwner))
	r.Register("GET /api/v1/owners/{id}", http.HandlerFunc(reg.Owners.GetOwner))
	r.Register("PUT /api/v1/owners/{id}", http.HandlerFunc(reg.Owners.UpdateOwner))
	r.Register("DELETE /api/v1/owners/{id}", http.HandlerFunc(reg.Owners.DeleteOwner))

	// Agent Groups routes: /api/v1/agent-groups
	r.Register("GET /api/v1/agent-groups", http.HandlerFunc(reg.AgentGroups.ListAgentGroups))
	r.Register("POST /api/v1/agent-groups", http.HandlerFunc(reg.AgentGroups.CreateAgentGroup))
	r.Register("GET /api/v1/agent-groups/{id}", http.HandlerFunc(reg.AgentGroups.GetAgentGroup))
	r.Register("PUT /api/v1/agent-groups/{id}", http.HandlerFunc(reg.AgentGroups.UpdateAgentGroup))
	r.Register("DELETE /api/v1/agent-groups/{id}", http.HandlerFunc(reg.AgentGroups.DeleteAgentGroup))
	r.Register("GET /api/v1/agent-groups/{id}/members", http.HandlerFunc(reg.AgentGroups.ListAgentGroupMembers))

	// Audit routes: /api/v1/audit
	r.Register("GET /api/v1/audit", http.HandlerFunc(reg.Audit.ListAuditEvents))
	r.Register("GET /api/v1/audit/{id}", http.HandlerFunc(reg.Audit.GetAuditEvent))

	// Bundle CRL/OCSP-Responder Phase 5: admin observability for the
	// scheduler-driven CRL pre-generation cache. Admin-gated inside
	// the handler (M-003 pattern); non-admin callers get 403.
	r.Register("GET /api/v1/admin/crl/cache", http.HandlerFunc(reg.AdminCRLCache.ListCache))
	// SCEP RFC 8894 + Intune master bundle Phase 9.2 + Phase 9 follow-up
	// (cowork/scep-gui-restructure-prompt.md). All three endpoints are
	// admin-gated at the handler layer; the M-008 regression scanner pins
	// the gate set and TestM008_AdminGatedHandlers_HaveTripletTests
	// enforces the per-handler test triplet.
	r.Register("GET /api/v1/admin/scep/profiles", http.HandlerFunc(reg.AdminSCEPIntune.Profiles))
	r.Register("GET /api/v1/admin/scep/intune/stats", http.HandlerFunc(reg.AdminSCEPIntune.Stats))
	r.Register("POST /api/v1/admin/scep/intune/reload-trust", http.HandlerFunc(reg.AdminSCEPIntune.ReloadTrust))
	// EST RFC 7030 hardening Phase 7.2 — admin-gated EST observability.
	r.Register("GET /api/v1/admin/est/profiles", http.HandlerFunc(reg.AdminEST.Profiles))
	r.Register("POST /api/v1/admin/est/reload-trust", http.HandlerFunc(reg.AdminEST.ReloadTrust))

	// Notifications routes: /api/v1/notifications
	r.Register("GET /api/v1/notifications", http.HandlerFunc(reg.Notifications.ListNotifications))
	r.Register("GET /api/v1/notifications/{id}", http.HandlerFunc(reg.Notifications.GetNotification))
	r.Register("POST /api/v1/notifications/{id}/read", http.HandlerFunc(reg.Notifications.MarkAsRead))
	// I-005: requeue a dead notification back to pending so the retry sweep
	// picks it up again. Go 1.22 ServeMux resolves the literal /requeue segment
	// before falling back to the {id} path-variable route above.
	r.Register("POST /api/v1/notifications/{id}/requeue", http.HandlerFunc(reg.Notifications.RequeueNotification))

	// Stats routes: /api/v1/stats
	r.Register("GET /api/v1/stats/summary", http.HandlerFunc(reg.Stats.GetDashboardSummary))
	r.Register("GET /api/v1/stats/certificates-by-status", http.HandlerFunc(reg.Stats.GetCertificatesByStatus))
	r.Register("GET /api/v1/stats/expiration-timeline", http.HandlerFunc(reg.Stats.GetExpirationTimeline))
	r.Register("GET /api/v1/stats/job-trends", http.HandlerFunc(reg.Stats.GetJobTrends))
	r.Register("GET /api/v1/stats/issuance-rate", http.HandlerFunc(reg.Stats.GetIssuanceRate))

	// Metrics routes: /api/v1/metrics
	r.Register("GET /api/v1/metrics", http.HandlerFunc(reg.Metrics.GetMetrics))
	r.Register("GET /api/v1/metrics/prometheus", http.HandlerFunc(reg.Metrics.GetPrometheusMetrics))

	// Discovery routes: /api/v1/discovered-certificates, /api/v1/discovery-scans
	r.Register("POST /api/v1/agents/{id}/discoveries", http.HandlerFunc(reg.Discovery.SubmitDiscoveryReport))
	r.Register("GET /api/v1/discovered-certificates", http.HandlerFunc(reg.Discovery.ListDiscovered))
	r.Register("GET /api/v1/discovered-certificates/{id}", http.HandlerFunc(reg.Discovery.GetDiscovered))
	r.Register("POST /api/v1/discovered-certificates/{id}/claim", http.HandlerFunc(reg.Discovery.ClaimDiscovered))
	r.Register("POST /api/v1/discovered-certificates/{id}/dismiss", http.HandlerFunc(reg.Discovery.DismissDiscovered))
	r.Register("GET /api/v1/discovery-scans", http.HandlerFunc(reg.Discovery.ListScans))
	r.Register("GET /api/v1/discovery-summary", http.HandlerFunc(reg.Discovery.GetDiscoverySummary))

	// Network scan routes: /api/v1/network-scan-targets
	r.Register("GET /api/v1/network-scan-targets", http.HandlerFunc(reg.NetworkScan.ListNetworkScanTargets))
	r.Register("POST /api/v1/network-scan-targets", http.HandlerFunc(reg.NetworkScan.CreateNetworkScanTarget))
	r.Register("GET /api/v1/network-scan-targets/{id}", http.HandlerFunc(reg.NetworkScan.GetNetworkScanTarget))
	r.Register("PUT /api/v1/network-scan-targets/{id}", http.HandlerFunc(reg.NetworkScan.UpdateNetworkScanTarget))
	r.Register("DELETE /api/v1/network-scan-targets/{id}", http.HandlerFunc(reg.NetworkScan.DeleteNetworkScanTarget))
	r.Register("POST /api/v1/network-scan-targets/{id}/scan", http.HandlerFunc(reg.NetworkScan.TriggerNetworkScan))
	// SCEP RFC 8894 + Intune master bundle Phase 11.5 — SCEP probe.
	// Bearer-auth gated by the standard middleware chain; not admin-
	// only because the probe is read-only against operator-supplied
	// URLs and reuses the existing SafeHTTPDialContext SSRF defense.
	r.Register("POST /api/v1/network-scan/scep-probe", http.HandlerFunc(reg.NetworkScan.ProbeSCEP))
	r.Register("GET /api/v1/network-scan/scep-probes", http.HandlerFunc(reg.NetworkScan.ListSCEPProbes))

	// Verification routes: /api/v1/jobs/{id}/verify and /api/v1/jobs/{id}/verification
	r.Register("POST /api/v1/jobs/{id}/verify", http.HandlerFunc(reg.Verification.VerifyDeployment))
	r.Register("GET /api/v1/jobs/{id}/verification", http.HandlerFunc(reg.Verification.GetVerificationStatus))

	// Digest routes: /api/v1/digest
	r.Register("GET /api/v1/digest/preview", http.HandlerFunc(reg.Digest.PreviewDigest))
	r.Register("POST /api/v1/digest/send", http.HandlerFunc(reg.Digest.SendDigest))

	// Health check routes: /api/v1/health-checks
	// Summary endpoint must be registered before {id} routes
	r.Register("GET /api/v1/health-checks/summary", http.HandlerFunc(reg.HealthChecks.GetHealthCheckSummary))
	r.Register("GET /api/v1/health-checks", http.HandlerFunc(reg.HealthChecks.ListHealthChecks))
	r.Register("POST /api/v1/health-checks", http.HandlerFunc(reg.HealthChecks.CreateHealthCheck))
	r.Register("GET /api/v1/health-checks/{id}", http.HandlerFunc(reg.HealthChecks.GetHealthCheck))
	r.Register("PUT /api/v1/health-checks/{id}", http.HandlerFunc(reg.HealthChecks.UpdateHealthCheck))
	r.Register("DELETE /api/v1/health-checks/{id}", http.HandlerFunc(reg.HealthChecks.DeleteHealthCheck))
	r.Register("GET /api/v1/health-checks/{id}/history", http.HandlerFunc(reg.HealthChecks.GetHealthCheckHistory))
	r.Register("POST /api/v1/health-checks/{id}/acknowledge", http.HandlerFunc(reg.HealthChecks.AcknowledgeHealthCheck))

	// ACME (RFC 8555 + RFC 9773 ARI) server endpoints. Phase 1a wires
	// directory + new-nonce only; Phases 1b-4 extend with the JWS-
	// authenticated POST surface (new-account, new-order, finalize,
	// challenges, revoke, ARI). Routes go through r.Register so the
	// standard middleware chain (CORS, body-limit, audit) applies —
	// ACME's own per-op metrics + RFC 8555 §6.5 Replay-Nonce headers
	// are added by the handler.
	//
	// Per-profile path family (canonical):
	r.Register("GET /acme/profile/{id}/directory", http.HandlerFunc(reg.ACME.Directory))
	r.Register("HEAD /acme/profile/{id}/new-nonce", http.HandlerFunc(reg.ACME.NewNonce))
	r.Register("GET /acme/profile/{id}/new-nonce", http.HandlerFunc(reg.ACME.NewNonce))
	// Default-profile shorthand. The handler's profile-resolution path
	// returns userActionRequired (RFC 7807 + RFC 8555 §6.7) when
	// CERTCTL_ACME_SERVER_DEFAULT_PROFILE_ID is unset; when set it
	// dispatches to the same handler as the per-profile path.
	r.Register("GET /acme/directory", http.HandlerFunc(reg.ACME.Directory))
	r.Register("HEAD /acme/new-nonce", http.HandlerFunc(reg.ACME.NewNonce))
	r.Register("GET /acme/new-nonce", http.HandlerFunc(reg.ACME.NewNonce))
}

// RegisterESTHandlers sets up EST (RFC 7030) routes under
// /.well-known/est/[<pathID>/].
//
// EST RFC 7030 hardening master bundle Phase 1: this signature was originally
// `RegisterESTHandlers(est handler.ESTHandler)` — a single handler installed
// at the legacy /.well-known/est/ root. The per-profile dispatch refactor
// takes a map keyed by ESTProfileConfig.PathID. Empty PathID maps to the
// legacy /.well-known/est/ root for backward compatibility (existing
// operators with the flat single-issuer config see no URL change);
// non-empty PathID values map to /.well-known/est/<pathID>/. Validate()
// guards PathID uniqueness + slug-shape so this loop never gets a
// collision or an invalid path segment.
//
// EST endpoints are intentionally unauthenticated at the HTTP middleware
// layer. Per RFC 7030 §3.2.3, authentication and authorization for
// enrollment are deployment-specific; pre-Phase-2 certctl relies on CSR
// signature verification, profile policy enforcement (allowed key types,
// max TTL, permitted EKUs), and the underlying issuer connector's own
// policy. Per RFC 7030 §4.1.1, /.well-known/est/<pathID>/cacerts is
// explicitly anonymous. Phase 2 + 3 of the EST hardening bundle add
// per-profile mTLS + HTTP Basic auth at the HANDLER layer (not the
// middleware layer) so the existing no-auth dispatch in
// cmd/server/main.go's finalHandler stays correct — auth is per-profile,
// not per-prefix.
//
// cmd/server/main.go's finalHandler dispatches /.well-known/est/* to a
// dedicated no-auth middleware chain (RequestID, structuredLogger,
// Recovery only) so EST clients — IoT devices, 802.1X supplicants,
// MDM-enrolled laptops — never hit the Bearer-token auth middleware they
// cannot satisfy. See M-001 audit 2026-04-19 (option D): prior builds
// routed EST through the authenticated apiHandler chain, which reduced
// every enrollment to a 401 before the handler was reached.
func (r *Router) RegisterESTHandlers(handlers map[string]handler.ESTHandler) {
	// Legacy /.well-known/est/ route for the empty-PathID profile is
	// registered with literal strings so the openapi-parity scanner
	// (Bundle D / Audit M-027, see openapi_parity_test.go) sees the four
	// EST operations as AST literals exactly the way it did pre-Phase-1.
	// The scanner walks for *ast.BasicLit string args to r.Register, so
	// dynamically-built paths would not appear in its index. Keeping the
	// empty-PathID case static preserves the spec parity contract for the
	// documented /.well-known/est/ endpoints that openapi.yaml describes.
	if h, ok := handlers[""]; ok {
		r.Register("GET /.well-known/est/cacerts", http.HandlerFunc(h.CACerts))
		r.Register("POST /.well-known/est/simpleenroll", http.HandlerFunc(h.SimpleEnroll))
		r.Register("POST /.well-known/est/simplereenroll", http.HandlerFunc(h.SimpleReEnroll))
		r.Register("GET /.well-known/est/csrattrs", http.HandlerFunc(h.CSRAttrs))
		// EST RFC 7030 hardening master bundle Phase 5: serverkeygen route
		// is always registered; the handler returns 404 unless the per-profile
		// SetServerKeygenEnabled(true) was called. Same registration shape as
		// the other endpoints so the openapi-parity guard sees the literal.
		r.Register("POST /.well-known/est/serverkeygen", http.HandlerFunc(h.ServerKeygen))
	}
	// Multi-profile routes register dynamically. These per-deployment
	// paths (/.well-known/est/<pathID>/) aren't in openapi.yaml because
	// the path segment is operator-defined; the spec covers the canonical
	// /.well-known/est/ root only. The parity scanner correctly skips
	// dynamic routes (it only checks literals). Mirrors the SCEP dispatch
	// pattern at RegisterSCEPHandlers above (commit 6d30493).
	for pathID, h := range handlers {
		if pathID == "" {
			continue // already handled by the static block above
		}
		hCopy := h // h is captured by value — ESTHandler is a small
		// struct (one interface field) so the per-iteration copy is
		// cheap and avoids any loop-variable-capture surprise if
		// ESTHandler ever grows pointer receivers in the future.
		prefix := "/.well-known/est/" + pathID
		r.Register("GET "+prefix+"/cacerts", http.HandlerFunc(hCopy.CACerts))
		r.Register("POST "+prefix+"/simpleenroll", http.HandlerFunc(hCopy.SimpleEnroll))
		r.Register("POST "+prefix+"/simplereenroll", http.HandlerFunc(hCopy.SimpleReEnroll))
		r.Register("GET "+prefix+"/csrattrs", http.HandlerFunc(hCopy.CSRAttrs))
		r.Register("POST "+prefix+"/serverkeygen", http.HandlerFunc(hCopy.ServerKeygen))
	}
}

// RegisterESTMTLSHandlers sets up the sibling `/.well-known/est-mtls/<PathID>/`
// routes for EST profiles that opted into mTLS via
// `CERTCTL_EST_PROFILE_<NAME>_MTLS_ENABLED=true`.
//
// EST RFC 7030 hardening master bundle Phase 2.2 + 2.3: enterprise
// procurement teams routinely reject 'shared password authentication' as
// a checkbox-fail regardless of how strong the password is. This sibling
// route adds client-cert auth at the handler layer AND keeps the (Phase 3)
// HTTP Basic enrollment-password as a defense-in-depth fallback for the
// non-mTLS profile. Devices present a bootstrap cert from a trusted CA,
// then EST-enroll for their long-lived cert. Mirrors the SCEP mTLS
// sibling pattern at RegisterSCEPMTLSHandlers below (commit 6b0d9e from
// the SCEP Phase 6.5 work).
//
// Path conventions: every mTLS profile gets a non-empty PathID, so the
// sibling routes are always /.well-known/est-mtls/<pathID>/. There is no
// "empty PathID = legacy /.well-known/est-mtls" case — mTLS is opt-in
// per profile, the legacy /.well-known/est root is always non-mTLS to
// preserve backward compat with existing deploys.
//
// Each handler in the map MUST have had SetMTLSTrust called so the
// per-profile cert verification has a trust anchor. cmd/server/main.go's
// per-profile EST loop wires this in the same loop iteration that
// registers the handler.
func (r *Router) RegisterESTMTLSHandlers(handlers map[string]handler.ESTHandler) {
	for pathID, h := range handlers {
		if pathID == "" {
			continue // mTLS sibling route requires per-profile PathID
		}
		hCopy := h // h is captured by value — see RegisterESTHandlers above
		prefix := "/.well-known/est-mtls/" + pathID
		r.Register("GET "+prefix+"/cacerts", http.HandlerFunc(hCopy.CACertsMTLS))
		r.Register("POST "+prefix+"/simpleenroll", http.HandlerFunc(hCopy.SimpleEnrollMTLS))
		r.Register("POST "+prefix+"/simplereenroll", http.HandlerFunc(hCopy.SimpleReEnrollMTLS))
		r.Register("GET "+prefix+"/csrattrs", http.HandlerFunc(hCopy.CSRAttrsMTLS))
		r.Register("POST "+prefix+"/serverkeygen", http.HandlerFunc(hCopy.ServerKeygenMTLS))
	}
}

// RegisterSCEPHandlers sets up SCEP (RFC 8894) routes.
// SCEP uses a single endpoint per profile with operation-based dispatch via
// query parameters. Authentication is via the challengePassword attribute in
// the PKCS#10 CSR, not via HTTP Bearer tokens or TLS client certs.
// cmd/server/main.go's finalHandler routes /scep* through the no-auth
// middleware chain (M-001 audit 2026-04-19, option D), and Config.Validate()
// refuses to start the server if any SCEP profile is enabled without a
// non-empty challenge password (H-2, CWE-306).
//
// SCEP RFC 8894 Phase 1.5: the handlers map is keyed by SCEPProfileConfig.PathID.
// Empty PathID maps to the legacy /scep root for backward compatibility;
// non-empty PathID values map to /scep/<pathID>. Registering N profiles
// produces 2N routes (GET + POST per profile). Validate() guards PathID
// uniqueness + slug-shape so this loop never gets a collision or an invalid
// path segment.
//
// The auth-exempt prefix `/scep` in AuthExemptDispatchPrefixes already covers
// every /scep[/...] path via prefix-match, so the multi-profile routes inherit
// the no-auth dispatch from the same dispatch table — no router-side change
// to the auth-exempt list is required.
func (r *Router) RegisterSCEPHandlers(handlers map[string]handler.SCEPHandler) {
	// Legacy /scep route for the empty-PathID profile is registered with
	// literal strings so the openapi-parity scanner (Bundle D / Audit M-027,
	// see openapi_parity_test.go) sees `GET /scep` + `POST /scep` as
	// AST literals exactly the way it did pre-Phase-1.5. The scanner walks
	// for *ast.BasicLit string args to r.Register, so dynamically-built
	// paths would not appear in its index. Keeping the empty-PathID case
	// static preserves the spec parity contract for the documented
	// /scep endpoint that openapi.yaml still describes.
	if h, ok := handlers[""]; ok {
		r.Register("GET /scep", http.HandlerFunc(h.HandleSCEP))
		r.Register("POST /scep", http.HandlerFunc(h.HandleSCEP))
	}
	// Multi-profile routes register dynamically. These per-deployment paths
	// (/scep/<pathID>) aren't in openapi.yaml because the path segment is
	// operator-defined; the spec covers the canonical /scep root only. The
	// parity scanner correctly skips dynamic routes (it only checks literals).
	for pathID, h := range handlers {
		if pathID == "" {
			continue // already handled by the static block above
		}
		hCopy := h // h is captured by value — SCEPHandler is a small struct
		// (one interface field) so the per-iteration copy is cheap and avoids
		// any loop-variable-capture surprise if SCEPHandler ever grows
		// pointer receivers in the future.
		r.Register("GET /scep/"+pathID, http.HandlerFunc(hCopy.HandleSCEP))
		r.Register("POST /scep/"+pathID, http.HandlerFunc(hCopy.HandleSCEP))
	}
}

// RegisterSCEPMTLSHandlers sets up the sibling `/scep-mtls/<PathID>` routes
// for SCEP profiles that opted into mTLS via
// `CERTCTL_SCEP_PROFILE_<NAME>_MTLS_ENABLED=true`.
//
// SCEP RFC 8894 + Intune master bundle Phase 6.5: enterprise procurement
// teams routinely reject 'shared password authentication' as a checkbox-
// fail regardless of how strong the password is. This sibling route adds
// client-cert auth at the handler layer AND keeps the challenge password
// (defense in depth, not replacement). Devices present a bootstrap cert
// from a trusted CA, then SCEP-enroll for their long-lived cert. Same
// model Apple's MDM and Cisco's BRSKI use.
//
// Path conventions mirror the standard SCEP route: empty PathID maps to
// `/scep-mtls` root (single-profile mTLS deploy); non-empty PathIDs map
// to `/scep-mtls/<pathID>`. The /scep-mtls prefix is in
// AuthExemptDispatchPrefixes — the auth boundary is the client cert
// (verified at the TLS layer + per-profile re-verified at the handler
// layer) plus the challenge password, NOT a Bearer token.
//
// Each handler in the map MUST have had SetMTLSTrustPool called so the
// per-profile cert verification has a trust anchor.
func (r *Router) RegisterSCEPMTLSHandlers(handlers map[string]handler.SCEPHandler) {
	if h, ok := handlers[""]; ok {
		r.Register("GET /scep-mtls", http.HandlerFunc(h.HandleSCEPMTLS))
		r.Register("POST /scep-mtls", http.HandlerFunc(h.HandleSCEPMTLS))
	}
	for pathID, h := range handlers {
		if pathID == "" {
			continue
		}
		hCopy := h
		r.Register("GET /scep-mtls/"+pathID, http.HandlerFunc(hCopy.HandleSCEPMTLS))
		r.Register("POST /scep-mtls/"+pathID, http.HandlerFunc(hCopy.HandleSCEPMTLS))
	}
}

// RegisterPKIHandlers sets up RFC 5280 CRL and RFC 6960 OCSP routes under
// /.well-known/pki/. These endpoints are intentionally unauthenticated so
// relying parties (browsers, OpenSSL, OCSP stapling sidecars, mTLS clients)
// can fetch revocation data without presenting certctl API credentials.
// The response bodies are DER-encoded and carry the IANA-registered content
// types application/pkix-crl and application/ocsp-response.
//
// Precedent: EST (RFC 7030) and SCEP (RFC 8894) follow the same pattern —
// standards-defined wire formats served via a dedicated router registration
// that cmd/server wires into a no-auth middleware chain.
func (r *Router) RegisterPKIHandlers(pki handler.CertificateHandler) {
	r.Register("GET /.well-known/pki/crl/{issuer_id}", http.HandlerFunc(pki.GetDERCRL))
	r.Register("GET /.well-known/pki/ocsp/{issuer_id}/{serial}", http.HandlerFunc(pki.HandleOCSP))
	// RFC 6960 §A.1.1 standard POST form. The binary OCSPRequest body
	// carries the serial; the URL only needs the issuer ID. Most
	// production OCSP clients use POST exclusively (see CRL/OCSP-Responder
	// Phase 4 prompt for the full client compatibility matrix).
	r.Register("POST /.well-known/pki/ocsp/{issuer_id}", http.HandlerFunc(pki.HandleOCSPPost))
}

// GetMux returns the underlying http.ServeMux for direct access if needed.
func (r *Router) GetMux() *http.ServeMux {
	return r.mux
}
