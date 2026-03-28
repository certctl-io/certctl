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

// RegisterHandlers sets up all API routes with their handlers.
func (r *Router) RegisterHandlers(
	certificates handler.CertificateHandler,
	issuers handler.IssuerHandler,
	targets handler.TargetHandler,
	agents handler.AgentHandler,
	jobs handler.JobHandler,
	policies handler.PolicyHandler,
	profiles handler.ProfileHandler,
	teams handler.TeamHandler,
	owners handler.OwnerHandler,
	agentGroups handler.AgentGroupHandler,
	audit handler.AuditHandler,
	notifications handler.NotificationHandler,
	stats handler.StatsHandler,
	metrics handler.MetricsHandler,
	health handler.HealthHandler,
	discovery handler.DiscoveryHandler,
	networkScan handler.NetworkScanHandler,
	verification handler.VerificationHandler,
) {
	// Health endpoints (no auth middleware — must always be accessible)
	r.mux.Handle("GET /health", middleware.Chain(
		http.HandlerFunc(health.Health),
		middleware.CORS,
		middleware.ContentType,
	))
	r.mux.Handle("GET /ready", middleware.Chain(
		http.HandlerFunc(health.Ready),
		middleware.CORS,
		middleware.ContentType,
	))
	// Auth info endpoint (no auth middleware — GUI needs this before login)
	r.mux.Handle("GET /api/v1/auth/info", middleware.Chain(
		http.HandlerFunc(health.AuthInfo),
		middleware.CORS,
		middleware.ContentType,
	))
	// Auth check endpoint (uses full middleware chain via r.Register)
	r.Register("GET /api/v1/auth/check", http.HandlerFunc(health.AuthCheck))

	// Certificates routes: /api/v1/certificates
	r.Register("GET /api/v1/certificates", http.HandlerFunc(certificates.ListCertificates))
	r.Register("POST /api/v1/certificates", http.HandlerFunc(certificates.CreateCertificate))
	r.Register("GET /api/v1/certificates/{id}", http.HandlerFunc(certificates.GetCertificate))
	r.Register("PUT /api/v1/certificates/{id}", http.HandlerFunc(certificates.UpdateCertificate))
	r.Register("DELETE /api/v1/certificates/{id}", http.HandlerFunc(certificates.ArchiveCertificate))
	r.Register("GET /api/v1/certificates/{id}/versions", http.HandlerFunc(certificates.GetCertificateVersions))
	r.Register("GET /api/v1/certificates/{id}/deployments", http.HandlerFunc(certificates.GetCertificateDeployments))
	r.Register("POST /api/v1/certificates/{id}/renew", http.HandlerFunc(certificates.TriggerRenewal))
	r.Register("POST /api/v1/certificates/{id}/deploy", http.HandlerFunc(certificates.TriggerDeployment))
	r.Register("POST /api/v1/certificates/{id}/revoke", http.HandlerFunc(certificates.RevokeCertificate))

	// CRL endpoints: /api/v1/crl (JSON) and /api/v1/crl/{issuer_id} (DER)
	r.Register("GET /api/v1/crl", http.HandlerFunc(certificates.GetCRL))
	r.Register("GET /api/v1/crl/{issuer_id}", http.HandlerFunc(certificates.GetDERCRL))

	// OCSP responder: /api/v1/ocsp/{issuer_id}/{serial}
	r.Register("GET /api/v1/ocsp/{issuer_id}/{serial}", http.HandlerFunc(certificates.HandleOCSP))

	// Issuers routes: /api/v1/issuers
	r.Register("GET /api/v1/issuers", http.HandlerFunc(issuers.ListIssuers))
	r.Register("POST /api/v1/issuers", http.HandlerFunc(issuers.CreateIssuer))
	r.Register("GET /api/v1/issuers/{id}", http.HandlerFunc(issuers.GetIssuer))
	r.Register("PUT /api/v1/issuers/{id}", http.HandlerFunc(issuers.UpdateIssuer))
	r.Register("DELETE /api/v1/issuers/{id}", http.HandlerFunc(issuers.DeleteIssuer))
	r.Register("POST /api/v1/issuers/{id}/test", http.HandlerFunc(issuers.TestConnection))

	// Targets routes: /api/v1/targets
	r.Register("GET /api/v1/targets", http.HandlerFunc(targets.ListTargets))
	r.Register("POST /api/v1/targets", http.HandlerFunc(targets.CreateTarget))
	r.Register("GET /api/v1/targets/{id}", http.HandlerFunc(targets.GetTarget))
	r.Register("PUT /api/v1/targets/{id}", http.HandlerFunc(targets.UpdateTarget))
	r.Register("DELETE /api/v1/targets/{id}", http.HandlerFunc(targets.DeleteTarget))

	// Agents routes: /api/v1/agents
	r.Register("GET /api/v1/agents", http.HandlerFunc(agents.ListAgents))
	r.Register("POST /api/v1/agents", http.HandlerFunc(agents.RegisterAgent))
	r.Register("GET /api/v1/agents/{id}", http.HandlerFunc(agents.GetAgent))
	r.Register("POST /api/v1/agents/{id}/heartbeat", http.HandlerFunc(agents.Heartbeat))
	r.Register("POST /api/v1/agents/{id}/csr", http.HandlerFunc(agents.AgentCSRSubmit))
	r.Register("GET /api/v1/agents/{id}/certificates/{cert_id}", http.HandlerFunc(agents.AgentCertificatePickup))
	r.Register("GET /api/v1/agents/{id}/work", http.HandlerFunc(agents.AgentGetWork))
	r.Register("POST /api/v1/agents/{id}/jobs/{job_id}/status", http.HandlerFunc(agents.AgentReportJobStatus))

	// Jobs routes: /api/v1/jobs
	r.Register("GET /api/v1/jobs", http.HandlerFunc(jobs.ListJobs))
	r.Register("GET /api/v1/jobs/{id}", http.HandlerFunc(jobs.GetJob))
	r.Register("POST /api/v1/jobs/{id}/cancel", http.HandlerFunc(jobs.CancelJob))
	r.Register("POST /api/v1/jobs/{id}/approve", http.HandlerFunc(jobs.ApproveJob))
	r.Register("POST /api/v1/jobs/{id}/reject", http.HandlerFunc(jobs.RejectJob))

	// Policies routes: /api/v1/policies
	r.Register("GET /api/v1/policies", http.HandlerFunc(policies.ListPolicies))
	r.Register("POST /api/v1/policies", http.HandlerFunc(policies.CreatePolicy))
	r.Register("GET /api/v1/policies/{id}", http.HandlerFunc(policies.GetPolicy))
	r.Register("PUT /api/v1/policies/{id}", http.HandlerFunc(policies.UpdatePolicy))
	r.Register("DELETE /api/v1/policies/{id}", http.HandlerFunc(policies.DeletePolicy))
	r.Register("GET /api/v1/policies/{id}/violations", http.HandlerFunc(policies.ListViolations))

	// Profiles routes: /api/v1/profiles
	r.Register("GET /api/v1/profiles", http.HandlerFunc(profiles.ListProfiles))
	r.Register("POST /api/v1/profiles", http.HandlerFunc(profiles.CreateProfile))
	r.Register("GET /api/v1/profiles/{id}", http.HandlerFunc(profiles.GetProfile))
	r.Register("PUT /api/v1/profiles/{id}", http.HandlerFunc(profiles.UpdateProfile))
	r.Register("DELETE /api/v1/profiles/{id}", http.HandlerFunc(profiles.DeleteProfile))

	// Teams routes: /api/v1/teams
	r.Register("GET /api/v1/teams", http.HandlerFunc(teams.ListTeams))
	r.Register("POST /api/v1/teams", http.HandlerFunc(teams.CreateTeam))
	r.Register("GET /api/v1/teams/{id}", http.HandlerFunc(teams.GetTeam))
	r.Register("PUT /api/v1/teams/{id}", http.HandlerFunc(teams.UpdateTeam))
	r.Register("DELETE /api/v1/teams/{id}", http.HandlerFunc(teams.DeleteTeam))

	// Owners routes: /api/v1/owners
	r.Register("GET /api/v1/owners", http.HandlerFunc(owners.ListOwners))
	r.Register("POST /api/v1/owners", http.HandlerFunc(owners.CreateOwner))
	r.Register("GET /api/v1/owners/{id}", http.HandlerFunc(owners.GetOwner))
	r.Register("PUT /api/v1/owners/{id}", http.HandlerFunc(owners.UpdateOwner))
	r.Register("DELETE /api/v1/owners/{id}", http.HandlerFunc(owners.DeleteOwner))

	// Agent Groups routes: /api/v1/agent-groups
	r.Register("GET /api/v1/agent-groups", http.HandlerFunc(agentGroups.ListAgentGroups))
	r.Register("POST /api/v1/agent-groups", http.HandlerFunc(agentGroups.CreateAgentGroup))
	r.Register("GET /api/v1/agent-groups/{id}", http.HandlerFunc(agentGroups.GetAgentGroup))
	r.Register("PUT /api/v1/agent-groups/{id}", http.HandlerFunc(agentGroups.UpdateAgentGroup))
	r.Register("DELETE /api/v1/agent-groups/{id}", http.HandlerFunc(agentGroups.DeleteAgentGroup))
	r.Register("GET /api/v1/agent-groups/{id}/members", http.HandlerFunc(agentGroups.ListAgentGroupMembers))

	// Audit routes: /api/v1/audit
	r.Register("GET /api/v1/audit", http.HandlerFunc(audit.ListAuditEvents))
	r.Register("GET /api/v1/audit/{id}", http.HandlerFunc(audit.GetAuditEvent))

	// Notifications routes: /api/v1/notifications
	r.Register("GET /api/v1/notifications", http.HandlerFunc(notifications.ListNotifications))
	r.Register("GET /api/v1/notifications/{id}", http.HandlerFunc(notifications.GetNotification))
	r.Register("POST /api/v1/notifications/{id}/read", http.HandlerFunc(notifications.MarkAsRead))

	// Stats routes: /api/v1/stats
	r.Register("GET /api/v1/stats/summary", http.HandlerFunc(stats.GetDashboardSummary))
	r.Register("GET /api/v1/stats/certificates-by-status", http.HandlerFunc(stats.GetCertificatesByStatus))
	r.Register("GET /api/v1/stats/expiration-timeline", http.HandlerFunc(stats.GetExpirationTimeline))
	r.Register("GET /api/v1/stats/job-trends", http.HandlerFunc(stats.GetJobTrends))
	r.Register("GET /api/v1/stats/issuance-rate", http.HandlerFunc(stats.GetIssuanceRate))

	// Metrics routes: /api/v1/metrics
	r.Register("GET /api/v1/metrics", http.HandlerFunc(metrics.GetMetrics))
	r.Register("GET /api/v1/metrics/prometheus", http.HandlerFunc(metrics.GetPrometheusMetrics))

	// Discovery routes: /api/v1/discovered-certificates, /api/v1/discovery-scans
	r.Register("POST /api/v1/agents/{id}/discoveries", http.HandlerFunc(discovery.SubmitDiscoveryReport))
	r.Register("GET /api/v1/discovered-certificates", http.HandlerFunc(discovery.ListDiscovered))
	r.Register("GET /api/v1/discovered-certificates/{id}", http.HandlerFunc(discovery.GetDiscovered))
	r.Register("POST /api/v1/discovered-certificates/{id}/claim", http.HandlerFunc(discovery.ClaimDiscovered))
	r.Register("POST /api/v1/discovered-certificates/{id}/dismiss", http.HandlerFunc(discovery.DismissDiscovered))
	r.Register("GET /api/v1/discovery-scans", http.HandlerFunc(discovery.ListScans))
	r.Register("GET /api/v1/discovery-summary", http.HandlerFunc(discovery.GetDiscoverySummary))

	// Network scan routes: /api/v1/network-scan-targets
	r.Register("GET /api/v1/network-scan-targets", http.HandlerFunc(networkScan.ListNetworkScanTargets))
	r.Register("POST /api/v1/network-scan-targets", http.HandlerFunc(networkScan.CreateNetworkScanTarget))
	r.Register("GET /api/v1/network-scan-targets/{id}", http.HandlerFunc(networkScan.GetNetworkScanTarget))
	r.Register("PUT /api/v1/network-scan-targets/{id}", http.HandlerFunc(networkScan.UpdateNetworkScanTarget))
	r.Register("DELETE /api/v1/network-scan-targets/{id}", http.HandlerFunc(networkScan.DeleteNetworkScanTarget))
	r.Register("POST /api/v1/network-scan-targets/{id}/scan", http.HandlerFunc(networkScan.TriggerNetworkScan))

	// Verification routes: /api/v1/jobs/{id}/verify and /api/v1/jobs/{id}/verification
	r.Register("POST /api/v1/jobs/{id}/verify", http.HandlerFunc(verification.VerifyDeployment))
	r.Register("GET /api/v1/jobs/{id}/verification", http.HandlerFunc(verification.GetVerificationStatus))
}

// RegisterESTHandlers sets up EST (RFC 7030) routes under /.well-known/est/.
// EST endpoints use a separate middleware chain (no API key auth — EST uses TLS client certs).
func (r *Router) RegisterESTHandlers(est handler.ESTHandler) {
	// EST endpoints per RFC 7030 Section 3.2.2
	r.Register("GET /.well-known/est/cacerts", http.HandlerFunc(est.CACerts))
	r.Register("POST /.well-known/est/simpleenroll", http.HandlerFunc(est.SimpleEnroll))
	r.Register("POST /.well-known/est/simplereenroll", http.HandlerFunc(est.SimpleReEnroll))
	r.Register("GET /.well-known/est/csrattrs", http.HandlerFunc(est.CSRAttrs))
}

// GetMux returns the underlying http.ServeMux for direct access if needed.
func (r *Router) GetMux() *http.ServeMux {
	return r.mux
}
