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

// HandlerRegistry groups all API handler dependencies for router registration.
type HandlerRegistry struct {
	Certificates  handler.CertificateHandler
	Issuers       handler.IssuerHandler
	Targets       handler.TargetHandler
	Agents        handler.AgentHandler
	Jobs          handler.JobHandler
	Policies      handler.PolicyHandler
	Profiles      handler.ProfileHandler
	Teams         handler.TeamHandler
	Owners        handler.OwnerHandler
	AgentGroups   handler.AgentGroupHandler
	Audit         handler.AuditHandler
	Notifications handler.NotificationHandler
	Stats         handler.StatsHandler
	Metrics       handler.MetricsHandler
	Health        handler.HealthHandler
	Discovery     handler.DiscoveryHandler
	NetworkScan   handler.NetworkScanHandler
	Verification  handler.VerificationHandler
	Export        handler.ExportHandler
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
	// Auth check endpoint (uses full middleware chain via r.Register)
	r.Register("GET /api/v1/auth/check", http.HandlerFunc(reg.Health.AuthCheck))

	// Certificates routes: /api/v1/certificates
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

	// CRL endpoints: /api/v1/crl (JSON) and /api/v1/crl/{issuer_id} (DER)
	r.Register("GET /api/v1/crl", http.HandlerFunc(reg.Certificates.GetCRL))
	r.Register("GET /api/v1/crl/{issuer_id}", http.HandlerFunc(reg.Certificates.GetDERCRL))

	// OCSP responder: /api/v1/ocsp/{issuer_id}/{serial}
	r.Register("GET /api/v1/ocsp/{issuer_id}/{serial}", http.HandlerFunc(reg.Certificates.HandleOCSP))

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

	// Agents routes: /api/v1/agents
	r.Register("GET /api/v1/agents", http.HandlerFunc(reg.Agents.ListAgents))
	r.Register("POST /api/v1/agents", http.HandlerFunc(reg.Agents.RegisterAgent))
	r.Register("GET /api/v1/agents/{id}", http.HandlerFunc(reg.Agents.GetAgent))
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

	// Notifications routes: /api/v1/notifications
	r.Register("GET /api/v1/notifications", http.HandlerFunc(reg.Notifications.ListNotifications))
	r.Register("GET /api/v1/notifications/{id}", http.HandlerFunc(reg.Notifications.GetNotification))
	r.Register("POST /api/v1/notifications/{id}/read", http.HandlerFunc(reg.Notifications.MarkAsRead))

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

	// Verification routes: /api/v1/jobs/{id}/verify and /api/v1/jobs/{id}/verification
	r.Register("POST /api/v1/jobs/{id}/verify", http.HandlerFunc(reg.Verification.VerifyDeployment))
	r.Register("GET /api/v1/jobs/{id}/verification", http.HandlerFunc(reg.Verification.GetVerificationStatus))
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
