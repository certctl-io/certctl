package router

import (
	"net/http"

	"github.com/certctl-io/certctl/internal/api/handler"
	"github.com/certctl-io/certctl/internal/api/middleware"
	"github.com/certctl-io/certctl/internal/auth"
)

// rbacGate wraps a handler with auth.RequirePermission(checker, perm,
// nil) — i.e. a GLOBAL-SCOPE permission check. Used by RegisterHandlers
// to gate every state-changing + read endpoint. When checker is nil the
// wrap is a no-op so tests / demo deployments without the RBAC stack
// continue to work.
//
// Every state-changing handler in this file MUST be wrapped by either
// rbacGate or rbacGateScoped (or appear in the AuthExemptRouterRoutes
// allowlist). The TestRouterRBACGateCoverage AST-level CI guard pins
// this contract; adding a new POST/PUT/PATCH/DELETE without an rbacGate
// wrap fails CI. See cowork/auth-bundles-audit-2026-05-10.md CRIT-1 for
// the closure history.
func rbacGate(checker auth.PermissionChecker, perm string, h http.HandlerFunc) http.Handler {
	if checker == nil {
		return h
	}
	return auth.RequirePermission(checker, perm, nil)(h)
}

// rbacGateScoped wraps a handler with a per-request scope-resolving
// permission check. The scopeFn extracts a scope identifier from the
// *http.Request (typically a path value, e.g. r.PathValue("id")) so
// the underlying permission check can match a profile- or issuer-
// scoped role-permission grant. When scopeFn returns an empty scope
// id the gate falls back to global checking — consistent with the
// rbacGate semantics — so unscoped grants continue to authorize.
//
// Used for path-bound state-changing routes such as
// PUT /api/v1/profiles/{id} (scope_type=profile, scope_id=<path id>)
// and PUT /api/v1/issuers/{id} (scope_type=issuer, scope_id=<path id>).
//
// When checker is nil the wrap is a no-op (test / demo path).
func rbacGateScoped(checker auth.PermissionChecker, perm, scopeType string,
	scopeFn func(*http.Request) string, h http.HandlerFunc) http.Handler {
	if checker == nil {
		return h
	}
	return auth.RequirePermission(checker, perm, func(r *http.Request) (string, *string) {
		id := scopeFn(r)
		if id == "" {
			return "global", nil
		}
		return scopeType, &id
	})(h)
}

// pathScope returns a scope extractor that reads a path parameter
// directly. Helper to keep the route registration block readable:
// rbacGateScoped(checker, "profile.edit", "profile", pathScope("id"), h).
func pathScope(param string) func(*http.Request) string {
	return func(r *http.Request) string { return r.PathValue(param) }
}

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
	"GET /health",                         // K8s/Docker liveness probe; cannot carry Bearer
	"GET /ready",                          // K8s/Docker readiness probe; cannot carry Bearer
	"GET /api/v1/auth/info",               // GUI calls before login to detect auth mode
	"GET /api/v1/version",                 // Rollout probes need build identity without key
	"GET /api/v1/auth/bootstrap",          // Bundle 1 Phase 6 — GUI / install one-liner probes "is bootstrap available?" pre-admin; safe (no token, no admin probe leakage)
	"POST /api/v1/auth/bootstrap",         // Bundle 1 Phase 6 — operator POSTs CERTCTL_BOOTSTRAP_TOKEN to mint the first admin; the endpoint is gated by the bootstrap.Strategy and the admin-existence probe
	"GET /auth/oidc/login",                // Auth Bundle 2 Phase 5 — kicks off OIDC flow; pre-auth by definition
	"GET /auth/oidc/callback",             // Auth Bundle 2 Phase 5 — IdP redirects here pre-auth; cookie + state validated inside
	"POST /auth/oidc/back-channel-logout", // Auth Bundle 2 Phase 5 — IdP-initiated; auth via the IdP-signed logout_token JWT in body
	"POST /auth/logout",                   // Auth Bundle 2 Phase 5 — caller's session-cookie is checked inside the handler; no Bearer requirement
	"POST /auth/breakglass/login",         // Auth Bundle 2 Phase 7.5 — local-password recovery; returns 404 when CERTCTL_BREAKGLASS_ENABLED=false (surface invisible)
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

	// Auth (Bundle 1 Phase 4) handles RBAC management endpoints under
	// /api/v1/auth/{roles,permissions,keys,me}. Wired in cmd/server with
	// the service-layer Authorizer + RoleService + ActorRoleService +
	// PermissionService dependencies. Phase 5 ships the CLI mirror.
	Auth handler.AuthHandler

	// Bootstrap (Bundle 1 Phase 6) handles the day-0 admin path under
	// /api/v1/auth/bootstrap. GET probes availability without revealing
	// state; POST consumes CERTCTL_BOOTSTRAP_TOKEN once and mints the
	// first admin API key. Both routes are auth-exempt (the endpoint
	// itself authenticates via the bootstrap token).
	Bootstrap handler.BootstrapHandler

	// DemoResidual (Audit 2026-05-11 A-8) handles
	// POST /api/v1/auth/demo-residual/cleanup. Removes residual
	// actor-demo-anon role grants from the actor_roles table. RBAC-
	// gated at the router via auth.role.assign (admin-class).
	// Refuses to run when the server is in demo mode (Auth.Type=none).
	DemoResidual handler.DemoResidualHandler

	// Checker is the load-bearing auth.PermissionChecker that
	// auth.RequirePermission middleware uses to gate the legacy admin
	// handlers (Bundle 1 Phase 3.5). cmd/server wires the postgres
	// Authorizer here via the authPermissionCheckerAdapter shim. When
	// nil, the wraps are no-ops and the routes fall through unguarded
	// (only valid in tests / demo deployments — production MUST
	// configure a Checker).
	Checker auth.PermissionChecker

	// CorsCfg is the operator-configured CORS middleware applied to the
	// credentialed auth-exempt routes (OIDC handshake, BCL, logout,
	// bootstrap, breakglass-login). Honors CERTCTL_CORS_ORIGINS — deny-
	// by-default when AllowedOrigins is empty. Audit 2026-05-10 CRIT-3
	// closure: previously these routes used middleware.CORSWildcard
	// (formerly middleware.CORS) which emitted Access-Control-Allow-
	// Origin: * regardless of operator config, ignoring the
	// CERTCTL_CORS_ORIGINS knob (CWE-942).
	//
	// Health probes (/health, /ready, /api/v1/version, /api/v1/auth/info)
	// continue to use middleware.CORSWildcard because they must be
	// reachable from any origin without credentials. Each wildcard call
	// site is listed in scripts/ci-guards/cors-wildcard-allowlist.sh —
	// the CI guard fails when a new wildcard wrap appears outside the
	// allowlist.
	CorsCfg middleware.CORSConfig
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

	// Approvals handles the issuance approval-workflow endpoints under
	// /api/v1/approvals/*. Rank 7 of the 2026-05-03 Infisical deep-
	// research deliverable — closes the two-person integrity / four-eyes
	// principle procurement gap. Routes:
	//   GET  /api/v1/approvals
	//   GET  /api/v1/approvals/{id}
	//   POST /api/v1/approvals/{id}/approve
	//   POST /api/v1/approvals/{id}/reject
	// Same-actor RBAC enforced at the service layer; the handler
	// surfaces ErrApproveBySameActor as HTTP 403. See
	// docs/approval-workflow.md for the operator playbook.
	Approvals handler.ApprovalHandler

	// AuthSessionOIDC handles the Auth Bundle 2 Phase 5 OIDC + session
	// HTTP surface. 13 endpoints across three groups:
	//   1. Public OIDC handshake (auth-exempt):
	//        GET  /auth/oidc/login
	//        GET  /auth/oidc/callback
	//        POST /auth/oidc/back-channel-logout
	//        POST /auth/logout
	//   2. Session management (RBAC-gated auth.session.*):
	//        GET    /api/v1/auth/sessions
	//        DELETE /api/v1/auth/sessions/{id}
	//   3. OIDC provider + group-mapping CRUD (RBAC-gated auth.oidc.*):
	//        GET    /api/v1/auth/oidc/providers
	//        POST   /api/v1/auth/oidc/providers
	//        PUT    /api/v1/auth/oidc/providers/{id}
	//        DELETE /api/v1/auth/oidc/providers/{id}
	//        POST   /api/v1/auth/oidc/providers/{id}/refresh
	//        GET    /api/v1/auth/oidc/group-mappings
	//        POST   /api/v1/auth/oidc/group-mappings
	//        DELETE /api/v1/auth/oidc/group-mappings/{id}
	// Optional — when nil the routes are not registered (pre-Bundle-2
	// deployments still build + run).
	AuthSessionOIDC *handler.AuthSessionOIDCHandler

	// AuthBreakglass handles the Auth Bundle 2 Phase 7.5 break-glass
	// admin HTTP surface — operator-toggleable local-password
	// recovery path for the SSO-broken case. 4 endpoints:
	//   POST   /auth/breakglass/login                                    (auth-exempt; returns 404 when disabled)
	//   POST   /api/v1/auth/breakglass/credentials                       (auth.breakglass.admin)
	//   POST   /api/v1/auth/breakglass/credentials/{actor_id}/unlock     (auth.breakglass.admin)
	//   DELETE /api/v1/auth/breakglass/credentials/{actor_id}            (auth.breakglass.admin)
	// Optional — when nil the routes are not registered.
	AuthBreakglass *handler.AuthBreakglassHandler

	// AuthUsers handles the MED-11 federated-user admin surface
	// (GET /api/v1/auth/users; DELETE /api/v1/auth/users/{id}).
	// Optional — when nil the routes are not registered.
	AuthUsers *handler.AuthUsersHandler

	// AuthRuntimeConfig handles the MED-12 admin-only runtime
	// config read endpoint (GET /api/v1/auth/runtime-config).
	// Optional — when nil the route is not registered.
	AuthRuntimeConfig *handler.AuthRuntimeConfigHandler

	// AuthOIDCJWKSStatus handles the MED-7 per-provider JWKS health
	// endpoint (GET /api/v1/auth/oidc/providers/{id}/jwks-status).
	// Optional — when nil the route is not registered.
	AuthOIDCJWKSStatus *handler.AuthOIDCJWKSStatusHandler

	// IntermediateCAs handles the admin-gated CA-hierarchy management
	// surface under /api/v1/issuers/{id}/intermediates and
	// /api/v1/intermediates/{id}. Rank 8 of the 2026-05-03 deep-
	// research deliverable — closes the multi-level CA hierarchy gap
	// for FedRAMP boundary-CA, financial-services policy-CA, and OT
	// network-CA deployments. Routes:
	//   POST /api/v1/issuers/{id}/intermediates
	//   GET  /api/v1/issuers/{id}/intermediates
	//   GET  /api/v1/intermediates/{id}
	//   POST /api/v1/intermediates/{id}/retire
	// Admin-gated at the handler layer (M-003 pattern). See
	// docs/intermediate-ca-hierarchy.md for the operator playbook.
	IntermediateCAs handler.IntermediateCAHandler
}

// RegisterHandlers sets up all API routes with their handlers.
func (r *Router) RegisterHandlers(reg HandlerRegistry) {
	// Health endpoints (no auth middleware — must always be accessible)
	r.mux.Handle("GET /health", middleware.Chain(
		http.HandlerFunc(reg.Health.Health),
		middleware.CORSWildcard,
		middleware.ContentType,
	))
	r.mux.Handle("GET /ready", middleware.Chain(
		http.HandlerFunc(reg.Health.Ready),
		middleware.CORSWildcard,
		middleware.ContentType,
	))
	// Auth info endpoint (no auth middleware — GUI needs this before login)
	r.mux.Handle("GET /api/v1/auth/info", middleware.Chain(
		http.HandlerFunc(reg.Health.AuthInfo),
		middleware.CORSWildcard,
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
		middleware.CORSWildcard,
		middleware.ContentType,
	))
	// Auth check endpoint (uses full middleware chain via r.Register)
	r.Register("GET /api/v1/auth/check", http.HandlerFunc(reg.Health.AuthCheck))

	// Bundle 1 Phase 6 — bootstrap routes. Auth-exempt because the
	// endpoint itself authenticates via the CERTCTL_BOOTSTRAP_TOKEN
	// (see internal/auth/bootstrap). Both routes are pinned in the
	// AuthExemptRouterRoutes allowlist above.
	r.mux.Handle("GET /api/v1/auth/bootstrap", middleware.Chain(
		http.HandlerFunc(reg.Bootstrap.Available),
		middleware.NewCORS(reg.CorsCfg),
		middleware.ContentType,
	))
	r.mux.Handle("POST /api/v1/auth/bootstrap", middleware.Chain(
		http.HandlerFunc(reg.Bootstrap.Mint),
		middleware.NewCORS(reg.CorsCfg),
		middleware.ContentType,
	))

	// RBAC management routes (Bundle 1 Phase 4 + audit 2026-05-10 CRIT-1
	// closure). Permission gates are now ALSO enforced at the router
	// level via rbacGate — Bundle 1 Phase 4 left these handler-only
	// (service-layer Authorizer check), which was a defense-in-depth
	// gap (HIGH-9 of the 2026-05-10 audit). /api/v1/auth/me and
	// /api/v1/auth/permissions remain ungated because every authenticated
	// caller is allowed to read their own identity / catalogue.
	r.Register("GET /api/v1/auth/me", http.HandlerFunc(reg.Auth.Me))
	r.Register("GET /api/v1/auth/permissions", http.HandlerFunc(reg.Auth.ListPermissions))
	r.Register("GET /api/v1/auth/roles", rbacGate(reg.Checker, "auth.role.list", reg.Auth.ListRoles))
	r.Register("POST /api/v1/auth/roles", rbacGate(reg.Checker, "auth.role.create", reg.Auth.CreateRole))
	r.Register("GET /api/v1/auth/roles/{id}", rbacGate(reg.Checker, "auth.role.list", reg.Auth.GetRole))
	r.Register("PUT /api/v1/auth/roles/{id}", rbacGate(reg.Checker, "auth.role.edit", reg.Auth.UpdateRole))
	r.Register("DELETE /api/v1/auth/roles/{id}", rbacGate(reg.Checker, "auth.role.delete", reg.Auth.DeleteRole))
	r.Register("POST /api/v1/auth/roles/{id}/permissions", rbacGate(reg.Checker, "auth.role.edit", reg.Auth.AddRolePermission))
	r.Register("DELETE /api/v1/auth/roles/{id}/permissions/{perm}", rbacGate(reg.Checker, "auth.role.edit", reg.Auth.RemoveRolePermission))
	r.Register("GET /api/v1/auth/keys", rbacGate(reg.Checker, "auth.key.list", reg.Auth.ListKeys))
	r.Register("POST /api/v1/auth/keys/{id}/roles", rbacGate(reg.Checker, "auth.role.assign", reg.Auth.AssignRoleToKey))
	r.Register("DELETE /api/v1/auth/keys/{id}/roles/{role_id}", rbacGate(reg.Checker, "auth.role.revoke", reg.Auth.RevokeRoleFromKey))

	// Audit 2026-05-11 A-8 closure — demo-mode residual-grants cleanup.
	// Gated auth.role.assign (admin-class) so non-admins can't wipe the
	// synthetic actor's grants. The handler additionally refuses to run
	// when the server is currently in demo mode (Auth.Type=none).
	r.Register("POST /api/v1/auth/demo-residual/cleanup",
		rbacGate(reg.Checker, "auth.role.assign", reg.DemoResidual.Cleanup))

	// =========================================================================
	// Auth Bundle 2 Phase 5 — OIDC + session HTTP surface.
	//
	// Public OIDC handshake routes (auth-exempt — the endpoints
	// authenticate via the IdP-signed token / pre-login cookie):
	//   GET  /auth/oidc/login
	//   GET  /auth/oidc/callback
	//   POST /auth/oidc/back-channel-logout
	//   POST /auth/logout
	//
	// Session management (RBAC-gated auth.session.* — see migration 000037):
	//   GET    /api/v1/auth/sessions           -> auth.session.list
	//   DELETE /api/v1/auth/sessions/{id}      -> auth.session.revoke
	//
	// OIDC provider + group-mapping CRUD (RBAC-gated auth.oidc.*):
	//   GET    /api/v1/auth/oidc/providers              -> auth.oidc.list
	//   POST   /api/v1/auth/oidc/providers              -> auth.oidc.create
	//   PUT    /api/v1/auth/oidc/providers/{id}         -> auth.oidc.edit
	//   DELETE /api/v1/auth/oidc/providers/{id}         -> auth.oidc.delete
	//   POST   /api/v1/auth/oidc/providers/{id}/refresh -> auth.oidc.edit
	//   GET    /api/v1/auth/oidc/group-mappings         -> auth.oidc.list
	//   POST   /api/v1/auth/oidc/group-mappings         -> auth.oidc.edit
	//   DELETE /api/v1/auth/oidc/group-mappings/{id}    -> auth.oidc.edit
	//
	// Routes are only registered when reg.AuthSessionOIDC is non-nil
	// (Phase 5 wiring — production main.go always passes it; pre-Phase-5
	// builds skip this block entirely).
	if reg.AuthSessionOIDC != nil {
		// Public OIDC handshake — auth-exempt. Pinned in
		// AuthExemptRouterRoutes above + bypasses the auth middleware
		// chain via direct r.mux.Handle calls. Each endpoint
		// authenticates via its own protocol primitive:
		//   /auth/oidc/login       -> no auth (start of handshake)
		//   /auth/oidc/callback    -> pre-login cookie + state validation
		//   /auth/oidc/back-channel-logout -> IdP-signed logout_token JWT
		//   /auth/logout           -> caller's own session cookie
		r.mux.Handle("GET /auth/oidc/login", middleware.Chain(
			http.HandlerFunc(reg.AuthSessionOIDC.LoginInitiate),
			middleware.NewCORS(reg.CorsCfg), middleware.ContentType,
		))
		r.mux.Handle("GET /auth/oidc/callback", middleware.Chain(
			http.HandlerFunc(reg.AuthSessionOIDC.LoginCallback),
			middleware.NewCORS(reg.CorsCfg), middleware.ContentType,
		))
		r.mux.Handle("POST /auth/oidc/back-channel-logout", middleware.Chain(
			http.HandlerFunc(reg.AuthSessionOIDC.BackChannelLogout),
			middleware.NewCORS(reg.CorsCfg), middleware.ContentType,
		))
		r.mux.Handle("POST /auth/logout", middleware.Chain(
			http.HandlerFunc(reg.AuthSessionOIDC.Logout),
			middleware.NewCORS(reg.CorsCfg), middleware.ContentType,
		))

		// Session management. auth.session.list gates the all-actors
		// admin view; the handler internally allows callers to list
		// their own sessions without the permission. Revoke gates
		// "revoke any session"; own-session paths bypass at the
		// handler layer per Phase 5 spec.
		r.Register("GET /api/v1/auth/sessions", rbacGate(reg.Checker, "auth.session.list", reg.AuthSessionOIDC.ListSessions))
		r.Register("DELETE /api/v1/auth/sessions/{id}", rbacGate(reg.Checker, "auth.session.revoke", reg.AuthSessionOIDC.RevokeSession))
		// Audit 2026-05-10 MED-3 closure — DELETE /api/v1/auth/sessions?except=current
		// is the "Sign out all other sessions" flow. Gated by
		// auth.session.revoke (any authenticated caller with the perm
		// can revoke their OWN remaining sessions; the handler reads
		// the current session ID from context and excludes it).
		r.Register("DELETE /api/v1/auth/sessions", rbacGate(reg.Checker, "auth.session.revoke", reg.AuthSessionOIDC.RevokeAllExceptCurrent))

		// OIDC provider CRUD.
		r.Register("GET /api/v1/auth/oidc/providers", rbacGate(reg.Checker, "auth.oidc.list", reg.AuthSessionOIDC.ListProviders))
		r.Register("POST /api/v1/auth/oidc/providers", rbacGate(reg.Checker, "auth.oidc.create", reg.AuthSessionOIDC.CreateProvider))
		r.Register("PUT /api/v1/auth/oidc/providers/{id}", rbacGate(reg.Checker, "auth.oidc.edit", reg.AuthSessionOIDC.UpdateProvider))
		r.Register("DELETE /api/v1/auth/oidc/providers/{id}", rbacGate(reg.Checker, "auth.oidc.delete", reg.AuthSessionOIDC.DeleteProvider))
		r.Register("POST /api/v1/auth/oidc/providers/{id}/refresh", rbacGate(reg.Checker, "auth.oidc.edit", reg.AuthSessionOIDC.RefreshProvider))
		// Audit 2026-05-10 MED-5 — dry-run validator for OIDC provider
		// config. Returns discovery + JWKS + alg-downgrade + iss-param
		// reachability without persisting.
		r.Register("POST /api/v1/auth/oidc/test", rbacGate(reg.Checker, "auth.oidc.create", reg.AuthSessionOIDC.TestProvider))

		// Audit 2026-05-10 MED-7 — JWKS health surface.
		if reg.AuthOIDCJWKSStatus != nil {
			r.Register("GET /api/v1/auth/oidc/providers/{id}/jwks-status",
				rbacGate(reg.Checker, "auth.oidc.list", reg.AuthOIDCJWKSStatus.Status))
		}

		// Audit 2026-05-10 MED-11 — federated-user admin surface.
		// Audit 2026-05-11 A-2 — added reactivate route. Same permission
		// gate as Deactivate (reactivation is the inverse op, not a
		// separate privilege).
		if reg.AuthUsers != nil {
			r.Register("GET /api/v1/auth/users",
				rbacGate(reg.Checker, "auth.user.read", reg.AuthUsers.List))
			r.Register("DELETE /api/v1/auth/users/{id}",
				rbacGate(reg.Checker, "auth.user.deactivate", reg.AuthUsers.Deactivate))
			r.Register("POST /api/v1/auth/users/{id}/reactivate",
				rbacGate(reg.Checker, "auth.user.deactivate", reg.AuthUsers.Reactivate))
		}

		// Audit 2026-05-10 MED-12 — auth runtime config read.
		// Gated auth.role.assign (admin-class) so non-admins can't
		// enumerate the deployment's auth knobs.
		if reg.AuthRuntimeConfig != nil {
			r.Register("GET /api/v1/auth/runtime-config",
				rbacGate(reg.Checker, "auth.role.assign", reg.AuthRuntimeConfig.Get))
		}

		// Group-mapping CRUD.
		r.Register("GET /api/v1/auth/oidc/group-mappings", rbacGate(reg.Checker, "auth.oidc.list", reg.AuthSessionOIDC.ListGroupMappings))
		r.Register("POST /api/v1/auth/oidc/group-mappings", rbacGate(reg.Checker, "auth.oidc.edit", reg.AuthSessionOIDC.AddGroupMapping))
		r.Register("DELETE /api/v1/auth/oidc/group-mappings/{id}", rbacGate(reg.Checker, "auth.oidc.edit", reg.AuthSessionOIDC.RemoveGroupMapping))
	}

	// =========================================================================
	// Auth Bundle 2 Phase 7.5 — break-glass admin HTTP surface.
	//
	// Public login endpoint (auth-exempt; the whole point is to log in
	// WITHOUT existing creds). Returns 404 when CERTCTL_BREAKGLASS_ENABLED
	// is false so the surface is invisible to scanners. Pinned in
	// AuthExemptRouterRoutes above.
	//
	// Admin endpoints (RBAC-gated auth.breakglass.admin per migration
	// 000038) — the handler also returns 404 when disabled, sharing the
	// surface-invisibility property with the public login path.
	if reg.AuthBreakglass != nil {
		r.mux.Handle("POST /auth/breakglass/login", middleware.Chain(
			http.HandlerFunc(reg.AuthBreakglass.Login),
			middleware.NewCORS(reg.CorsCfg), middleware.ContentType,
		))
		r.Register("GET /api/v1/auth/breakglass/credentials", rbacGate(reg.Checker, "auth.breakglass.admin", reg.AuthBreakglass.ListCredentials))
		r.Register("POST /api/v1/auth/breakglass/credentials", rbacGate(reg.Checker, "auth.breakglass.admin", reg.AuthBreakglass.SetPassword))
		r.Register("POST /api/v1/auth/breakglass/credentials/{actor_id}/unlock", rbacGate(reg.Checker, "auth.breakglass.admin", reg.AuthBreakglass.Unlock))
		r.Register("DELETE /api/v1/auth/breakglass/credentials/{actor_id}", rbacGate(reg.Checker, "auth.breakglass.admin", reg.AuthBreakglass.Remove))
	}

	// Certificates routes: /api/v1/certificates
	// Bulk operations MUST register before {id} routes — Go 1.22 ServeMux
	// gives literal segments precedence over pattern-var segments, but
	// listing the bulk paths first makes the precedence operator-visible
	// and prevents a future refactor from accidentally inverting it. All
	// three bulk endpoints share the same envelope shape (criteria/IDs
	// in, {total_matched, total_<verb>, total_skipped, total_failed,
	// errors[]} out). L-1 master added bulk-renew + bulk-reassign
	// alongside the pre-existing bulk-revoke.
	r.Register("POST /api/v1/certificates/bulk-revoke", rbacGate(reg.Checker, "cert.bulk_revoke", reg.BulkRevocation.BulkRevoke))
	// EST RFC 7030 hardening Phase 11.2 — Source-scoped EST bulk-revoke.
	// Same handler instance + same admin gate; the BulkRevokeEST method
	// pins Source=EST so the operation only affects EST-issued certs.
	r.Register("POST /api/v1/est/certificates/bulk-revoke", rbacGate(reg.Checker, "cert.bulk_revoke", reg.BulkRevocation.BulkRevokeEST))
	r.Register("POST /api/v1/certificates/bulk-renew", rbacGate(reg.Checker, "cert.issue", reg.BulkRenewal.BulkRenew))
	r.Register("POST /api/v1/certificates/bulk-reassign", rbacGate(reg.Checker, "cert.edit", reg.BulkReassignment.BulkReassign))
	r.Register("GET /api/v1/certificates", rbacGate(reg.Checker, "cert.read", reg.Certificates.ListCertificates))
	r.Register("POST /api/v1/certificates", rbacGate(reg.Checker, "cert.issue", reg.Certificates.CreateCertificate))
	r.Register("GET /api/v1/certificates/{id}", rbacGate(reg.Checker, "cert.read", reg.Certificates.GetCertificate))
	r.Register("PUT /api/v1/certificates/{id}", rbacGate(reg.Checker, "cert.edit", reg.Certificates.UpdateCertificate))
	r.Register("DELETE /api/v1/certificates/{id}", rbacGate(reg.Checker, "cert.delete", reg.Certificates.ArchiveCertificate))
	r.Register("GET /api/v1/certificates/{id}/versions", rbacGate(reg.Checker, "cert.read", reg.Certificates.GetCertificateVersions))
	r.Register("GET /api/v1/certificates/{id}/deployments", rbacGate(reg.Checker, "cert.read", reg.Certificates.GetCertificateDeployments))
	r.Register("POST /api/v1/certificates/{id}/renew", rbacGate(reg.Checker, "cert.issue", reg.Certificates.TriggerRenewal))
	r.Register("POST /api/v1/certificates/{id}/deploy", rbacGate(reg.Checker, "cert.edit", reg.Certificates.TriggerDeployment))
	r.Register("POST /api/v1/certificates/{id}/revoke", rbacGate(reg.Checker, "cert.revoke", reg.Certificates.RevokeCertificate))

	// Export endpoints: /api/v1/certificates/{id}/export/{format}.
	// Reading bytes — gated by cert.read.
	r.Register("GET /api/v1/certificates/{id}/export/pem", rbacGate(reg.Checker, "cert.read", reg.Export.ExportPEM))
	r.Register("POST /api/v1/certificates/{id}/export/pkcs12", rbacGate(reg.Checker, "cert.read", reg.Export.ExportPKCS12))

	// NOTE: RFC 5280 CRL and RFC 6960 OCSP endpoints are registered separately
	// via RegisterPKIHandlers under /.well-known/pki/ so relying parties can
	// fetch them without presenting certctl API credentials. The legacy
	// /api/v1/crl and /api/v1/ocsp paths have been retired (see M-006).

	// Issuers routes: /api/v1/issuers
	// Path-scoped: PUT / DELETE / test on /{id} honor per-issuer
	// scope-bound role-permission grants. Operators who grant
	// issuer.edit scope_type=issuer scope_id=iss-internal-ca only
	// authorize edits to that specific issuer.
	r.Register("GET /api/v1/issuers", rbacGate(reg.Checker, "issuer.read", reg.Issuers.ListIssuers))
	r.Register("POST /api/v1/issuers", rbacGate(reg.Checker, "issuer.edit", reg.Issuers.CreateIssuer))
	r.Register("GET /api/v1/issuers/{id}", rbacGateScoped(reg.Checker, "issuer.read", "issuer", pathScope("id"), reg.Issuers.GetIssuer))
	r.Register("PUT /api/v1/issuers/{id}", rbacGateScoped(reg.Checker, "issuer.edit", "issuer", pathScope("id"), reg.Issuers.UpdateIssuer))
	r.Register("DELETE /api/v1/issuers/{id}", rbacGateScoped(reg.Checker, "issuer.delete", "issuer", pathScope("id"), reg.Issuers.DeleteIssuer))
	r.Register("POST /api/v1/issuers/{id}/test", rbacGateScoped(reg.Checker, "issuer.edit", "issuer", pathScope("id"), reg.Issuers.TestConnection))

	// Targets routes: /api/v1/targets
	r.Register("GET /api/v1/targets", rbacGate(reg.Checker, "target.read", reg.Targets.ListTargets))
	r.Register("POST /api/v1/targets", rbacGate(reg.Checker, "target.edit", reg.Targets.CreateTarget))
	r.Register("GET /api/v1/targets/{id}", rbacGate(reg.Checker, "target.read", reg.Targets.GetTarget))
	r.Register("PUT /api/v1/targets/{id}", rbacGate(reg.Checker, "target.edit", reg.Targets.UpdateTarget))
	r.Register("DELETE /api/v1/targets/{id}", rbacGate(reg.Checker, "target.delete", reg.Targets.DeleteTarget))
	r.Register("POST /api/v1/targets/{id}/test", rbacGate(reg.Checker, "target.edit", reg.Targets.TestTargetConnection))

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
	r.Register("GET /api/v1/agents", rbacGate(reg.Checker, "agent.read", reg.Agents.ListAgents))
	r.Register("POST /api/v1/agents", rbacGate(reg.Checker, "agent.edit", reg.Agents.RegisterAgent))
	r.Register("GET /api/v1/agents/retired", rbacGate(reg.Checker, "agent.read", reg.Agents.ListRetiredAgents))
	r.Register("GET /api/v1/agents/{id}", rbacGate(reg.Checker, "agent.read", reg.Agents.GetAgent))
	r.Register("DELETE /api/v1/agents/{id}", rbacGate(reg.Checker, "agent.retire", reg.Agents.RetireAgent))
	r.Register("POST /api/v1/agents/{id}/heartbeat", rbacGate(reg.Checker, "agent.heartbeat", reg.Agents.Heartbeat))
	r.Register("POST /api/v1/agents/{id}/csr", rbacGate(reg.Checker, "agent.job.poll", reg.Agents.AgentCSRSubmit))
	r.Register("GET /api/v1/agents/{id}/certificates/{cert_id}", rbacGate(reg.Checker, "cert.read", reg.Agents.AgentCertificatePickup))
	r.Register("GET /api/v1/agents/{id}/work", rbacGate(reg.Checker, "agent.job.poll", reg.Agents.AgentGetWork))
	r.Register("POST /api/v1/agents/{id}/jobs/{job_id}/status", rbacGate(reg.Checker, "agent.job.complete", reg.Agents.AgentReportJobStatus))

	// Jobs routes: /api/v1/jobs
	r.Register("GET /api/v1/jobs", rbacGate(reg.Checker, "job.read", reg.Jobs.ListJobs))
	r.Register("GET /api/v1/jobs/{id}", rbacGate(reg.Checker, "job.read", reg.Jobs.GetJob))
	r.Register("POST /api/v1/jobs/{id}/cancel", rbacGate(reg.Checker, "job.cancel", reg.Jobs.CancelJob))
	r.Register("POST /api/v1/jobs/{id}/approve", rbacGate(reg.Checker, "approval.approve", reg.Jobs.ApproveJob))
	r.Register("POST /api/v1/jobs/{id}/reject", rbacGate(reg.Checker, "approval.reject", reg.Jobs.RejectJob))

	// Policies routes: /api/v1/policies
	r.Register("GET /api/v1/policies", rbacGate(reg.Checker, "policy.read", reg.Policies.ListPolicies))
	r.Register("POST /api/v1/policies", rbacGate(reg.Checker, "policy.edit", reg.Policies.CreatePolicy))
	r.Register("GET /api/v1/policies/{id}", rbacGate(reg.Checker, "policy.read", reg.Policies.GetPolicy))
	r.Register("PUT /api/v1/policies/{id}", rbacGate(reg.Checker, "policy.edit", reg.Policies.UpdatePolicy))
	r.Register("DELETE /api/v1/policies/{id}", rbacGate(reg.Checker, "policy.delete", reg.Policies.DeletePolicy))
	r.Register("GET /api/v1/policies/{id}/violations", rbacGate(reg.Checker, "policy.read", reg.Policies.ListViolations))

	// Renewal Policies routes: /api/v1/renewal-policies
	// G-1: fixes frontend FK drift — OnboardingWizard + CertificatesPage dropdowns
	// were previously populating renewal_policy_id from /api/v1/policies (compliance
	// rules, pol-* IDs), violating FK managed_certificates.renewal_policy_id →
	// renewal_policies(id) ON DELETE RESTRICT. This block is the backend half; the
	// frontend half swaps getPolicies → getRenewalPolicies at 3 call sites.
	// Reuses the policy.* permission catalogue entry (renewal policies are a
	// subtype of policy from the operator's perspective).
	r.Register("GET /api/v1/renewal-policies", rbacGate(reg.Checker, "policy.read", reg.RenewalPolicies.ListRenewalPolicies))
	r.Register("POST /api/v1/renewal-policies", rbacGate(reg.Checker, "policy.edit", reg.RenewalPolicies.CreateRenewalPolicy))
	r.Register("GET /api/v1/renewal-policies/{id}", rbacGate(reg.Checker, "policy.read", reg.RenewalPolicies.GetRenewalPolicy))
	r.Register("PUT /api/v1/renewal-policies/{id}", rbacGate(reg.Checker, "policy.edit", reg.RenewalPolicies.UpdateRenewalPolicy))
	r.Register("DELETE /api/v1/renewal-policies/{id}", rbacGate(reg.Checker, "policy.delete", reg.RenewalPolicies.DeleteRenewalPolicy))

	// Profiles routes: /api/v1/profiles
	// Path-scoped: PUT / DELETE on /{id} honor per-profile scope-bound
	// role-permission grants. Operators who grant profile.edit
	// scope_type=profile scope_id=p-finance only authorize edits to
	// that specific profile.
	r.Register("GET /api/v1/profiles", rbacGate(reg.Checker, "profile.read", reg.Profiles.ListProfiles))
	r.Register("POST /api/v1/profiles", rbacGate(reg.Checker, "profile.edit", reg.Profiles.CreateProfile))
	r.Register("GET /api/v1/profiles/{id}", rbacGateScoped(reg.Checker, "profile.read", "profile", pathScope("id"), reg.Profiles.GetProfile))
	r.Register("PUT /api/v1/profiles/{id}", rbacGateScoped(reg.Checker, "profile.edit", "profile", pathScope("id"), reg.Profiles.UpdateProfile))
	r.Register("DELETE /api/v1/profiles/{id}", rbacGateScoped(reg.Checker, "profile.delete", "profile", pathScope("id"), reg.Profiles.DeleteProfile))

	// Teams routes: /api/v1/teams
	r.Register("GET /api/v1/teams", rbacGate(reg.Checker, "team.read", reg.Teams.ListTeams))
	r.Register("POST /api/v1/teams", rbacGate(reg.Checker, "team.edit", reg.Teams.CreateTeam))
	r.Register("GET /api/v1/teams/{id}", rbacGate(reg.Checker, "team.read", reg.Teams.GetTeam))
	r.Register("PUT /api/v1/teams/{id}", rbacGate(reg.Checker, "team.edit", reg.Teams.UpdateTeam))
	r.Register("DELETE /api/v1/teams/{id}", rbacGate(reg.Checker, "team.delete", reg.Teams.DeleteTeam))

	// Owners routes: /api/v1/owners
	r.Register("GET /api/v1/owners", rbacGate(reg.Checker, "owner.read", reg.Owners.ListOwners))
	r.Register("POST /api/v1/owners", rbacGate(reg.Checker, "owner.edit", reg.Owners.CreateOwner))
	r.Register("GET /api/v1/owners/{id}", rbacGate(reg.Checker, "owner.read", reg.Owners.GetOwner))
	r.Register("PUT /api/v1/owners/{id}", rbacGate(reg.Checker, "owner.edit", reg.Owners.UpdateOwner))
	r.Register("DELETE /api/v1/owners/{id}", rbacGate(reg.Checker, "owner.delete", reg.Owners.DeleteOwner))

	// Agent Groups routes: /api/v1/agent-groups
	// Reuses agent.* permissions (agent-groups are an organizational
	// view on top of the agent resource).
	r.Register("GET /api/v1/agent-groups", rbacGate(reg.Checker, "agent.read", reg.AgentGroups.ListAgentGroups))
	r.Register("POST /api/v1/agent-groups", rbacGate(reg.Checker, "agent.edit", reg.AgentGroups.CreateAgentGroup))
	r.Register("GET /api/v1/agent-groups/{id}", rbacGate(reg.Checker, "agent.read", reg.AgentGroups.GetAgentGroup))
	r.Register("PUT /api/v1/agent-groups/{id}", rbacGate(reg.Checker, "agent.edit", reg.AgentGroups.UpdateAgentGroup))
	r.Register("DELETE /api/v1/agent-groups/{id}", rbacGate(reg.Checker, "agent.edit", reg.AgentGroups.DeleteAgentGroup))
	r.Register("GET /api/v1/agent-groups/{id}/members", rbacGate(reg.Checker, "agent.read", reg.AgentGroups.ListAgentGroupMembers))

	// Audit routes: /api/v1/audit
	r.Register("GET /api/v1/audit", rbacGate(reg.Checker, "audit.read", reg.Audit.ListAuditEvents))
	// Audit 2026-05-10 HIGH-11 closure — `audit.export` permission was
	// already seeded into r-admin + r-auditor (migration 000031), but
	// no endpoint enforced it pre-fix; r-auditor's claim was misleading
	// capability advertisement. The export endpoint makes the grant
	// load-bearing. Register `/audit/export` BEFORE `/audit/{id}` so
	// Go's net/http stdlib routing gives the more specific path
	// precedence over the catch-all.
	r.Register("GET /api/v1/audit/export", rbacGate(reg.Checker, "audit.export", reg.Audit.ExportAudit))
	r.Register("GET /api/v1/audit/{id}", rbacGate(reg.Checker, "audit.read", reg.Audit.GetAuditEvent))

	// Bundle CRL/OCSP-Responder Phase 5: admin observability for the
	// scheduler-driven CRL pre-generation cache. Admin-gated inside
	// the handler (M-003 pattern); non-admin callers get 403.
	r.Register("GET /api/v1/admin/crl/cache", rbacGate(reg.Checker, "crl.admin", reg.AdminCRLCache.ListCache))
	// SCEP RFC 8894 + Intune master bundle Phase 9.2 + Phase 9 follow-up
	// (the project's SCEP GUI restructure spec). All three endpoints are
	// admin-gated at the handler layer; the M-008 regression scanner pins
	// the gate set and TestM008_AdminGatedHandlers_HaveTripletTests
	// enforces the per-handler test triplet.
	r.Register("GET /api/v1/admin/scep/profiles", rbacGate(reg.Checker, "scep.admin", reg.AdminSCEPIntune.Profiles))
	r.Register("GET /api/v1/admin/scep/intune/stats", rbacGate(reg.Checker, "scep.admin", reg.AdminSCEPIntune.Stats))
	r.Register("POST /api/v1/admin/scep/intune/reload-trust", rbacGate(reg.Checker, "scep.admin", reg.AdminSCEPIntune.ReloadTrust))
	// EST RFC 7030 hardening Phase 7.2 — admin-gated EST observability.
	r.Register("GET /api/v1/admin/est/profiles", rbacGate(reg.Checker, "est.admin", reg.AdminEST.Profiles))
	r.Register("POST /api/v1/admin/est/reload-trust", rbacGate(reg.Checker, "est.admin", reg.AdminEST.ReloadTrust))

	// Notifications routes: /api/v1/notifications
	r.Register("GET /api/v1/notifications", rbacGate(reg.Checker, "notification.read", reg.Notifications.ListNotifications))
	r.Register("GET /api/v1/notifications/{id}", rbacGate(reg.Checker, "notification.read", reg.Notifications.GetNotification))
	r.Register("POST /api/v1/notifications/{id}/read", rbacGate(reg.Checker, "notification.read", reg.Notifications.MarkAsRead))
	// I-005: requeue a dead notification back to pending so the retry sweep
	// picks it up again. Go 1.22 ServeMux resolves the literal /requeue segment
	// before falling back to the {id} path-variable route above.
	r.Register("POST /api/v1/notifications/{id}/requeue", rbacGate(reg.Checker, "notification.edit", reg.Notifications.RequeueNotification))

	// Approvals routes: /api/v1/approvals (Rank 7).
	// Same Go 1.22 ServeMux precedence as the notifications block — literal
	// /approve and /reject segments resolve before the {id} pattern-var
	// route. Same-actor RBAC enforced at the service layer; the handler
	// surfaces ErrApproveBySameActor as HTTP 403. Router-level gates
	// added in the 2026-05-10 audit CRIT-1 closure (defense in depth).
	r.Register("GET /api/v1/approvals", rbacGate(reg.Checker, "approval.read", reg.Approvals.ListApprovals))
	r.Register("GET /api/v1/approvals/{id}", rbacGate(reg.Checker, "approval.read", reg.Approvals.GetApproval))
	r.Register("POST /api/v1/approvals/{id}/approve", rbacGate(reg.Checker, "approval.approve", reg.Approvals.Approve))
	r.Register("POST /api/v1/approvals/{id}/reject", rbacGate(reg.Checker, "approval.reject", reg.Approvals.Reject))

	// IntermediateCA hierarchy routes (Rank 8). Admin-gated inside the
	// handler (M-003 pattern); non-admin Bearer callers get 403. The
	// /retire literal segment resolves before the {id} pattern-var
	// route under Go 1.22 ServeMux precedence — the ordering below
	// matches the notifications + approvals blocks above.
	r.Register("POST /api/v1/issuers/{id}/intermediates", rbacGate(reg.Checker, "ca.hierarchy.manage", reg.IntermediateCAs.Create))
	r.Register("GET /api/v1/issuers/{id}/intermediates", rbacGate(reg.Checker, "ca.hierarchy.manage", reg.IntermediateCAs.List))
	r.Register("POST /api/v1/intermediates/{id}/retire", rbacGate(reg.Checker, "ca.hierarchy.manage", reg.IntermediateCAs.Retire))
	r.Register("GET /api/v1/intermediates/{id}", rbacGate(reg.Checker, "ca.hierarchy.manage", reg.IntermediateCAs.Get))

	// Stats routes: /api/v1/stats
	r.Register("GET /api/v1/stats/summary", rbacGate(reg.Checker, "stats.read", reg.Stats.GetDashboardSummary))
	r.Register("GET /api/v1/stats/certificates-by-status", rbacGate(reg.Checker, "stats.read", reg.Stats.GetCertificatesByStatus))
	r.Register("GET /api/v1/stats/expiration-timeline", rbacGate(reg.Checker, "stats.read", reg.Stats.GetExpirationTimeline))
	r.Register("GET /api/v1/stats/job-trends", rbacGate(reg.Checker, "stats.read", reg.Stats.GetJobTrends))
	r.Register("GET /api/v1/stats/issuance-rate", rbacGate(reg.Checker, "stats.read", reg.Stats.GetIssuanceRate))

	// Metrics routes: /api/v1/metrics
	r.Register("GET /api/v1/metrics", rbacGate(reg.Checker, "metrics.read", reg.Metrics.GetMetrics))
	r.Register("GET /api/v1/metrics/prometheus", rbacGate(reg.Checker, "metrics.read", reg.Metrics.GetPrometheusMetrics))

	// Discovery routes: /api/v1/discovered-certificates, /api/v1/discovery-scans
	r.Register("POST /api/v1/agents/{id}/discoveries", rbacGate(reg.Checker, "discovery.run", reg.Discovery.SubmitDiscoveryReport))
	r.Register("GET /api/v1/discovered-certificates", rbacGate(reg.Checker, "discovery.read", reg.Discovery.ListDiscovered))
	r.Register("GET /api/v1/discovered-certificates/{id}", rbacGate(reg.Checker, "discovery.read", reg.Discovery.GetDiscovered))
	r.Register("POST /api/v1/discovered-certificates/{id}/claim", rbacGate(reg.Checker, "discovery.claim", reg.Discovery.ClaimDiscovered))
	r.Register("POST /api/v1/discovered-certificates/{id}/dismiss", rbacGate(reg.Checker, "discovery.claim", reg.Discovery.DismissDiscovered))
	r.Register("GET /api/v1/discovery-scans", rbacGate(reg.Checker, "discovery.read", reg.Discovery.ListScans))
	r.Register("GET /api/v1/discovery-summary", rbacGate(reg.Checker, "discovery.read", reg.Discovery.GetDiscoverySummary))

	// Network scan routes: /api/v1/network-scan-targets
	r.Register("GET /api/v1/network-scan-targets", rbacGate(reg.Checker, "network_scan.read", reg.NetworkScan.ListNetworkScanTargets))
	r.Register("POST /api/v1/network-scan-targets", rbacGate(reg.Checker, "network_scan.edit", reg.NetworkScan.CreateNetworkScanTarget))
	r.Register("GET /api/v1/network-scan-targets/{id}", rbacGate(reg.Checker, "network_scan.read", reg.NetworkScan.GetNetworkScanTarget))
	r.Register("PUT /api/v1/network-scan-targets/{id}", rbacGate(reg.Checker, "network_scan.edit", reg.NetworkScan.UpdateNetworkScanTarget))
	r.Register("DELETE /api/v1/network-scan-targets/{id}", rbacGate(reg.Checker, "network_scan.edit", reg.NetworkScan.DeleteNetworkScanTarget))
	r.Register("POST /api/v1/network-scan-targets/{id}/scan", rbacGate(reg.Checker, "network_scan.run", reg.NetworkScan.TriggerNetworkScan))
	// SCEP RFC 8894 + Intune master bundle Phase 11.5 — SCEP probe.
	// Now RBAC-gated by network_scan.run (was Bearer-only pre-audit).
	r.Register("POST /api/v1/network-scan/scep-probe", rbacGate(reg.Checker, "network_scan.run", reg.NetworkScan.ProbeSCEP))
	r.Register("GET /api/v1/network-scan/scep-probes", rbacGate(reg.Checker, "network_scan.read", reg.NetworkScan.ListSCEPProbes))

	// Verification routes: /api/v1/jobs/{id}/verify and /api/v1/jobs/{id}/verification
	r.Register("POST /api/v1/jobs/{id}/verify", rbacGate(reg.Checker, "verification.run", reg.Verification.VerifyDeployment))
	r.Register("GET /api/v1/jobs/{id}/verification", rbacGate(reg.Checker, "verification.read", reg.Verification.GetVerificationStatus))

	// Digest routes: /api/v1/digest
	r.Register("GET /api/v1/digest/preview", rbacGate(reg.Checker, "digest.read", reg.Digest.PreviewDigest))
	r.Register("POST /api/v1/digest/send", rbacGate(reg.Checker, "digest.send", reg.Digest.SendDigest))

	// Health check routes: /api/v1/health-checks
	// Summary endpoint must be registered before {id} routes
	r.Register("GET /api/v1/health-checks/summary", rbacGate(reg.Checker, "healthcheck.read", reg.HealthChecks.GetHealthCheckSummary))
	r.Register("GET /api/v1/health-checks", rbacGate(reg.Checker, "healthcheck.read", reg.HealthChecks.ListHealthChecks))
	r.Register("POST /api/v1/health-checks", rbacGate(reg.Checker, "healthcheck.edit", reg.HealthChecks.CreateHealthCheck))
	r.Register("GET /api/v1/health-checks/{id}", rbacGate(reg.Checker, "healthcheck.read", reg.HealthChecks.GetHealthCheck))
	r.Register("PUT /api/v1/health-checks/{id}", rbacGate(reg.Checker, "healthcheck.edit", reg.HealthChecks.UpdateHealthCheck))
	r.Register("DELETE /api/v1/health-checks/{id}", rbacGate(reg.Checker, "healthcheck.delete", reg.HealthChecks.DeleteHealthCheck))
	r.Register("GET /api/v1/health-checks/{id}/history", rbacGate(reg.Checker, "healthcheck.read", reg.HealthChecks.GetHealthCheckHistory))
	r.Register("POST /api/v1/health-checks/{id}/acknowledge", rbacGate(reg.Checker, "healthcheck.acknowledge", reg.HealthChecks.AcknowledgeHealthCheck))

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
	r.Register("POST /acme/profile/{id}/new-account", http.HandlerFunc(reg.ACME.NewAccount))
	r.Register("POST /acme/profile/{id}/account/{acc_id}", http.HandlerFunc(reg.ACME.Account))
	r.Register("POST /acme/profile/{id}/new-order", http.HandlerFunc(reg.ACME.NewOrder))
	r.Register("POST /acme/profile/{id}/order/{ord_id}", http.HandlerFunc(reg.ACME.Order))
	r.Register("POST /acme/profile/{id}/order/{ord_id}/finalize", http.HandlerFunc(reg.ACME.OrderFinalize))
	r.Register("POST /acme/profile/{id}/authz/{authz_id}", http.HandlerFunc(reg.ACME.Authz))
	r.Register("POST /acme/profile/{id}/challenge/{chall_id}", http.HandlerFunc(reg.ACME.Challenge))
	r.Register("POST /acme/profile/{id}/cert/{cert_id}", http.HandlerFunc(reg.ACME.Cert))
	r.Register("POST /acme/profile/{id}/key-change", http.HandlerFunc(reg.ACME.KeyChange))
	r.Register("POST /acme/profile/{id}/revoke-cert", http.HandlerFunc(reg.ACME.RevokeCert))
	// RFC 9773 ARI: GET-only + unauthenticated (cert-manager-shaped
	// clients fetch this without a JWS).
	r.Register("GET /acme/profile/{id}/renewal-info/{cert_id}", http.HandlerFunc(reg.ACME.RenewalInfo))
	// Default-profile shorthand. The handler's profile-resolution path
	// returns userActionRequired (RFC 7807 + RFC 8555 §6.7) when
	// CERTCTL_ACME_SERVER_DEFAULT_PROFILE_ID is unset; when set it
	// dispatches to the same handler as the per-profile path.
	r.Register("GET /acme/directory", http.HandlerFunc(reg.ACME.Directory))
	r.Register("HEAD /acme/new-nonce", http.HandlerFunc(reg.ACME.NewNonce))
	r.Register("GET /acme/new-nonce", http.HandlerFunc(reg.ACME.NewNonce))
	r.Register("POST /acme/new-account", http.HandlerFunc(reg.ACME.NewAccount))
	r.Register("POST /acme/account/{acc_id}", http.HandlerFunc(reg.ACME.Account))
	r.Register("POST /acme/new-order", http.HandlerFunc(reg.ACME.NewOrder))
	r.Register("POST /acme/order/{ord_id}", http.HandlerFunc(reg.ACME.Order))
	r.Register("POST /acme/order/{ord_id}/finalize", http.HandlerFunc(reg.ACME.OrderFinalize))
	r.Register("POST /acme/authz/{authz_id}", http.HandlerFunc(reg.ACME.Authz))
	r.Register("POST /acme/challenge/{chall_id}", http.HandlerFunc(reg.ACME.Challenge))
	r.Register("POST /acme/cert/{cert_id}", http.HandlerFunc(reg.ACME.Cert))
	r.Register("POST /acme/key-change", http.HandlerFunc(reg.ACME.KeyChange))
	r.Register("POST /acme/revoke-cert", http.HandlerFunc(reg.ACME.RevokeCert))
	r.Register("GET /acme/renewal-info/{cert_id}", http.HandlerFunc(reg.ACME.RenewalInfo))
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
