package handler

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/certctl-io/certctl/internal/auth"
	"github.com/certctl-io/certctl/internal/domain"
	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/repository"
)

// AuthCheckResolver is the optional dependency HealthHandler uses to enrich
// the /v1/auth/check response with the caller's standing roles and
// effective permission set. The auth handler's /v1/auth/me endpoint
// returns the same shape; we duplicate it here so the GUI can render the
// auth gate from a single round-trip on app boot. main.go wires this
// from the same authsvc.ActorRoleService used by AuthHandler; tests pass
// nil and AuthCheck degrades to the legacy minimal payload.
//
// Bundle 1 Phase 3 closure (M1): pre-closure, /v1/auth/check returned
// only {status, user, admin}. The GUI had to second-fetch /v1/auth/me to
// know which buttons to render — and Me is gated by the rbacGate on
// auth.role.list which the GUI's pre-render path may not yet hold (chicken-
// and-egg with the role-list affordance). Folding the same payload into
// AuthCheck keeps the GUI's boot path single-shot.
type AuthCheckResolver interface {
	// ListRoles returns the actor's standing role grants.
	ListRoles(ctx context.Context, actorID string, actorType domain.ActorType, tenantID string) ([]*authdomain.ActorRole, error)
	// EffectivePermissions returns the deduplicated (perm, scope) triples
	// the actor holds across all of its roles.
	EffectivePermissions(ctx context.Context, actorID string, actorType domain.ActorType, tenantID string) ([]repository.EffectivePermission, error)
}

// HealthHandler handles health and readiness check endpoints.
//
// Bundle-5 / Audit H-006 / CWE-754 (Improper Check for Unusual or
// Exceptional Conditions): pre-Bundle-5, both /health and /ready returned
// 200 unconditionally with no DB probe. A Kubernetes readinessProbe pointed
// at /ready would succeed even when the control plane was disconnected from
// Postgres, masking outages and routing user traffic to a broken instance.
//
// Post-Bundle-5 contract:
//
//	GET /health  → 200 always (process alive — liveness signal). No DB probe.
//	             k8s liveness probe: do NOT restart pod for DB hiccups.
//	GET /ready   → 200 if db.PingContext(2s) succeeds; 503 +
//	             {"status":"db_unavailable","error":"..."} if it fails.
//	             k8s readiness probe: drain pod when DB unreachable.
//
// The handler accepts a nullable DB pool. When nil (test fixtures, or the
// rare deploy without a DB), Ready degrades to "no probe configured" and
// returns 200 with {"status":"ready","db":"not_configured"} — preserves
// backwards compat for callers that haven't wired the dependency yet.
//
// G-1 (P1): AuthType is one of "api-key" or "none" — see
// internal/config.AuthType / config.ValidAuthTypes() for the typed
// constants and the rationale for dropping "jwt" (no JWT middleware
// ships with certctl; operators who need JWT/OIDC front certctl with
// an authenticating gateway and set AuthType="none" on the upstream).
type HealthHandler struct {
	AuthType string // "api-key" or "none" (see config.AuthType constants)

	// DB is the database pool used by Ready for connectivity probing.
	// May be nil (test fixtures / no-db deploys); Ready degrades gracefully.
	DB *sql.DB

	// ReadyProbeTimeout is the per-probe ceiling for the DB ping. Defaults
	// to 2s when zero. Exposed so tests can shorten it.
	ReadyProbeTimeout time.Duration

	// AuthCheck (M1) — optional. When set, AuthCheck includes the caller's
	// standing roles + effective permissions in the response so the GUI
	// can gate affordances from a single fetch. Nil resolver degrades to
	// the legacy {status, user, admin} payload (preserves test fixtures
	// and the no-db deploy path).
	Resolver AuthCheckResolver

	// OIDCProvidersResolver (Bundle 2 Phase 6 / Category E) — optional.
	// When set, AuthInfo additionally returns the list of configured
	// OIDC providers (id, display_name, login_url) so the GUI Login
	// page can render the correct buttons. Wired in cmd/server/main.go
	// from the postgres OIDCProviderRepository. The endpoint stays
	// auth-exempt; the providers list is public configuration (provider
	// name + IdP URL — same info present in the IdP's discovery doc).
	// Nil resolver preserves the pre-Phase-6 minimal payload shape so
	// existing test fixtures + no-db deploys keep compiling.
	OIDCProvidersResolver OIDCProvidersListResolver
}

// OIDCProvidersListResolver is the slice of repository.OIDCProviderRepository
// the AuthInfo handler consumes for the Phase 6 GUI-facing providers
// list. Defining the projection here keeps the handler decoupled from
// the wider repo surface.
type OIDCProvidersListResolver interface {
	List(ctx context.Context, tenantID string) ([]*OIDCProviderInfo, error)
}

// OIDCProviderInfo is the minimal public-safe payload returned by
// AuthInfo for each configured OIDC provider. The login_url is the
// `/auth/oidc/login?provider=<id>` redirect target the GUI navigates
// to when the user clicks the corresponding "Sign in with X" button.
type OIDCProviderInfo struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	LoginURL    string `json:"login_url"`
}

// NewHealthHandler creates a new HealthHandler.
//
// Bundle-5 / H-006: db may be nil (test fixtures + no-db deploys). When nil,
// Ready returns 200 with {"db":"not_configured"} — preserves backwards
// compatibility for the call sites that haven't wired the dependency yet.
// Production main.go always passes a non-nil pool.
//
// Bundle 1 Phase 3 closure (M1): the resolver is wired separately via
// HealthHandler.Resolver after construction so existing call sites
// (legacy tests, no-db deploys) keep compiling without churn.
func NewHealthHandler(authType string, db *sql.DB) HealthHandler {
	return HealthHandler{
		AuthType:          authType,
		DB:                db,
		ReadyProbeTimeout: 2 * time.Second,
	}
}

// Health responds with a simple health check indicating the service is alive.
// GET /health
//
// Bundle-5 / H-006: shallow on purpose — k8s liveness probe should NOT
// restart the pod when Postgres is degraded. Use /ready for readiness.
func (h HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]string{
		"status": "healthy",
	}

	JSON(w, http.StatusOK, response)
}

// Ready responds with readiness status, indicating whether the service is
// ready to handle requests.
// GET /ready
//
// Bundle-5 / H-006: deep probe via db.PingContext with a 2-second ceiling.
// Returns 503 + {"status":"db_unavailable","error":"<sanitized>"} when the
// DB is unreachable so k8s drains the pod. Returns 200 when ping succeeds
// or when no DB pool is wired (test/no-db deploys).
func (h HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.DB == nil {
		// No DB wired (test fixture or no-db deploy). Don't fail the probe;
		// surface the state for operator visibility.
		JSON(w, http.StatusOK, map[string]string{
			"status": "ready",
			"db":     "not_configured",
		})
		return
	}

	timeout := h.ReadyProbeTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	if err := h.DB.PingContext(ctx); err != nil {
		// 503 is the correct readiness-failure status — k8s will drain
		// traffic but won't tear down the pod (that's liveness's job).
		JSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "db_unavailable",
			"error":  err.Error(),
		})
		return
	}

	JSON(w, http.StatusOK, map[string]string{
		"status": "ready",
		"db":     "reachable",
	})
}

// AuthInfo responds with the server's authentication configuration.
// This lets the GUI know whether to show a login screen.
// GET /api/v1/auth/info (served without auth middleware)
//
// Bundle 2 Phase 6 / Category E: when h.OIDCProvidersResolver is wired,
// the response is extended with the list of configured OIDC providers
// (id, display_name, login_url) so the GUI's Login page can render the
// correct "Sign in with X" buttons. The endpoint stays auth-exempt;
// the providers list is public configuration. Resolver lookups are
// best-effort: failures fall back to the minimal payload rather than
// 500-ing the GUI's auth probe.
func (h HealthHandler) AuthInfo(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"auth_type": h.AuthType,
		"required":  h.AuthType != "none",
	}
	if h.OIDCProvidersResolver != nil {
		// Audit 2026-05-10 MED-9 closure — the adapter
		// (cmd/server/main.go::oidcProvidersListAdapter.List) filters
		// disabled providers before constructing OIDCProviderInfo, so
		// the LoginPage never sees a button for an offline IdP. The
		// HandleAuthRequest service-layer ErrProviderDisabled check
		// is the defense-in-depth guard for direct API / MCP / CLI
		// callers that bypass the GUI.
		if provs, err := h.OIDCProvidersResolver.List(r.Context(), authdomain.DefaultTenantID); err == nil {
			response["oidc_providers"] = provs
		}
	}
	JSON(w, http.StatusOK, response)
}

// AuthCheck returns 200 if the request has valid auth credentials, along with
// the resolved named-key identity and admin flag so the GUI can gate
// admin-only affordances (e.g., the bulk-revoke button).
//
// M-003 (Phase B.4): surface the admin flag so the frontend hides affordances
// that would otherwise 403 at the server. This is a hint for UX only —
// authorization remains enforced at the handler layer (bulk_revocation.go).
//
// Bundle 1 Phase 3 closure (M1): when HealthHandler.Resolver is wired,
// the response is enriched with the caller's standing roles and effective
// permissions. This mirrors the /v1/auth/me payload but lives on /auth/check
// so the GUI can gate affordance rendering with a single fetch on app
// boot. Resolver lookups are best-effort: failures fall back to the
// legacy minimal payload rather than 500-ing the GUI's auth probe.
//
// The auth middleware runs before this handler, so reaching here means auth
// passed. `user` falls back to an empty string when auth is disabled
// (CERTCTL_AUTH_TYPE=none).
// GET /api/v1/auth/check
func (h HealthHandler) AuthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	response := map[string]interface{}{
		"status": "authenticated",
		"user":   auth.GetUser(ctx),
		"admin":  auth.IsAdmin(ctx),
	}

	if h.Resolver != nil {
		actorID, _ := ctx.Value(auth.ActorIDKey{}).(string)
		actorType, _ := ctx.Value(auth.ActorTypeKey{}).(string)
		tenantID, _ := ctx.Value(auth.TenantIDKey{}).(string)
		if tenantID == "" {
			tenantID = authdomain.DefaultTenantID
		}
		if actorID != "" && actorType != "" {
			at := domain.ActorType(actorType)
			roles, rerr := h.Resolver.ListRoles(ctx, actorID, at, tenantID)
			perms, perr := h.Resolver.EffectivePermissions(ctx, actorID, at, tenantID)
			if rerr == nil && perr == nil {
				roleIDs := make([]string, 0, len(roles))
				hasAdmin := false
				for _, role := range roles {
					roleIDs = append(roleIDs, role.RoleID)
					if role.RoleID == authdomain.RoleIDAdmin {
						hasAdmin = true
					}
				}
				permPayload := make([]map[string]interface{}, 0, len(perms))
				for _, p := range perms {
					entry := map[string]interface{}{
						"permission": p.PermissionName,
						"scope_type": string(p.ScopeType),
					}
					if p.ScopeID != nil {
						entry["scope_id"] = *p.ScopeID
					}
					permPayload = append(permPayload, entry)
				}
				response["actor_id"] = actorID
				response["actor_type"] = actorType
				response["tenant_id"] = tenantID
				response["roles"] = roleIDs
				response["effective_permissions"] = permPayload
				// Authoritative admin signal: the standing-roles list. The
				// legacy `admin` boolean above is preserved for back-compat
				// (in-handler IsAdmin for non-rbacGate routes), but the
				// rbacGate-gated routes now key off effective_permissions.
				response["admin_via_role"] = hasAdmin
			}
		}
	}

	JSON(w, http.StatusOK, response)
}
