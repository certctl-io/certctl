package handler

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/shankar0123/certctl/internal/api/middleware"
)

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
}

// NewHealthHandler creates a new HealthHandler.
//
// Bundle-5 / H-006: db may be nil (test fixtures + no-db deploys). When nil,
// Ready returns 200 with {"db":"not_configured"} — preserves backwards
// compatibility for the call sites that haven't wired the dependency yet.
// Production main.go always passes a non-nil pool.
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
func (h HealthHandler) AuthInfo(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"auth_type": h.AuthType,
		"required":  h.AuthType != "none",
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
// The auth middleware runs before this handler, so reaching here means auth
// passed. `user` falls back to an empty string when auth is disabled
// (CERTCTL_AUTH_TYPE=none).
// GET /api/v1/auth/check
func (h HealthHandler) AuthCheck(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status": "authenticated",
		"user":   middleware.GetUser(r.Context()),
		"admin":  middleware.IsAdmin(r.Context()),
	}
	JSON(w, http.StatusOK, response)
}
