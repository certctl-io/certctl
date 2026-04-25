package handler

import (
	"net/http"

	"github.com/shankar0123/certctl/internal/api/middleware"
)

// HealthHandler handles health and readiness check endpoints.
//
// G-1 (P1): AuthType is one of "api-key" or "none" — see
// internal/config.AuthType / config.ValidAuthTypes() for the typed
// constants and the rationale for dropping "jwt" (no JWT middleware
// ships with certctl; operators who need JWT/OIDC front certctl with
// an authenticating gateway and set AuthType="none" on the upstream).
type HealthHandler struct {
	AuthType string // "api-key" or "none" (see config.AuthType constants)
}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler(authType string) HealthHandler {
	return HealthHandler{AuthType: authType}
}

// Health responds with a simple health check indicating the service is alive.
// GET /health
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

// Ready responds with readiness status, indicating whether the service is ready to handle requests.
// GET /ready
func (h HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]string{
		"status": "ready",
	}

	JSON(w, http.StatusOK, response)
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
