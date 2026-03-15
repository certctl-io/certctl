package handler

import (
	"net/http"
)

// HealthHandler handles health and readiness check endpoints.
type HealthHandler struct {
	AuthType string // "api-key", "jwt", "none"
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

// AuthCheck returns 200 if the request has valid auth credentials.
// The auth middleware runs before this handler, so reaching here means auth passed.
// GET /api/v1/auth/check
func (h HealthHandler) AuthCheck(w http.ResponseWriter, r *http.Request) {
	JSON(w, http.StatusOK, map[string]string{"status": "authenticated"})
}
