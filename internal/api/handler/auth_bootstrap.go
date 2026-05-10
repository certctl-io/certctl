package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/certctl-io/certctl/internal/auth/bootstrap"
)

// BootstrapHandler exposes the Bundle 1 Phase 6 day-0 admin path.
//
// Threat model (from cowork/auth-bundle-1-prompt.md): the control
// plane comes up with no admin actors. The operator hands the
// CERTCTL_BOOTSTRAP_TOKEN to a single curl call; the server mints
// the first admin key and locks the door. No subsequent invocation
// can mint another admin via this path — the strategy state and the
// "admin already exists" probe both close it. After bootstrap the
// operator manages keys via /v1/auth/keys/...
//
// Handler shape:
//
//	GET  /v1/auth/bootstrap          → 200 {available:true|false}
//	POST /v1/auth/bootstrap          → 201 {api_key, key_value, actor_id}
//
// The GET surface is intentionally probable from any caller; it
// returns availability (no token, no admin probe) so the GUI and the
// install one-liner can decide whether to render the bootstrap
// affordance. The POST surface requires the bootstrap token and
// returns the plaintext key value once.
type BootstrapHandler struct {
	svc *bootstrap.Service
}

// NewBootstrapHandler constructs a BootstrapHandler. svc may be nil
// to disable both methods (handler returns 410 Gone on every call).
func NewBootstrapHandler(svc *bootstrap.Service) BootstrapHandler {
	return BootstrapHandler{svc: svc}
}

type bootstrapAvailableResponse struct {
	Available bool `json:"available"`
}

type bootstrapRequest struct {
	Token     string `json:"token"`
	ActorName string `json:"actor_name"`
}

type bootstrapResponse struct {
	ActorID   string `json:"actor_id"`
	APIKeyID  string `json:"api_key_id"`
	KeyValue  string `json:"key_value"`
	CreatedAt string `json:"created_at"`
	Message   string `json:"message"`
}

// Available is the GET probe. Returns {available: true} when the
// strategy is callable AND no admin actors exist; otherwise {available:
// false}. The endpoint never reveals the bootstrap token's existence
// independently of admin actor state — the GUI uses this to decide
// whether to render the "first-time setup" wizard.
func (h BootstrapHandler) Available(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	available := false
	if h.svc != nil {
		ok, err := h.svc.Available(r.Context())
		if err == nil {
			available = ok
		}
	}
	JSON(w, http.StatusOK, bootstrapAvailableResponse{Available: available})
}

// Mint is the POST handler that consumes the token + creates the
// first admin key.
//
// Status mapping:
//
//	410 Gone        → strategy disabled (no token, admin exists, or one-shot already consumed)
//	401 Unauthorized → token mismatch
//	400 Bad Request  → invalid actor_name
//	201 Created     → key minted; response carries the plaintext key value
func (h BootstrapHandler) Mint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if h.svc == nil {
		// No service wired = endpoint disabled. Same status as the
		// "already consumed" path so callers can't differentiate
		// configuration from state.
		Error(w, http.StatusGone, "bootstrap endpoint disabled")
		return
	}
	var body bootstrapRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		Error(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	body.ActorName = strings.TrimSpace(body.ActorName)
	result, err := h.svc.ValidateAndMint(r.Context(), body.Token, body.ActorName)
	if err != nil {
		switch {
		case errors.Is(err, bootstrap.ErrDisabled):
			Error(w, http.StatusGone, "bootstrap endpoint disabled")
		case errors.Is(err, bootstrap.ErrInvalidToken):
			Error(w, http.StatusUnauthorized, "Invalid bootstrap token")
		case errors.Is(err, bootstrap.ErrInvalidActorName):
			Error(w, http.StatusBadRequest, "Invalid actor_name (3-64 chars, lowercase alnum + - + _)")
		default:
			Error(w, http.StatusInternalServerError, "Bootstrap failed")
		}
		return
	}
	JSON(w, http.StatusCreated, bootstrapResponse{
		ActorID:   result.APIKey.Name,
		APIKeyID:  result.APIKey.ID,
		KeyValue:  result.KeyValue,
		CreatedAt: result.APIKey.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		Message:   "Admin API key created. This is the only time the key value is shown — capture it now.",
	})
}
