package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/certctl-io/certctl/internal/auth"
	"github.com/certctl-io/certctl/internal/domain"
	authdomain "github.com/certctl-io/certctl/internal/domain/auth"
)

// DemoResidualCleanupFn deletes every live actor_roles row for the
// synthetic actor-demo-anon and returns the count removed. Provided by
// cmd/server/main.go which holds the *sql.DB. Returning an error from
// this func surfaces as HTTP 500; returning (0, nil) is the legitimate
// "nothing to clean up" idempotent response.
type DemoResidualCleanupFn func(ctx context.Context) (int64, error)

// DemoResidualHandler exposes POST /api/v1/auth/demo-residual/cleanup —
// an admin-gated convenience endpoint that removes residual
// actor-demo-anon role grants from a deployment that previously ran
// CERTCTL_AUTH_TYPE=none (or any deployment, since migration 000029
// seeds the row unconditionally). Audit 2026-05-11 A-8 closure.
//
// The endpoint refuses to run when the server is currently in demo
// mode (Auth.Type == "none") because the residual IS the active
// runtime state at that auth type; deleting it would break the demo
// path. The 503 response makes the constraint observable to the GUI.
type DemoResidualHandler struct {
	cleanup     DemoResidualCleanupFn
	authType    func() string
	auditWriter AuditWriter
}

// AuditWriter is the minimal projection of *service.AuditService that
// the DemoResidualHandler uses. Kept local to avoid pulling the full
// service package into the handler's import set.
type AuditWriter interface {
	RecordEventWithCategory(
		ctx context.Context, actor string, actorType domain.ActorType,
		action, eventCategory, resourceType, resourceID string,
		details map[string]interface{},
	) error
}

// NewDemoResidualHandler wires the cleanup function and auth-type
// getter. authType is a closure so the handler always sees the
// live config value (post-startup mutation is unsupported, but
// the closure pattern keeps the dependency direction clean).
func NewDemoResidualHandler(
	cleanup DemoResidualCleanupFn,
	authType func() string,
	audit AuditWriter,
) DemoResidualHandler {
	return DemoResidualHandler{
		cleanup:     cleanup,
		authType:    authType,
		auditWriter: audit,
	}
}

// demoResidualCleanupResponse is the JSON body returned by POST
// /api/v1/auth/demo-residual/cleanup. Removed is the count of
// actor_roles rows that were live for actor-demo-anon at the time
// of the call. Always present; idempotent calls return removed=0.
type demoResidualCleanupResponse struct {
	Removed int64 `json:"removed"`
}

// Cleanup handles POST /api/v1/auth/demo-residual/cleanup. RBAC-gated
// at the router via auth.role.assign (the admin-class permission).
// Rejects requests when the server is in demo mode (Auth.Type=none)
// with HTTP 503. Emits an audit row recording the count removed +
// the caller actor on every successful run.
func (h DemoResidualHandler) Cleanup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.cleanup == nil {
		_ = Error(w, http.StatusInternalServerError, "demo-residual cleanup not configured")
		return
	}

	authType := ""
	if h.authType != nil {
		authType = h.authType()
	}
	if authType == "none" {
		// Refusing to "clean up" the active demo-mode state. The
		// GUI surface should hide the button when /api/v1/auth/info
		// reports auth_type=none; this guard is defense-in-depth.
		_ = Error(w, http.StatusServiceUnavailable,
			"demo-residual cleanup refused: server is currently in demo mode (CERTCTL_AUTH_TYPE=none); the actor-demo-anon grants are the active runtime state at this auth type")
		return
	}

	removed, err := h.cleanup(ctx)
	if err != nil {
		_ = Error(w, http.StatusInternalServerError, "demo-residual cleanup failed")
		return
	}

	// Audit row records the count removed + the caller. The actor is
	// pulled from the request context (set by the auth middleware
	// chain after the rbacGate at the router level has authorized).
	if h.auditWriter != nil {
		actorID, _ := r.Context().Value(auth.ActorIDKey{}).(string)
		if actorID == "" {
			actorID = "unknown"
		}
		actorTypeRaw, _ := r.Context().Value(auth.ActorTypeKey{}).(string)
		actorType := domain.ActorType(actorTypeRaw)
		if actorType == "" {
			actorType = domain.ActorTypeAPIKey
		}
		_ = h.auditWriter.RecordEventWithCategory(
			ctx, actorID, actorType,
			"auth.demo_residual_grants_cleaned",
			domain.EventCategoryAuth,
			"actor_roles", authdomain.DemoAnonActorID,
			map[string]interface{}{"removed": removed},
		)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(demoResidualCleanupResponse{Removed: removed})
}

// ErrDemoResidualNotConfigured is returned by callers that probe the
// handler's wiring state. Currently unused outside tests but exported
// to keep the contract observable for documentation purposes.
var ErrDemoResidualNotConfigured = errors.New("demo-residual cleanup not configured")
