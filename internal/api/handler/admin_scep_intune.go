package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/service"
)

// AdminSCEPIntuneService is the slice of the per-profile SCEPService set
// the admin endpoint needs. The handler depends on this narrow interface
// rather than the concrete *service.SCEPService set so wiring stays
// service-side and the handler stays test-friendly.
//
// SCEP RFC 8894 + Intune master bundle Phase 9.1, extended in the
// Phase 9 follow-up (cowork/scep-gui-restructure-prompt.md) with
// Profiles for the per-profile SCEP Administration tab.
type AdminSCEPIntuneService interface {
	// Stats returns one snapshot per configured SCEP profile (Intune-
	// enabled or not) in the Phase 9.1 flat shape. Backward-compat for
	// the existing /admin/scep/intune/stats endpoint.
	Stats(ctx context.Context, now time.Time) ([]service.IntuneStatsSnapshot, error)

	// Profiles returns one snapshot per configured SCEP profile in the
	// new shape (always-present per-profile fields + optional Intune
	// sub-block). Backs the new /admin/scep/profiles endpoint.
	Profiles(ctx context.Context, now time.Time) ([]service.SCEPProfileStatsSnapshot, error)

	// ReloadTrust triggers the SIGHUP-equivalent Reload on the named
	// profile's trust holder. Returns ErrAdminSCEPProfileNotFound if
	// the PathID isn't known, or ErrSCEPProfileIntuneDisabled if the
	// profile exists but doesn't have Intune turned on, or the
	// underlying parse error from intune.LoadTrustAnchor on a bad
	// reload (the holder retains the OLD pool either way — the
	// fail-safe is enforced one layer down).
	ReloadTrust(ctx context.Context, pathID string) error
}

// ErrAdminSCEPProfileNotFound is returned by AdminSCEPIntuneService
// implementations when the operator targets a PathID that doesn't map
// to any configured profile. The handler maps this to HTTP 404.
var ErrAdminSCEPProfileNotFound = errors.New("admin scep intune: profile not found for the given path_id")

// AdminSCEPIntuneHandler serves the per-profile SCEP observability
// endpoints for the GUI SCEP Administration page.
//
// Endpoints:
//
//	GET  /api/v1/admin/scep/profiles                — Phase 9 follow-up
//	GET  /api/v1/admin/scep/intune/stats            — Phase 9.2
//	POST /api/v1/admin/scep/intune/reload-trust     — Phase 9.2 (JSON body: {"path_id": "corp"})
//
// All three endpoints are admin-gated (M-008 pattern). Non-admin Bearer
// callers get 403 — the stats endpoint reveals the operator's profile
// set + trust anchor expiries (sensitive operational metadata), the
// profiles endpoint additionally reveals RA cert expiries + mTLS bundle
// paths, and the reload endpoint is a privileged action.
type AdminSCEPIntuneHandler struct {
	svc AdminSCEPIntuneService
}

// NewAdminSCEPIntuneHandler creates a new admin handler.
func NewAdminSCEPIntuneHandler(svc AdminSCEPIntuneService) AdminSCEPIntuneHandler {
	return AdminSCEPIntuneHandler{svc: svc}
}

// adminScepIntuneReloadRequest is the POST body shape for the reload-
// trust endpoint. PathID="" targets the legacy /scep root profile (the
// one with empty PathID), matching the convention used elsewhere in the
// per-profile dispatch.
type adminScepIntuneReloadRequest struct {
	PathID string `json:"path_id"`
}

// Profiles handles GET /api/v1/admin/scep/profiles.
//
// Phase 9 follow-up endpoint backing the SCEP Administration page's
// Profiles tab. Returns one snapshot per configured SCEP profile in
// the SCEPProfileStatsSnapshot shape (always-present per-profile
// fields + optional Intune sub-block).
//
// Same M-008 admin gate as Stats. Profiles where Intune is disabled
// appear with Intune=null in the response.
func (h AdminSCEPIntuneHandler) Profiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !middleware.IsAdmin(r.Context()) {
		Error(w, http.StatusForbidden, "Admin access required")
		return
	}

	now := time.Now()
	rows, err := h.svc.Profiles(r.Context(), now)
	if err != nil {
		Error(w, http.StatusInternalServerError, "Failed to read SCEP profiles")
		return
	}
	if rows == nil {
		// Avoid serialising as `null` — the GUI expects an array.
		rows = []service.SCEPProfileStatsSnapshot{}
	}
	_ = JSON(w, http.StatusOK, map[string]any{
		"profiles":      rows,
		"profile_count": len(rows),
		"generated_at":  now.UTC(),
	})
}

// Stats handles GET /api/v1/admin/scep/intune/stats.
func (h AdminSCEPIntuneHandler) Stats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !middleware.IsAdmin(r.Context()) {
		Error(w, http.StatusForbidden, "Admin access required")
		return
	}

	now := time.Now()
	rows, err := h.svc.Stats(r.Context(), now)
	if err != nil {
		Error(w, http.StatusInternalServerError, "Failed to read SCEP Intune stats")
		return
	}
	if rows == nil {
		// Avoid serialising as `null` — the GUI expects an array.
		rows = []service.IntuneStatsSnapshot{}
	}
	_ = JSON(w, http.StatusOK, map[string]any{
		"profiles":      rows,
		"profile_count": len(rows),
		"generated_at":  now.UTC(),
	})
}

// ReloadTrust handles POST /api/v1/admin/scep/intune/reload-trust.
func (h AdminSCEPIntuneHandler) ReloadTrust(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !middleware.IsAdmin(r.Context()) {
		Error(w, http.StatusForbidden, "Admin access required")
		return
	}

	var body adminScepIntuneReloadRequest
	// An empty body is permitted: it implicitly targets the legacy
	// /scep root profile (PathID=""). Operators with multi-profile
	// deploys MUST supply a path_id JSON field.
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			Error(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
			return
		}
	}

	err := h.svc.ReloadTrust(r.Context(), body.PathID)
	switch {
	case err == nil:
		_ = JSON(w, http.StatusOK, map[string]any{
			"reloaded":    true,
			"path_id":     body.PathID,
			"reloaded_at": time.Now().UTC(),
		})
	case errors.Is(err, ErrAdminSCEPProfileNotFound):
		Error(w, http.StatusNotFound, "SCEP profile not found for path_id="+body.PathID)
	case errors.Is(err, service.ErrSCEPProfileIntuneDisabled):
		// 409 Conflict: the profile exists but Intune isn't turned on,
		// so there's no trust anchor to reload. Distinct from 404 so
		// the operator can correct the request without re-checking the
		// profile list.
		Error(w, http.StatusConflict, "SCEP profile path_id="+body.PathID+" does not have Intune enabled")
	default:
		// Underlying intune.LoadTrustAnchor errors (parse failure,
		// expired cert, missing file). The holder retains its previous
		// pool — the operator's enrollments keep working off the old
		// trust anchor while the operator fixes the file.
		Error(w, http.StatusInternalServerError, "Trust anchor reload failed: "+err.Error())
	}
}

// AdminSCEPIntuneServiceImpl is the production implementation of
// AdminSCEPIntuneService. It walks the per-profile SCEPService set
// supplied by the caller (cmd/server/main.go) and aggregates the
// per-profile snapshots.
//
// Lives in the handler package because it's a thin handler-side
// composition; the heavy lifting is the per-service IntuneStats /
// ReloadIntuneTrust methods that already encapsulate the policy.
type AdminSCEPIntuneServiceImpl struct {
	// services is keyed by SCEP profile PathID (empty string = legacy
	// /scep root). Built once at server startup; the slice/map shape
	// matches the per-profile SCEPService construction loop in
	// cmd/server/main.go.
	services map[string]*service.SCEPService
}

// NewAdminSCEPIntuneServiceImpl constructs the handler-side service
// from the per-profile SCEPService map built at startup.
func NewAdminSCEPIntuneServiceImpl(services map[string]*service.SCEPService) *AdminSCEPIntuneServiceImpl {
	if services == nil {
		services = map[string]*service.SCEPService{}
	}
	return &AdminSCEPIntuneServiceImpl{services: services}
}

// Stats implements AdminSCEPIntuneService.
func (s *AdminSCEPIntuneServiceImpl) Stats(_ context.Context, now time.Time) ([]service.IntuneStatsSnapshot, error) {
	out := make([]service.IntuneStatsSnapshot, 0, len(s.services))
	for _, svc := range s.services {
		out = append(out, svc.IntuneStats(now))
	}
	return out, nil
}

// Profiles implements AdminSCEPIntuneService for the new
// /admin/scep/profiles endpoint. Walks the same per-profile SCEPService
// map but emits the SCEPProfileStatsSnapshot shape (always-present
// fields + optional Intune sub-block).
func (s *AdminSCEPIntuneServiceImpl) Profiles(_ context.Context, now time.Time) ([]service.SCEPProfileStatsSnapshot, error) {
	out := make([]service.SCEPProfileStatsSnapshot, 0, len(s.services))
	for _, svc := range s.services {
		out = append(out, svc.ProfileStats(now))
	}
	return out, nil
}

// ReloadTrust implements AdminSCEPIntuneService.
func (s *AdminSCEPIntuneServiceImpl) ReloadTrust(_ context.Context, pathID string) error {
	svc, ok := s.services[pathID]
	if !ok {
		return ErrAdminSCEPProfileNotFound
	}
	return svc.ReloadIntuneTrust()
}

// Compile-time interface check.
var _ AdminSCEPIntuneService = (*AdminSCEPIntuneServiceImpl)(nil)
