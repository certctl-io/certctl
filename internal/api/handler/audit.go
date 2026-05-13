// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certctl-io/certctl/internal/api/middleware"
	"github.com/certctl-io/certctl/internal/auth"
	"github.com/certctl-io/certctl/internal/domain"
)

// AuditService defines the service interface for audit event operations.
type AuditService interface {
	ListAuditEvents(ctx context.Context, page, perPage int) ([]domain.AuditEvent, int64, error)
	GetAuditEvent(ctx context.Context, id string) (*domain.AuditEvent, error)
	// ListAuditEventsByCategory (Bundle 1 Phase 8) returns audit
	// rows whose event_category column matches eventCategory.
	// eventCategory is one of "cert_lifecycle", "auth", "config";
	// empty string returns all categories. Used by the auditor role
	// (filtered to "auth" via /v1/audit?category=auth).
	ListAuditEventsByCategory(ctx context.Context, eventCategory string, page, perPage int) ([]domain.AuditEvent, int64, error)
	// ExportEventsByFilter returns audit events matching a
	// (from, to, eventCategory) filter, capped at maxRows. Audit
	// 2026-05-10 HIGH-11 closure — backs the new
	// GET /api/v1/audit/export endpoint that makes the `audit.export`
	// permission load-bearing.
	ExportEventsByFilter(ctx context.Context, from, to time.Time, eventCategory string, maxRows int) ([]domain.AuditEvent, error)
	// RecordEventWithCategory is needed by the export handler so it
	// can recursively self-audit each export call (operator-visible
	// proof that compliance evidence pulls happened + by whom + over
	// what range). The bare-string actor type is the existing wire
	// shape used by every other Phase 8 caller.
	RecordEventWithCategory(ctx context.Context, actor string, actorType domain.ActorType, action, eventCategory, resourceType, resourceID string, details map[string]interface{}) error
}

// AuditHandler handles HTTP requests for audit event operations.
type AuditHandler struct {
	svc AuditService
}

// NewAuditHandler creates a new AuditHandler with a service dependency.
func NewAuditHandler(svc AuditService) AuditHandler {
	return AuditHandler{svc: svc}
}

// ListAuditEvents lists audit events.
// GET /api/v1/audit?page=1&per_page=50&category=auth
//
// Bundle 1 Phase 8 adds the optional `category` query parameter for
// auditor-role filtering. Allowed values: cert_lifecycle, auth, config.
// Unknown values surface 400 so misuse is caught loud (instead of
// silently returning all rows).
func (h AuditHandler) ListAuditEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	page := 1
	perPage := 50
	query := r.URL.Query()
	if p := query.Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if pp := query.Get("per_page"); pp != "" {
		if parsed, err := strconv.Atoi(pp); err == nil && parsed > 0 && parsed <= 500 {
			perPage = parsed
		}
	}
	category := query.Get("category")
	if category != "" {
		switch category {
		case domain.EventCategoryCertLifecycle, domain.EventCategoryAuth, domain.EventCategoryConfig:
			// ok
		default:
			ErrorWithRequestID(w, http.StatusBadRequest,
				"Invalid category — allowed: cert_lifecycle, auth, config",
				requestID)
			return
		}
	}

	var (
		events []domain.AuditEvent
		total  int64
		err    error
	)
	if category != "" {
		events, total, err = h.svc.ListAuditEventsByCategory(r.Context(), category, page, perPage)
	} else {
		events, total, err = h.svc.ListAuditEvents(r.Context(), page, perPage)
	}
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to list audit events", requestID)
		return
	}

	response := PagedResponse{
		Data:    events,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	JSON(w, http.StatusOK, response)
}

// GetAuditEvent retrieves a single audit event by ID.
// GET /api/v1/audit/{id}
func (h AuditHandler) GetAuditEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/audit/")
	parts := strings.Split(id, "/")
	if len(parts) == 0 || parts[0] == "" {
		ErrorWithRequestID(w, http.StatusBadRequest, "Audit event ID is required", requestID)
		return
	}
	id = parts[0]

	event, err := h.svc.GetAuditEvent(r.Context(), id)
	if err != nil {
		ErrorWithRequestID(w, http.StatusNotFound, "Audit event not found", requestID)
		return
	}

	JSON(w, http.StatusOK, event)
}

// ExportAudit streams an NDJSON export of audit events for compliance
// evidence collection. Gated by the `audit.export` permission (already
// seeded into r-admin + r-auditor by migration 000031).
//
// Audit 2026-05-10 HIGH-11 closure — pre-fix, the permission existed
// in the catalogue + role grants but no endpoint enforced it; r-auditor's
// "audit.export" claim was misleading capability advertisement. This
// endpoint makes the permission load-bearing and the auditor role's
// surface complete.
//
// GET /api/v1/audit/export?from=<RFC3339>&to=<RFC3339>&category=<cat>
//
// Constraints:
//   - from + to are required, RFC3339 format.
//   - to - from MUST be ≤ 90 days (compliance window).
//   - category optional: cert_lifecycle | auth | config.
//   - max 50,000 rows per export (operator-tunable via query param
//     up to 100,000); larger exports require operator-side pagination
//     by date range.
//
// Response: application/x-ndjson, one event per line. Newline-delimited
// JSON is the de-facto compliance-archive format consumed by SIEMs
// (Splunk universal forwarder, Elastic Filebeat, Vector, etc.).
//
// The export itself is recursively audited: every successful export
// emits an `audit.export` event capturing actor, range, category, and
// row count so the audit log itself records who pulled which compliance
// evidence and when.
func (h AuditHandler) ExportAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	q := r.URL.Query()
	fromStr := q.Get("from")
	toStr := q.Get("to")
	if fromStr == "" || toStr == "" {
		ErrorWithRequestID(w, http.StatusBadRequest,
			"`from` and `to` query params are required (RFC3339 format)",
			requestID)
		return
	}
	from, err := time.Parse(time.RFC3339, fromStr)
	if err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest,
			"`from` must be RFC3339 (e.g. 2026-04-01T00:00:00Z)",
			requestID)
		return
	}
	to, err := time.Parse(time.RFC3339, toStr)
	if err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest,
			"`to` must be RFC3339 (e.g. 2026-05-01T00:00:00Z)",
			requestID)
		return
	}
	if !to.After(from) {
		ErrorWithRequestID(w, http.StatusBadRequest,
			"`to` must be after `from`",
			requestID)
		return
	}
	const maxWindow = 90 * 24 * time.Hour
	if to.Sub(from) > maxWindow {
		ErrorWithRequestID(w, http.StatusBadRequest,
			fmt.Sprintf("range exceeds 90-day max (got %s); paginate by narrower date range", to.Sub(from)),
			requestID)
		return
	}

	category := q.Get("category")
	if category != "" {
		switch category {
		case domain.EventCategoryCertLifecycle, domain.EventCategoryAuth, domain.EventCategoryConfig:
			// ok
		default:
			ErrorWithRequestID(w, http.StatusBadRequest,
				"Invalid category — allowed: cert_lifecycle, auth, config",
				requestID)
			return
		}
	}

	maxRows := 50000
	if lim := q.Get("limit"); lim != "" {
		if parsed, err := strconv.Atoi(lim); err == nil && parsed > 0 && parsed <= 100000 {
			maxRows = parsed
		}
	}

	events, err := h.svc.ExportEventsByFilter(r.Context(), from, to, category, maxRows)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError,
			"Failed to export audit events",
			requestID)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="certctl-audit-%s_to_%s.ndjson"`,
			from.UTC().Format("2006-01-02"), to.UTC().Format("2006-01-02")))
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	for i := range events {
		if err := enc.Encode(&events[i]); err != nil {
			// Mid-stream encode error — connection probably closed by
			// client. Logged + abandoned; the partial response is
			// already on the wire and rolling back the headers isn't
			// possible.
			slog.WarnContext(r.Context(), "audit export: encode failed mid-stream",
				"err", err, "rows_written", i, "rows_total", len(events))
			return
		}
	}

	// Recursively self-audit the export. The audit row captures actor,
	// from, to, category, and row count so compliance reviewers can see
	// who pulled which evidence and when. Best-effort (the data is
	// already on the wire); failure logs WARN per the HIGH-6 closure.
	actorID, _ := r.Context().Value(auth.ActorIDKey{}).(string)
	if actorID == "" {
		actorID = "unknown"
	}
	if err := h.svc.RecordEventWithCategory(r.Context(),
		actorID, domain.ActorTypeUser,
		"audit.export", domain.EventCategoryAuth,
		"audit", "export",
		map[string]interface{}{
			"from":     from.UTC().Format(time.RFC3339),
			"to":       to.UTC().Format(time.RFC3339),
			"category": category,
			"rows":     len(events),
		}); err != nil {
		slog.WarnContext(r.Context(), "audit.export self-audit failed (export already streamed)",
			"actor_id", actorID, "rows", len(events), "err", err)
	}
}
