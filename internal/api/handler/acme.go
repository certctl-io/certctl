// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/shankar0123/certctl/internal/api/acme"
	"github.com/shankar0123/certctl/internal/service"
)

// ACMEService is the handler-facing surface for the ACME server. The
// service-layer concrete type is *service.ACMEService; the interface
// definition lives here to keep the handler import-direction
// canonical (handler imports service, not the reverse). Phase 1a
// pins two methods; Phase 1b extends with VerifyJWS, NewAccount,
// LookupAccount, UpdateAccount, DeactivateAccount.
type ACMEService interface {
	BuildDirectory(ctx context.Context, profileID, baseURL string) (*acme.Directory, error)
	IssueNonce(ctx context.Context) (string, error)
}

// ACMEHandler exposes the ACME server's RFC 8555 endpoints under the
// per-profile path /acme/profile/<id>/* and (optionally) the
// /acme/* shorthand when CERTCTL_ACME_SERVER_DEFAULT_PROFILE_ID is
// set. Phase 1a wires:
//
//   - GET  /acme/profile/{id}/directory
//   - HEAD /acme/profile/{id}/new-nonce
//   - GET  /acme/profile/{id}/new-nonce
//   - GET  /acme/directory     (shorthand)
//   - HEAD /acme/new-nonce     (shorthand)
//   - GET  /acme/new-nonce     (shorthand)
//
// Phase 1b adds new-account + account/<id>; Phase 2 adds new-order +
// order/<id>(/finalize) + authz/<id> + cert/<id>; Phase 3 adds
// challenge/<id>; Phase 4 adds key-change + revoke-cert + renewal-info.
//
// Handler shape mirrors internal/api/handler/scep.go:73-91 (struct
// holding the service interface, factory function returning the
// struct value).
type ACMEHandler struct {
	svc ACMEService
}

// NewACMEHandler constructs an ACMEHandler. Returns the value (not a
// pointer) — same convention as NewSCEPHandler at scep.go:89.
func NewACMEHandler(svc ACMEService) ACMEHandler {
	return ACMEHandler{svc: svc}
}

// Directory handles GET requests to the directory URL. The Go 1.22+
// stdlib router parses the {id} path parameter via r.PathValue("id").
// When the path is /acme/directory (no profile in URL), PathValue
// returns ""; the service layer applies the
// CERTCTL_ACME_SERVER_DEFAULT_PROFILE_ID fallback (or returns
// userActionRequired if unset).
func (h ACMEHandler) Directory(w http.ResponseWriter, r *http.Request) {
	profileID := r.PathValue("id")
	baseURL := h.directoryBaseURL(r, profileID)

	dir, err := h.svc.BuildDirectory(r.Context(), profileID, baseURL)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	// RFC 8555 §6.5: every successful response carries Replay-Nonce.
	// The directory endpoint is not JWS-authenticated but ACME clients
	// expect the header so they can use it on the very next POST.
	if nonce, err := h.svc.IssueNonce(r.Context()); err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
	w.Header().Set("Cache-Control", "public, max-age=0, no-cache")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dir)
}

// NewNonce handles HEAD and GET on the new-nonce URL.
//
// RFC 8555 §7.2:
//   - HEAD MUST return 200 with Replay-Nonce + zero-length body.
//   - GET MUST return 204 No Content with Replay-Nonce + zero-length body.
//
// Both verbs MUST set Cache-Control: no-store so middleboxes don't
// inadvertently re-serve a stale nonce.
//
// We resolve the profile here (rather than passing it through the
// service) only to validate it exists — the nonce itself is global
// to the server (one acme_nonces table), but if the operator hits
// /acme/profile/<bogus>/new-nonce we return 404 so the path-shape
// failure is operator-visible.
func (h ACMEHandler) NewNonce(w http.ResponseWriter, r *http.Request) {
	profileID := r.PathValue("id")
	// Same profile-resolution path as Directory — go through
	// BuildDirectory only to leverage its profile-not-found / user-
	// action-required mapping. The directory document is not used.
	baseURL := h.directoryBaseURL(r, profileID)
	if _, err := h.svc.BuildDirectory(r.Context(), profileID, baseURL); err != nil {
		writeServiceError(w, err)
		return
	}

	nonce, err := h.svc.IssueNonce(r.Context())
	if err != nil {
		acme.WriteProblem(w, acme.ServerInternal("nonce issuance failed"))
		return
	}

	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// directoryBaseURL composes the per-profile base URL the directory's
// inner URLs are built against. The composition lives in the handler
// (NOT the service) because it depends on the inbound request's
// scheme + host + observed path; the service layer would need to
// import net/http to do this.
//
// For requests on /acme/profile/<id>/* we strip the trailing path
// element to produce the base. For shorthand /acme/* requests we
// strip the trailing element from /acme — the result is just the
// scheme://host/acme prefix, which the service then uses to build
// /acme/new-nonce, /acme/new-account, etc.
func (h ACMEHandler) directoryBaseURL(r *http.Request, profileID string) string {
	scheme := "https"
	if r.TLS == nil {
		// HTTPS-only architecture decision (CLAUDE.md): the listener
		// is TLS 1.3 pinned. r.TLS == nil only happens in tests with
		// httptest.NewServer (non-TLS); honor http: for those.
		scheme = "http"
	}
	if profileID != "" {
		return scheme + "://" + r.Host + "/acme/profile/" + profileID
	}
	return scheme + "://" + r.Host + "/acme"
}

// writeServiceError maps service-layer sentinels to RFC 7807 + RFC
// 8555 §6.7 problem responses. Centralized so every handler method
// gets identical mapping; future Phase 1b/2/3/4 sentinels extend
// the switch.
func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrACMEUserActionRequired):
		acme.WriteProblem(w, acme.UserActionRequired(
			"this server requires the per-profile path /acme/profile/<id>/* — "+
				"set CERTCTL_ACME_SERVER_DEFAULT_PROFILE_ID for /acme/* shorthand"))
	case errors.Is(err, service.ErrACMEProfileNotFound):
		acme.WriteProblem(w, acme.Problem{
			Type:   "urn:ietf:params:acme:error:userActionRequired",
			Detail: "profile not found",
			Status: http.StatusNotFound,
		})
	default:
		// Avoid leaking internal error text per master-prompt
		// criterion #10 (operator-actionable errors with no info
		// leak). The detail is operator-facing but generic.
		acme.WriteProblem(w, acme.ServerInternal("ACME server error"))
	}
}
