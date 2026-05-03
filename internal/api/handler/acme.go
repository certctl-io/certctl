// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/shankar0123/certctl/internal/api/acme"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/service"
)

// MaxJWSBodyBytes caps the per-request JWS payload at 64 KiB. RFC 8555
// payloads are tiny (a JWK is < 1 KiB; a CSR < 4 KiB), so anything
// larger is either malformed or hostile. The router-level body-limit
// middleware already caps requests at the server-wide
// CERTCTL_MAX_BODY_SIZE (default 1 MiB), but ACME-specifically we
// tighten further.
const MaxJWSBodyBytes = 64 * 1024

// ACMEService is the handler-facing surface for the ACME server. The
// service-layer concrete type is *service.ACMEService; the interface
// definition lives here to keep the handler import-direction
// canonical (handler imports service, not the reverse).
type ACMEService interface {
	BuildDirectory(ctx context.Context, profileID, baseURL string) (*acme.Directory, error)
	IssueNonce(ctx context.Context) (string, error)
	// Phase 1b — JWS verification + account resource.
	VerifyJWS(ctx context.Context, body []byte, requestURL string, expectNewAccount bool, accountKID func(accountID string) string) (*acme.VerifiedRequest, error)
	NewAccount(ctx context.Context, profileID string, jwk *jose.JSONWebKey, contact []string, onlyReturnExisting bool, tosAgreed bool) (*domain.ACMEAccount, bool, error)
	LookupAccount(ctx context.Context, accountID string) (*domain.ACMEAccount, error)
	UpdateAccount(ctx context.Context, accountID string, contact []string) (*domain.ACMEAccount, error)
	DeactivateAccount(ctx context.Context, accountID string) (*domain.ACMEAccount, error)
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
// gets identical mapping; new sentinels extend the switch as later
// phases land.
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
	case errors.Is(err, service.ErrACMEAccountNotFound):
		acme.WriteProblem(w, acme.AccountDoesNotExist("account not found"))
	case errors.Is(err, service.ErrACMEAccountDoesNotExist):
		acme.WriteProblem(w, acme.AccountDoesNotExist(
			"no account exists for this JWK; submit a new-account request without onlyReturnExisting"))
	default:
		// Avoid leaking internal error text per master-prompt
		// criterion #10 (operator-actionable errors with no info
		// leak). The detail is operator-facing but generic.
		acme.WriteProblem(w, acme.ServerInternal("ACME server error"))
	}
}

// NewAccount handles POST /acme/profile/{id}/new-account (RFC 8555
// §7.3). The request body is a JWS with `jwk` (NOT `kid`) in the
// protected header — the verifier enforces this via
// ExpectNewAccount=true.
//
// Behavior matrix:
//   - JWK already registered + payload.OnlyReturnExisting=false →
//     200 + existing account row (idempotent re-registration per
//     RFC 8555 §7.3.1).
//   - JWK already registered + payload.OnlyReturnExisting=true →
//     same 200 + existing row.
//   - JWK new + OnlyReturnExisting=false → 201 + newly-created row.
//   - JWK new + OnlyReturnExisting=true → 400 + accountDoesNotExist.
func (h ACMEHandler) NewAccount(w http.ResponseWriter, r *http.Request) {
	profileID := r.PathValue("id")
	requestURL := h.requestURL(r)

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxJWSBodyBytes+1))
	if err != nil {
		acme.WriteProblem(w, acme.Malformed("could not read request body"))
		return
	}
	if len(body) > MaxJWSBodyBytes {
		acme.WriteProblem(w, acme.Malformed("request body too large"))
		return
	}

	verified, err := h.svc.VerifyJWS(r.Context(), body, requestURL, true /*expectNewAccount*/, h.accountKID(r, profileID))
	if err != nil {
		acme.WriteProblem(w, acme.MapJWSErrorToProblem(err))
		return
	}

	var req acme.NewAccountRequest
	if err := json.Unmarshal(verified.Payload, &req); err != nil {
		acme.WriteProblem(w, acme.Malformed("could not parse new-account payload"))
		return
	}

	acct, isNew, err := h.svc.NewAccount(
		r.Context(), profileID, verified.JWK, req.Contact,
		req.OnlyReturnExisting, req.TermsOfServiceAgreed,
	)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	if nonce, err := h.svc.IssueNonce(r.Context()); err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
	w.Header().Set("Location", h.accountKID(r, profileID)(acct.AccountID))
	w.Header().Set("Content-Type", "application/json")
	if isNew {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(
		acme.MarshalAccount(acct, h.accountOrdersURL(r, profileID, acct.AccountID)),
	)
}

// Account handles POST /acme/profile/{id}/account/{acc-id} (RFC 8555
// §7.3.2 + §7.3.6 + POST-as-GET per §6.3). The verifier requires
// `kid` (NOT `jwk`); the kid path-segment must match the URL
// path-segment.
//
// Payload variants:
//   - empty body or empty JSON {}: POST-as-GET; returns the account.
//   - {"contact": [...]}: contact update (RFC 8555 §7.3.2).
//   - {"status": "deactivated"}: deactivation (RFC 8555 §7.3.6).
//
// Mixing contact + status in one request is permitted; we apply
// status first (deactivation is the more conservative action).
func (h ACMEHandler) Account(w http.ResponseWriter, r *http.Request) {
	profileID := r.PathValue("id")
	urlAccountID := r.PathValue("acc_id")
	requestURL := h.requestURL(r)

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxJWSBodyBytes+1))
	if err != nil {
		acme.WriteProblem(w, acme.Malformed("could not read request body"))
		return
	}
	if len(body) > MaxJWSBodyBytes {
		acme.WriteProblem(w, acme.Malformed("request body too large"))
		return
	}

	verified, err := h.svc.VerifyJWS(r.Context(), body, requestURL, false /*expectNewAccount*/, h.accountKID(r, profileID))
	if err != nil {
		acme.WriteProblem(w, acme.MapJWSErrorToProblem(err))
		return
	}

	// kid path-segment must equal URL path-segment (defense in depth —
	// the verifier already round-tripped the kid against the canonical
	// URL).
	if verified.Account == nil || verified.Account.AccountID != urlAccountID {
		acme.WriteProblem(w, acme.Problem{
			Type:   "urn:ietf:params:acme:error:unauthorized",
			Detail: "kid does not match URL account id",
			Status: http.StatusUnauthorized,
		})
		return
	}

	var (
		updated  *domain.ACMEAccount
		readOnly bool
	)
	// Empty body or empty JSON object → POST-as-GET (§6.3).
	trimmed := trimBody(verified.Payload)
	if len(trimmed) == 0 || string(trimmed) == "{}" {
		readOnly = true
		updated = verified.Account
	} else {
		var req acme.AccountUpdateRequest
		if err := json.Unmarshal(verified.Payload, &req); err != nil {
			acme.WriteProblem(w, acme.Malformed("could not parse account update payload"))
			return
		}
		// Status transition first (the more conservative action).
		switch req.Status {
		case "":
			// no-op
		case "deactivated":
			acct, err := h.svc.DeactivateAccount(r.Context(), urlAccountID)
			if err != nil {
				writeServiceError(w, err)
				return
			}
			updated = acct
		default:
			acme.WriteProblem(w, acme.Malformed(
				"only `deactivated` is a valid status for account update; got "+req.Status))
			return
		}
		// Contact update.
		if req.Contact != nil {
			acct, err := h.svc.UpdateAccount(r.Context(), urlAccountID, req.Contact)
			if err != nil {
				writeServiceError(w, err)
				return
			}
			updated = acct
		}
		if updated == nil {
			// Empty status + nil contact → no-op; treat as POST-as-GET.
			updated = verified.Account
			readOnly = true
		}
	}

	if nonce, err := h.svc.IssueNonce(r.Context()); err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
	if readOnly {
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(
		acme.MarshalAccount(updated, h.accountOrdersURL(r, profileID, updated.AccountID)),
	)
}

// requestURL composes the full URL the JWS protected-header `url`
// MUST equal. Equivalent to scheme://host + r.URL.Path.
func (h ACMEHandler) requestURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

// accountKID returns the closure VerifyJWS uses to round-trip-check
// inbound `kid` headers. Centralized so both NewAccount + Account
// build the same URL shape.
func (h ACMEHandler) accountKID(r *http.Request, profileID string) func(accountID string) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	prefix := scheme + "://" + r.Host
	if profileID != "" {
		prefix += "/acme/profile/" + profileID
	} else {
		prefix += "/acme"
	}
	return func(accountID string) string { return prefix + "/account/" + accountID }
}

// accountOrdersURL is the URL Phase 2 will serve account orders at.
// Phase 1b emits it in the account JSON for RFC 8555 §7.1.2.1
// compliance even though hitting it returns 404 until Phase 2.
func (h ACMEHandler) accountOrdersURL(r *http.Request, profileID, accountID string) string {
	return h.accountKID(r, profileID)(accountID) + "/orders"
}

// trimBody is a minimal JSON-aware trim that returns a copy with
// outer whitespace removed. We don't need full JSON parsing here —
// just enough to detect empty body / empty object for POST-as-GET
// routing.
func trimBody(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r') {
		b = b[1:]
	}
	for len(b) > 0 {
		c := b[len(b)-1]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			break
		}
		b = b[:len(b)-1]
	}
	return b
}
