// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package handler

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"time"

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
	// Phase 2 — orders + finalize + authz + cert download.
	CreateOrder(ctx context.Context, accountID, profileID string, identifiers []domain.ACMEIdentifier, notBefore, notAfter *time.Time) (*domain.ACMEOrder, error)
	LookupOrder(ctx context.Context, orderID, accountID string) (*domain.ACMEOrder, error)
	LookupAuthz(ctx context.Context, authzID string) (*domain.ACMEAuthorization, error)
	ListAuthzsByOrder(ctx context.Context, orderID string) ([]*domain.ACMEAuthorization, error)
	FinalizeOrder(ctx context.Context, accountID, orderID, profileID string, csr *x509.CertificateRequest, csrPEM string) (*service.FinalizeOrderResult, error)
	LookupCertificate(ctx context.Context, certID, accountID string) (string, error)
	// Phase 3 — challenge validation.
	RespondToChallenge(ctx context.Context, accountID, challengeID string, accountJWK *jose.JSONWebKey) (*domain.ACMEChallenge, error)
	// Phase 4 — key rollover + revocation + ARI.
	RotateAccountKey(ctx context.Context, oldAccount *domain.ACMEAccount, newJWK *jose.JSONWebKey) (*domain.ACMEAccount, error)
	RevokeCert(ctx context.Context, verified *acme.VerifiedRequest, certDER []byte, reasonCode int) error
	RenewalInfo(ctx context.Context, profileID, certID string) (*acme.RenewalInfoResponse, time.Duration, error)
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
	case errors.Is(err, service.ErrACMEOrderNotFound), errors.Is(err, service.ErrACMEAuthzNotFound), errors.Is(err, service.ErrACMECertificateNotFound):
		acme.WriteProblem(w, acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "resource not found",
			Status: http.StatusNotFound,
		})
	case errors.Is(err, service.ErrACMEOrderUnauthorized):
		acme.WriteProblem(w, acme.Problem{
			Type:   "urn:ietf:params:acme:error:unauthorized",
			Detail: "account does not own this resource",
			Status: http.StatusUnauthorized,
		})
	case errors.Is(err, service.ErrACMEOrderNotReady):
		acme.WriteProblem(w, acme.Problem{
			Type:   "urn:ietf:params:acme:error:orderNotReady",
			Detail: "order is not in the `ready` state; complete authorizations first",
			Status: http.StatusForbidden,
		})
	case errors.Is(err, service.ErrACMEUnsupportedAuthMode), errors.Is(err, service.ErrACMEFinalizeUnconfigured), errors.Is(err, service.ErrACMEChallengePoolUnconfigured):
		acme.WriteProblem(w, acme.ServerInternal("ACME server is not fully configured; contact the operator"))
	case errors.Is(err, service.ErrACMEChallengeNotFound):
		acme.WriteProblem(w, acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "challenge not found",
			Status: http.StatusNotFound,
		})
	case errors.Is(err, service.ErrACMEChallengeWrongState):
		acme.WriteProblem(w, acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "challenge is no longer in pending state",
			Status: http.StatusBadRequest,
		})
	case errors.Is(err, service.ErrACMERevocationUnconfigured):
		acme.WriteProblem(w, acme.ServerInternal("revocation pipeline is not wired"))
	case errors.Is(err, service.ErrACMEKeyRolloverConcurrent),
		errors.Is(err, service.ErrACMEKeyRolloverDuplicateKey):
		acme.WriteProblem(w, acme.Problem{
			Type:   "urn:ietf:params:acme:error:unauthorized",
			Detail: "the supplied new account key is unavailable: " + err.Error(),
			Status: http.StatusConflict,
		})
	case errors.Is(err, service.ErrACMEKeyRolloverInvalid):
		acme.WriteProblem(w, acme.Malformed("key rollover request rejected"))
	case errors.Is(err, service.ErrACMERevocationCertNotFound):
		acme.WriteProblem(w, acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "the supplied certificate is not known to this server",
			Status: http.StatusNotFound,
		})
	case errors.Is(err, service.ErrACMERevocationUnauthorized):
		acme.WriteProblem(w, acme.Problem{
			Type:   "urn:ietf:params:acme:error:unauthorized",
			Detail: "the requester is not authorized to revoke this certificate",
			Status: http.StatusUnauthorized,
		})
	case errors.Is(err, service.ErrACMERevocationAlreadyRevoked):
		acme.WriteProblem(w, acme.Problem{
			Type:   "urn:ietf:params:acme:error:alreadyRevoked",
			Detail: "the certificate has already been revoked",
			Status: http.StatusBadRequest,
		})
	case errors.Is(err, service.ErrACMERevocationBadCSR):
		acme.WriteProblem(w, acme.Problem{
			Type:   "urn:ietf:params:acme:error:badCSR",
			Detail: "the supplied `certificate` field is not a valid X.509 cert",
			Status: http.StatusBadRequest,
		})
	case errors.Is(err, service.ErrACMEARIDisabled):
		acme.WriteProblem(w, acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "ACME Renewal Information is disabled on this server",
			Status: http.StatusNotFound,
		})
	case errors.Is(err, service.ErrACMEARIBadCertID):
		acme.WriteProblem(w, acme.Malformed("ARI cert-id is malformed"))
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

// --- Phase 2 — orders + finalize + authz + cert handlers ---------------

// NewOrder handles POST /acme/profile/{id}/new-order (RFC 8555 §7.4).
// JWS path: kid (registered account).
func (h ACMEHandler) NewOrder(w http.ResponseWriter, r *http.Request) {
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

	verified, err := h.svc.VerifyJWS(r.Context(), body, requestURL, false /*expectNewAccount*/, h.accountKID(r, profileID))
	if err != nil {
		acme.WriteProblem(w, acme.MapJWSErrorToProblem(err))
		return
	}
	if verified.Account == nil {
		acme.WriteProblem(w, acme.MapJWSErrorToProblem(acme.ErrJWSAccountNotFound))
		return
	}

	var req acme.NewOrderRequest
	if err := json.Unmarshal(verified.Payload, &req); err != nil {
		acme.WriteProblem(w, acme.Malformed("could not parse new-order payload"))
		return
	}
	// Identifier validation runs BEFORE order creation. Rejected
	// identifiers do NOT create an acme_orders row.
	if probs := acme.ValidateIdentifiers(req.Identifiers); len(probs) > 0 {
		// Multi-rejection → wrap in subproblems.
		w.Header().Set("Content-Type", acme.ProblemContentType)
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(acme.Problem{
			Type:        "urn:ietf:params:acme:error:rejectedIdentifier",
			Detail:      "one or more identifiers were rejected",
			Status:      http.StatusBadRequest,
			Subproblems: probs,
		})
		return
	}

	// Translate wire shape to domain shape.
	domainIDs := make([]domain.ACMEIdentifier, 0, len(req.Identifiers))
	for _, id := range req.Identifiers {
		domainIDs = append(domainIDs, domain.ACMEIdentifier{Type: id.Type, Value: id.Value})
	}
	notBefore := parseOptionalTime(req.NotBefore)
	notAfter := parseOptionalTime(req.NotAfter)

	order, err := h.svc.CreateOrder(r.Context(), verified.Account.AccountID, profileID, domainIDs, notBefore, notAfter)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	if nonce, err := h.svc.IssueNonce(r.Context()); err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
	w.Header().Set("Location", h.orderURL(r, profileID, order.OrderID))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(h.marshalOrderForResponse(r, profileID, order))
}

// Order handles POST /acme/profile/{id}/order/{ord_id} (RFC 8555 §7.4
// POST-as-GET — empty payload returns the current order state).
func (h ACMEHandler) Order(w http.ResponseWriter, r *http.Request) {
	profileID := r.PathValue("id")
	orderID := r.PathValue("ord_id")
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

	verified, err := h.svc.VerifyJWS(r.Context(), body, requestURL, false, h.accountKID(r, profileID))
	if err != nil {
		acme.WriteProblem(w, acme.MapJWSErrorToProblem(err))
		return
	}
	if verified.Account == nil {
		acme.WriteProblem(w, acme.MapJWSErrorToProblem(acme.ErrJWSAccountNotFound))
		return
	}

	order, err := h.svc.LookupOrder(r.Context(), orderID, verified.Account.AccountID)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	if nonce, err := h.svc.IssueNonce(r.Context()); err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(h.marshalOrderForResponse(r, profileID, order))
}

// OrderFinalize handles POST /acme/profile/{id}/order/{ord_id}/finalize
// (RFC 8555 §7.4). Payload carries the base64url-DER CSR.
func (h ACMEHandler) OrderFinalize(w http.ResponseWriter, r *http.Request) {
	profileID := r.PathValue("id")
	orderID := r.PathValue("ord_id")
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

	verified, err := h.svc.VerifyJWS(r.Context(), body, requestURL, false, h.accountKID(r, profileID))
	if err != nil {
		acme.WriteProblem(w, acme.MapJWSErrorToProblem(err))
		return
	}
	if verified.Account == nil {
		acme.WriteProblem(w, acme.MapJWSErrorToProblem(acme.ErrJWSAccountNotFound))
		return
	}

	var req acme.FinalizeRequest
	if err := json.Unmarshal(verified.Payload, &req); err != nil {
		acme.WriteProblem(w, acme.Malformed("could not parse finalize payload"))
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		acme.WriteProblem(w, acme.Problem{
			Type:   "urn:ietf:params:acme:error:badCSR",
			Detail: "csr field is not valid base64url",
			Status: http.StatusBadRequest,
		})
		return
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		acme.WriteProblem(w, acme.Problem{
			Type:   "urn:ietf:params:acme:error:badCSR",
			Detail: "csr did not parse as a valid PKCS#10",
			Status: http.StatusBadRequest,
		})
		return
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	result, err := h.svc.FinalizeOrder(r.Context(), verified.Account.AccountID, orderID, profileID, csr, csrPEM)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	if nonce, err := h.svc.IssueNonce(r.Context()); err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
	w.Header().Set("Location", h.orderURL(r, profileID, result.Order.OrderID))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(h.marshalOrderForResponse(r, profileID, result.Order))
}

// Authz handles POST /acme/profile/{id}/authz/{authz_id} (RFC 8555
// §7.5 POST-as-GET).
func (h ACMEHandler) Authz(w http.ResponseWriter, r *http.Request) {
	profileID := r.PathValue("id")
	authzID := r.PathValue("authz_id")
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

	verified, err := h.svc.VerifyJWS(r.Context(), body, requestURL, false, h.accountKID(r, profileID))
	if err != nil {
		acme.WriteProblem(w, acme.MapJWSErrorToProblem(err))
		return
	}
	if verified.Account == nil {
		acme.WriteProblem(w, acme.MapJWSErrorToProblem(acme.ErrJWSAccountNotFound))
		return
	}

	authz, err := h.svc.LookupAuthz(r.Context(), authzID)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	if nonce, err := h.svc.IssueNonce(r.Context()); err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(acme.MarshalAuthorization(authz, h.challengeURLBuilder(r, profileID)))
}

// Cert handles POST /acme/profile/{id}/cert/{cert_id} (RFC 8555 §7.4.2
// POST-as-GET cert download). Returns the PEM chain.
func (h ACMEHandler) Cert(w http.ResponseWriter, r *http.Request) {
	profileID := r.PathValue("id")
	certID := r.PathValue("cert_id")
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

	verified, err := h.svc.VerifyJWS(r.Context(), body, requestURL, false, h.accountKID(r, profileID))
	if err != nil {
		acme.WriteProblem(w, acme.MapJWSErrorToProblem(err))
		return
	}
	if verified.Account == nil {
		acme.WriteProblem(w, acme.MapJWSErrorToProblem(acme.ErrJWSAccountNotFound))
		return
	}

	pemChain, err := h.svc.LookupCertificate(r.Context(), certID, verified.Account.AccountID)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	if nonce, err := h.svc.IssueNonce(r.Context()); err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(pemChain))
}

// orderURL composes the per-order URL for Location headers and the
// finalize URL embedded in the order JSON.
func (h ACMEHandler) orderURL(r *http.Request, profileID, orderID string) string {
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
	return prefix + "/order/" + orderID
}

func (h ACMEHandler) authzURL(r *http.Request, profileID, authzID string) string {
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
	return prefix + "/authz/" + authzID
}

func (h ACMEHandler) certURL(r *http.Request, profileID, certID string) string {
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
	return prefix + "/cert/" + certID
}

// challengeURLBuilder returns a closure for MarshalAuthorization to
// compute per-challenge URLs.
func (h ACMEHandler) challengeURLBuilder(r *http.Request, profileID string) func(challengeID string) string {
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
	return func(challengeID string) string { return prefix + "/challenge/" + challengeID }
}

// marshalOrderForResponse builds the OrderResponseJSON for an order,
// fetching the per-order authzs to populate the URL list. The cert URL
// is populated only when status=valid + certificate_id is set.
func (h ACMEHandler) marshalOrderForResponse(r *http.Request, profileID string, order *domain.ACMEOrder) acme.OrderResponseJSON {
	authzs, _ := h.svc.ListAuthzsByOrder(r.Context(), order.OrderID)
	authzURLs := make([]string, 0, len(authzs))
	for _, a := range authzs {
		authzURLs = append(authzURLs, h.authzURL(r, profileID, a.AuthzID))
	}
	finalize := h.orderURL(r, profileID, order.OrderID) + "/finalize"
	certURL := ""
	if order.CertificateID != "" {
		certURL = h.certURL(r, profileID, order.CertificateID)
	}
	return acme.MarshalOrder(order, authzURLs, finalize, certURL)
}

// parseOptionalTime parses an RFC 3339 string; returns nil on empty or
// parse failure (the latter is best-effort — the spec leaves notBefore
// / notAfter as advisory).
func parseOptionalTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

// Challenge handles POST /acme/profile/{id}/challenge/{chall_id}
// (RFC 8555 §7.5.1). The client posts an empty body (modern ACME) or
// a `{}` payload to indicate "I'm ready for you to validate this
// challenge." The handler dispatches the validator-pool work + returns
// the challenge in its current (processing) state. Clients poll authz
// or challenge for the eventual outcome.
//
// Phase 3: account JWK is needed to compute the key authorization. The
// JWS verifier returns the registered account's stored JWKPEM in the
// VerifiedRequest.Account; we round-trip that PEM through ParseJWKFromPEM
// to get the *jose.JSONWebKey the validator pool needs.
func (h ACMEHandler) Challenge(w http.ResponseWriter, r *http.Request) {
	profileID := r.PathValue("id")
	challengeID := r.PathValue("chall_id")
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
	if verified.Account == nil {
		acme.WriteProblem(w, acme.MapJWSErrorToProblem(acme.ErrJWSAccountNotFound))
		return
	}

	// Reconstruct the account's public JWK from its stored PEM. This
	// is what the validator pool needs to compute key authorizations.
	jwk, err := acme.ParseJWKFromPEM(verified.Account.JWKPEM)
	if err != nil {
		acme.WriteProblem(w, acme.ServerInternal("could not parse stored account JWK"))
		return
	}

	ch, err := h.svc.RespondToChallenge(r.Context(), verified.Account.AccountID, challengeID, jwk)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	if nonce, err := h.svc.IssueNonce(r.Context()); err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(marshalChallengeResponse(ch, h.challengeURLBuilder(r, profileID)))
}

// marshalChallengeResponse renders a single ACMEChallenge in the
// RFC 8555 §8 wire shape. Distinct from MarshalAuthorization (which
// embeds challenges in an authz wrapper); the challenge endpoint
// returns one challenge directly per RFC 8555 §7.5.1.
func marshalChallengeResponse(ch *domain.ACMEChallenge, urlBuilder func(string) string) acme.ChallengeResponseJSON {
	out := acme.ChallengeResponseJSON{
		Type:   string(ch.Type),
		URL:    urlBuilder(ch.ChallengeID),
		Status: string(ch.Status),
		Token:  ch.Token,
	}
	if ch.ValidatedAt != nil {
		out.Validated = ch.ValidatedAt.UTC().Format(time.RFC3339)
	}
	if ch.Error != nil {
		out.Error = &acme.Problem{Type: ch.Error.Type, Detail: ch.Error.Detail, Status: ch.Error.Status}
	}
	return out
}

// --- Phase 4 — key rollover + revocation + ARI -------------------------

// KeyChange handles POST /acme/profile/{id}/key-change (RFC 8555 §7.3.5).
// Doubly-signed JWS: the OUTER is signed by the OLD account key (kid
// path); the inner — embedded as the outer's payload — is signed by the
// NEW account key (jwk path).
//
// We run the outer through the existing VerifyJWS pipeline (kid path,
// nonce consumed there), then ParseAndVerifyKeyChangeInner against the
// outer's verified payload bytes. The service's RotateAccountKey is the
// committing actor: it asserts uniqueness and atomically swaps the
// row's jwk_thumbprint + jwk_pem under SELECT…FOR UPDATE.
func (h ACMEHandler) KeyChange(w http.ResponseWriter, r *http.Request) {
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

	verified, err := h.svc.VerifyJWS(r.Context(), body, requestURL, false /*expectNewAccount*/, h.accountKID(r, profileID))
	if err != nil {
		acme.WriteProblem(w, acme.MapJWSErrorToProblem(err))
		return
	}
	if verified.Account == nil {
		acme.WriteProblem(w, acme.MapJWSErrorToProblem(acme.ErrJWSAccountNotFound))
		return
	}

	// The outer's verified payload IS the inner JWS (compact-serialized).
	// Reconstruct the OLD account's stored JWK so the inner can assert
	// payload.oldKey matches it.
	registeredOldJWK, err := acme.ParseJWKFromPEM(verified.Account.JWKPEM)
	if err != nil {
		acme.WriteProblem(w, acme.ServerInternal("could not parse stored account JWK"))
		return
	}

	outerKID := h.accountKID(r, profileID)(verified.Account.AccountID)
	inner, err := acme.ParseAndVerifyKeyChangeInner(
		verified.Payload, outerKID, requestURL, registeredOldJWK,
	)
	if err != nil {
		acme.WriteProblem(w, acme.MapKeyChangeErrorToProblem(err))
		return
	}

	rolled, err := h.svc.RotateAccountKey(r.Context(), verified.Account, inner.NewJWK)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	if nonce, err := h.svc.IssueNonce(r.Context()); err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(
		acme.MarshalAccount(rolled, h.accountOrdersURL(r, profileID, rolled.AccountID)),
	)
}

// RevokeCert handles POST /acme/profile/{id}/revoke-cert (RFC 8555 §7.6).
// JWS may use EITHER kid (account that owns the cert) OR jwk (the cert's
// own public key). VerifyJWS produces either Account-set (kid) or
// JWK-set (jwk). The service's RevokeCert routes through the existing
// RevocationSvc pipeline.
func (h ACMEHandler) RevokeCert(w http.ResponseWriter, r *http.Request) {
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

	// RFC 8555 §7.6 explicitly permits both kid and jwk on revoke-cert.
	// Run a kid-first verify; on the kid-path-specific
	// "this endpoint requires kid" failure, retry as jwk path.
	verified, errKid := h.svc.VerifyJWS(r.Context(), body, requestURL, false /*expectNewAccount=false → kid*/, h.accountKID(r, profileID))
	if errKid != nil && (errors.Is(errKid, acme.ErrJWSExpectKidGotJWK) || errors.Is(errKid, acme.ErrJWSAccountNotFound)) {
		// jwk path. ExpectNewAccount=true asserts jwk + rejects kid.
		v2, err2 := h.svc.VerifyJWS(r.Context(), body, requestURL, true /*expectNewAccount=true → jwk*/, h.accountKID(r, profileID))
		if err2 != nil {
			acme.WriteProblem(w, acme.MapJWSErrorToProblem(err2))
			return
		}
		verified = v2
	} else if errKid != nil {
		acme.WriteProblem(w, acme.MapJWSErrorToProblem(errKid))
		return
	}

	var req acme.RevokeCertRequest
	if err := json.Unmarshal(verified.Payload, &req); err != nil {
		acme.WriteProblem(w, acme.Malformed("could not parse revoke-cert payload"))
		return
	}
	certDER, err := base64.RawURLEncoding.DecodeString(req.Certificate)
	if err != nil || len(certDER) == 0 {
		acme.WriteProblem(w, acme.Problem{
			Type:   "urn:ietf:params:acme:error:badCSR",
			Detail: "`certificate` is not valid base64url-DER",
			Status: http.StatusBadRequest,
		})
		return
	}

	if err := h.svc.RevokeCert(r.Context(), verified, certDER, req.Reason); err != nil {
		writeServiceError(w, err)
		return
	}

	if nonce, err := h.svc.IssueNonce(r.Context()); err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
	_ = profileID
	w.WriteHeader(http.StatusOK)
}

// RenewalInfo handles GET /acme/profile/{id}/renewal-info/{cert_id}
// (RFC 9773). UNAUTHENTICATED — RFC 9773 §4 mandates ARI be readable
// without JWS so cert-manager-shaped clients can fetch the suggested
// window cheaply.
func (h ACMEHandler) RenewalInfo(w http.ResponseWriter, r *http.Request) {
	profileID := r.PathValue("id")
	certID := r.PathValue("cert_id")

	resp, retryAfter, err := h.svc.RenewalInfo(r.Context(), profileID, certID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if retryAfter > 0 {
		// RFC 7231 §7.1.3 Retry-After accepts either an HTTP-date or a
		// delta-seconds. ACME ARI uses delta-seconds per RFC 9773 §4.2.
		secs := int(retryAfter.Seconds())
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", itoaForRetryAfter(secs))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// itoaForRetryAfter is a localized integer-to-string helper. Using
// strconv.Itoa would be marginally more idiomatic but pulls a fresh
// import for one call site; this one-off is fine.
func itoaForRetryAfter(n int) string {
	if n == 0 {
		return "0"
	}
	negative := false
	if n < 0 {
		negative = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
