// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"encoding/json"
	"net/http"
)

// ProblemContentType is the MIME type RFC 7807 §3 mandates for the
// JSON-Problem error envelope. ACME inherits this from RFC 8555 §6.7.
const ProblemContentType = "application/problem+json"

// ACME error type URN prefix per RFC 8555 §6.7.
const acmeErrorPrefix = "urn:ietf:params:acme:error:"

// Problem is the RFC 7807 Problem Details document. ACME extends it
// per RFC 8555 §6.7 with subproblems (per-identifier-rejection
// breakdowns) and identifier (the failing identifier on
// rejectedIdentifier). Both extension fields land in Phase 2 along
// with the order endpoints; Phase 1a only emits the base shape.
type Problem struct {
	Type        string      `json:"type"`
	Detail      string      `json:"detail"`
	Status      int         `json:"status"`
	Subproblems []Problem   `json:"subproblems,omitempty"`
	Identifier  *Identifier `json:"identifier,omitempty"`
}

// Identifier is the ACME identifier shape (RFC 8555 §7.4). Defined here
// (rather than in a Phase-2-only file) so Phase 1a's Problem struct can
// reference *Identifier without a forward-package-dependency.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Malformed is RFC 8555 §6.7's "request body did not parse / decode" /
// "the JWS was malformed" / "payload JSON was malformed" error. HTTP
// status 400.
func Malformed(detail string) Problem {
	return Problem{
		Type:   acmeErrorPrefix + "malformed",
		Detail: detail,
		Status: http.StatusBadRequest,
	}
}

// ServerInternal is the catch-all for unexpected server-side errors.
// HTTP status 500. The detail string is operator-facing; per the
// master prompt's acquisition-readiness criterion #10 it MUST NOT
// echo SQL errors, internal trace IDs, or credential bytes.
func ServerInternal(detail string) Problem {
	return Problem{
		Type:   acmeErrorPrefix + "serverInternal",
		Detail: detail,
		Status: http.StatusInternalServerError,
	}
}

// UserActionRequired is RFC 8555 §6.7's "the user has to do something
// out of band before this request will succeed" error. We return it
// from the /acme/* shorthand path family when
// CERTCTL_ACME_SERVER_DEFAULT_PROFILE_ID is not set — the operator
// has to either set the env var or update the client to use
// /acme/profile/<id>/*. HTTP status 403 per RFC 8555.
func UserActionRequired(detail string) Problem {
	return Problem{
		Type:   acmeErrorPrefix + "userActionRequired",
		Detail: detail,
		Status: http.StatusForbidden,
	}
}

// UnsupportedContentType is RFC 7807-shaped (no ACME error type) for
// requests with a Content-Type the endpoint doesn't accept. Phase 1b
// will switch the JWS endpoints to require
// "application/jose+json" specifically; Phase 1a's directory + nonce
// have no Content-Type requirements and never emit this.
func UnsupportedContentType(got string) Problem {
	return Problem{
		Type:   "about:blank",
		Detail: "unsupported content type: " + got,
		Status: http.StatusUnsupportedMediaType,
	}
}

// AccountDoesNotExist (RFC 8555 §7.3.1) is what the JWS verifier returns
// when the request's `kid` points at an unknown account. Phase 1b
// implements the verifier; this shape is exposed in Phase 1a for the
// errors_test.go round-trip cases.
func AccountDoesNotExist(detail string) Problem {
	return Problem{
		Type:   acmeErrorPrefix + "accountDoesNotExist",
		Detail: detail,
		Status: http.StatusBadRequest,
	}
}

// BadNonce is what the JWS verifier returns on a missing / replayed /
// expired nonce per RFC 8555 §6.5.1. Phase 1b wires the verifier;
// shape exposed now so errors_test.go can round-trip it.
func BadNonce(detail string) Problem {
	return Problem{
		Type:   acmeErrorPrefix + "badNonce",
		Detail: detail,
		Status: http.StatusBadRequest,
	}
}

// WriteProblem renders a Problem as RFC 7807 JSON to w, with the
// appropriate Content-Type and status. Any nil-Problem is rendered as
// 500 + serverInternal so the handler never panics on a forgotten
// error path.
func WriteProblem(w http.ResponseWriter, p Problem) {
	if p.Status == 0 {
		p = ServerInternal("unspecified error")
	}
	w.Header().Set("Content-Type", ProblemContentType)
	w.WriteHeader(p.Status)
	// Marshaling can only fail on un-encodable types; Problem only
	// uses primitives + slices so json.Marshal cannot fail. The
	// _ = ... discard mirrors how response.go handles json.Encoder
	// errors.
	_ = json.NewEncoder(w).Encode(p)
}
