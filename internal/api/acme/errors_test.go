// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProblem_Malformed_Shape(t *testing.T) {
	p := Malformed("payload was not valid JSON")
	if p.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", p.Status, http.StatusBadRequest)
	}
	if p.Type != "urn:ietf:params:acme:error:malformed" {
		t.Errorf("type = %q", p.Type)
	}
	if p.Detail != "payload was not valid JSON" {
		t.Errorf("detail = %q", p.Detail)
	}
	// Subproblems and Identifier are Phase-2 extensions; both stay empty
	// for a Phase-1a-emitted problem.
	if len(p.Subproblems) != 0 {
		t.Errorf("subproblems should be empty; got %v", p.Subproblems)
	}
	if p.Identifier != nil {
		t.Errorf("identifier should be nil; got %+v", p.Identifier)
	}
}

func TestProblem_AllHelperShapes(t *testing.T) {
	cases := []struct {
		name       string
		p          Problem
		wantType   string
		wantStatus int
	}{
		{"Malformed", Malformed("x"), "urn:ietf:params:acme:error:malformed", http.StatusBadRequest},
		{"ServerInternal", ServerInternal("x"), "urn:ietf:params:acme:error:serverInternal", http.StatusInternalServerError},
		{"UserActionRequired", UserActionRequired("x"), "urn:ietf:params:acme:error:userActionRequired", http.StatusForbidden},
		{"AccountDoesNotExist", AccountDoesNotExist("x"), "urn:ietf:params:acme:error:accountDoesNotExist", http.StatusBadRequest},
		{"BadNonce", BadNonce("x"), "urn:ietf:params:acme:error:badNonce", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.p.Type != tc.wantType {
				t.Errorf("type = %q, want %q", tc.p.Type, tc.wantType)
			}
			if tc.p.Status != tc.wantStatus {
				t.Errorf("status = %d, want %d", tc.p.Status, tc.wantStatus)
			}
		})
	}
}

func TestProblem_UnsupportedContentType(t *testing.T) {
	p := UnsupportedContentType("application/json")
	if p.Status != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", p.Status)
	}
	if p.Type != "about:blank" {
		t.Errorf("UnsupportedContentType uses RFC 7807 about:blank; got %q", p.Type)
	}
	if !strings.Contains(p.Detail, "application/json") {
		t.Errorf("detail should echo content-type; got %q", p.Detail)
	}
}

func TestWriteProblem_Headers(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteProblem(rec, Malformed("oops"))

	if got, want := rec.Code, http.StatusBadRequest; got != want {
		t.Errorf("status = %d, want %d", got, want)
	}
	if got, want := rec.Header().Get("Content-Type"), ProblemContentType; got != want {
		t.Errorf("content-type = %q, want %q", got, want)
	}

	var p Problem
	if err := json.NewDecoder(rec.Body).Decode(&p); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.Type != "urn:ietf:params:acme:error:malformed" {
		t.Errorf("decoded type = %q", p.Type)
	}
}

func TestWriteProblem_NilStatusFallsBackTo500(t *testing.T) {
	// Defensive check: a hand-constructed Problem with Status=0 (e.g.
	// from a forgotten error path) still renders cleanly as 500 +
	// serverInternal rather than emitting an HTTP/0 response.
	rec := httptest.NewRecorder()
	WriteProblem(rec, Problem{})

	if got, want := rec.Code, http.StatusInternalServerError; got != want {
		t.Errorf("status = %d, want %d", got, want)
	}
	if got, want := rec.Header().Get("Content-Type"), ProblemContentType; got != want {
		t.Errorf("content-type = %q, want %q", got, want)
	}
}
