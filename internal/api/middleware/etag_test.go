// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Phase 6 SCALE-L2 contract pin (2026-05-14): the ETag middleware
// must:
//   1. Emit an ETag header on successful GET / HEAD responses.
//   2. Return 304 Not Modified when the client's If-None-Match
//      matches the computed ETag (cache hit).
//   3. Return 200 + new ETag when the body has changed (cache miss
//      after mutation).
//   4. NOT apply to POST / PUT / DELETE.
//   5. NOT apply to non-2xx responses (errors pass through unchanged).
//   6. Skip ETag for over-sized responses (degrade gracefully, not
//      crash).

func TestETag_GET_EmitsETagHeader(t *testing.T) {
	handler := ETag(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"id":"cert-1"}],"total":1}`))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", rec.Code)
	}
	if etag := rec.Header().Get("ETag"); etag == "" {
		t.Errorf("ETag header is empty; want non-empty strong validator")
	}
	if !strings.Contains(rec.Body.String(), "cert-1") {
		t.Errorf("body missing handler output: %q", rec.Body.String())
	}
}

func TestETag_RepeatedRequest_Returns304(t *testing.T) {
	body := []byte(`{"items":[{"id":"cert-1"}],"total":1}`)
	handler := ETag(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))

	// First request — establish the cache.
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	etag := rec1.Header().Get("ETag")
	if etag == "" {
		t.Fatal("first response missing ETag — cannot run cache-hit test")
	}

	// Second request with If-None-Match — should 304.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req2.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusNotModified {
		t.Errorf("status = %d; want 304 Not Modified (cache hit)", rec2.Code)
	}
	if rec2.Body.Len() != 0 {
		t.Errorf("304 response body non-empty: %q (RFC 7232 §4.1: 304 MUST NOT have a body)", rec2.Body.String())
	}
	if rec2.Header().Get("ETag") != etag {
		t.Errorf("304 response ETag = %q; want %q (must be preserved for next request)", rec2.Header().Get("ETag"), etag)
	}
}

func TestETag_AfterMutation_Returns200WithNewETag(t *testing.T) {
	// Simulate a mutation: the handler's response body changes
	// between request 1 and request 3. Request 2 (with stale
	// If-None-Match) must miss and return 200 + the new ETag.
	currentBody := []byte(`{"items":[{"id":"cert-1"}],"total":1}`)
	handler := ETag(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(currentBody)
	}))

	// Initial request — capture ETag.
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	etag1 := rec1.Header().Get("ETag")

	// Simulate a mutation by changing the response body.
	currentBody = []byte(`{"items":[{"id":"cert-1"},{"id":"cert-2"}],"total":2}`)

	// Repeat request with stale ETag — should miss (200, new ETag).
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req2.Header.Set("If-None-Match", etag1)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("status = %d; want 200 (cache miss after mutation)", rec2.Code)
	}
	etag2 := rec2.Header().Get("ETag")
	if etag2 == etag1 {
		t.Errorf("ETag unchanged after body mutation: %q = %q", etag1, etag2)
	}
	if !strings.Contains(rec2.Body.String(), "cert-2") {
		t.Errorf("post-mutation body missing new content: %q", rec2.Body.String())
	}
}

func TestETag_POST_BypassesMiddleware(t *testing.T) {
	handler := ETag(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"cert-new"}`))
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d; want 201", rec.Code)
	}
	if etag := rec.Header().Get("ETag"); etag != "" {
		t.Errorf("ETag header set on POST response: %q (POST/PUT/DELETE must not have ETag)", etag)
	}
}

func TestETag_5xx_PassesThroughWithoutETag(t *testing.T) {
	handler := ETag(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", rec.Code)
	}
	if etag := rec.Header().Get("ETag"); etag != "" {
		t.Errorf("ETag set on 500 response: %q (non-2xx must not be cached)", etag)
	}
	if !strings.Contains(rec.Body.String(), "boom") {
		t.Errorf("error body lost: %q", rec.Body.String())
	}
}

func TestETag_4xx_PassesThroughWithoutETag(t *testing.T) {
	handler := ETag(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid query"}`))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?bad=true", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
	if etag := rec.Header().Get("ETag"); etag != "" {
		t.Errorf("ETag set on 400 response: %q (non-2xx must not be cached)", etag)
	}
}

func TestETag_OversizedResponse_DegradesGracefully(t *testing.T) {
	// Response larger than maxETagBufferBytes (64 KiB) must not
	// be ETag'd, but the response itself must reach the client
	// intact.
	bigBody := make([]byte, maxETagBufferBytes+1024)
	for i := range bigBody {
		bigBody[i] = 'x'
	}
	handler := ETag(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(bigBody)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?limit=10000", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; want 200 (oversize body should not 5xx)", rec.Code)
	}
	if etag := rec.Header().Get("ETag"); etag != "" {
		t.Errorf("ETag emitted for oversize response: %q (should degrade silently)", etag)
	}
	if got, want := rec.Body.Len(), len(bigBody); got != want {
		t.Errorf("body bytes received = %d; want %d (oversize body should not be truncated on the wire)", got, want)
	}
}

func TestETag_Wildcard_MatchesAny(t *testing.T) {
	// RFC 7232 §3.2: If-None-Match: * matches any current
	// representation. Clients use this for "give me 304 if anything
	// exists" semantics.
	handler := ETag(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"any":"thing"}`))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req.Header.Set("If-None-Match", "*")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotModified {
		t.Errorf("status = %d; want 304 (If-None-Match: * always matches)", rec.Code)
	}
}

func TestETag_HEAD_TreatedLikeGET(t *testing.T) {
	body := []byte(`{"items":[],"total":0}`)
	handler := ETag(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A real HEAD handler wouldn't actually write a body but
		// the middleware shouldn't care — the ETag derives from
		// whatever the handler emits.
		_, _ = w.Write(body)
	}))

	req := httptest.NewRequest(http.MethodHead, "/api/v1/certificates", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", rec.Code)
	}
	if etag := rec.Header().Get("ETag"); etag == "" {
		t.Errorf("HEAD response missing ETag (HEAD should be treated like GET)")
	}
}

// TestETag_ChainCheck — paranoia check that the recorder doesn't
// drop bytes vs the underlying ResponseWriter. Reads back the
// body and asserts byte-equality with what the handler wrote.
func TestETag_PassThrough_PreservesBody(t *testing.T) {
	body := []byte(`{"a":1,"b":2,"c":3}`)
	handler := ETag(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	got, _ := io.ReadAll(rec.Body)
	if string(got) != string(body) {
		t.Errorf("body bytes mismatched: got %q, want %q", string(got), string(body))
	}
}
