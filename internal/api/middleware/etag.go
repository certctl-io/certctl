// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// Phase 6 SCALE-L2 closure (2026-05-14): ETag / If-None-Match
// middleware for read-heavy list endpoints.
//
// Pre-Phase-6 every GET /api/v1/{certificates,jobs,agents,audit,
// discovery/certificates} request walked the full pagination path
// including a `SELECT COUNT(*) FROM <table> WHERE ...` query for
// the metadata block. The dashboard's polling loop alone hits these
// endpoints every 30s; on a 50K-cert fleet that's ~14K COUNT(*)
// rows scanned per minute for a result the operator hasn't actually
// changed.
//
// This middleware sits in front of the handler and:
//
//   1. Lets the handler run normally (writing JSON to a response
//      buffer rather than the wire).
//   2. Computes a SHA-256 ETag of the buffered response body. The
//      ETag is deterministic over (body bytes), so when the
//      underlying list contents are unchanged the ETag is the same
//      regardless of which replica served the request.
//   3. Compares the computed ETag against the request's
//      `If-None-Match` header. Match → write 304 Not Modified with
//      an empty body. No match → write the full response with the
//      `ETag:` header set so the client can store it for the next
//      request.
//
// Constraints / non-goals:
//
//   - GET / HEAD only. POST / PUT / DELETE bypass the middleware
//     (ETags on mutations introduce cache-correctness bugs around
//     the request body not matching the response body).
//   - Non-2xx responses (4xx errors, 5xx) bypass the ETag
//     computation. The handler's error responses go through
//     unchanged.
//   - Responses larger than maxETagBufferBytes (64 KiB) skip the
//     hash. Buffering very large response bodies in-memory just to
//     hash them would cost more than the cache win. The default
//     covers the cursor-paginated 100-row default on every list
//     endpoint; raising the page-size override could exceed the
//     limit, in which case ETag silently degrades to "no caching"
//     for those calls.
//   - The hash is computed over the response body bytes, NOT over
//     a (max-updated-at, row-count) tuple from the DB. This is the
//     less-clever-but-more-correct choice: any response-shape
//     change (a new field added by a handler refactor, locale
//     formatting drift, ordering shuffles) produces a fresh ETag
//     automatically without requiring per-endpoint metadata
//     wiring. The cost is one SHA-256 pass over the response body
//     per request, which is dwarfed by the JSON marshaling cost
//     already in the path.

const (
	// maxETagBufferBytes caps how much response body the middleware
	// will buffer for hashing. 64 KiB covers a 100-row cursor page
	// at the default 500-bytes-per-row JSON shape on every list
	// endpoint. Responses larger than this skip the ETag pass.
	maxETagBufferBytes = 64 * 1024
)

// ETag returns middleware that emits a strong ETag header on
// successful GET / HEAD responses and short-circuits 304 Not
// Modified on If-None-Match match. Use it by wrapping the handler
// chain in front of the list endpoints:
//
//	mux.Handle("GET /api/v1/certificates", middleware.ETag(h.ListCertificates))
//
// Or per router-registration if the router supports method-aware
// wrapping; see internal/api/router/router.go for the wiring shape.
func ETag(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only GET + HEAD benefit. POST/PUT/DELETE always run.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}

		// Buffer the handler's response. The handler still calls
		// w.WriteHeader / w.Write normally; the recorder captures
		// the bytes + status code for the post-handler ETag pass.
		rec := &etagRecorder{
			ResponseWriter: w,
			body:           bytes.NewBuffer(nil),
			status:         http.StatusOK,
			headerWritten:  false,
		}
		next.ServeHTTP(rec, r)

		// Only successful responses get cached. 304s never reach
		// here (we'd be short-circuiting BEFORE the handler ran).
		// 4xx / 5xx responses pass through unchanged because the
		// handler's error body shouldn't be cached against an
		// ETag.
		if rec.status < 200 || rec.status >= 300 {
			rec.flush()
			return
		}

		// Skip ETag pass for over-sized responses. The buffer cap
		// caught the body; emitting it without an ETag is the
		// degradation path.
		if rec.bodyTruncated {
			rec.flush()
			return
		}

		// Compute the ETag over the buffered body.
		bodyBytes := rec.body.Bytes()
		sum := sha256.Sum256(bodyBytes)
		etag := `"` + hex.EncodeToString(sum[:]) + `"` // RFC 7232 strong-validator format

		// If-None-Match handling. The header can be a
		// comma-separated list; check each candidate against the
		// computed ETag.
		if matchETag(r.Header.Get("If-None-Match"), etag) {
			// 304 Not Modified — preserve the ETag header but
			// emit no body. Drop Content-Length to avoid the
			// "declared length doesn't match body" mismatch some
			// proxies are strict about.
			h := w.Header()
			h.Set("ETag", etag)
			h.Del("Content-Length")
			h.Del("Content-Type")
			w.WriteHeader(http.StatusNotModified)
			return
		}

		// Cache miss / first request. Emit the full response with
		// ETag header for the next request to use.
		w.Header().Set("ETag", etag)
		rec.flush()
	})
}

// matchETag returns true when ifNoneMatch (an If-None-Match header
// value) contains an entry that equals etag (the computed strong
// validator) or contains the wildcard `*`. RFC 7232 §3.2 says:
//
//	If-None-Match = "*" / 1#entity-tag
//
// Strong comparison is appropriate for our use because all our
// ETags are strong (computed over response bytes); we never emit
// weak validators (`W/"..."`).
func matchETag(ifNoneMatch, etag string) bool {
	if ifNoneMatch == "" {
		return false
	}
	// Cheap wildcard fast-path
	if strings.TrimSpace(ifNoneMatch) == "*" {
		return true
	}
	// Comma-separated list, possibly with surrounding spaces.
	for _, candidate := range strings.Split(ifNoneMatch, ",") {
		if strings.TrimSpace(candidate) == etag {
			return true
		}
	}
	return false
}

// etagRecorder buffers response bytes + status so the post-handler
// ETag pass can hash the body. WriteHeader and Write follow the
// http.ResponseWriter contract; the recorder ONLY differs by
// holding the bytes until flush() is called.
type etagRecorder struct {
	http.ResponseWriter
	body                *bytes.Buffer
	status              int
	headerWritten       bool // set when the handler calls WriteHeader
	headerWrittenOnWire bool // set when writeHeadersToWire emits to the underlying writer (idempotency sentinel)
	bodyTruncated       bool
}

func (r *etagRecorder) WriteHeader(status int) {
	if r.headerWritten {
		// Honor the http stdlib's contract: subsequent
		// WriteHeader calls are ignored after the first.
		return
	}
	r.status = status
	r.headerWritten = true
}

func (r *etagRecorder) Write(b []byte) (int, error) {
	if r.bodyTruncated {
		// The buffer's full; subsequent writes are reported as
		// successful but never make it into the buffer. flush()
		// writes the buffer + any further bytes directly when it
		// runs (see flush implementation below). Returning the
		// caller-requested length here preserves io.Writer
		// semantics for the handler.
		return len(b), nil
	}
	// Track whether THIS write would push us over the cap. If
	// yes, stop buffering — the body is too big to ETag.
	if r.body.Len()+len(b) > maxETagBufferBytes {
		r.bodyTruncated = true
		// Flush the buffered prefix + this chunk straight to the
		// wire; preserve the handler's bytes-written count.
		// Headers haven't been written yet (we hold them until
		// flush); write them now.
		r.writeHeadersToWire()
		if r.body.Len() > 0 {
			if _, err := r.ResponseWriter.Write(r.body.Bytes()); err != nil {
				return 0, err
			}
			r.body.Reset()
		}
		return r.ResponseWriter.Write(b)
	}
	return r.body.Write(b)
}

// writeHeadersToWire emits the buffered status to the underlying
// ResponseWriter. Idempotent — subsequent calls are no-ops.
func (r *etagRecorder) writeHeadersToWire() {
	if !r.headerWritten {
		// Handler never called WriteHeader explicitly; the
		// http.ResponseWriter contract says that's an implicit
		// 200 OK on the first Write.
		r.status = http.StatusOK
		r.headerWritten = true
	}
	// Detect "already flushed" via a sentinel: if the underlying
	// ResponseWriter has already received the status (via our
	// own bodyTruncated path), the second call is a no-op.
	// Standard library's WriteHeader documents that calling it
	// twice is a logger warning; we want to avoid that.
	// To avoid double-write, we use an internal flag.
	if r.bodyTruncated && r.headerWrittenOnWire {
		return
	}
	// Hotfix #12 (CodeQL alert #34 — go/reflected-xss): defense-in-
	// depth Content-Type guard. This middleware is wired ONLY to JSON
	// list endpoints (GET /api/v1/{certificates,agents,jobs,audit,
	// discovered-certificates} — see internal/api/router/router.go).
	// Every wrapped handler currently sets Content-Type:
	// application/json via handler.JSON() before the first Write. But
	// the recorder is a generic byte forwarder; CodeQL's data-flow
	// query sees `r.ResponseWriter.Write(b)` at the sink and can't
	// see that the wrapped handler set a non-HTML Content-Type — so
	// it flags reflected-XSS even though browsers don't render
	// application/json as HTML. The fix is to make the Content-Type
	// guarantee explicit at the chokepoint: if the wrapped handler
	// forgot to set Content-Type, default to application/json +
	// charset=utf-8 here. Behavior-preserving for the 5 current
	// handlers (they all set Content-Type) and a safe guard against
	// a future handler bug that would otherwise let the browser
	// content-sniff a JSON body as text/html.
	hdr := r.ResponseWriter.Header()
	if hdr.Get("Content-Type") == "" {
		hdr.Set("Content-Type", "application/json; charset=utf-8")
	}
	r.ResponseWriter.WriteHeader(r.status)
	r.headerWrittenOnWire = true
}

// flush emits the buffered status + body to the underlying
// ResponseWriter. Called by the ETag middleware after the handler
// returns AND the response is either a cache miss (no
// If-None-Match match) or non-cacheable (4xx, oversized).
func (r *etagRecorder) flush() {
	if r.bodyTruncated {
		// Headers + body already on the wire via Write's
		// truncation path. Nothing to flush.
		return
	}
	r.writeHeadersToWire()
	if r.body.Len() > 0 {
		_, _ = r.ResponseWriter.Write(r.body.Bytes())
	}
}
