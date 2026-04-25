package middleware

import (
	"net/http"
	"strings"
)

// SecurityHeadersConfig configures the SecurityHeaders middleware.
//
// Each field is the literal value to send. An empty string means
// "do not send this header" — operators behind a customising reverse
// proxy can disable any header per-deployment without touching code.
// Defaults are applied via SecurityHeadersDefaults() which encodes
// the H-1 closure's recommended baseline for an HTTPS-only API+UI
// host: HSTS, deny-frame, no-MIME-sniff, conservative CSP, and a
// no-referrer-when-downgrade fallback.
//
// H-1 closure (cat-s11-missing_security_headers).
type SecurityHeadersConfig struct {
	HSTS                  string // Strict-Transport-Security
	FrameOptions          string // X-Frame-Options
	ContentTypeOptions    string // X-Content-Type-Options
	ReferrerPolicy        string // Referrer-Policy
	ContentSecurityPolicy string // Content-Security-Policy
}

// SecurityHeadersDefaults returns a recommended baseline.
//
// CSP: default-src 'self' confines fetches to the same origin.
// img-src 'self' data: allows inline base64 images (used by the
// dashboard's certctl-logo and a few status icons).
// style-src 'self' 'unsafe-inline' is required because Tailwind
// (via Vite) injects per-component <style> blocks at build time;
// without 'unsafe-inline' the dashboard would render unstyled.
// 'unsafe-inline' is intentionally NOT in script-src — the
// front-end ships as a bundled JS file, no inline scripts.
//
// HSTS: 1-year max-age + includeSubDomains. No `preload` directive
// because preload submission requires explicit operator action and
// the deployment topology may not span all subdomains.
//
// X-Frame-Options: DENY — the dashboard does not need to be embedded
// anywhere, and DENY is more conservative than SAMEORIGIN against
// clickjacking via subdomain takeover.
//
// X-Content-Type-Options: nosniff — prevent MIME sniffing on
// JSON/PEM responses that browsers might otherwise interpret as HTML.
//
// Referrer-Policy: no-referrer-when-downgrade — preserves Referer
// for same-origin navigation (useful for support/diagnostics) but
// strips it on HTTPS→HTTP transitions.
func SecurityHeadersDefaults() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		HSTS:                  "max-age=31536000; includeSubDomains",
		FrameOptions:          "DENY",
		ContentTypeOptions:    "nosniff",
		ReferrerPolicy:        "no-referrer-when-downgrade",
		ContentSecurityPolicy: "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
	}
}

// SecurityHeaders returns a middleware that applies the configured
// HTTP response headers on every response. Headers configured to the
// empty string are omitted (operator opted out for that deployment).
//
// Apply BEFORE the audit middleware so headers reach 4xx/5xx responses
// — which is where header omissions matter most for the security
// posture (an attacker probing for misconfiguration sees the same
// headers on a 401 as on a 200).
func SecurityHeaders(cfg SecurityHeadersConfig) func(http.Handler) http.Handler {
	// Pre-trim each value once; the per-request hot path stays a
	// straight set of map writes.
	type headerEntry struct{ name, value string }
	entries := make([]headerEntry, 0, 5)
	add := func(name, value string) {
		v := strings.TrimSpace(value)
		if v != "" {
			entries = append(entries, headerEntry{name, v})
		}
	}
	add("Strict-Transport-Security", cfg.HSTS)
	add("X-Frame-Options", cfg.FrameOptions)
	add("X-Content-Type-Options", cfg.ContentTypeOptions)
	add("Referrer-Policy", cfg.ReferrerPolicy)
	add("Content-Security-Policy", cfg.ContentSecurityPolicy)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			for _, e := range entries {
				h.Set(e.name, e.value)
			}
			next.ServeHTTP(w, r)
		})
	}
}
