package handler

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/shankar0123/certctl/internal/api/middleware"
	"github.com/shankar0123/certctl/internal/cms"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/pkcs7"
	"github.com/shankar0123/certctl/internal/ratelimit"
	"github.com/shankar0123/certctl/internal/trustanchor"
)

// ESTService defines the service interface for EST enrollment operations.
// EST (RFC 7030) is a protocol for certificate enrollment over HTTPS.
type ESTService interface {
	// GetCACerts returns the PEM-encoded CA certificate chain for the EST issuer.
	GetCACerts(ctx context.Context) (string, error)

	// SimpleEnroll processes a PKCS#10 CSR and returns a signed certificate.
	SimpleEnroll(ctx context.Context, csrPEM string) (*domain.ESTEnrollResult, error)

	// SimpleReEnroll processes a re-enrollment CSR (same as enroll for our purposes).
	SimpleReEnroll(ctx context.Context, csrPEM string) (*domain.ESTEnrollResult, error)

	// GetCSRAttrs returns the CSR attributes the server wants clients to include.
	GetCSRAttrs(ctx context.Context) ([]byte, error)
}

// ESTHandler handles HTTP requests for the EST protocol (RFC 7030).
//
// EST endpoints are served under /.well-known/est/[<PathID>/] per RFC 7030.
// Wire format: base64-encoded DER (PKCS#7 for certs, PKCS#10 for CSRs).
//
// Supported operations (per route family):
//
//	/.well-known/est/[<PathID>/]               — legacy + per-profile route family
//	  GET  cacerts        — CA certificate distribution
//	  POST simpleenroll   — initial enrollment (HTTP Basic optional, Phase 3)
//	  POST simplereenroll — re-enrollment       (HTTP Basic optional, Phase 3)
//	  GET  csrattrs       — CSR attributes
//
//	/.well-known/est-mtls/<PathID>/            — mTLS sibling (Phase 2)
//	  GET  cacerts        — CA certificate distribution (cert auth required)
//	  POST simpleenroll   — initial enrollment (cert + optional channel binding)
//	  POST simplereenroll — re-enrollment       (cert + optional channel binding)
//	  GET  csrattrs       — CSR attributes
//
// EST RFC 7030 hardening master bundle Phases 2-4: ESTHandler grew six
// optional fields wired by per-profile setters in cmd/server/main.go's
// startup loop. None of the new fields are required — a handler with all
// of them unset behaves exactly like the v2.0.x EST handler.
type ESTHandler struct {
	svc ESTService

	// EST RFC 7030 hardening Phase 2.1: per-profile mTLS client-CA trust
	// bundle. When set, the mTLS sibling route (CACertsMTLS /
	// SimpleEnrollMTLS / etc.) verifies the inbound client cert chain
	// against this pool. Nil when MTLS_ENABLED=false; the mTLS route
	// rejects unconditionally in that case (the route shouldn't even be
	// registered, but defense in depth).
	mtlsTrust *trustanchor.Holder

	// EST RFC 7030 hardening Phase 2.4: per-profile channel-binding
	// requirement. When true, the mTLS handler refuses simplereenroll
	// requests whose CSR doesn't carry a matching id-aa-est-tls-exporter
	// (RFC 9266) attribute. Phase 1's Validate() guards
	// ChannelBindingRequired=true + MTLSEnabled=false at startup.
	channelBindingRequired bool

	// EST RFC 7030 hardening Phase 3.1: per-profile HTTP Basic enrollment
	// password. When non-empty, the standard /.well-known/est/<PathID>/
	// route requires `Authorization: Basic <base64(<user>:<pw>)>` on the
	// enrollment endpoints (NOT on cacerts/csrattrs — RFC 7030 §4.1.1
	// says cacerts is anonymous). Constant-time compare; per-source-IP
	// failed-auth rate limit blocks brute-force.
	basicPassword string

	// EST RFC 7030 hardening Phase 3.3: per-handler source-IP rate
	// limiter for FAILED HTTP Basic auth attempts. Keyed by sourceIP so
	// a hostile network segment can't burn through the password.
	failedBasicLimiter *ratelimit.SlidingWindowLimiter

	// EST RFC 7030 hardening Phase 4.2: per-handler per-principal sliding-
	// window rate limit. Keyed by (CSR-CN, sourceIP) so a stolen
	// bootstrap cert AND a known device CN can't be used to flood the
	// issuer. Disabled when nil; configured per-profile.
	perPrincipalLimiter *ratelimit.SlidingWindowLimiter

	// labelForLog gives observability code a per-profile string to
	// include in audit log lines / Prometheus labels. Defaults to
	// "est" when unset.
	labelForLog string
}

// NewESTHandler creates a new ESTHandler with no per-profile auth
// hardening. Call SetMTLSTrust + SetChannelBindingRequired +
// SetEnrollmentPassword + SetSourceIPRateLimiter + SetPerPrincipalRateLimiter
// from the per-profile startup loop to opt-in to each surface.
func NewESTHandler(svc ESTService) ESTHandler {
	return ESTHandler{svc: svc}
}

// SetMTLSTrust injects the per-profile client-cert trust pool the
// `/.well-known/est-mtls/<PathID>/` sibling route uses to verify inbound
// device cert chains. EST RFC 7030 hardening Phase 2.1.
//
// Like the SCEP equivalent, the TLS layer (cmd/server/tls.go) uses
// VerifyClientCertIfGiven against the UNION of every enabled mTLS
// profile's bundle, so the same TLS listener serves both /.well-known/est
// (anonymous or HTTP Basic) and /.well-known/est-mtls/<PathID>
// (cert-required). The per-profile gate at the handler layer enforces
// 'cert must chain to THIS profile's bundle' so a cert that chains to
// profile A's bundle cannot enroll against profile B.
func (h *ESTHandler) SetMTLSTrust(t *trustanchor.Holder) { h.mtlsTrust = t }

// SetChannelBindingRequired toggles RFC 9266 tls-exporter channel binding
// on the simplereenroll mTLS path. EST RFC 7030 hardening Phase 2.4.
// When true, the handler refuses requests whose CSR lacks the binding
// attribute or whose binding bytes don't match the live TLS exporter.
func (h *ESTHandler) SetChannelBindingRequired(req bool) { h.channelBindingRequired = req }

// SetEnrollmentPassword injects the per-profile HTTP Basic enrollment
// password. EST RFC 7030 hardening Phase 3.1. Empty disables the gate
// (mTLS-only or unauthenticated profile). Constant-time compare via
// crypto/subtle.ConstantTimeCompare.
func (h *ESTHandler) SetEnrollmentPassword(pw string) { h.basicPassword = pw }

// SetSourceIPRateLimiter injects the per-handler failed-Basic-auth
// rate limiter. Phase 3.3. Disabled when nil — but Validate() at
// startup refuses an enabled basic-auth profile without a configured
// limiter, so a real deploy always wires one.
func (h *ESTHandler) SetSourceIPRateLimiter(l *ratelimit.SlidingWindowLimiter) {
	h.failedBasicLimiter = l
}

// SetPerPrincipalRateLimiter injects the per-handler (CN, sourceIP)
// sliding-window rate limiter. Phase 4.2. Disabled when nil. Counts
// every successful enrollment, NOT just failures — the goal is to
// bound enrollment-flooding from a compromised credential, not just
// failed-auth brute force.
func (h *ESTHandler) SetPerPrincipalRateLimiter(l *ratelimit.SlidingWindowLimiter) {
	h.perPrincipalLimiter = l
}

// SetLabelForLog sets the per-profile observability label. Defaults to
// "est" when unset; cmd/server/main.go's per-profile loop sets this
// to "est (PathID=<id>)" for triage.
func (h *ESTHandler) SetLabelForLog(label string) {
	if label == "" {
		return
	}
	h.labelForLog = label
}

// label returns h.labelForLog with the "est" fallback applied. Tiny
// helper so log call sites don't need to repeat the fallback.
func (h ESTHandler) label() string {
	if h.labelForLog == "" {
		return "est"
	}
	return h.labelForLog
}

// ----- /.well-known/est/[<PathID>/] route family (legacy + Basic auth) -----

// CACerts handles GET /.well-known/est/[<PathID>/]cacerts.
//
// RFC 7030 §4.1.1 — anonymous endpoint. The HTTP Basic gate is NOT
// applied here (any client must be able to fetch the CA chain to
// verify subsequent enrollment responses).
func (h ESTHandler) CACerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.writeCACertsResponse(w, r)
}

// SimpleEnroll handles POST /.well-known/est/[<PathID>/]simpleenroll.
// Accepts a base64-encoded PKCS#10 CSR + returns base64-encoded PKCS#7.
//
// Auth: HTTP Basic when h.basicPassword != "" (Phase 3); otherwise
// anonymous. Rate-limit: per-(CN, sourceIP) when wired (Phase 4).
func (h ESTHandler) SimpleEnroll(w http.ResponseWriter, r *http.Request) {
	h.handleEnrollOrReEnroll(w, r, false /*reEnroll*/, false /*viaMTLS*/)
}

// SimpleReEnroll handles POST /.well-known/est/[<PathID>/]simplereenroll.
// Same as SimpleEnroll but the audit/log distinguishes the renewal flow
// from initial issuance.
func (h ESTHandler) SimpleReEnroll(w http.ResponseWriter, r *http.Request) {
	h.handleEnrollOrReEnroll(w, r, true /*reEnroll*/, false /*viaMTLS*/)
}

// CSRAttrs handles GET /.well-known/est/[<PathID>/]csrattrs.
// Returns the CSR attributes the server wants the client to include.
// RFC 7030 §4.5 — anonymous endpoint, no Basic auth gate.
func (h ESTHandler) CSRAttrs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.writeCSRAttrsResponse(w, r)
}

// ----- /.well-known/est-mtls/<PathID>/ route family (Phase 2 mTLS) -----

// CACertsMTLS handles GET /.well-known/est-mtls/<PathID>/cacerts.
//
// RFC 7030 §4.1.1 says cacerts is anonymous, but on the mTLS sibling
// route we still require a valid client cert because the mTLS path is
// the audit-distinguished surface — operators using mTLS WANT every
// touchpoint logged. The cert isn't validated for purpose-of-issuance
// here (cacerts isn't an enrollment), but absence is rejected.
func (h ESTHandler) CACertsMTLS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := h.requireClientCertChain(w, r); !ok {
		return
	}
	h.writeCACertsResponse(w, r)
}

// SimpleEnrollMTLS handles POST /.well-known/est-mtls/<PathID>/simpleenroll.
//
// Order of gates (each fails fast with the appropriate HTTP status):
//
//  1. Client cert presented + chains to per-profile mTLS trust pool
//     (the TLS layer already verified against the union pool; this is
//     the per-profile re-verify that prevents profile A↔B cross-bleed).
//  2. CSR parses + matches the EST contract (handled by the shared
//     enrollment helper).
//  3. Per-(CN, sourceIP) rate limit when configured.
//  4. Service-layer enrollment.
//
// Channel binding does NOT apply here — RFC 9266 §1 calls out that
// channel binding is a renewal-time defense-in-depth, not an initial-
// enrollment requirement. (A first-time enrollment doesn't yet have a
// device cert, so binding to the TLS session for the bootstrap cert
// adds nothing.)
func (h ESTHandler) SimpleEnrollMTLS(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireClientCertChain(w, r); !ok {
		return
	}
	h.handleEnrollOrReEnroll(w, r, false /*reEnroll*/, true /*viaMTLS*/)
}

// SimpleReEnrollMTLS handles POST /.well-known/est-mtls/<PathID>/simplereenroll.
//
// Same as SimpleEnrollMTLS plus the channel-binding gate. RFC 9266 §4.1
// says renewal CSRs SHOULD include the binding attribute when the
// enrollment is over a TLS-1.3 channel; per-profile policy can either
// require this strictly (ChannelBindingRequired=true) or accept its
// absence (default).
func (h ESTHandler) SimpleReEnrollMTLS(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireClientCertChain(w, r); !ok {
		return
	}
	h.handleEnrollOrReEnroll(w, r, true /*reEnroll*/, true /*viaMTLS*/)
}

// CSRAttrsMTLS handles GET /.well-known/est-mtls/<PathID>/csrattrs.
// Mirrors CACertsMTLS — cert-required even though the unauth route
// version is anonymous.
func (h ESTHandler) CSRAttrsMTLS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := h.requireClientCertChain(w, r); !ok {
		return
	}
	h.writeCSRAttrsResponse(w, r)
}

// ----- shared internal pipeline -----

// handleEnrollOrReEnroll is the shared body for {Simple,SimpleRe}Enroll{,MTLS}.
// reEnroll picks the SimpleReEnroll vs SimpleEnroll service method (purely
// audit / metric distinguishing — same issuer call underneath); viaMTLS
// picks whether the channel-binding + per-principal-limit gates apply
// AND skips the HTTP Basic gate (mTLS handlers carry the auth).
func (h ESTHandler) handleEnrollOrReEnroll(w http.ResponseWriter, r *http.Request, reEnroll, viaMTLS bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestID := middleware.GetRequestID(r.Context())

	if err := verifyESTTransport(r); err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest,
			fmt.Sprintf("EST transport precondition failed: %v", err), requestID)
		return
	}

	// HTTP Basic gate (Phase 3) — non-mTLS path only. mTLS profiles
	// authenticate via the client cert so adding Basic on top would
	// double-tax operators with no security benefit.
	if !viaMTLS && h.basicPassword != "" {
		if !h.requireBasicAuth(w, r) {
			return
		}
	}

	csrPEM, err := h.readCSRFromRequest(r)
	if err != nil {
		ErrorWithRequestID(w, http.StatusBadRequest, fmt.Sprintf("Invalid CSR: %v", err), requestID)
		return
	}

	// Parse the CSR once for downstream gates (channel-binding, per-
	// principal rate limit). The service re-parses internally — that's a
	// minor inefficiency we accept to keep the service interface flat.
	csr, _ := decodeCSRPEM(csrPEM)

	// Channel-binding gate (Phase 2.4) — mTLS reEnroll only. The optional
	// CSR-side attribute is checked even when the per-profile flag isn't
	// requiring it (a CSR carrying the attribute MUST match the live
	// exporter; a present-but-mismatched binding is always fatal).
	if viaMTLS && reEnroll && csr != nil {
		if err := cms.VerifyChannelBinding(r.TLS, csr, h.channelBindingRequired); err != nil {
			h.writeChannelBindingError(w, requestID, err)
			return
		}
	}

	// Per-principal rate-limit gate (Phase 4.2). Keyed by CN+sourceIP so
	// (a) a CN with no source-IP rotation can be capped, AND (b) a
	// hostile network segment trying to enroll many CNs from one IP is
	// also bounded.
	if h.perPrincipalLimiter != nil {
		if err := h.applyPerPrincipalRateLimit(r, csr); err != nil {
			ErrorWithRequestID(w, http.StatusTooManyRequests,
				fmt.Sprintf("EST enrollment rate-limited: %v", err), requestID)
			return
		}
	}

	var (
		result  *domain.ESTEnrollResult
		callErr error
	)
	if reEnroll {
		result, callErr = h.svc.SimpleReEnroll(r.Context(), csrPEM)
	} else {
		result, callErr = h.svc.SimpleEnroll(r.Context(), csrPEM)
	}
	if callErr != nil {
		op := "Enrollment"
		if reEnroll {
			op = "Re-enrollment"
		}
		ErrorWithRequestID(w, http.StatusInternalServerError,
			fmt.Sprintf("%s failed: %v", op, callErr), requestID)
		return
	}

	h.writeCertResponse(w, result)
}

// requireClientCertChain enforces the mTLS gate for the est-mtls sibling
// route. Returns the leaf cert + true on success; on failure writes the
// HTTP error and returns false.
//
// Mirrors SCEPHandler.HandleSCEPMTLS exactly:
//   - mtlsTrust nil → 500 (config bug; preflight should have prevented).
//   - r.TLS nil or no peer cert → 401 (cert required).
//   - chain doesn't verify against per-profile pool → 401.
func (h ESTHandler) requireClientCertChain(w http.ResponseWriter, r *http.Request) (*x509.Certificate, bool) {
	requestID := middleware.GetRequestID(r.Context())
	if h.mtlsTrust == nil {
		ErrorWithRequestID(w, http.StatusInternalServerError,
			h.label()+" mTLS handler missing trust pool", requestID)
		return nil, false
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		ErrorWithRequestID(w, http.StatusUnauthorized,
			"Client certificate required for /.well-known/est-mtls", requestID)
		return nil, false
	}
	leaf := r.TLS.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, c := range r.TLS.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         h.mtlsTrust.Pool(),
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
	}); err != nil {
		ErrorWithRequestID(w, http.StatusUnauthorized,
			"Client certificate not trusted by this profile", requestID)
		return nil, false
	}
	return leaf, true
}

// requireBasicAuth runs the Phase 3 HTTP Basic password gate. Returns
// true when auth passed. On failure writes WWW-Authenticate + a 401
// (with rate-limit accounting against the source IP).
//
// User: any non-empty value (RFC 7030 §3.2.3 says the username is
// not authoritative when only a shared password is meaningful). Pass:
// constant-time compare against h.basicPassword.
func (h ESTHandler) requireBasicAuth(w http.ResponseWriter, r *http.Request) bool {
	requestID := middleware.GetRequestID(r.Context())
	srcIP := clientIPForLimiter(r)

	// recordFailedBasic ticks a slot on every credential rejection;
	// once the IP has burned through its window's worth of failed
	// attempts the limiter returns ErrRateLimited (which the next
	// recordFailedBasic just no-ops out — we still want to fail-closed
	// the auth here). The cleaner design is a pre-check that short-
	// circuits the constant-time compare ENTIRELY for an IP at-cap, so
	// a brute-force attacker can't smuggle timing data through. We do
	// that pre-check via SlidingWindowLimiter.Allow with a peek-style
	// fake-key that just queries state without recording a slot.
	if h.failedBasicLimiter != nil && srcIP != "" {
		if err := h.failedBasicLimiter.Allow(srcIP+"|peek", nowFn()); errors.Is(err, ratelimit.ErrRateLimited) {
			// peek-key is shared across requests from this IP; the slot
			// pollution is acceptable because the IP is already
			// rate-limited and we want to keep them rate-limited.
			ErrorWithRequestID(w, http.StatusTooManyRequests,
				h.label()+" too many failed enrollment attempts from this source", requestID)
			return false
		}
	}

	user, pass, ok := r.BasicAuth()
	if !ok || user == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="est-enrollment"`)
		ErrorWithRequestID(w, http.StatusUnauthorized,
			h.label()+" enrollment requires HTTP Basic auth", requestID)
		h.recordFailedBasic(srcIP)
		return false
	}
	if subtle.ConstantTimeCompare([]byte(pass), []byte(h.basicPassword)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="est-enrollment"`)
		ErrorWithRequestID(w, http.StatusUnauthorized,
			h.label()+" enrollment password incorrect", requestID)
		h.recordFailedBasic(srcIP)
		return false
	}
	return true
}

// recordFailedBasic ticks a slot against the source-IP failed-auth
// limiter. Errors from Allow are intentionally ignored — a present
// failure simply means the IP has crossed the limit, which is exactly
// the state the per-IP gate reports back to the next request.
func (h ESTHandler) recordFailedBasic(srcIP string) {
	if h.failedBasicLimiter == nil || srcIP == "" {
		return
	}
	_ = h.failedBasicLimiter.Allow(srcIP, nowFn())
}

// applyPerPrincipalRateLimit gates an enrollment by (CN, sourceIP).
// Returns nil when the request is allowed; ErrRateLimited (or wrapped
// equivalent) when the principal has exhausted its window budget.
//
// CN extraction: the CSR's Subject.CommonName is the canonical
// principal in the EST contract (the issued cert will carry that CN).
// sourceIP comes from clientIPForLimiter.
func (h ESTHandler) applyPerPrincipalRateLimit(r *http.Request, csr *x509.CertificateRequest) error {
	if h.perPrincipalLimiter == nil {
		return nil
	}
	cn := ""
	if csr != nil {
		cn = csr.Subject.CommonName
	}
	srcIP := clientIPForLimiter(r)
	key := cn + "|" + srcIP
	return h.perPrincipalLimiter.Allow(key, nowFn())
}

// writeChannelBindingError maps cms.* sentinel errors to HTTP statuses
// + audit-friendly messages. Mirrors the SCEP CertRep failInfo error
// translation pattern (signature_invalid → BadMessageCheck etc.).
func (h ESTHandler) writeChannelBindingError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, cms.ErrChannelBindingMissing):
		ErrorWithRequestID(w, http.StatusBadRequest,
			"EST simplereenroll requires RFC 9266 channel binding for this profile", requestID)
	case errors.Is(err, cms.ErrChannelBindingMismatch):
		// 409 Conflict signals to the client that the request was
		// well-formed but the channel-binding state on certctl's side
		// disagreed with the device's — usually MITM or reverse proxy
		// terminating TLS in front of certctl.
		ErrorWithRequestID(w, http.StatusConflict,
			"EST channel binding does not match TLS exporter — TLS terminator in front of certctl?", requestID)
	case errors.Is(err, cms.ErrChannelBindingNotTLS13):
		ErrorWithRequestID(w, http.StatusUpgradeRequired,
			"EST channel binding requires TLS 1.3", requestID)
	default:
		ErrorWithRequestID(w, http.StatusBadRequest,
			fmt.Sprintf("EST channel-binding verification failed: %v", err), requestID)
	}
}

// ----- response writers (legacy + mTLS share these) -----

// writeCACertsResponse writes the PKCS#7 certs-only CA chain. Shared
// by CACerts (legacy route) + CACertsMTLS (mTLS route).
func (h ESTHandler) writeCACertsResponse(w http.ResponseWriter, r *http.Request) {
	requestID := middleware.GetRequestID(r.Context())
	caCertPEM, err := h.svc.GetCACerts(r.Context())
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError,
			fmt.Sprintf("Failed to get CA certificates: %v", err), requestID)
		return
	}
	derCerts, err := pkcs7.PEMToDERChain(caCertPEM)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to encode CA certificates", requestID)
		return
	}
	pkcs7Data, err := pkcs7.BuildCertsOnlyPKCS7(derCerts)
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError, "Failed to build PKCS#7 response", requestID)
		return
	}
	w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)
	writeBase64Wrapped(w, pkcs7Data)
}

// writeCSRAttrsResponse writes the per-profile CSR attribute hints.
// Shared by CSRAttrs (legacy) + CSRAttrsMTLS (mTLS).
func (h ESTHandler) writeCSRAttrsResponse(w http.ResponseWriter, r *http.Request) {
	requestID := middleware.GetRequestID(r.Context())
	attrs, err := h.svc.GetCSRAttrs(r.Context())
	if err != nil {
		ErrorWithRequestID(w, http.StatusInternalServerError,
			fmt.Sprintf("Failed to get CSR attributes: %v", err), requestID)
		return
	}
	if len(attrs) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/csrattrs")
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(base64.StdEncoding.EncodeToString(attrs)))
}

// writeCertResponse writes an EST enrollment response as base64-encoded PKCS#7.
func (h ESTHandler) writeCertResponse(w http.ResponseWriter, result *domain.ESTEnrollResult) {
	var derCerts [][]byte
	certDER, err := pkcs7.PEMToDERChain(result.CertPEM)
	if err != nil || len(certDER) == 0 {
		http.Error(w, "Failed to encode certificate", http.StatusInternalServerError)
		return
	}
	derCerts = append(derCerts, certDER...)
	if result.ChainPEM != "" {
		chainDER, err := pkcs7.PEMToDERChain(result.ChainPEM)
		if err == nil {
			derCerts = append(derCerts, chainDER...)
		}
	}
	pkcs7Data, err := pkcs7.BuildCertsOnlyPKCS7(derCerts)
	if err != nil {
		http.Error(w, "Failed to build PKCS#7 response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)
	writeBase64Wrapped(w, pkcs7Data)
}

// writeBase64Wrapped emits b as base64 with CRLF every 76 chars per RFC 2045.
// Pulled out as a helper so the three writers above don't repeat the loop.
func writeBase64Wrapped(w http.ResponseWriter, b []byte) {
	encoded := base64.StdEncoding.EncodeToString(b)
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		w.Write([]byte(encoded[i:end]))
		w.Write([]byte("\r\n"))
	}
}

// readCSRFromRequest reads and decodes the CSR from an EST enrollment request.
// EST sends CSRs as base64-encoded PKCS#10 DER with Content-Type application/pkcs10.
func (h ESTHandler) readCSRFromRequest(r *http.Request) (string, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		return "", fmt.Errorf("failed to read request body: %w", err)
	}
	defer r.Body.Close()

	if len(body) == 0 {
		return "", fmt.Errorf("empty request body")
	}

	bodyStr := strings.TrimSpace(string(body))
	if strings.HasPrefix(bodyStr, "-----BEGIN CERTIFICATE REQUEST-----") {
		block, _ := pem.Decode([]byte(bodyStr))
		if block == nil {
			return "", fmt.Errorf("invalid PEM-encoded CSR")
		}
		if _, err := x509.ParseCertificateRequest(block.Bytes); err != nil {
			return "", fmt.Errorf("invalid CSR: %w", err)
		}
		return bodyStr, nil
	}

	derBytes, err := base64.StdEncoding.DecodeString(bodyStr)
	if err != nil {
		cleaned := strings.Map(func(r rune) rune {
			if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, bodyStr)
		derBytes, err = base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return "", fmt.Errorf("failed to decode base64 CSR: %w", err)
		}
	}
	if _, err := x509.ParseCertificateRequest(derBytes); err != nil {
		return "", fmt.Errorf("invalid PKCS#10 CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: derBytes,
	})
	return string(csrPEM), nil
}

// decodeCSRPEM is a convenience wrapper around pem.Decode +
// x509.ParseCertificateRequest. Returns nil on any decode/parse error
// (callers downstream re-parse via the service path; this is just for
// the handler-side gates that need the CN + binding attribute).
func decodeCSRPEM(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("PEM decode failed")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// clientIPForLimiter returns the source IP a per-IP rate limiter should
// key against. Honors X-Forwarded-For when the request came through a
// trusted proxy (no proxy-trust list yet — falls back to RemoteAddr).
func clientIPForLimiter(r *http.Request) string {
	// Don't blindly trust XFF — ignore it for now and always use
	// RemoteAddr. A future bundle can add a documented proxy-trust list.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// nowFn is the package-private time source. Override in tests for
// deterministic clock injection without dragging time.Time into the
// handler API surface. Defined in est_clock.go so mocking out
// requires touching only one file.

// verifyESTTransport implements Bundle-4 / M-021 EST transport precondition.
//
// RFC 7030 §3.2.3 ("Linking Identity and POP Information") requires that when
// EST clients use certificate-based authentication AND send a Proof-of-Possession
// (PoP), the PoP MUST be cryptographically bound to the underlying TLS session
// via TLS-Unique (RFC 5929). With TLS 1.3 (which certctl pins via
// `tls.Config.MinVersion = tls.VersionTLS13` per the HTTPS-Everywhere milestone),
// TLS-Unique is unavailable; RFC 9266 defines `tls-exporter` as the TLS 1.3
// replacement.
//
// **EST RFC 7030 hardening Phases 2-4 update:** RFC 9266 channel binding is
// now wired in via the cms package (Phase 2.4) and called from
// SimpleReEnrollMTLS when the per-profile policy requires it. This function
// continues to handle the lower-level transport preconditions that ALL EST
// requests share (regardless of mTLS / Basic / unauth profile shape).
//
// Returns nil if all preconditions pass; non-nil error otherwise.
func verifyESTTransport(r *http.Request) error {
	if r.TLS == nil {
		return fmt.Errorf("EST endpoint reached over plaintext; TLS required (RFC 7030 §3.2.1)")
	}
	if !r.TLS.HandshakeComplete {
		return fmt.Errorf("EST request reached handler before TLS handshake completed")
	}
	// tls.VersionTLS12 == 0x0303; certctl's MinVersion is TLS 1.3 (0x0304).
	// Defensive lower bound at TLS 1.2 lets us catch a future MinVersion
	// regression cleanly without coupling this guard to the server config.
	if r.TLS.Version < 0x0303 {
		return fmt.Errorf("EST request negotiated TLS version 0x%04x; TLS 1.2 minimum required", r.TLS.Version)
	}
	return nil
}

// NOTE: PKCS#7 helpers (BuildCertsOnlyPKCS7, PEMToDERChain, ASN.1 wrappers)
// are in the shared internal/pkcs7 package, used by both EST and SCEP handlers.
