// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/certctl-io/certctl/internal/api/handler"
	oidcdomain "github.com/certctl-io/certctl/internal/auth/oidc/domain"
	"github.com/certctl-io/certctl/internal/auth/session"
	userdomain "github.com/certctl-io/certctl/internal/auth/user/domain"
	"github.com/certctl-io/certctl/internal/domain"
	authdomainAlias "github.com/certctl-io/certctl/internal/domain/auth"
	"github.com/certctl-io/certctl/internal/repository"
	"github.com/certctl-io/certctl/internal/repository/postgres"
	"github.com/certctl-io/certctl/internal/scep/intune"
	"github.com/certctl-io/certctl/internal/service"
	authsvc "github.com/certctl-io/certctl/internal/service/auth"
	"github.com/certctl-io/certctl/internal/trustanchor"
)

// Phase 9 ARCH-M2 closure Sprint 8 (2026-05-14): extracted from
// cmd/server/main.go. Different shape from the config.go cuts —
// the move is by FUNCTIONAL CONCERN (boot-time preflight + DI
// adapter wiring), not by TYPE FAMILY.
//
// Sprint 8 ships TWO of the three files the Phase 9 prompt names:
//   - main.go      — entrypoint (unchanged; what's left after the cut)
//   - wire.go      — this file (DI assembly: preflight helpers +
//                    adapter types that bridge package boundaries)
//
// The third file the prompt names — migrations.go — is NOT in this
// commit. See "What's NOT in this sprint" below for the deferral
// rationale.
//
// What lives here
// ===============
// Seven preflight + DI helper functions:
//   - preflightSCEPChallengePassword   (H-2 fix: SCEP needs non-empty
//                                       shared secret if enabled)
//   - preflightSCEPMTLSTrustBundle     (SCEP Phase 6.5: per-profile
//                                       mTLS CA bundle validation)
//   - preflightESTMTLSClientCATrustBundle (EST Phase 2.5: same shape,
//                                       returns SIGHUP-reloadable
//                                       *trustanchor.Holder)
//   - preflightSCEPIntuneTrustAnchor   (SCEP Phase 8.2: Intune
//                                       Connector signing-cert bundle)
//   - loadSCEPRAPair                   (post-preflight cert+key load)
//   - preflightSCEPRACertKey           (RA cert/key validation: file
//                                       mode 0600, cert+key match,
//                                       NotAfter, RSA-or-ECDSA alg)
//   - preflightEnrollmentIssuer        (L-005: EST/SCEP issuer can
//                                       serve GetCACertPEM)
//   - buildFinalHandler                (M-001 option D: HTTP dispatch
//                                       wrapper routing
//                                       authenticated vs no-auth
//                                       chains by URL prefix)
//
// Five adapter types that bridge package boundaries (avoid import
// cycles between internal/auth, internal/service/auth,
// internal/api/handler, internal/auth/oidc, internal/auth/session,
// internal/auth/breakglass):
//   - authPermissionCheckerAdapter      (typed-string → plain-string
//                                        auth.PermissionChecker
//                                        interface)
//   - authCheckResolverAdapter          (postgres ActorRoleRepository
//                                        → handler.AuthCheckResolver)
//   - sessionMinterAdapter              (session.Service → OIDC
//                                        SessionMinter port)
//   - breakglassSessionMinterAdapter    (session.Service → breakglass
//                                        SessionMinter port + audit
//                                        2026-05-10 HIGH-1 revoke-all)
//   - oidcProvidersListAdapter          (postgres OIDCProviderRepository
//                                        → handler.OIDCProvidersListResolver
//                                        with MED-9 enabled-filter)
//
// Plus the silenceUnusedImports var-block that pins
// oidcdomain.OIDCProvider as a load-bearing reference (the adapter
// types use *userdomain.User and repository.OIDCProviderRepository
// indirectly; oidcdomain.OIDCProvider isn't named in any function
// signature here but is part of the Phase 3 SessionMinter contract).
//
// What's NOT in this sprint (and why)
// ===================================
// migrations.go is deferred. The Phase 9 prompt asks for three files:
// main.go (entrypoint) + wire.go (this file) + migrations.go (boot-
// time migration handling). The migration code (Phase 4 DEPL-M1
// --migrate-only flag handling + RunMigrations + RunSeed call +
// CERTCTL_MIGRATIONS_VIA_HOOK gating) lives INLINE inside the 2300-
// line main() function — lines ~59-264 in the original — not as a
// standalone helper.
//
// Extracting it into a migrations.go would require:
//   1. Creating a new unexported function (e.g.,
//      runMigrations(ctx, cfg, db, logger) error) that consolidates
//      lines ~71-77 (--migrate-only parse) + ~199-248 (the migration
//      branch + --migrate-only early-exit) + ~250-264 (the demo
//      overlay seed branch).
//   2. Replacing the inline block in main() with a single call.
//   3. Threading the early-exit semantics out (os.Exit(0) vs return
//      "migration done" sentinel error vs a third option) so main's
//      defer ordering doesn't change.
//
// That's behavior-change territory — a new function call frame, a
// new defer scope, error-handling pattern shift. Different risk
// shape from the pure-data type relocations Sprints 1-7 did. The
// Phase 9 prompt says "Do NOT change exported type signatures; the
// refactor is mechanical relocation; behavior change is a separate
// concern." Extracting an inline block from main() into a new
// function is the same shape of risk that rule was guarding against.
//
// Recommended path for the migrations.go cut:
//   - Land it as a separate, smaller PR with its own review focus
//     (the runMigrations function shape, the early-exit semantics,
//     unit tests for the new function via the existing main_test.go
//     fixture). The infrastructure for the PR exists today; only
//     the operator's go-ahead on the behavior-change risk is needed.
//   - Estimated impact: another ~80-120 LOC out of main.go (the
//     migration + seed + early-exit block) into a new migrations.go.
//   - Phase 4's --migrate-only code path already runs through this
//     code section, so the extracted function should reproduce that
//     exact flow without behavior change beyond the call-frame
//     introduction.
//
// Public-surface invariant
// ========================
// The moved helpers + adapter types are all in package `main`
// (which Go cannot expose to external importers). No exported
// surface changes. The reorganization is invisible outside
// cmd/server/. Same-package callers in main.go (preflight*
// invocations, adapter instantiation) resolve via the package
// symbol table without modification.

// preflightSCEPChallengePassword enforces the H-2 fix: if SCEP is enabled, a
// non-empty challenge password MUST be configured. Returns a non-nil error
// otherwise so the caller can refuse to start the control plane (CWE-306,
// missing authentication for a critical function).
//
// This helper is extracted so the check can be unit tested without booting
// the full server. The caller (main) is responsible for translating the
// returned error into a structured log line and os.Exit(1).
func preflightSCEPChallengePassword(enabled bool, challengePassword string) error {
	if !enabled {
		return nil
	}
	if challengePassword == "" {
		return fmt.Errorf("SCEP enabled but CERTCTL_SCEP_CHALLENGE_PASSWORD is empty: " +
			"SCEP enrollment would accept any client (CWE-306); " +
			"configure a non-empty shared secret or set CERTCTL_SCEP_ENABLED=false")
	}
	return nil
}

// preflightSCEPMTLSTrustBundle validates a per-profile mTLS client-CA
// trust bundle. SCEP RFC 8894 + Intune master bundle Phase 6.5.
//
// Mirrors preflightSCEPRACertKey's no-op-when-disabled pattern; otherwise
// the checks are:
//
//  1. Path is non-empty (the Validate() refuse covers this too, but
//     preflight reports the specific failure with an actionable error
//     string + os.Exit(1) at the call site).
//  2. File exists + readable.
//  3. PEM-decodes to ≥1 CERTIFICATE block.
//  4. None of the bundled certs is past NotAfter — an expired trust
//     anchor would silently reject every client cert at runtime.
//
// On success, returns the parsed *x509.CertPool ready to inject into the
// per-profile SCEPHandler via SetMTLSTrustPool. Each bundled cert also
// contributes to the union pool that backs the TLS-layer
// VerifyClientCertIfGiven.
func preflightSCEPMTLSTrustBundle(enabled bool, bundlePath string) (*x509.CertPool, error) {
	if !enabled {
		return nil, nil
	}
	if bundlePath == "" {
		return nil, fmt.Errorf("MTLS enabled but trust bundle path empty: " +
			"set CERTCTL_SCEP_PROFILE_<NAME>_MTLS_CLIENT_CA_TRUST_BUNDLE_PATH to a PEM file " +
			"containing the bootstrap-CA certs the operator allows to enroll")
	}
	body, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("read MTLS trust bundle: %w (path=%s)", err, bundlePath)
	}
	pool := x509.NewCertPool()
	rest := body
	count := 0
	now := time.Now()
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse MTLS trust bundle cert: %w (path=%s)", err, bundlePath)
		}
		if now.After(cert.NotAfter) {
			return nil, fmt.Errorf("MTLS trust bundle cert expired at %s (subject=%q, path=%s) — replace before restart",
				cert.NotAfter.Format(time.RFC3339), cert.Subject.CommonName, bundlePath)
		}
		pool.AddCert(cert)
		count++
	}
	if count == 0 {
		return nil, fmt.Errorf("MTLS trust bundle contained no CERTIFICATE PEM blocks (path=%s)", bundlePath)
	}
	return pool, nil
}

// preflightESTMTLSClientCATrustBundle validates a per-profile EST mTLS
// client-CA trust bundle and returns a SIGHUP-reloadable holder.
//
// EST RFC 7030 hardening master bundle Phase 2.5.
//
// Mirrors preflightSCEPMTLSTrustBundle's checks (file exists, parses as
// PEM, ≥1 cert, none expired) but returns a *trustanchor.Holder rather
// than a raw *x509.CertPool — the EST handler stores the holder so a
// SIGHUP rotates the trust bundle live without a server restart, exactly
// the way the Intune trust anchor rotation works (Phase 8.5 of the SCEP
// bundle). The handler-side .Pool() accessor on the holder rebuilds an
// x509.CertPool from the current snapshot for each Verify call.
//
// Uses the shared internal/trustanchor.LoadBundle (extracted in EST
// hardening Phase 2.1 from the original Intune-only path) so the EST
// + Intune callers exercise the same loader semantics — empty bundle
// rejected, expired cert rejected with subject in error message,
// non-CERTIFICATE PEM blocks tolerated.
func preflightESTMTLSClientCATrustBundle(enabled bool, pathID, bundlePath string, logger *slog.Logger) (*trustanchor.Holder, error) {
	if !enabled {
		return nil, nil
	}
	if bundlePath == "" {
		return nil, fmt.Errorf("EST profile (PathID=%q) MTLS enabled but trust bundle path empty: "+
			"set CERTCTL_EST_PROFILE_<NAME>_MTLS_CLIENT_CA_TRUST_BUNDLE_PATH to a PEM file "+
			"containing the bootstrap-CA certs the operator allows to enroll", pathID)
	}
	holder, err := trustanchor.New(bundlePath, logger)
	if err != nil {
		return nil, fmt.Errorf("EST profile (PathID=%q) MTLS trust bundle preflight: %w", pathID, err)
	}
	holder.SetLabelForLog(fmt.Sprintf("EST mTLS client CA bundle (PathID=%q)", pathID))
	return holder, nil
}

// preflightSCEPIntuneTrustAnchor validates a per-profile Microsoft Intune
// Certificate Connector signing-cert trust bundle.
//
// SCEP RFC 8894 + Intune master bundle Phase 8.2.
//
// No-op when this profile has Intune disabled (the common case for
// non-Intune SCEP deploys). When enabled:
//
//  1. Path is non-empty (Validate() refuse covers this too; we re-check
//     here so the caller can os.Exit(1) with the specific PathID in the
//     log line).
//  2. File exists + readable.
//  3. PEM-decodes to ≥1 CERTIFICATE block (intune.LoadTrustAnchor enforces
//     this and skips non-CERTIFICATE blocks like accidentally-pasted
//     priv-key blocks).
//  4. None of the bundled certs is past NotAfter — an expired Intune
//     trust anchor would silently reject every Connector challenge at
//     runtime, which is a much worse failure mode than failing fast at
//     boot. intune.LoadTrustAnchor enforces this and surfaces the subject
//     CN in the error message so the operator knows which cert to rotate.
//
// On success returns the freshly-built *intune.TrustAnchorHolder ready to
// inject into the per-profile SCEPService via SetIntuneIntegration. The
// holder also installs the SIGHUP watcher (started by the caller).
func preflightSCEPIntuneTrustAnchor(enabled bool, pathID, path string, logger *slog.Logger) (*intune.TrustAnchorHolder, error) {
	if !enabled {
		return nil, nil
	}
	// pathIDLabel renders the empty-string PathID as "<root>" so the
	// operator's boot-log error doesn't read like a missing variable.
	pathIDLabel := pathID
	if pathIDLabel == "" {
		pathIDLabel = "<root>"
	}
	if path == "" {
		return nil, fmt.Errorf("SCEP profile (PathID=%q) INTUNE enabled but trust anchor path empty: "+
			"set CERTCTL_SCEP_PROFILE_<NAME>_INTUNE_CONNECTOR_CERT_PATH to a PEM bundle "+
			"of the Microsoft Intune Certificate Connector's signing certs", pathIDLabel)
	}
	holder, err := intune.NewTrustAnchorHolder(path, logger)
	if err != nil {
		return nil, fmt.Errorf("SCEP profile (PathID=%q) INTUNE trust anchor load failed: %w (path=%s)", pathIDLabel, err, path)
	}
	return holder, nil
}

// loadSCEPRAPair reads the RA cert PEM + key PEM and returns the parsed
// x509.Certificate + crypto.PrivateKey ready for the SCEP handler's RFC
// 8894 path. Called AFTER preflightSCEPRACertKey passed; failures here
// indicate a TOCTOU race or a filesystem change between preflight and
// the load (rare).
//
// Cert PEM may carry a chain (CA + RA + intermediate); we use the FIRST
// CERTIFICATE block, matching the RFC 8894 §3.5.1 single-cert convention
// for the GetCACert response.
func loadSCEPRAPair(certPath, keyPath string) (*x509.Certificate, crypto.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read RA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read RA key: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse RA pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, nil, fmt.Errorf("RA cert PEM contained no certificate blocks")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse RA cert: %w", err)
	}
	return leaf, pair.PrivateKey, nil
}

// preflightSCEPRACertKey validates the RA cert/key pair the RFC 8894 SCEP
// path requires. Mirrors preflightSCEPChallengePassword's no-op-when-disabled
// pattern; otherwise the checks are:
//
//  1. Both paths are non-empty (the Validate() refuse covers this too,
//     but preflight reports the specific failure mode + os.Exit(1) so the
//     operator sees a clear log line in addition to the config error).
//  2. The key file mode is 0600 (refuse world-/group-readable RA key —
//     defense-in-depth against credential leak via a misconfigured
//     deploy that leaves /etc/certctl/scep/*.key as 0644).
//  3. Cert PEM parses to exactly one x509.Certificate.
//  4. Key PEM parses to a Go crypto.Signer (RSA or ECDSA — RFC 8894
//     §3.5.2 advertises those as the CMS-compatible algorithms).
//  5. The cert's PublicKey matches the key's Public() — refuses pairs
//     accidentally swapped between profiles in a multi-profile config.
//  6. The cert's NotAfter is in the future — an expired RA cert would
//     fail TLS handshake on EnvelopedData decryption per RFC 5652.
//
// Each check returns a wrapped error; the caller (main) is responsible for
// translating to a structured slog.Error + os.Exit(1) so the helper stays
// unit-testable without booting the full server.
func preflightSCEPRACertKey(enabled bool, raCertPath, raKeyPath string) error {
	if !enabled {
		return nil
	}
	if raCertPath == "" || raKeyPath == "" {
		return fmt.Errorf("SCEP enabled but RA pair missing: " +
			"set CERTCTL_SCEP_RA_CERT_PATH + CERTCTL_SCEP_RA_KEY_PATH " +
			"(RFC 8894 §3.2.2 requires an RA pair so clients can encrypt the " +
			"CSR to the RA cert and the server can sign the CertRep response)")
	}

	// File mode check FIRST so a world-readable key never gets read into the
	// process address space. Ignored on Windows (Stat().Mode() doesn't carry
	// POSIX bits there); the production deploy is Linux per the Dockerfile.
	keyInfo, err := os.Stat(raKeyPath)
	if err != nil {
		return fmt.Errorf("CERTCTL_SCEP_RA_KEY_PATH stat failed: %w (path=%s)", err, raKeyPath)
	}
	mode := keyInfo.Mode().Perm()
	if mode&0o077 != 0 {
		return fmt.Errorf("CERTCTL_SCEP_RA_KEY_PATH has insecure permissions %#o; "+
			"RA private key must be mode 0600 (owner read/write only) — "+
			"chmod 0600 %s and restart", mode, raKeyPath)
	}

	certPEM, err := os.ReadFile(raCertPath)
	if err != nil {
		return fmt.Errorf("CERTCTL_SCEP_RA_CERT_PATH read failed: %w (path=%s)", err, raCertPath)
	}
	keyPEM, err := os.ReadFile(raKeyPath)
	if err != nil {
		return fmt.Errorf("CERTCTL_SCEP_RA_KEY_PATH read failed: %w (path=%s)", err, raKeyPath)
	}

	// tls.X509KeyPair validates that the cert + key parse, share an algorithm,
	// and the cert's PublicKey matches the key's Public() — three of our six
	// checks in a single stdlib call, so we use it rather than re-implementing.
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("RA cert/key pair invalid: %w "+
			"(cert=%s key=%s) — verify the cert and key are matching halves of "+
			"the same RA pair, both PEM-encoded, with the cert containing exactly "+
			"one CERTIFICATE block and the key containing one PRIVATE KEY block",
			err, raCertPath, raKeyPath)
	}
	if len(pair.Certificate) == 0 {
		// Defensive — tls.X509KeyPair already errors on this, but the contract
		// for the next x509.ParseCertificate call needs the slice non-empty.
		return fmt.Errorf("RA cert PEM at %s contains no certificate blocks", raCertPath)
	}

	// Re-parse the leaf so we can read NotAfter + the public-key alg.
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("RA cert at %s does not parse as x509: %w", raCertPath, err)
	}
	if time.Now().After(leaf.NotAfter) {
		return fmt.Errorf("RA cert at %s expired at %s — "+
			"generate a fresh RA pair (the SCEP CertRep signature would be "+
			"rejected by every conformant client)", raCertPath, leaf.NotAfter.Format(time.RFC3339))
	}

	// CMS-compatible public-key algorithm gate. RFC 8894 §3.5.2 advertises RSA
	// and AES; the responder cert algorithm pertains to the signature scheme
	// used on the CertRep, which means the cert's PublicKey must be RSA or
	// ECDSA. Catches pre-shared Ed25519 dev keys that micromdm/scep clients
	// reject.
	switch leaf.PublicKeyAlgorithm {
	case x509.RSA, x509.ECDSA:
		// ok — supported by golang.org/x/crypto/ocsp + every SCEP client
	default:
		return fmt.Errorf("RA cert at %s uses unsupported public-key algorithm %s — "+
			"RFC 8894 §3.5.2 CMS signing requires RSA or ECDSA",
			raCertPath, leaf.PublicKeyAlgorithm)
	}

	return nil
}

// preflightEnrollmentIssuer validates at startup that an EST/SCEP-bound issuer
// can actually serve a CA certificate. This closes audit finding L-005:
// pre-Bundle-4 the EST/SCEP startup path verified the issuer existed in the
// registry but did not verify the issuer TYPE could emit a CA cert. An
// operator who bound CERTCTL_EST_ISSUER_ID to an ACME issuer (which does
// not have a static CA cert — see internal/connector/issuer/acme/acme.go::
// GetCACertPEM returning an explicit error) would boot successfully and
// only see failures at the first /est/cacerts request, hiding the misconfig
// for hours/days behind a degraded enrollment surface.
//
// Strategy: call issuerConn.GetCACertPEM(ctx) at startup with a short
// timeout. If the issuer can serve a CA cert (local, vault, openssl,
// stepca, awsacmpca, etc.), the call succeeds and we proceed. If not
// (acme, digicert, sectigo, entrust, googlecas, ejbca, globalsign — most
// vendor-CA issuers that hand back chains per-issuance), the call fails
// loudly with the connector's own error string, and the caller os.Exit(1)s.
//
// Returns nil on success, non-nil error suitable for structured logging
// + os.Exit(1) by the caller. Caller is responsible for the timeout context.
func preflightEnrollmentIssuer(ctx context.Context, protocol, issuerID string, issuerConn service.IssuerConnector) error {
	if issuerConn == nil {
		return fmt.Errorf("%s issuer %q: connector is nil", protocol, issuerID)
	}
	caCertPEM, err := issuerConn.GetCACertPEM(ctx)
	if err != nil {
		return fmt.Errorf("%s issuer %q: cannot serve CA certificate (%w); "+
			"choose an issuer type that exposes a static CA chain "+
			"(local / vault / openssl / stepca / awsacmpca) or disable %s",
			protocol, issuerID, err, protocol)
	}
	if caCertPEM == "" {
		return fmt.Errorf("%s issuer %q: GetCACertPEM returned empty PEM with no error; "+
			"choose an issuer type that exposes a static CA chain", protocol, issuerID)
	}
	return nil
}

// buildFinalHandler builds the outer HTTP dispatch handler that routes incoming
// requests to either the authenticated apiHandler chain or the unauthenticated
// noAuthHandler chain based on URL path prefix. Extracted from main() so the
// dispatch logic can be unit tested without booting the full server stack
// (see cmd/server/finalhandler_test.go).
//
// Dispatch rules (M-001, audit 2026-04-19, option D):
//
//   - /health, /ready, /api/v1/auth/info           → no-auth (probes + login detection)
//   - /api/v1/version                              → no-auth (U-3 ride-along: build identity for rollout/probes)
//   - /.well-known/pki/*                           → no-auth (RFC 5280 CRL, RFC 6960 OCSP)
//   - /.well-known/est/*                           → no-auth (RFC 7030 §3.2.3)
//   - /scep, /scep/*                               → no-auth (RFC 8894 §3.2, CSR challengePassword)
//   - /api/v1/*                                    → auth (Bearer token required)
//   - /assets/*                                    → static file server (dashboard only)
//   - anything else                                → SPA index.html fallback (dashboard only)
//     OR apiHandler (no dashboard)
//
// EST/SCEP clients (IoT devices, 802.1X supplicants, MDM endpoints, network
// appliances) cannot present certctl Bearer tokens, so those endpoints must be
// reachable without the Auth middleware. Authentication is instead enforced by
// CSR signature verification, profile policy gates, and for SCEP the
// challengePassword shared secret (fail-loud gated by preflightSCEPChallengePassword
// above).
//
// webDir must point to a directory containing index.html + assets/ when
// dashboardEnabled is true; it is ignored otherwise.
func buildFinalHandler(apiHandler, noAuthHandler http.Handler, webDir string, dashboardEnabled bool) http.Handler {
	var fileServer http.Handler
	if dashboardEnabled {
		fileServer = http.FileServer(http.Dir(webDir))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Health/ready, auth/info, and version bypass auth middleware.
		// Health/ready: Docker/K8s health probes don't carry Bearer tokens.
		// auth/info: React app calls this before login to detect auth mode.
		// version: U-3 ride-along (cat-u-no_version_endpoint) — rollout
		// systems and blackbox probes need build identity without a key.
		if path == "/health" || path == "/ready" || path == "/api/v1/auth/info" || path == "/api/v1/version" {
			noAuthHandler.ServeHTTP(w, r)
			return
		}

		// RFC 5280 CRL and RFC 6960 OCSP live under /.well-known/pki/ and MUST
		// be served unauthenticated — relying parties (browsers, OpenSSL, OCSP
		// stapling sidecars, mTLS clients) cannot present certctl Bearer tokens.
		if strings.HasPrefix(path, "/.well-known/pki") {
			noAuthHandler.ServeHTTP(w, r)
			return
		}

		// RFC 7030 EST endpoints ride the no-auth middleware chain (M-001,
		// option D, audit 2026-04-19). Trust boundary is CSR signature +
		// (per EST hardening Phase 2) optional client cert at the handler
		// layer, not HTTP Bearer. /.well-known/est/cacerts is explicitly
		// anonymous per RFC 7030 §4.1.1; /.well-known/est-mtls/<PathID>/
		// (EST hardening Phase 2 sibling route) requires a client cert
		// gate at the handler layer — both share this prefix gate because
		// "/.well-known/est-mtls" is itself prefixed by "/.well-known/est".
		// EST hardening Phase 3's HTTP Basic enrollment-password is a
		// per-profile handler-layer auth that runs INSIDE the no-auth
		// middleware chain (since the chain skips the Bearer middleware,
		// the handler gets to define its own auth contract).
		if strings.HasPrefix(path, "/.well-known/est") {
			noAuthHandler.ServeHTTP(w, r)
			return
		}

		// RFC 8894 SCEP rides the no-auth chain (M-001, option D). SCEP clients
		// authenticate via the challengePassword attribute in the PKCS#10 CSR,
		// not via HTTP Bearer tokens. preflightSCEPChallengePassword refuses to
		// start the server if SCEP is enabled without a non-empty shared secret.
		//
		// SCEP RFC 8894 + Intune master bundle Phase 6.5: the sibling
		// /scep-mtls[/<pathID>] route also rides the no-auth chain. Its
		// auth boundary is (a) client cert verified at the TLS layer +
		// re-verified per-profile at the handler layer, plus (b) the
		// challenge password — neither is a Bearer token. The /scepxyz
		// vs /scep-mtls disambiguation: 'xyz' starts with a letter so the
		// HasPrefix(path, "/scep/") gate doesn't match it; 'mtls' is its
		// own dedicated prefix gated below to avoid the same overlap.
		if path == "/scep" || strings.HasPrefix(path, "/scep/") {
			noAuthHandler.ServeHTTP(w, r)
			return
		}
		if path == "/scep-mtls" || strings.HasPrefix(path, "/scep-mtls/") {
			noAuthHandler.ServeHTTP(w, r)
			return
		}

		// Authenticated API routes — full middleware stack including Auth.
		if strings.HasPrefix(path, "/api/v1/") {
			apiHandler.ServeHTTP(w, r)
			return
		}

		if !dashboardEnabled {
			// No dashboard: everything non-special falls through to the
			// authenticated handler (preserves pre-M-001 behavior for API-only
			// deployments).
			apiHandler.ServeHTTP(w, r)
			return
		}

		// Dashboard-present: serve static assets directly, SPA fallback for
		// everything else.
		if strings.HasPrefix(path, "/assets/") {
			fileServer.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, webDir+"/index.html")
	})
}

// authPermissionCheckerAdapter bridges the typed-string Authorizer
// signature (authsvc.Authorizer.CheckPermission takes
// authdomain.ActorTypeValue + authdomain.ScopeType) to the plain-string
// auth.PermissionChecker interface used by the auth.RequirePermission
// middleware factory. Lives in cmd/server so internal/auth doesn't have
// to import internal/service/auth + internal/domain/auth (would create
// a cycle).
type authPermissionCheckerAdapter struct {
	a *authsvc.Authorizer
}

func (ad authPermissionCheckerAdapter) CheckPermission(
	ctx context.Context,
	actorID string,
	actorType string,
	tenantID string,
	permission string,
	scopeType string,
	scopeID *string,
) (bool, error) {
	return ad.a.CheckPermission(
		ctx,
		actorID,
		authdomainAlias.ActorTypeValue(actorType),
		tenantID,
		permission,
		authdomainAlias.ScopeType(scopeType),
		scopeID,
	)
}

// authCheckResolverAdapter bridges the postgres ActorRoleRepository
// (authdomain.ActorTypeValue) to handler.AuthCheckResolver
// (domain.ActorType). Lives in cmd/server so the handler layer keeps its
// existing import set; the GUI's /v1/auth/check probe round-trips
// through this on every page load. Read-only — no caller / no audit row.
//
// Bundle 1 Phase 3 closure (M1): the equivalent surface area on
// /v1/auth/me runs through the service layer's auth.role.list permission
// gate, which the GUI may not yet hold during initial render. AuthCheck
// has no permission gate (its only requirement is "the request
// authenticated"), so the bypass is by design.
type authCheckResolverAdapter struct {
	repo *postgres.ActorRoleRepository
}

func (ad authCheckResolverAdapter) ListRoles(
	ctx context.Context,
	actorID string,
	actorType domain.ActorType,
	tenantID string,
) ([]*authdomainAlias.ActorRole, error) {
	return ad.repo.ListByActor(ctx, actorID, authdomainAlias.ActorTypeValue(actorType), tenantID)
}

func (ad authCheckResolverAdapter) EffectivePermissions(
	ctx context.Context,
	actorID string,
	actorType domain.ActorType,
	tenantID string,
) ([]repository.EffectivePermission, error) {
	return ad.repo.EffectivePermissions(ctx, actorID, authdomainAlias.ActorTypeValue(actorType), tenantID)
}

// =============================================================================
// sessionMinterAdapter — bridge from *session.Service to oidcsvc.SessionMinter.
//
// The OIDC service's SessionMinter port (Phase 3) takes a *userdomain.User
// + role IDs and returns (cookie, csrf, err). The session.Service's
// Create method takes (actorID, actorType, ip, ua) -> *CreateResult.
// This adapter unwraps the User into actorID/actorType + reshapes the
// return tuple. Lives in cmd/server so the session package doesn't have
// to know about user.User and the user package doesn't have to know
// about session.CreateResult.
// =============================================================================

type sessionMinterAdapter struct {
	svc *session.Service
}

func (a *sessionMinterAdapter) MintForUser(
	ctx context.Context,
	user *userdomain.User,
	_ []string, // roleIDs unused at the session-mint layer; the rbac middleware looks them up at request time
	ip, userAgent string,
) (cookieValue, csrfToken string, err error) {
	if user == nil {
		return "", "", fmt.Errorf("session mint: user is nil")
	}
	res, err := a.svc.Create(ctx, user.ID, string(domain.ActorTypeUser), ip, userAgent)
	if err != nil {
		return "", "", err
	}
	return res.CookieValue, res.CSRFToken, nil
}

// silenceUnusedImports keeps the new oidcsvc + oidcdomain imports load-
// bearing in case any file shuffles. Linker dead-code elimination handles
// the runtime cost.
var (
	_ = oidcdomain.OIDCProvider{}
)

// =============================================================================
// breakglassSessionMinterAdapter — bridge from *session.Service to
// breakglass.SessionMinter.
//
// The break-glass service's SessionMinter port (Phase 7.5) returns
// (cookie, csrf, err); the underlying *session.Service.Create returns
// *CreateResult. This adapter unwraps the result. Lives in cmd/server
// so the breakglass package doesn't have to know about session.Service.
// =============================================================================

type breakglassSessionMinterAdapter struct {
	svc *session.Service
}

func (a breakglassSessionMinterAdapter) Create(ctx context.Context, actorID, actorType, ip, userAgent string) (string, string, error) {
	res, err := a.svc.Create(ctx, actorID, actorType, ip, userAgent)
	if err != nil {
		return "", "", err
	}
	return res.CookieValue, res.CSRFToken, nil
}

// RevokeAllForActor — Audit 2026-05-10 HIGH-1 wire. After a break-glass
// password rotation or credential removal, every active session for the
// target actor must be revoked so a phished-then-rotated credential
// doesn't leave the attacker's session live.
func (a breakglassSessionMinterAdapter) RevokeAllForActor(ctx context.Context, actorID, actorType string) error {
	return a.svc.RevokeAllForActor(ctx, actorID, actorType)
}

// oidcProvidersListAdapter bridges the postgres OIDCProviderRepository
// to handler.OIDCProvidersListResolver. The handler returns
// []*OIDCProviderInfo (id + display_name + login_url) for the public-
// safe GUI Login-page payload; the repo returns the full OIDCProvider
// row. The adapter projects + maps the login_url shape that
// /auth/oidc/login?provider=<id> expects. Auth Bundle 2 Phase 6 /
// Category E.
type oidcProvidersListAdapter struct {
	repo repository.OIDCProviderRepository
}

func (a oidcProvidersListAdapter) List(ctx context.Context, tenantID string) ([]*handler.OIDCProviderInfo, error) {
	provs, err := a.repo.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]*handler.OIDCProviderInfo, 0, len(provs))
	for _, p := range provs {
		// Audit 2026-05-10 MED-9 closure — filter disabled providers
		// at the adapter so the LoginPage's "Sign in with X" buttons
		// don't render for offline IdPs. The HandleAuthRequest
		// service-layer ErrProviderDisabled check is the
		// defense-in-depth guard for direct API / MCP / CLI callers.
		if !p.Enabled {
			continue
		}
		out = append(out, &handler.OIDCProviderInfo{
			ID:          p.ID,
			DisplayName: p.Name,
			LoginURL:    "/auth/oidc/login?provider=" + p.ID,
		})
	}
	return out, nil
}
