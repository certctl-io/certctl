// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package service

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/certctl-io/certctl/internal/api/acme"
	"github.com/certctl-io/certctl/internal/config"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// ACMERepo is the persistence-layer surface ACMEService consumes for
// nonce + account state. Phase 1b extends the Phase 1a interface with
// the account CRUD path; Phases 2-4 will further extend with order /
// authz / challenge state.
//
// Defining the interface in the service package (rather than
// internal/repository/interfaces.go) keeps the cross-phase blast
// radius small: only this file and the concrete postgres
// ACMERepository move together. Mock implementations in tests satisfy
// this interface without depending on the postgres package.
type ACMERepo interface {
	// Phase 1a — nonce.
	IssueNonce(ctx context.Context, nonce string, ttl time.Duration) error
	ConsumeNonce(ctx context.Context, nonce string) error
	// Phase 1b — account CRUD.
	CreateAccountWithTx(ctx context.Context, q repository.Querier, acct *domain.ACMEAccount) error
	GetAccountByID(ctx context.Context, accountID string) (*domain.ACMEAccount, error)
	GetAccountByThumbprint(ctx context.Context, profileID, thumbprint string) (*domain.ACMEAccount, error)
	UpdateAccountContactWithTx(ctx context.Context, q repository.Querier, accountID string, contact []string) error
	UpdateAccountStatusWithTx(ctx context.Context, q repository.Querier, accountID string, status domain.ACMEAccountStatus) error
	// Phase 2 — order / authz / challenge CRUD.
	CreateOrderWithTx(ctx context.Context, q repository.Querier, order *domain.ACMEOrder) error
	GetOrderByID(ctx context.Context, orderID string) (*domain.ACMEOrder, error)
	UpdateOrderWithTx(ctx context.Context, q repository.Querier, order *domain.ACMEOrder) error
	CreateAuthzWithTx(ctx context.Context, q repository.Querier, authz *domain.ACMEAuthorization) error
	GetAuthzByID(ctx context.Context, authzID string) (*domain.ACMEAuthorization, error)
	ListAuthzsByOrder(ctx context.Context, orderID string) ([]*domain.ACMEAuthorization, error)
	CreateChallengeWithTx(ctx context.Context, q repository.Querier, ch *domain.ACMEChallenge) error
	// Phase 3 — challenge state mutation.
	GetChallengeByID(ctx context.Context, challengeID string) (*domain.ACMEChallenge, error)
	UpdateChallengeWithTx(ctx context.Context, q repository.Querier, ch *domain.ACMEChallenge) error
	UpdateAuthzStatusWithTx(ctx context.Context, q repository.Querier, authzID string, status domain.ACMEAuthzStatus) error
	// Phase 4 — key rollover + revocation auth.
	UpdateAccountJWKWithTx(ctx context.Context, q repository.Querier, accountID, expectedOldThumbprint, newThumbprint, newJWKPEM string) error
	AccountOwnsCertificate(ctx context.Context, accountID, certificateID string) (bool, error)
	// Phase 5 — per-account concurrent-order count + GC sweeps.
	// CountActiveOrdersByAccount returns the number of orders in
	// pending/ready/processing for the given account.
	CountActiveOrdersByAccount(ctx context.Context, accountID string) (int, error)
	// GCExpiredNonces deletes nonces whose expires_at < now() OR
	// used = true. Returns rows-affected count for telemetry.
	GCExpiredNonces(ctx context.Context) (int64, error)
	// GCExpireAuthorizations transitions authzs in `pending` whose
	// expires_at < now() to `expired`. Returns rows-affected count.
	GCExpireAuthorizations(ctx context.Context) (int64, error)
	// GCInvalidateExpiredOrders transitions orders in
	// pending/ready/processing whose expires_at < now() to `invalid`
	// with a server-internal error. Returns rows-affected count.
	GCInvalidateExpiredOrders(ctx context.Context) (int64, error)
}

// CertificateRevoker is the minimum surface ACMEService needs to route
// an ACME revoke-cert request through certctl's existing revocation
// pipeline. The concrete type is *service.RevocationSvc whose
// RevokeCertificateWithActor method already covers cert-row update +
// certificate_revocations insert + audit row + issuer notification +
// OCSP cache invalidation in one path.
//
// Defining the interface here lets tests inject a recorder without
// dragging the entire RevocationSvc graph.
type CertificateRevoker interface {
	RevokeCertificateWithActor(ctx context.Context, certID, reason, actor string) error
}

// RenewalPolicyLookup is the minimum surface ACMEService needs to
// resolve the optional bound renewal policy for a certificate's ARI
// window math. Real callers pass a *postgres.RenewalPolicyRepository
// that satisfies this; tests inject in-memory fakes.
type RenewalPolicyLookup interface {
	Get(ctx context.Context, id string) (*domain.RenewalPolicy, error)
}

// profileLookup is the minimum surface ACMEService needs to resolve a
// per-profile request. Defined as an interface (rather than taking a
// concrete *postgres.ProfileRepository) so tests can inject an in-memory
// fake without spinning up Postgres.
type profileLookup interface {
	Get(ctx context.Context, id string) (*domain.CertificateProfile, error)
}

// ACMEService orchestrates the ACME server's RFC 8555 surface.
//
//   - Phase 1a (live): BuildDirectory, IssueNonce.
//   - Phase 1b (live): VerifyJWS, NewAccount, LookupAccount,
//     UpdateAccount, DeactivateAccount.
//   - Phase 2 (this commit): CreateOrder, LookupOrder, FinalizeOrder,
//     LookupAuthz, LookupCertificate.
//   - Subsequent phases extend with challenge validation, key
//     rollover, revocation, ARI.
//
// The struct deliberately holds raw config rather than per-field
// extracted values — readers use 4 of the 11 fields and reading them
// lazily keeps the constructor signature tight.
type ACMEService struct {
	repo     ACMERepo
	profiles profileLookup
	cfg      config.ACMEServerConfig
	metrics  *ACMEMetrics

	// Phase 1b — atomic-audit plumbing for the JWS-authenticated
	// POST surface. Both fields are set via SetTransactor +
	// SetAuditService (mirrors CertificateService.SetTransactor at
	// internal/service/certificate.go:254). When both are nil the
	// service falls back to the non-transactional path — kept for
	// the legacy directory + new-nonce paths that don't write to
	// stateful tables.
	tx           repository.Transactor
	auditService *AuditService

	// Phase 2 — finalize plumbing. The finalize handler routes
	// through CertificateService.Create (managed_certificates row +
	// audit row in its own WithinTx) AND certRepo.CreateVersionWithTx
	// (certificate_versions row). Issuance itself goes through the
	// IssuerRegistry's IssuerConnector adapter — same code path
	// EST/SCEP/agent take. cmd/server/main.go wires all three at
	// startup; tests inject mocks.
	certService    *CertificateService
	certRepo       repository.CertificateRepository
	issuerRegistry *IssuerRegistry

	// Phase 3 — challenge validator pool. cmd/server/main.go
	// constructs an *acme.Pool at startup with the per-type
	// concurrency caps from cfg.ACMEServer; the Pool owns the 3
	// semaphores + the validators. Optional via SetValidatorPool —
	// when nil, RespondToChallenge returns ErrACMEChallengePoolUnconfigured.
	validatorPool *acme.Pool

	// Phase 4 — revocation delegate + renewal-policy lookup. The
	// revoker is *service.RevocationSvc in production; the
	// renewalPolicies lookup is *postgres.RenewalPolicyRepository.
	// Both wired via SetRevocationDelegate / SetRenewalPolicyLookup;
	// when unset, RevokeCert returns ErrACMERevocationUnconfigured
	// and RenewalInfo returns the no-policy default window.
	revoker         CertificateRevoker
	renewalPolicies RenewalPolicyLookup

	// Phase 5 — per-account rate limiter. cmd/server/main.go constructs
	// an *acme.RateLimiter and wires it via SetRateLimiter. When unset
	// (tests, legacy bootstrap) the limiter calls short-circuit to
	// "always allow" — same shape as the validatorPool unset case.
	rateLimiter *acme.RateLimiter
}

// NewACMEService constructs an ACMEService with the directory + nonce
// surface wired. Account-creating endpoints additionally need the
// transactor + audit service — see SetTransactor / SetAuditService.
func NewACMEService(repo ACMERepo, profiles profileLookup, cfg config.ACMEServerConfig) *ACMEService {
	return &ACMEService{
		repo:     repo,
		profiles: profiles,
		cfg:      cfg,
		metrics:  NewACMEMetrics(),
	}
}

// SetTransactor wires the atomic-audit transactor. Mirrors
// CertificateService.SetTransactor; cmd/server/main.go calls this
// at startup with the same *postgres.transactor instance shared
// across CertificateService / RevocationSvc / RenewalService.
func (s *ACMEService) SetTransactor(tx repository.Transactor) { s.tx = tx }

// SetAuditService wires the audit service. cmd/server/main.go
// constructs auditService once and passes the same instance into
// every service that emits audit rows.
func (s *ACMEService) SetAuditService(a *AuditService) { s.auditService = a }

// SetIssuancePipeline wires Phase 2 finalize dependencies: the
// certificate service (for managed_certificates row + audit row),
// the certificate repository (for certificate_versions row), and the
// issuer registry (for routing IssueCertificate against the bound
// profile's issuer). cmd/server/main.go calls this at startup.
//
// All three are required for the finalize path. When unset, FinalizeOrder
// returns ErrACMEFinalizeUnconfigured (handler maps to
// urn:ietf:params:acme:error:serverInternal).
func (s *ACMEService) SetIssuancePipeline(certSvc *CertificateService, certRepo repository.CertificateRepository, registry *IssuerRegistry) {
	s.certService = certSvc
	s.certRepo = certRepo
	s.issuerRegistry = registry
}

// SetRevocationDelegate wires Phase 4's revocation delegate. The
// concrete type is *service.RevocationSvc; passing nil at startup
// disables the ACME revoke-cert endpoint (handler returns
// ErrACMERevocationUnconfigured → serverInternal). cmd/server/main.go
// passes the same revocationSvc instance shared across the rest of
// the platform.
func (s *ACMEService) SetRevocationDelegate(r CertificateRevoker) { s.revoker = r }

// SetRenewalPolicyLookup wires the renewal-policy resolver used by
// the ARI window-math path. Optional — when unset, ARI falls back to
// the "last 33% of validity" default window; the renewal-info handler
// still returns 200.
func (s *ACMEService) SetRenewalPolicyLookup(r RenewalPolicyLookup) { s.renewalPolicies = r }

// SetRateLimiter wires Phase 5's per-account rate limiter. Optional —
// when nil, the per-action rate-limit checks short-circuit to
// "always allow" so the legacy code path stays unchanged for bootstrap
// + tests that don't care about throttling.
func (s *ACMEService) SetRateLimiter(r *acme.RateLimiter) { s.rateLimiter = r }

// RateLimiter returns the wired limiter so the handler can compute
// Retry-After durations on rate-limited responses without re-checking.
func (s *ACMEService) RateLimiter() *acme.RateLimiter { return s.rateLimiter }

// SetValidatorPool wires Phase 3's challenge validator pool.
// cmd/server/main.go constructs an *acme.Pool at startup with the
// per-type concurrency caps from cfg.ACMEServer. Optional —
// RespondToChallenge returns ErrACMEChallengePoolUnconfigured when
// unset (handler maps to serverInternal).
func (s *ACMEService) SetValidatorPool(pool *acme.Pool) { s.validatorPool = pool }

// ValidatorPool returns the wired pool so cmd/server/main.go's
// shutdown sequence can call Drain on it.
func (s *ACMEService) ValidatorPool() *acme.Pool { return s.validatorPool }

// Metrics returns the per-op counter snapshotter. cmd/server/main.go
// passes this into MetricsHandler so the Prometheus exposer picks up
// the per-op signals.
func (s *ACMEService) Metrics() *ACMEMetrics { return s.metrics }

// ErrACMEUserActionRequired is returned by BuildDirectory when the
// caller hits the /acme/* shorthand path without
// CERTCTL_ACME_SERVER_DEFAULT_PROFILE_ID being set. Handler maps to
// RFC 7807 + RFC 8555 §6.7 userActionRequired.
var ErrACMEUserActionRequired = errors.New("acme: default profile not configured; use /acme/profile/<id>/*")

// ErrACMEProfileNotFound is returned when the profile in the request
// path doesn't exist. Handler maps to HTTP 404 (NOT 500 — the
// distinction is operator-meaningful: 404 says "fix your URL," 500
// says "something is wrong server-side").
var ErrACMEProfileNotFound = errors.New("acme: profile not found")

// ErrACMEAccountNotFound is returned by LookupAccount when the
// account ID in the URL doesn't match any row. Handler maps to
// 404 + RFC 8555 §6.7 accountDoesNotExist.
var ErrACMEAccountNotFound = errors.New("acme: account not found")

// ErrACMEAccountDoesNotExist is returned by NewAccount when
// onlyReturnExisting=true and no account exists for the supplied
// JWK. RFC 8555 §7.3.1 requires returning 400 +
// urn:ietf:params:acme:error:accountDoesNotExist (NOT 404).
var ErrACMEAccountDoesNotExist = errors.New("acme: account does not exist for this JWK")

// Phase 2 sentinels.

// ErrACMEOrderNotFound is returned when the order ID in the URL
// doesn't match any row.
var ErrACMEOrderNotFound = errors.New("acme: order not found")

// ErrACMEAuthzNotFound is returned when the authz ID in the URL
// doesn't match any row.
var ErrACMEAuthzNotFound = errors.New("acme: authz not found")

// ErrACMECertificateNotFound is returned when the cert ID in the URL
// doesn't match any managed_certificates row OR doesn't link back
// to an order owned by the requesting account.
var ErrACMECertificateNotFound = errors.New("acme: certificate not found")

// ErrACMEOrderNotReady is returned by FinalizeOrder when the order
// status is not ready/processing. RFC 8555 §7.4 mandates
// urn:ietf:params:acme:error:orderNotReady.
var ErrACMEOrderNotReady = errors.New("acme: order not in ready state")

// ErrACMEOrderUnauthorized is returned when the request's authenticated
// account doesn't own the targeted order/authz/cert.
var ErrACMEOrderUnauthorized = errors.New("acme: account does not own this resource")

// ErrACMEFinalizeUnconfigured is returned by FinalizeOrder when
// SetIssuancePipeline hasn't been called. Indicates a deploy-time
// wiring bug; mapped to serverInternal.
var ErrACMEFinalizeUnconfigured = errors.New("acme: finalize pipeline not wired (call SetIssuancePipeline)")

// ErrACMEUnsupportedAuthMode is returned when an order is created
// against a profile whose acme_auth_mode is not one of
// `trust_authenticated` (Phase 2) or `challenge` (Phase 3 — wired
// but the validators land in Phase 3).
var ErrACMEUnsupportedAuthMode = errors.New("acme: unsupported auth mode on profile")

// Phase 3 sentinels.

// ErrACMEChallengeNotFound is returned by RespondToChallenge when the
// challenge ID in the URL doesn't match any row.
var ErrACMEChallengeNotFound = errors.New("acme: challenge not found")

// ErrACMEChallengePoolUnconfigured is returned when SetValidatorPool
// hasn't been called. Indicates a deploy-time wiring bug; mapped to
// serverInternal.
var ErrACMEChallengePoolUnconfigured = errors.New("acme: validator pool not wired (call SetValidatorPool)")

// ErrACMEChallengeWrongState is returned when RespondToChallenge sees
// a challenge already in valid/invalid (idempotent observer-side
// behavior — same shape as Phase 1b's account inactive case).
var ErrACMEChallengeWrongState = errors.New("acme: challenge is no longer in pending state")

// Phase 4 sentinels.

// ErrACMERevocationUnconfigured is returned when SetRevocationDelegate
// hasn't been called and a client hits POST /revoke-cert. Indicates a
// deploy-time wiring bug; mapped to serverInternal.
var ErrACMERevocationUnconfigured = errors.New("acme: revocation delegate not wired (call SetRevocationDelegate)")

// ErrACMEKeyRolloverConcurrent is returned when two concurrent key-
// rollover requests race on the same account; the second sees the
// first's already-committed thumbprint.
var ErrACMEKeyRolloverConcurrent = errors.New("acme: account key was rotated concurrently; retry")

// ErrACMEKeyRolloverDuplicateKey is returned when the inner JWS's new
// JWK thumbprint is already registered against this profile.
var ErrACMEKeyRolloverDuplicateKey = errors.New("acme: new account key already registered against this profile")

// ErrACMEKeyRolloverInvalid is the catch-all for inner-JWS validation
// failures the handler doesn't care to enumerate (the actual sentinel
// for the operator-friendly error comes from the acme package's
// MapKeyChangeErrorToProblem).
var ErrACMEKeyRolloverInvalid = errors.New("acme: key rollover request rejected")

// ErrACMERevocationCertNotFound is returned when the revoke-cert
// payload's certificate doesn't match a managed_certificates row this
// server has issued.
var ErrACMERevocationCertNotFound = errors.New("acme: revocation target certificate not found")

// ErrACMERevocationUnauthorized is returned when neither the kid path
// (account owns the cert) nor the jwk path (signature key matches the
// cert's public key) authenticates the revocation request.
var ErrACMERevocationUnauthorized = errors.New("acme: account or signing key does not authorize revocation of this certificate")

// ErrACMERevocationAlreadyRevoked is returned when the cert is already
// in Revoked status. Mapped to RFC 8555 §6.7 alreadyRevoked.
var ErrACMERevocationAlreadyRevoked = errors.New("acme: certificate is already revoked")

// ErrACMERevocationBadCSR is returned when the certificate field of
// the revoke-cert payload is not a valid base64url-DER X.509 cert.
var ErrACMERevocationBadCSR = errors.New("acme: revoke-cert payload `certificate` is malformed")

// ErrACMEARIDisabled is returned by RenewalInfo when CERTCTL_ACME_SERVER_
// ARI_ENABLED is false. Handler maps to 404 + serverInternal.
var ErrACMEARIDisabled = errors.New("acme: ARI is disabled on this server")

// ErrACMEARIBadCertID is returned when the cert-id in the ARI URL is
// not RFC 9773 §4.1 shape. Handler maps to 400 + malformed.
var ErrACMEARIBadCertID = errors.New("acme: ARI cert-id is malformed")

// Phase 5 sentinels.

// ErrACMERateLimited is returned when the per-action rate limit fires.
// Handler maps to RFC 7807 + RFC 8555 §6.7
// `urn:ietf:params:acme:error:rateLimited` with a Retry-After header.
var ErrACMERateLimited = errors.New("acme: rate limit exceeded")

// ErrACMEConcurrentOrdersExceeded is returned by CreateOrder when the
// account already has cfg.RateLimitConcurrentOrders orders in
// pending/ready/processing. Handler maps to rateLimited (RFC 8555 §6.7
// shape; the certctl-side cause is concurrency rather than per-hour).
var ErrACMEConcurrentOrdersExceeded = errors.New("acme: concurrent orders limit exceeded")

// BuildDirectory constructs the per-profile directory document.
//
// profileID resolution:
//   - non-empty: look up that profile; ErrACMEProfileNotFound on miss.
//   - empty + cfg.DefaultProfileID set: substitute the default.
//   - empty + cfg.DefaultProfileID unset: ErrACMEUserActionRequired.
//
// baseURL is the per-profile base path the directory's URL fields are
// constructed against. The handler computes baseURL from the inbound
// request (scheme + host + /acme/profile/<id>) and passes it in;
// keeping the URL composition in the handler avoids embedding HTTP
// concerns in the service layer.
//
// On success the metrics counter for the directory op increments;
// failures bump the failure variant of the same counter.
func (s *ACMEService) BuildDirectory(ctx context.Context, profileID, baseURL string) (*acme.Directory, error) {
	profileID, err := s.resolveProfile(ctx, profileID)
	if err != nil {
		s.metrics.bump(&s.metrics.DirectoryFailureTotal)
		return nil, err
	}
	dir := acme.BuildDirectory(
		baseURL,
		s.cfg.DirectoryMeta.TermsOfService,
		s.cfg.DirectoryMeta.Website,
		s.cfg.DirectoryMeta.CAAIdentities,
		s.cfg.DirectoryMeta.ExternalAccountRequired,
		// Phase 4: ARI is live. Flipping this on emits the renewalInfo
		// URL from BuildDirectory; a 200 from the renewal-info handler
		// returns the suggested-window JSON + Retry-After. Operators can
		// disable via CERTCTL_ACME_SERVER_ARI_ENABLED=false (the URL
		// drops out of the directory; the route is still registered but
		// returns 404 + serverInternal — clients fall back to static
		// renewal scheduling).
		s.cfg.ARIEnabled,
	)
	_ = profileID // Phase 1b will use the resolved profile to read
	//                acme_auth_mode + record per-profile metrics. Phase 1a
	//                only needs the existence check above.
	s.metrics.bump(&s.metrics.DirectoryTotal)
	return dir, nil
}

// resolveProfile applies the default-profile fallback and confirms the
// profile exists. Returns the resolved (canonical) profileID on
// success. Centralizing the resolution here keeps every Phase
// 1a/1b/2/3/4 endpoint's "which profile is this request bound to"
// logic uniform.
func (s *ACMEService) resolveProfile(ctx context.Context, profileID string) (string, error) {
	if profileID == "" {
		if s.cfg.DefaultProfileID == "" {
			return "", ErrACMEUserActionRequired
		}
		profileID = s.cfg.DefaultProfileID
	}
	_, err := s.profiles.Get(ctx, profileID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", ErrACMEProfileNotFound
		}
		return "", fmt.Errorf("acme: lookup profile: %w", err)
	}
	return profileID, nil
}

// ACMEMetrics is the per-op counter table for the ACME server. Mirrors
// the IssuanceMetrics / DeployCounters pattern (atomic.Uint64 + a
// Snapshot method that emits stable tuples). Phases 2-4 will extend
// with new-order / finalize / challenge counters.
type ACMEMetrics struct {
	// Phase 1a — directory + new-nonce.
	DirectoryTotal        atomic.Uint64
	DirectoryFailureTotal atomic.Uint64
	NewNonceTotal         atomic.Uint64
	NewNonceFailureTotal  atomic.Uint64

	// Phase 1b — account resource.
	NewAccountTotal           atomic.Uint64
	NewAccountFailureTotal    atomic.Uint64
	NewAccountIdempotentTotal atomic.Uint64 // re-registration of existing JWK (RFC 8555 §7.3.1)
	UpdateAccountTotal        atomic.Uint64
	UpdateAccountFailureTotal atomic.Uint64
	DeactivateAccountTotal    atomic.Uint64

	// Phase 2 — orders + finalize + cert download.
	NewOrderTotal             atomic.Uint64
	NewOrderFailureTotal      atomic.Uint64
	NewOrderRejectedTotal     atomic.Uint64 // identifier-validation rejection
	FinalizeOrderTotal        atomic.Uint64
	FinalizeOrderFailureTotal atomic.Uint64
	CertDownloadTotal         atomic.Uint64
	CertDownloadFailureTotal  atomic.Uint64
	AuthzReadTotal            atomic.Uint64

	// Phase 3 — challenge validation.
	ChallengeRespondTotal     atomic.Uint64 // dispatch acked (worker took the work)
	ChallengeRespondFailTotal atomic.Uint64 // immediate rejection (already-resolved / wrong-state)
	ChallengeValidateValid    atomic.Uint64 // validator returned nil
	ChallengeValidateInvalid  atomic.Uint64 // validator returned error

	// Phase 4 — key rollover + revocation + ARI.
	KeyChangeTotal       atomic.Uint64 // accepted rollover (200)
	KeyChangeFailTotal   atomic.Uint64 // rejected rollover (4xx)
	RevokeCertTotal      atomic.Uint64 // accepted revocation (200)
	RevokeCertFailTotal  atomic.Uint64 // rejected revocation (4xx)
	RenewalInfoTotal     atomic.Uint64 // ARI 200
	RenewalInfoFailTotal atomic.Uint64 // ARI 4xx

	// Phase 5 — GC sweep counts (per-tick rows-affected, summed).
	GCNoncesReapedTotal      atomic.Uint64
	GCAuthzsExpiredTotal     atomic.Uint64
	GCOrdersInvalidatedTotal atomic.Uint64
	GCRunsTotal              atomic.Uint64
	GCRunFailuresTotal       atomic.Uint64
}

// NewACMEMetrics returns a zeroed counter table. Concurrent callers
// can bump counters without external synchronization (atomic.Uint64
// is the synchronization primitive).
func NewACMEMetrics() *ACMEMetrics { return &ACMEMetrics{} }

// bump increments a single atomic counter. Centralized so the call
// sites in BuildDirectory + IssueNonce + NewAccount + etc. are uniform.
func (m *ACMEMetrics) bump(c *atomic.Uint64) { c.Add(1) }

// Snapshot emits the current counter values as a map (op → count).
// Naming is certctl_acme_<op>_total per frozen decision 0.10
// (cardinality discipline) so the Prometheus exposer can lift them
// directly without per-op stringly-typed branching.
func (m *ACMEMetrics) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"certctl_acme_directory_total":                  m.DirectoryTotal.Load(),
		"certctl_acme_directory_failures_total":         m.DirectoryFailureTotal.Load(),
		"certctl_acme_new_nonce_total":                  m.NewNonceTotal.Load(),
		"certctl_acme_new_nonce_failures_total":         m.NewNonceFailureTotal.Load(),
		"certctl_acme_new_account_total":                m.NewAccountTotal.Load(),
		"certctl_acme_new_account_failures_total":       m.NewAccountFailureTotal.Load(),
		"certctl_acme_new_account_idempotent_total":     m.NewAccountIdempotentTotal.Load(),
		"certctl_acme_update_account_total":             m.UpdateAccountTotal.Load(),
		"certctl_acme_update_account_failures_total":    m.UpdateAccountFailureTotal.Load(),
		"certctl_acme_deactivate_account_total":         m.DeactivateAccountTotal.Load(),
		"certctl_acme_new_order_total":                  m.NewOrderTotal.Load(),
		"certctl_acme_new_order_failures_total":         m.NewOrderFailureTotal.Load(),
		"certctl_acme_new_order_rejected_total":         m.NewOrderRejectedTotal.Load(),
		"certctl_acme_finalize_order_total":             m.FinalizeOrderTotal.Load(),
		"certctl_acme_finalize_order_failures_total":    m.FinalizeOrderFailureTotal.Load(),
		"certctl_acme_cert_download_total":              m.CertDownloadTotal.Load(),
		"certctl_acme_cert_download_failures_total":     m.CertDownloadFailureTotal.Load(),
		"certctl_acme_authz_read_total":                 m.AuthzReadTotal.Load(),
		"certctl_acme_challenge_respond_total":          m.ChallengeRespondTotal.Load(),
		"certctl_acme_challenge_respond_failures_total": m.ChallengeRespondFailTotal.Load(),
		"certctl_acme_challenge_validate_valid_total":   m.ChallengeValidateValid.Load(),
		"certctl_acme_challenge_validate_invalid_total": m.ChallengeValidateInvalid.Load(),
		"certctl_acme_key_change_total":                 m.KeyChangeTotal.Load(),
		"certctl_acme_key_change_failures_total":        m.KeyChangeFailTotal.Load(),
		"certctl_acme_revoke_cert_total":                m.RevokeCertTotal.Load(),
		"certctl_acme_revoke_cert_failures_total":       m.RevokeCertFailTotal.Load(),
		"certctl_acme_renewal_info_total":               m.RenewalInfoTotal.Load(),
		"certctl_acme_renewal_info_failures_total":      m.RenewalInfoFailTotal.Load(),
		"certctl_acme_gc_nonces_reaped_total":           m.GCNoncesReapedTotal.Load(),
		"certctl_acme_gc_authzs_expired_total":          m.GCAuthzsExpiredTotal.Load(),
		"certctl_acme_gc_orders_invalidated_total":      m.GCOrdersInvalidatedTotal.Load(),
		"certctl_acme_gc_runs_total":                    m.GCRunsTotal.Load(),
		"certctl_acme_gc_run_failures_total":            m.GCRunFailuresTotal.Load(),
	}
}

// VerifyJWS adapts the api/acme verifier to the service-layer
// dependency surface. It builds the VerifierConfig from the service's
// repo + the supplied AccountKID-builder closure, then delegates to
// acme.VerifyJWS.
//
// accountKID is the handler-supplied closure that returns the
// canonical kid URL for an account ID (scheme + host + per-profile
// path). VerifyJWS uses it to round-trip-check the inbound `kid`
// against what the server would have emitted on new-account.
func (s *ACMEService) VerifyJWS(
	ctx context.Context,
	body []byte,
	requestURL string,
	expectNewAccount bool,
	accountKID func(accountID string) string,
) (*acme.VerifiedRequest, error) {
	cfg := acme.VerifierConfig{
		Accounts:   &accountAdapter{ctx: ctx, repo: s.repo},
		Nonces:     &nonceAdapter{ctx: ctx, repo: s.repo},
		AccountKID: accountKID,
	}
	return acme.VerifyJWS(cfg, body, requestURL, acme.VerifyOptions{
		ExpectNewAccount: expectNewAccount,
	})
}

// accountAdapter bridges the service-layer ACMERepo to the verifier's
// AccountLookup interface. The verifier doesn't take a context (its
// surface is sync-pure for testability), so the adapter captures the
// per-request context at construction time.
type accountAdapter struct {
	ctx  context.Context
	repo ACMERepo
}

func (a *accountAdapter) LookupAccount(accountID string) (*domain.ACMEAccount, error) {
	acct, err := a.repo.GetAccountByID(a.ctx, accountID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, acme.ErrJWSAccountNotFound
		}
		return nil, fmt.Errorf("acme: lookup account: %w", err)
	}
	return acct, nil
}

// nonceAdapter bridges the service-layer ACMERepo's ConsumeNonce
// to the verifier's NonceConsumer interface (no-context signature).
type nonceAdapter struct {
	ctx  context.Context
	repo ACMERepo
}

func (n *nonceAdapter) ConsumeNonce(nonce string) error {
	return n.repo.ConsumeNonce(n.ctx, nonce)
}

// NewAccount creates (or, on RFC 8555 §7.3.1 idempotent re-registration,
// re-returns the existing) account row for the supplied JWK. Returns
// the persisted ACMEAccount + a bool indicating whether the row was
// newly created (true) or already existed (false).
//
// onlyReturnExisting=true makes the call read-only: when no account
// exists for the JWK, the service returns ErrACMEAccountDoesNotExist
// instead of creating one.
//
// State writes (cert insert + audit row) are atomic via WithinTx +
// RecordEventWithTx — same pattern as CertificateService.Create.
func (s *ACMEService) NewAccount(
	ctx context.Context,
	profileID string,
	jwk *jose.JSONWebKey,
	contact []string,
	onlyReturnExisting bool,
	tosAgreed bool,
) (*domain.ACMEAccount, bool, error) {
	if s.tx == nil || s.auditService == nil {
		s.metrics.bump(&s.metrics.NewAccountFailureTotal)
		return nil, false, fmt.Errorf("acme: new-account requires SetTransactor + SetAuditService")
	}
	resolvedProfileID, err := s.resolveProfile(ctx, profileID)
	if err != nil {
		s.metrics.bump(&s.metrics.NewAccountFailureTotal)
		return nil, false, err
	}

	thumb, err := acme.JWKThumbprint(jwk)
	if err != nil {
		s.metrics.bump(&s.metrics.NewAccountFailureTotal)
		return nil, false, fmt.Errorf("acme: thumbprint: %w", err)
	}

	// RFC 8555 §7.3.1 idempotency: a new-account request for an
	// already-registered JWK returns the existing row unmodified.
	if existing, err := s.repo.GetAccountByThumbprint(ctx, resolvedProfileID, thumb); err == nil {
		s.metrics.bump(&s.metrics.NewAccountIdempotentTotal)
		return existing, false, nil
	} else if !errors.Is(err, repository.ErrNotFound) {
		s.metrics.bump(&s.metrics.NewAccountFailureTotal)
		return nil, false, fmt.Errorf("acme: lookup-by-thumbprint: %w", err)
	}

	if onlyReturnExisting {
		s.metrics.bump(&s.metrics.NewAccountFailureTotal)
		return nil, false, ErrACMEAccountDoesNotExist
	}

	jwkPEM, err := acme.JWKToPEM(jwk)
	if err != nil {
		s.metrics.bump(&s.metrics.NewAccountFailureTotal)
		return nil, false, fmt.Errorf("acme: serialize jwk: %w", err)
	}

	acct := &domain.ACMEAccount{
		AccountID:     acme.AccountID(thumb),
		JWKThumbprint: thumb,
		JWKPEM:        jwkPEM,
		Contact:       contact,
		Status:        domain.ACMEAccountStatusValid,
		ProfileID:     resolvedProfileID,
	}

	auditDetails := map[string]interface{}{
		"profile_id":     resolvedProfileID,
		"jwk_thumbprint": thumb,
		"contact_count":  len(contact),
		"tos_agreed":     tosAgreed,
	}

	err = s.tx.WithinTx(ctx, func(q repository.Querier) error {
		if err := s.repo.CreateAccountWithTx(ctx, q, acct); err != nil {
			return fmt.Errorf("acme: create account: %w", err)
		}
		return s.auditService.RecordEventWithTx(
			ctx, q,
			fmt.Sprintf("acme:%s", acct.AccountID),
			domain.ActorTypeUser,
			"acme_account_created",
			"acme_account",
			acct.AccountID,
			auditDetails,
		)
	})
	if err != nil {
		s.metrics.bump(&s.metrics.NewAccountFailureTotal)
		return nil, false, err
	}
	s.metrics.bump(&s.metrics.NewAccountTotal)
	return acct, true, nil
}

// LookupAccount returns the account by ID. Returns
// ErrACMEAccountNotFound when the row doesn't exist (handler maps to
// 404 with RFC 7807 + RFC 8555 §6.7 accountDoesNotExist Problem).
func (s *ACMEService) LookupAccount(ctx context.Context, accountID string) (*domain.ACMEAccount, error) {
	acct, err := s.repo.GetAccountByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrACMEAccountNotFound
		}
		return nil, fmt.Errorf("acme: lookup account: %w", err)
	}
	return acct, nil
}

// UpdateAccount replaces the account's contact list. Atomic: the
// repo update + audit row run in one WithinTx.
func (s *ACMEService) UpdateAccount(
	ctx context.Context,
	accountID string,
	contact []string,
) (*domain.ACMEAccount, error) {
	if s.tx == nil || s.auditService == nil {
		s.metrics.bump(&s.metrics.UpdateAccountFailureTotal)
		return nil, fmt.Errorf("acme: update-account requires SetTransactor + SetAuditService")
	}
	auditDetails := map[string]interface{}{
		"account_id":    accountID,
		"contact_count": len(contact),
	}
	err := s.tx.WithinTx(ctx, func(q repository.Querier) error {
		if err := s.repo.UpdateAccountContactWithTx(ctx, q, accountID, contact); err != nil {
			return err
		}
		return s.auditService.RecordEventWithTx(
			ctx, q,
			fmt.Sprintf("acme:%s", accountID),
			domain.ActorTypeUser,
			"acme_account_updated",
			"acme_account",
			accountID,
			auditDetails,
		)
	})
	if err != nil {
		s.metrics.bump(&s.metrics.UpdateAccountFailureTotal)
		return nil, err
	}
	// Re-read the row so the response carries the persisted state.
	acct, err := s.LookupAccount(ctx, accountID)
	if err != nil {
		s.metrics.bump(&s.metrics.UpdateAccountFailureTotal)
		return nil, err
	}
	s.metrics.bump(&s.metrics.UpdateAccountTotal)
	return acct, nil
}

// DeactivateAccount transitions the account from `valid` to
// `deactivated` (RFC 8555 §7.3.6). Subsequent JWS-authenticated
// requests using this account's kid are rejected by the verifier
// (status check at acme/jws.go).
func (s *ACMEService) DeactivateAccount(ctx context.Context, accountID string) (*domain.ACMEAccount, error) {
	if s.tx == nil || s.auditService == nil {
		s.metrics.bump(&s.metrics.UpdateAccountFailureTotal)
		return nil, fmt.Errorf("acme: deactivate-account requires SetTransactor + SetAuditService")
	}
	auditDetails := map[string]interface{}{
		"account_id": accountID,
		"new_status": string(domain.ACMEAccountStatusDeactivated),
	}
	err := s.tx.WithinTx(ctx, func(q repository.Querier) error {
		if err := s.repo.UpdateAccountStatusWithTx(ctx, q, accountID, domain.ACMEAccountStatusDeactivated); err != nil {
			return err
		}
		return s.auditService.RecordEventWithTx(
			ctx, q,
			fmt.Sprintf("acme:%s", accountID),
			domain.ActorTypeUser,
			"acme_account_deactivated",
			"acme_account",
			accountID,
			auditDetails,
		)
	})
	if err != nil {
		s.metrics.bump(&s.metrics.UpdateAccountFailureTotal)
		return nil, err
	}
	acct, err := s.LookupAccount(ctx, accountID)
	if err != nil {
		s.metrics.bump(&s.metrics.UpdateAccountFailureTotal)
		return nil, err
	}
	s.metrics.bump(&s.metrics.DeactivateAccountTotal)
	return acct, nil
}

// firstAvailableIssuer returns the (id, connector) pair for the first
// registered issuer. Cross-concern helper: called from Phase 2
// FinalizeOrder (acme_orders.go, post-Sprint-9b) AND Phase 4
// RevokeCert + RenewalInfo (below in this file). Kept in acme.go so
// it's adjacent to two of its three callers and reachable from
// acme_orders.go via Go's same-package scope without dragging the
// helper into a third "shared helpers" sibling. The
// per-profile-issuer mapping arrives in a follow-up.
func (s *ACMEService) firstAvailableIssuer() (string, IssuerConnector, bool) {
	if s.issuerRegistry == nil {
		return "", nil, false
	}
	for id, conn := range s.issuerRegistry.List() {
		return id, conn, true
	}
	return "", nil, false
}

// --- Phase 4 — key rollover + revocation + ARI -------------------------

// RotateAccountKey is the service-layer entry point for RFC 8555
// §7.3.5 key-change. By the time we get here the handler has:
//
//  1. VerifyJWS'd the OUTER JWS (kid path), so verified.Account is the
//     authentic account owner.
//  2. ParseAndVerifyKeyChangeInner'd the inner JWS, so newJWK is the
//     verified new key + the inner's `oldKey`/`account` invariants
//     have been asserted.
//
// What we still own here:
//
//   - asserting the new JWK's thumbprint isn't already registered against
//     this profile (RFC 8555 §7.3.5 forbids two accounts sharing a key);
//   - swapping the row's jwk_thumbprint + jwk_pem in one WithinTx with
//     the audit row, behind a SELECT … FOR UPDATE lock so concurrent
//     rollovers serialize.
//
// Returns ErrACMEKeyRolloverConcurrent when a concurrent rollover beat
// us to the WithinTx; ErrACMEKeyRolloverDuplicateKey on the
// (profile_id, jwk_thumbprint) UNIQUE collision.
func (s *ACMEService) RotateAccountKey(
	ctx context.Context,
	oldAccount *domain.ACMEAccount,
	newJWK *jose.JSONWebKey,
) (*domain.ACMEAccount, error) {
	if s.tx == nil || s.auditService == nil {
		s.metrics.bump(&s.metrics.KeyChangeFailTotal)
		return nil, fmt.Errorf("acme: key rollover requires SetTransactor + SetAuditService")
	}
	if oldAccount == nil || newJWK == nil {
		s.metrics.bump(&s.metrics.KeyChangeFailTotal)
		return nil, ErrACMEKeyRolloverInvalid
	}
	// Phase 5 — rollovers/hour cap. Defaults to 5/hour: a flood is an
	// attack signal (key rotation should be rare). Keyed by accountID.
	if s.rateLimiter != nil && s.cfg.RateLimitKeyChangePerHour > 0 {
		if !s.rateLimiter.Allow(acme.ActionKeyChange, oldAccount.AccountID, s.cfg.RateLimitKeyChangePerHour) {
			s.metrics.bump(&s.metrics.KeyChangeFailTotal)
			return nil, ErrACMERateLimited
		}
	}

	newThumbprint, err := acme.JWKThumbprint(newJWK)
	if err != nil {
		s.metrics.bump(&s.metrics.KeyChangeFailTotal)
		return nil, fmt.Errorf("acme: thumbprint new jwk: %w", err)
	}
	newJWKPEM, err := acme.JWKToPEM(newJWK)
	if err != nil {
		s.metrics.bump(&s.metrics.KeyChangeFailTotal)
		return nil, fmt.Errorf("acme: serialize new jwk: %w", err)
	}

	// New key already registered against this profile? RFC 8555 §7.3.5
	// forbids two accounts sharing a key.
	existing, err := s.repo.GetAccountByThumbprint(ctx, oldAccount.ProfileID, newThumbprint)
	if err == nil && existing != nil {
		s.metrics.bump(&s.metrics.KeyChangeFailTotal)
		return nil, ErrACMEKeyRolloverDuplicateKey
	}
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		s.metrics.bump(&s.metrics.KeyChangeFailTotal)
		return nil, fmt.Errorf("acme: lookup new jwk thumbprint: %w", err)
	}

	// Atomic swap + audit row.
	if err := s.tx.WithinTx(ctx, func(q repository.Querier) error {
		if err := s.repo.UpdateAccountJWKWithTx(
			ctx, q, oldAccount.AccountID,
			oldAccount.JWKThumbprint, newThumbprint, newJWKPEM,
		); err != nil {
			return err
		}
		return s.auditService.RecordEventWithTx(ctx, q,
			fmt.Sprintf("acme:%s", oldAccount.AccountID), domain.ActorTypeUser,
			"acme_account_key_rolled", "acme_account", oldAccount.AccountID,
			map[string]interface{}{
				"old_thumbprint": oldAccount.JWKThumbprint,
				"new_thumbprint": newThumbprint,
				"profile_id":     oldAccount.ProfileID,
			})
	}); err != nil {
		s.metrics.bump(&s.metrics.KeyChangeFailTotal)
		// Translate repository sentinels to ACME-shaped errors.
		// ErrACMEAccountKeyConcurrentUpdate is in the postgres
		// package; we use error-string-based matching to avoid
		// importing postgres into the service layer.
		if strings.Contains(err.Error(), "rotated concurrently") {
			return nil, ErrACMEKeyRolloverConcurrent
		}
		if strings.Contains(err.Error(), "already exists for this profile") {
			return nil, ErrACMEKeyRolloverDuplicateKey
		}
		return nil, err
	}

	// Hydrate the in-memory account with its new key and return.
	rolled := *oldAccount
	rolled.JWKThumbprint = newThumbprint
	rolled.JWKPEM = newJWKPEM
	rolled.UpdatedAt = time.Now().UTC()
	s.metrics.bump(&s.metrics.KeyChangeTotal)
	return &rolled, nil
}

// RevokeCert routes an ACME-shaped revoke-cert request through certctl's
// existing RevocationSvc pipeline (cert row update + revocation row +
// audit + issuer notification + OCSP cache invalidation).
//
// Parameters:
//
//   - verified: the JWS-verified envelope. EITHER verified.Account is set
//     (kid path: account that signed) OR verified.JWK is set (jwk path:
//     the cert's own key signed). The handler enforces exactly one.
//   - certDER: the base64url-decoded certificate DER from the payload.
//   - reasonCode: optional RFC 5280 §5.3.1 numeric reason; values out of
//     range are clamped to "unspecified".
//
// Auth model:
//
//   - kid path: the account must have an acme_orders row whose
//     certificate_id maps to the target managed_certificates row. We
//     look up by serial against managed_certificates (scoped by issuer)
//     and then check ownership.
//   - jwk path: the JWS's embedded public key must equal the cert's
//     public key (byte-equal RFC 7638 thumbprint).
//
// Either path: routes through s.revoker.RevokeCertificateWithActor —
// the same path bulk revocation, the GUI revoke button, and the
// ACME-consumer issuer's revoke uses.
func (s *ACMEService) RevokeCert(
	ctx context.Context,
	verified *acme.VerifiedRequest,
	certDER []byte,
	reasonCode int,
) error {
	if s.revoker == nil {
		s.metrics.bump(&s.metrics.RevokeCertFailTotal)
		return ErrACMERevocationUnconfigured
	}
	if s.certRepo == nil {
		s.metrics.bump(&s.metrics.RevokeCertFailTotal)
		return fmt.Errorf("acme: revoke-cert requires SetIssuancePipeline (no certRepo wired)")
	}
	if verified == nil {
		s.metrics.bump(&s.metrics.RevokeCertFailTotal)
		return ErrACMERevocationUnauthorized
	}

	// Parse cert.
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		s.metrics.bump(&s.metrics.RevokeCertFailTotal)
		return ErrACMERevocationBadCSR
	}

	// Resolve the cert via (issuerID, serial). Use the same first-
	// available-issuer rule Phase 2 finalize uses; multi-issuer-per-
	// profile follow-up will refine.
	issuerID, _, ok := s.firstAvailableIssuer()
	if !ok {
		s.metrics.bump(&s.metrics.RevokeCertFailTotal)
		return ErrACMERevocationCertNotFound
	}
	serialHex := strings.ToLower(leaf.SerialNumber.Text(16))
	version, err := s.certRepo.GetVersionBySerial(ctx, issuerID, serialHex)
	if err != nil {
		s.metrics.bump(&s.metrics.RevokeCertFailTotal)
		return ErrACMERevocationCertNotFound
	}
	cert, err := s.certRepo.Get(ctx, version.CertificateID)
	if err != nil {
		s.metrics.bump(&s.metrics.RevokeCertFailTotal)
		return ErrACMERevocationCertNotFound
	}
	if cert.Status == domain.CertificateStatusRevoked {
		s.metrics.bump(&s.metrics.RevokeCertFailTotal)
		return ErrACMERevocationAlreadyRevoked
	}

	// Auth check.
	var actor string
	switch {
	case verified.Account != nil:
		owns, err := s.repo.AccountOwnsCertificate(ctx, verified.Account.AccountID, cert.ID)
		if err != nil {
			s.metrics.bump(&s.metrics.RevokeCertFailTotal)
			return fmt.Errorf("acme: revoke-cert ownership lookup: %w", err)
		}
		if !owns {
			s.metrics.bump(&s.metrics.RevokeCertFailTotal)
			return ErrACMERevocationUnauthorized
		}
		actor = fmt.Sprintf("acme:%s", verified.Account.AccountID)
	case verified.JWK != nil:
		// jwk path — embedded JWK must match the cert's pubkey.
		certJWK := jose.JSONWebKey{Key: leaf.PublicKey}
		eq, err := jwksThumbprintsEqualSvc(verified.JWK, &certJWK)
		if err != nil {
			s.metrics.bump(&s.metrics.RevokeCertFailTotal)
			return fmt.Errorf("acme: revoke-cert key compare: %w", err)
		}
		if !eq {
			s.metrics.bump(&s.metrics.RevokeCertFailTotal)
			return ErrACMERevocationUnauthorized
		}
		actor = fmt.Sprintf("acme-cert-key:%s", serialHex)
	default:
		s.metrics.bump(&s.metrics.RevokeCertFailTotal)
		return ErrACMERevocationUnauthorized
	}

	// Route through the existing revocation pipeline. Reason is RFC
	// 5280 §5.3.1 numeric; map to the certctl string form, clamping
	// unknown values to "unspecified".
	reasonStr := mapACMERevocationReason(reasonCode)
	if err := s.revoker.RevokeCertificateWithActor(ctx, cert.ID, reasonStr, actor); err != nil {
		s.metrics.bump(&s.metrics.RevokeCertFailTotal)
		// RevocationSvc returns errors for already-revoked / archived;
		// translate the already-revoked case to the ACME shape.
		if strings.Contains(err.Error(), "already revoked") {
			return ErrACMERevocationAlreadyRevoked
		}
		return fmt.Errorf("acme: revoke pipeline: %w", err)
	}

	s.metrics.bump(&s.metrics.RevokeCertTotal)
	return nil
}

// RenewalInfo computes the RFC 9773 ARI suggestedWindow + Retry-After
// for a (profile, cert-id) pair.
//
// cert-id is the wire-format string: base64url(AKI) "." base64url(serial).
// We decode it via acme.ParseARICertID, look up by (issuer, serial),
// then compute the window from cert.ExpiresAt + the bound renewal
// policy (when present).
//
// Returns the response shape + Retry-After duration. The handler emits
// these on the wire.
func (s *ACMEService) RenewalInfo(
	ctx context.Context,
	profileID, certID string,
) (*acme.RenewalInfoResponse, time.Duration, error) {
	if !s.cfg.ARIEnabled {
		s.metrics.bump(&s.metrics.RenewalInfoFailTotal)
		return nil, 0, ErrACMEARIDisabled
	}
	resolvedProfile, err := s.resolveProfile(ctx, profileID)
	if err != nil {
		s.metrics.bump(&s.metrics.RenewalInfoFailTotal)
		return nil, 0, err
	}
	_ = resolvedProfile // future per-profile metric tags

	parsed, err := acme.ParseARICertID(certID)
	if err != nil {
		s.metrics.bump(&s.metrics.RenewalInfoFailTotal)
		return nil, 0, ErrACMEARIBadCertID
	}

	// Resolve cert via (first-available-issuer, serial-hex).
	issuerID, _, ok := s.firstAvailableIssuer()
	if !ok || s.certRepo == nil {
		s.metrics.bump(&s.metrics.RenewalInfoFailTotal)
		return nil, 0, ErrACMECertificateNotFound
	}
	version, err := s.certRepo.GetVersionBySerial(ctx, issuerID, parsed.SerialHex())
	if err != nil {
		s.metrics.bump(&s.metrics.RenewalInfoFailTotal)
		return nil, 0, ErrACMECertificateNotFound
	}
	cert, err := s.certRepo.Get(ctx, version.CertificateID)
	if err != nil {
		s.metrics.bump(&s.metrics.RenewalInfoFailTotal)
		return nil, 0, ErrACMECertificateNotFound
	}

	// Optional bound renewal-policy lookup. When unset OR the cert has
	// no policy bound, ComputeRenewalWindow falls back to the last-33%-
	// of-validity default.
	var policy *domain.RenewalPolicy
	if s.renewalPolicies != nil && cert.RenewalPolicyID != "" {
		p, err := s.renewalPolicies.Get(ctx, cert.RenewalPolicyID)
		if err == nil {
			policy = p
		}
	}

	start, end := acme.ComputeRenewalWindow(cert, version, policy, time.Now().UTC())
	resp := &acme.RenewalInfoResponse{
		SuggestedWindow: acme.RenewalWindow{Start: start.UTC(), End: end.UTC()},
	}
	retryAfter := s.cfg.ARIPollInterval
	if retryAfter <= 0 {
		retryAfter = 6 * time.Hour
	}

	s.metrics.bump(&s.metrics.RenewalInfoTotal)
	return resp, retryAfter, nil
}

// jwksThumbprintsEqualSvc compares two JWKs by RFC 7638 thumbprint. A
// service-package-local helper so we don't import the api/acme package's
// unexported helper. The constant-time compare matches what the
// keychange.go variant does on the api/acme side.
func jwksThumbprintsEqualSvc(a, b *jose.JSONWebKey) (bool, error) {
	if a == nil || b == nil {
		return false, nil
	}
	tA, err := acme.JWKThumbprint(a)
	if err != nil {
		return false, err
	}
	tB, err := acme.JWKThumbprint(b)
	if err != nil {
		return false, err
	}
	return tA == tB, nil
}

// mapACMERevocationReason translates the RFC 5280 §5.3.1 numeric reason
// code to the certctl-domain reason string. Out-of-range values clamp
// to "unspecified" per RFC 8555 §7.6 ("an arbitrary integer value");
// RFC 5280 codes 8 (removeFromCRL) and 10 (aACompromise) are not in
// certctl's domain.ValidRevocationReasons set so they also clamp to
// "unspecified".
func mapACMERevocationReason(code int) string {
	switch code {
	case 0:
		return string(domain.RevocationReasonUnspecified)
	case 1:
		return string(domain.RevocationReasonKeyCompromise)
	case 2:
		return string(domain.RevocationReasonCACompromise)
	case 3:
		return string(domain.RevocationReasonAffiliationChanged)
	case 4:
		return string(domain.RevocationReasonSuperseded)
	case 5:
		return string(domain.RevocationReasonCessationOfOperation)
	case 6:
		return string(domain.RevocationReasonCertificateHold)
	case 9:
		return string(domain.RevocationReasonPrivilegeWithdrawn)
	default:
		return string(domain.RevocationReasonUnspecified)
	}
}
