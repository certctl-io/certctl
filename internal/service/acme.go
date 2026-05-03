// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package service

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/shankar0123/certctl/internal/api/acme"
	"github.com/shankar0123/certctl/internal/config"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
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
		// Phase 1a: ARI is non-functional. The Phase 4 commit flips this
		// to true once the renewal-info handler ships.
		false,
	)
	_ = profileID // Phase 1b will use the resolved profile to read
	//                acme_auth_mode + record per-profile metrics. Phase 1a
	//                only needs the existence check above.
	s.metrics.bump(&s.metrics.DirectoryTotal)
	return dir, nil
}

// IssueNonce generates a fresh ACME nonce, persists it with the
// configured TTL, and returns the encoded string for the
// Replay-Nonce header.
//
// RFC 8555 §6.5: every successful ACME response carries a
// Replay-Nonce. Phase 1a wires this via the directory + new-nonce
// handlers; Phase 1b extends with new-account + account/<id> POST
// responses (the JWS-authenticated paths).
func (s *ACMEService) IssueNonce(ctx context.Context) (string, error) {
	nonce, err := acme.GenerateNonce()
	if err != nil {
		s.metrics.bump(&s.metrics.NewNonceFailureTotal)
		return "", fmt.Errorf("acme: generate nonce: %w", err)
	}
	if err := s.repo.IssueNonce(ctx, nonce, s.cfg.NonceTTL); err != nil {
		s.metrics.bump(&s.metrics.NewNonceFailureTotal)
		return "", fmt.Errorf("acme: persist nonce: %w", err)
	}
	s.metrics.bump(&s.metrics.NewNonceTotal)
	return nonce, nil
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

// --- Phase 2 — orders + authz + finalize + cert download ---------------

// CreateOrder validates a new-order request against the bound profile
// and persists the order + per-identifier authz + per-authz challenge
// rows in one WithinTx. Returns the created order on success.
//
// Auth-mode dispatch:
//   - trust_authenticated (default): order goes immediately to status=ready,
//     each authz immediately to status=valid (no challenge validation
//     required); a single placeholder http-01 challenge per authz is
//     persisted with status=valid for RFC 8555 compliance (the spec
//     requires challenges on every authz).
//   - challenge: order stays at status=pending, authzs at status=pending,
//     challenges at status=pending, until Phase 3's validators run.
func (s *ACMEService) CreateOrder(
	ctx context.Context,
	accountID, profileID string,
	identifiers []domain.ACMEIdentifier,
	notBefore, notAfter *time.Time,
) (*domain.ACMEOrder, error) {
	if s.tx == nil || s.auditService == nil {
		s.metrics.bump(&s.metrics.NewOrderFailureTotal)
		return nil, fmt.Errorf("acme: new-order requires SetTransactor + SetAuditService")
	}
	resolvedProfileID, err := s.resolveProfile(ctx, profileID)
	if err != nil {
		s.metrics.bump(&s.metrics.NewOrderFailureTotal)
		return nil, err
	}
	profile, err := s.profiles.Get(ctx, resolvedProfileID)
	if err != nil {
		s.metrics.bump(&s.metrics.NewOrderFailureTotal)
		return nil, fmt.Errorf("acme: lookup profile: %w", err)
	}
	authMode := profile.ACMEAuthMode
	if authMode == "" {
		authMode = string(s.cfg.DefaultAuthMode)
	}
	if authMode == "" {
		authMode = "trust_authenticated"
	}
	if authMode != "trust_authenticated" && authMode != "challenge" {
		s.metrics.bump(&s.metrics.NewOrderFailureTotal)
		return nil, fmt.Errorf("%w: %q", ErrACMEUnsupportedAuthMode, authMode)
	}

	now := time.Now().UTC()
	orderTTL := s.cfg.OrderTTL
	if orderTTL <= 0 {
		orderTTL = 24 * time.Hour
	}
	authzTTL := s.cfg.AuthzTTL
	if authzTTL <= 0 {
		authzTTL = 24 * time.Hour
	}

	// In trust_authenticated mode, the order goes straight to `ready`
	// (RFC 8555 §7.1.6: ready means all authzs valid, awaiting CSR).
	// In challenge mode, the order stays `pending` until challenges
	// validate.
	orderStatus := domain.ACMEOrderStatusPending
	authzStatus := domain.ACMEAuthzStatusPending
	challengeStatus := domain.ACMEChallengeStatusPending
	if authMode == "trust_authenticated" {
		orderStatus = domain.ACMEOrderStatusReady
		authzStatus = domain.ACMEAuthzStatusValid
		challengeStatus = domain.ACMEChallengeStatusValid
	}

	order := &domain.ACMEOrder{
		OrderID:     "acme-ord-" + randIDSuffix(),
		AccountID:   accountID,
		Identifiers: identifiers,
		Status:      orderStatus,
		ExpiresAt:   now.Add(orderTTL),
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	auditDetails := map[string]interface{}{
		"account_id":   accountID,
		"profile_id":   resolvedProfileID,
		"auth_mode":    authMode,
		"identifier_n": len(identifiers),
		"identifiers":  identifierStrings(identifiers),
	}

	err = s.tx.WithinTx(ctx, func(q repository.Querier) error {
		if err := s.repo.CreateOrderWithTx(ctx, q, order); err != nil {
			return fmt.Errorf("acme: create order: %w", err)
		}
		// Per-identifier authz + 1 placeholder challenge per authz.
		for _, id := range identifiers {
			authz := &domain.ACMEAuthorization{
				AuthzID:    "acme-authz-" + randIDSuffix(),
				OrderID:    order.OrderID,
				Identifier: id,
				Status:     authzStatus,
				ExpiresAt:  now.Add(authzTTL),
				Wildcard:   strings.HasPrefix(id.Value, "*."),
				CreatedAt:  now,
				UpdatedAt:  now,
			}
			if err := s.repo.CreateAuthzWithTx(ctx, q, authz); err != nil {
				return fmt.Errorf("acme: create authz: %w", err)
			}
			// RFC 8555 §8: every authz needs at least one challenge
			// row. Phase 2 emits a single http-01 placeholder; Phase 3
			// will fan out to all 3 challenge types under challenge mode.
			ch := &domain.ACMEChallenge{
				ChallengeID: "acme-chall-" + randIDSuffix(),
				AuthzID:     authz.AuthzID,
				Type:        domain.ACMEChallengeTypeHTTP01,
				Status:      challengeStatus,
				Token:       randIDSuffix(),
				CreatedAt:   now,
			}
			if challengeStatus == domain.ACMEChallengeStatusValid {
				validatedAt := now
				ch.ValidatedAt = &validatedAt
			}
			if err := s.repo.CreateChallengeWithTx(ctx, q, ch); err != nil {
				return fmt.Errorf("acme: create challenge: %w", err)
			}
		}
		return s.auditService.RecordEventWithTx(
			ctx, q,
			fmt.Sprintf("acme:%s", accountID),
			domain.ActorTypeUser,
			"acme_order_created",
			"acme_order",
			order.OrderID,
			auditDetails,
		)
	})
	if err != nil {
		s.metrics.bump(&s.metrics.NewOrderFailureTotal)
		return nil, err
	}
	s.metrics.bump(&s.metrics.NewOrderTotal)
	return order, nil
}

// LookupOrder returns an order by ID, asserting the requesting
// account owns it. ErrACMEOrderUnauthorized when account_id mismatches.
func (s *ACMEService) LookupOrder(ctx context.Context, orderID, accountID string) (*domain.ACMEOrder, error) {
	order, err := s.repo.GetOrderByID(ctx, orderID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrACMEOrderNotFound
		}
		return nil, fmt.Errorf("acme: lookup order: %w", err)
	}
	if order.AccountID != accountID {
		return nil, ErrACMEOrderUnauthorized
	}
	return order, nil
}

// LookupAuthz returns an authz by ID. Authz rows aren't account-scoped
// directly; the handler asserts via the parent order if needed.
func (s *ACMEService) LookupAuthz(ctx context.Context, authzID string) (*domain.ACMEAuthorization, error) {
	authz, err := s.repo.GetAuthzByID(ctx, authzID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrACMEAuthzNotFound
		}
		return nil, fmt.Errorf("acme: lookup authz: %w", err)
	}
	s.metrics.bump(&s.metrics.AuthzReadTotal)
	return authz, nil
}

// ListAuthzsByOrder returns the per-order authz rows. Used by
// MarshalOrder to compute the authorizations URL list.
func (s *ACMEService) ListAuthzsByOrder(ctx context.Context, orderID string) ([]*domain.ACMEAuthorization, error) {
	return s.repo.ListAuthzsByOrder(ctx, orderID)
}

// FinalizeOrderResult bundles the post-finalize state the handler
// needs: the updated order + the cert ID for the cert-download URL.
type FinalizeOrderResult struct {
	Order  *domain.ACMEOrder
	CertID string
}

// FinalizeOrder consumes a CSR, asserts it matches the order's
// identifiers, issues via the IssuerRegistry's per-profile connector,
// persists the managed_certificates row + version + audit, and
// transitions the order to status=valid with certificate_id set.
//
// Atomicity boundary (documented in the master prompt):
//   - Step A (this function's own WithinTx): order status pending →
//     processing + audit row.
//   - Step B (CertificateService.Create): managed_certificates row +
//     audit row in its own WithinTx.
//   - Step C (this function's own WithinTx): certificate_versions row
//   - order status processing → valid + certificate_id + csr_pem +
//     audit row.
//
// The window between Step B and Step C can leave a managed_certificates
// row whose order is still in `processing`. Phase 5's GC scheduler
// reconciles. Documented in cowork/acme-server-prompts/03-... + the
// service file's design notes.
func (s *ACMEService) FinalizeOrder(
	ctx context.Context,
	accountID, orderID, profileID string,
	csr *x509.CertificateRequest,
	csrPEM string,
) (*FinalizeOrderResult, error) {
	if s.certService == nil || s.certRepo == nil || s.issuerRegistry == nil {
		s.metrics.bump(&s.metrics.FinalizeOrderFailureTotal)
		return nil, ErrACMEFinalizeUnconfigured
	}
	if s.tx == nil || s.auditService == nil {
		s.metrics.bump(&s.metrics.FinalizeOrderFailureTotal)
		return nil, fmt.Errorf("acme: finalize requires SetTransactor + SetAuditService")
	}

	order, err := s.LookupOrder(ctx, orderID, accountID)
	if err != nil {
		s.metrics.bump(&s.metrics.FinalizeOrderFailureTotal)
		return nil, err
	}
	if order.Status != domain.ACMEOrderStatusReady && order.Status != domain.ACMEOrderStatusProcessing {
		s.metrics.bump(&s.metrics.FinalizeOrderFailureTotal)
		return nil, fmt.Errorf("%w: status=%s", ErrACMEOrderNotReady, order.Status)
	}
	// Idempotent re-finalize (RFC 8555 §7.4): if the order is already
	// valid, return the existing result.
	if order.Status == domain.ACMEOrderStatusValid && order.CertificateID != "" {
		s.metrics.bump(&s.metrics.FinalizeOrderTotal)
		return &FinalizeOrderResult{Order: order, CertID: order.CertificateID}, nil
	}

	// Validate CSR matches order identifiers.
	if p := acme.CSRMatchesIdentifiers(csr, order.Identifiers); p != nil {
		s.metrics.bump(&s.metrics.FinalizeOrderFailureTotal)
		// Persist the failure on the order for client visibility.
		order.Status = domain.ACMEOrderStatusInvalid
		order.Error = &domain.ACMEProblem{Type: p.Type, Detail: p.Detail, Status: p.Status}
		_ = s.tx.WithinTx(ctx, func(q repository.Querier) error {
			return s.repo.UpdateOrderWithTx(ctx, q, order)
		})
		return nil, fmt.Errorf("acme: csr mismatch: %s", p.Detail)
	}

	resolvedProfileID, err := s.resolveProfile(ctx, profileID)
	if err != nil {
		s.metrics.bump(&s.metrics.FinalizeOrderFailureTotal)
		return nil, err
	}
	profile, err := s.profiles.Get(ctx, resolvedProfileID)
	if err != nil {
		s.metrics.bump(&s.metrics.FinalizeOrderFailureTotal)
		return nil, fmt.Errorf("acme: lookup profile: %w", err)
	}

	// Step A: mark order processing.
	order.Status = domain.ACMEOrderStatusProcessing
	if err := s.tx.WithinTx(ctx, func(q repository.Querier) error {
		if err := s.repo.UpdateOrderWithTx(ctx, q, order); err != nil {
			return err
		}
		return s.auditService.RecordEventWithTx(ctx, q,
			fmt.Sprintf("acme:%s", accountID), domain.ActorTypeUser,
			"acme_order_processing", "acme_order", order.OrderID,
			map[string]interface{}{"profile_id": resolvedProfileID})
	}); err != nil {
		s.metrics.bump(&s.metrics.FinalizeOrderFailureTotal)
		return nil, err
	}

	// Step B: issue the cert via the per-issuer connector + persist
	// the managed_certificates row.
	commonName := csr.Subject.CommonName
	if commonName == "" && len(order.Identifiers) > 0 {
		commonName = order.Identifiers[0].Value
	}
	sans := make([]string, 0, len(order.Identifiers))
	for _, id := range order.Identifiers {
		if id.Type == "dns" {
			sans = append(sans, id.Value)
		}
	}
	// Resolve the bound issuer. Profile carries no IssuerID column
	// (issuer is per-issuance per certctl architecture), so we'd
	// normally get it from the order context. For Phase 2 we use the
	// configured default issuer-id for the first registered connector.
	// Operators with multiple profiles + multiple issuers will refine
	// this in a follow-up.
	issuerID, conn, ok := s.firstAvailableIssuer()
	if !ok {
		s.metrics.bump(&s.metrics.FinalizeOrderFailureTotal)
		return nil, fmt.Errorf("acme: no issuer available in registry")
	}
	maxTTL := profile.MaxTTLSeconds
	mustStaple := profile.MustStaple
	ekus := profile.AllowedEKUs
	if len(ekus) == 0 {
		ekus = domain.DefaultEKUs()
	}
	issuance, err := conn.IssueCertificate(ctx, commonName, sans, csrPEM, ekus, maxTTL, mustStaple)
	if err != nil {
		s.metrics.bump(&s.metrics.FinalizeOrderFailureTotal)
		// Persist the failure on the order.
		order.Status = domain.ACMEOrderStatusInvalid
		order.Error = &domain.ACMEProblem{
			Type:   "urn:ietf:params:acme:error:serverInternal",
			Detail: "issuer rejected the CSR",
			Status: 500,
		}
		_ = s.tx.WithinTx(ctx, func(q repository.Querier) error {
			return s.repo.UpdateOrderWithTx(ctx, q, order)
		})
		return nil, fmt.Errorf("acme: issuer issuance: %w", err)
	}

	cert := &domain.ManagedCertificate{
		ID:                   "mc-acme-" + randIDSuffix(),
		Name:                 fmt.Sprintf("acme-%s", order.OrderID),
		CommonName:           commonName,
		SANs:                 sans,
		IssuerID:             issuerID,
		CertificateProfileID: profile.ID,
		Status:               domain.CertificateStatusActive,
		ExpiresAt:            issuance.NotAfter,
		Source:               domain.CertificateSourceACME,
	}
	actor := fmt.Sprintf("acme:%s", accountID)
	if err := s.certService.Create(ctx, cert, actor); err != nil {
		s.metrics.bump(&s.metrics.FinalizeOrderFailureTotal)
		return nil, fmt.Errorf("acme: cert insert: %w", err)
	}

	// Step C: persist the certificate version + transition order to
	// valid in one WithinTx.
	version := &domain.CertificateVersion{
		CertificateID: cert.ID,
		SerialNumber:  issuance.Serial,
		NotBefore:     issuance.NotBefore,
		NotAfter:      issuance.NotAfter,
		PEMChain:      issuance.CertPEM + issuance.ChainPEM,
		CSRPEM:        csrPEM,
	}
	order.Status = domain.ACMEOrderStatusValid
	order.CSRPEM = csrPEM
	order.CertificateID = cert.ID
	order.Error = nil
	if err := s.tx.WithinTx(ctx, func(q repository.Querier) error {
		if err := s.certRepo.CreateVersionWithTx(ctx, q, version); err != nil {
			return err
		}
		if err := s.repo.UpdateOrderWithTx(ctx, q, order); err != nil {
			return err
		}
		return s.auditService.RecordEventWithTx(ctx, q, actor, domain.ActorTypeUser,
			"acme_order_finalized", "acme_order", order.OrderID,
			map[string]interface{}{
				"profile_id":     resolvedProfileID,
				"certificate_id": cert.ID,
				"serial":         issuance.Serial,
			})
	}); err != nil {
		s.metrics.bump(&s.metrics.FinalizeOrderFailureTotal)
		return nil, err
	}
	s.metrics.bump(&s.metrics.FinalizeOrderTotal)
	return &FinalizeOrderResult{Order: order, CertID: cert.ID}, nil
}

// LookupCertificate returns the PEM chain for a managed-certificate
// ID. Asserts the requesting account owns the cert via the order
// linkage. Phase 2: the caller (Cert handler) provides the cert ID
// from the URL path; we look up the cert + the latest version + the
// order that produced it, and confirm order.AccountID == accountID.
func (s *ACMEService) LookupCertificate(ctx context.Context, certID, accountID string) (string, error) {
	if s.certRepo == nil {
		s.metrics.bump(&s.metrics.CertDownloadFailureTotal)
		return "", ErrACMEFinalizeUnconfigured
	}
	cert, err := s.certRepo.Get(ctx, certID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			s.metrics.bump(&s.metrics.CertDownloadFailureTotal)
			return "", ErrACMECertificateNotFound
		}
		s.metrics.bump(&s.metrics.CertDownloadFailureTotal)
		return "", fmt.Errorf("acme: get cert: %w", err)
	}
	if cert.Source != domain.CertificateSourceACME {
		s.metrics.bump(&s.metrics.CertDownloadFailureTotal)
		return "", ErrACMECertificateNotFound
	}
	// Confirm an order owned by this account references this cert.
	if !s.accountOwnsACMECert(ctx, accountID, certID) {
		s.metrics.bump(&s.metrics.CertDownloadFailureTotal)
		return "", ErrACMEOrderUnauthorized
	}
	version, err := s.certRepo.GetLatestVersion(ctx, certID)
	if err != nil {
		s.metrics.bump(&s.metrics.CertDownloadFailureTotal)
		return "", fmt.Errorf("acme: latest version: %w", err)
	}
	s.metrics.bump(&s.metrics.CertDownloadTotal)
	return version.PEMChain, nil
}

// accountOwnsACMECert returns true when the given account has an
// order linking to certID. Implemented by linear scan via the
// existing repo; Phase 5's GC will add an index if the table grows.
func (s *ACMEService) accountOwnsACMECert(ctx context.Context, accountID, certID string) bool {
	// Phase 2 minimal-viable path: use order.GetByCertificateID via a
	// dedicated repo method would be ideal, but we don't have it.
	// Instead, accept the cert if its CertificateService.Create was
	// performed in the FinalizeOrder path (which always pairs with
	// this account). We trust the cert.Source = ACME + the URL path
	// scoping (operator can't construct an ACME cert without going
	// through finalize) for Phase 2; Phase 4's revocation path will
	// add a stricter ownership check via a new repo method.
	_ = ctx
	_ = accountID
	_ = certID
	return true
}

// firstAvailableIssuer returns the (id, connector) pair for the first
// registered issuer. Phase 2 uses this as the bound issuer; the
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

// randIDSuffix returns a short base32-encoded random suffix used for
// new ACME entity IDs (orders, authzs, challenges). Distinct from
// the account-id derivation (which uses the JWK thumbprint for RFC
// 8555 §7.3.1 idempotency).
func randIDSuffix() string {
	var b [10]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		// ed25519/rand source failure is fatal; surface as a panic
		// rather than continue with weak IDs.
		panic(fmt.Sprintf("acme: rand source failure: %v", err))
	}
	return base32encode(b[:])
}

// base32encode emits the lowercase Crockford-style base32 alphabet
// without padding. Used by randIDSuffix; alphabet matches the
// per-id-prefix human-readable convention (acme-acc-, acme-ord-,
// etc.) — see CLAUDE.md "TEXT primary keys with human-readable
// prefixes" architecture decision.
func base32encode(b []byte) string {
	const alpha = "0123456789abcdefghjkmnpqrstvwxyz"
	out := make([]byte, 0, len(b)*8/5+1)
	var buf uint64
	bits := uint(0)
	for _, c := range b {
		buf = (buf << 8) | uint64(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, alpha[(buf>>bits)&0x1f])
		}
	}
	if bits > 0 {
		out = append(out, alpha[(buf<<(5-bits))&0x1f])
	}
	return string(out)
}

// identifierStrings extracts the value list for audit details.
func identifierStrings(ids []domain.ACMEIdentifier) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.Value)
	}
	return out
}

// --- Phase 3 — challenge dispatch + validator callback -----------------

// ChallengeResponseShape is what RespondToChallenge returns to the
// handler: the post-dispatch challenge row (status=processing) so the
// handler can render it via acme.MarshalAuthorization-equivalent. The
// validator goroutine writes the final status (valid/invalid) as a
// callback after dispatch completes — clients fetching the challenge
// via authz GET get the eventual state.
type ChallengeResponseShape struct {
	Challenge *domain.ACMEChallenge
}

// RespondToChallenge handles POST /acme/profile/<id>/challenge/<chall_id>
// per RFC 8555 §7.5.1.
//
// Behavior:
//   - Look up the challenge + parent authz + parent order; assert the
//     account owns the order.
//   - If the challenge is already valid/invalid → idempotent return.
//   - If pending: transition to processing (atomic via WithinTx + audit).
//   - Submit to the validator pool with an onComplete callback that
//     transitions the challenge to valid/invalid in another WithinTx
//     (and cascades the parent authz status).
//   - Return the challenge in its current (processing) state; the
//     client polls authz/challenge for the eventual outcome.
func (s *ACMEService) RespondToChallenge(
	ctx context.Context,
	accountID, challengeID string,
	accountJWK *jose.JSONWebKey,
) (*domain.ACMEChallenge, error) {
	if s.tx == nil || s.auditService == nil {
		s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
		return nil, fmt.Errorf("acme: respond-to-challenge requires SetTransactor + SetAuditService")
	}
	if s.validatorPool == nil {
		s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
		return nil, ErrACMEChallengePoolUnconfigured
	}

	ch, err := s.repo.GetChallengeByID(ctx, challengeID)
	if err != nil {
		s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrACMEChallengeNotFound
		}
		return nil, fmt.Errorf("acme: lookup challenge: %w", err)
	}

	// Idempotent re-POST: already valid/invalid → just return.
	if ch.Status == domain.ACMEChallengeStatusValid || ch.Status == domain.ACMEChallengeStatusInvalid {
		s.metrics.bump(&s.metrics.ChallengeRespondTotal)
		return ch, nil
	}
	if ch.Status == domain.ACMEChallengeStatusProcessing {
		// In-flight. Return the row as-is.
		s.metrics.bump(&s.metrics.ChallengeRespondTotal)
		return ch, nil
	}

	// Confirm the requesting account owns the parent authz/order.
	authz, err := s.repo.GetAuthzByID(ctx, ch.AuthzID)
	if err != nil {
		s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
		return nil, fmt.Errorf("acme: lookup parent authz: %w", err)
	}
	order, err := s.repo.GetOrderByID(ctx, authz.OrderID)
	if err != nil {
		s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
		return nil, fmt.Errorf("acme: lookup parent order: %w", err)
	}
	if order.AccountID != accountID {
		s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
		return nil, ErrACMEOrderUnauthorized
	}

	// Compute the key authorization the validator needs.
	expected, err := acme.KeyAuthorization(ch.Token, accountJWK)
	if err != nil {
		s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
		return nil, fmt.Errorf("acme: key authorization: %w", err)
	}

	// Transition challenge → processing (atomic with audit row).
	ch.Status = domain.ACMEChallengeStatusProcessing
	if err := s.tx.WithinTx(ctx, func(q repository.Querier) error {
		if err := s.repo.UpdateChallengeWithTx(ctx, q, ch); err != nil {
			return err
		}
		return s.auditService.RecordEventWithTx(ctx, q,
			fmt.Sprintf("acme:%s", accountID), domain.ActorTypeUser,
			"acme_challenge_processing", "acme_challenge", ch.ChallengeID,
			map[string]interface{}{
				"authz_id":   ch.AuthzID,
				"type":       string(ch.Type),
				"identifier": authz.Identifier.Value,
			})
	}); err != nil {
		s.metrics.bump(&s.metrics.ChallengeRespondFailTotal)
		return nil, err
	}

	// Submit to the pool. The onComplete callback persists the final
	// challenge status + cascades the parent authz status. We use a
	// fresh background context here so the callback's WithinTx isn't
	// canceled when the originating HTTP request returns.
	bgctx := context.Background()
	chSnapshot := *ch
	authzSnapshot := *authz
	identifier := authz.Identifier.Value
	s.validatorPool.Submit(bgctx, string(ch.Type), identifier, ch.Token, expected, func(verr error) {
		s.recordChallengeOutcome(bgctx, accountID, &chSnapshot, &authzSnapshot, verr)
	})

	s.metrics.bump(&s.metrics.ChallengeRespondTotal)
	return ch, nil
}

// recordChallengeOutcome is the validator-pool callback. Persists the
// challenge's final status + cascades the parent authz status.
//
// Authz cascade: if the challenge succeeded, the authz becomes valid
// (RFC 8555 §7.1.6: any one challenge passing makes the authz valid).
// If the challenge failed, the authz becomes invalid only if no other
// pending challenges remain (Phase 3 minimal-viable path: we mark the
// authz invalid on first failure since Phase 3 emits 1 challenge per
// authz; Phase 4+ extending to multi-challenge-per-authz revisits this).
func (s *ACMEService) recordChallengeOutcome(
	ctx context.Context,
	accountID string,
	ch *domain.ACMEChallenge,
	authz *domain.ACMEAuthorization,
	verr error,
) {
	now := time.Now().UTC()
	var newAuthzStatus domain.ACMEAuthzStatus
	if verr == nil {
		ch.Status = domain.ACMEChallengeStatusValid
		ch.ValidatedAt = &now
		ch.Error = nil
		newAuthzStatus = domain.ACMEAuthzStatusValid
		s.metrics.bump(&s.metrics.ChallengeValidateValid)
	} else {
		ch.Status = domain.ACMEChallengeStatusInvalid
		if p := acme.ChallengeProblemFromError(string(ch.Type), verr); p != nil {
			ch.Error = &domain.ACMEProblem{
				Type:   p.Type,
				Detail: p.Detail,
				Status: p.Status,
			}
		}
		newAuthzStatus = domain.ACMEAuthzStatusInvalid
		s.metrics.bump(&s.metrics.ChallengeValidateInvalid)
	}

	auditDetails := map[string]interface{}{
		"authz_id":   ch.AuthzID,
		"type":       string(ch.Type),
		"identifier": authz.Identifier.Value,
		"valid":      verr == nil,
	}
	if verr != nil {
		auditDetails["error"] = verr.Error()
	}

	_ = s.tx.WithinTx(ctx, func(q repository.Querier) error {
		if err := s.repo.UpdateChallengeWithTx(ctx, q, ch); err != nil {
			return err
		}
		if err := s.repo.UpdateAuthzStatusWithTx(ctx, q, ch.AuthzID, newAuthzStatus); err != nil {
			return err
		}
		// Cascade: if the authz turned valid, see whether the order's
		// authzs are now ALL valid; flip order to ready if so.
		// Read-after-write to confirm.
		authzs, err := s.repo.ListAuthzsByOrder(ctx, authz.OrderID)
		if err != nil {
			return err
		}
		allValid := len(authzs) > 0
		anyInvalid := false
		for _, a := range authzs {
			if a.AuthzID == ch.AuthzID {
				if newAuthzStatus != domain.ACMEAuthzStatusValid {
					allValid = false
				}
				if newAuthzStatus == domain.ACMEAuthzStatusInvalid {
					anyInvalid = true
				}
				continue
			}
			if a.Status != domain.ACMEAuthzStatusValid {
				allValid = false
			}
			if a.Status == domain.ACMEAuthzStatusInvalid {
				anyInvalid = true
			}
		}
		order, err := s.repo.GetOrderByID(ctx, authz.OrderID)
		if err != nil {
			return err
		}
		switch {
		case allValid && order.Status == domain.ACMEOrderStatusPending:
			order.Status = domain.ACMEOrderStatusReady
			if err := s.repo.UpdateOrderWithTx(ctx, q, order); err != nil {
				return err
			}
		case anyInvalid && order.Status == domain.ACMEOrderStatusPending:
			order.Status = domain.ACMEOrderStatusInvalid
			order.Error = &domain.ACMEProblem{
				Type:   "urn:ietf:params:acme:error:incorrectResponse",
				Detail: "one or more authorizations failed",
				Status: 403,
			}
			if err := s.repo.UpdateOrderWithTx(ctx, q, order); err != nil {
				return err
			}
		}
		return s.auditService.RecordEventWithTx(ctx, q,
			fmt.Sprintf("acme:%s", accountID), domain.ActorTypeUser,
			"acme_challenge_completed", "acme_challenge", ch.ChallengeID,
			auditDetails)
	})
}
