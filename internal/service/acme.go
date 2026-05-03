// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package service

import (
	"context"
	"errors"
	"fmt"
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
//   - Phase 1b (this commit): VerifyJWS, NewAccount, LookupAccount,
//     UpdateAccount, DeactivateAccount.
//   - Subsequent phases extend with new-order, finalize, challenges,
//     key-change, revoke, ARI.
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
		"certctl_acme_directory_total":               m.DirectoryTotal.Load(),
		"certctl_acme_directory_failures_total":      m.DirectoryFailureTotal.Load(),
		"certctl_acme_new_nonce_total":               m.NewNonceTotal.Load(),
		"certctl_acme_new_nonce_failures_total":      m.NewNonceFailureTotal.Load(),
		"certctl_acme_new_account_total":             m.NewAccountTotal.Load(),
		"certctl_acme_new_account_failures_total":    m.NewAccountFailureTotal.Load(),
		"certctl_acme_new_account_idempotent_total":  m.NewAccountIdempotentTotal.Load(),
		"certctl_acme_update_account_total":          m.UpdateAccountTotal.Load(),
		"certctl_acme_update_account_failures_total": m.UpdateAccountFailureTotal.Load(),
		"certctl_acme_deactivate_account_total":      m.DeactivateAccountTotal.Load(),
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
