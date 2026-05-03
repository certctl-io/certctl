// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package service

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/shankar0123/certctl/internal/api/acme"
	"github.com/shankar0123/certctl/internal/config"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// ACMERepo is the persistence-layer surface ACMEService consumes for
// nonce + (later phases) account / order / authz / challenge state.
// Phase 1a wires only the nonce path; the interface is tightened in
// Phase 1b along with the AccountService.
//
// Defining the interface in the service package (rather than
// internal/repository/interfaces.go) keeps the cross-phase blast
// radius small: when Phase 1b adds CreateAccountWithTx /
// GetAccountByThumbprint / etc., only this file's interface and the
// concrete postgres ACMERepository move together. Mock implementations
// in tests satisfy this interface without depending on the postgres
// package.
type ACMERepo interface {
	IssueNonce(ctx context.Context, nonce string, ttl time.Duration) error
	ConsumeNonce(ctx context.Context, nonce string) error
}

// profileLookup is the minimum surface ACMEService needs to resolve a
// per-profile request. Defined as an interface (rather than taking a
// concrete *postgres.ProfileRepository) so tests can inject an in-memory
// fake without spinning up Postgres.
type profileLookup interface {
	Get(ctx context.Context, id string) (*domain.CertificateProfile, error)
}

// ACMEService orchestrates the ACME server's RFC 8555 surface. Phase 1a
// implements:
//
//   - BuildDirectory: returns the per-profile directory document.
//   - IssueNonce: returns a Replay-Nonce, persisted with TTL.
//
// Phase 1b will extend with VerifyJWS, NewAccount, LookupAccount,
// UpdateAccount, DeactivateAccount.
//
// The struct deliberately holds raw config rather than per-field
// extracted values — the directory builder uses 4 of the 11 fields
// and reading them lazily keeps the constructor signature tight.
type ACMEService struct {
	repo     ACMERepo
	profiles profileLookup
	cfg      config.ACMEServerConfig
	metrics  *ACMEMetrics
}

// NewACMEService constructs an ACMEService. The constructor matches
// certctl's per-service convention: required dependencies in the
// argument list (repo, profile lookup, config), optional wiring via
// post-construction setters (metrics is wired now to keep the
// Phase-1a-only footprint clean; Phase 1b adds SetTransactor +
// SetAuditService for the JWS-authenticated POST path).
func NewACMEService(repo ACMERepo, profiles profileLookup, cfg config.ACMEServerConfig) *ACMEService {
	return &ACMEService{
		repo:     repo,
		profiles: profiles,
		cfg:      cfg,
		metrics:  NewACMEMetrics(),
	}
}

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
// Snapshot method that emits stable tuples). Phase 1a tracks just
// directory + new-nonce; subsequent phases add new-account / new-order
// / etc.
type ACMEMetrics struct {
	DirectoryTotal        atomic.Uint64
	DirectoryFailureTotal atomic.Uint64
	NewNonceTotal         atomic.Uint64
	NewNonceFailureTotal  atomic.Uint64
}

// NewACMEMetrics returns a zeroed counter table. Concurrent callers
// can bump counters without external synchronization (atomic.Uint64
// is the synchronization primitive).
func NewACMEMetrics() *ACMEMetrics { return &ACMEMetrics{} }

// bump increments a single atomic counter. Centralized so the call
// sites in BuildDirectory + IssueNonce are uniform.
func (m *ACMEMetrics) bump(c *atomic.Uint64) { c.Add(1) }

// Snapshot emits the current counter values as a map (op → count).
// Naming is certctl_acme_<op>_total per frozen decision 0.10
// (cardinality discipline) so the Prometheus exposer can lift them
// directly without per-op stringly-typed branching.
func (m *ACMEMetrics) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"certctl_acme_directory_total":          m.DirectoryTotal.Load(),
		"certctl_acme_directory_failures_total": m.DirectoryFailureTotal.Load(),
		"certctl_acme_new_nonce_total":          m.NewNonceTotal.Load(),
		"certctl_acme_new_nonce_failures_total": m.NewNonceFailureTotal.Load(),
	}
}
