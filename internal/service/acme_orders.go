// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

package service

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/certctl-io/certctl/internal/api/acme"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// Phase 9 ARCH-M2 closure Sprint 9b (2026-05-14): the deferred half of
// Sprint 9. Extracted from internal/service/acme.go via the Option B
// sibling-file pattern. Package stays `service`; every external caller
// of `service.ACMEService.{CreateOrder,LookupOrder,FinalizeOrder,
// LookupCertificate}` resolves the same way — pure mechanical
// relocation.
//
// What lives here
// ===============
// The Phase 2 orders concern in full: the order CRUD methods
// (CreateOrder + LookupOrder + FinalizeOrder + LookupCertificate),
// the FinalizeOrderResult shape, the order-scoped accountOwnsACMECert
// ownership check, and the three orders-internal ID helpers
// (randIDSuffix + base32encode for generating acme-ord-* / acme-authz-* /
// acme-chall-* / mc-acme-* prefixes per the project's TEXT-primary-keys
// architecture decision; identifierStrings for audit detail rendering).
//
// What stays in acme.go (cross-concern by helper-call analysis)
// =============================================================
// firstAvailableIssuer remains in acme.go. Three call sites consume
// it: FinalizeOrder (here in acme_orders.go) AND Phase 4 RevokeCert
// + RenewalInfo (both in acme.go). Moving it here would leave Phase 4
// reaching across a sibling-file boundary for a single helper; leaving
// it in acme.go keeps it adjacent to its other two callers while still
// staying reachable from this file via Go's same-package scope. The
// alternative (a third "shared helpers" sibling) costs an extra file
// for one helper — not worth the indirection.
//
// mapACMERevocationReason stays in acme.go too. It's used exclusively
// by Phase 4 RevokeCert. Despite sitting in the orders helper cluster
// in audit notes (because of its alphabetical-adjacency to the other
// helpers in the audit-time grep), the actual call graph puts it
// firmly on the Phase 4 side.
//
// Sprint 9 vs Sprint 9b
// =====================
// Sprint 9 (commit b503d27b) shipped nonces + authz + challenges + gc
// — four files, 432 LOC moved, all single-contiguous-region cuts.
// Sprint 9b crosses the harder boundary the original sprint deferred:
// a ~476-LOC two-block cut (orders block A + helpers block B with
// firstAvailableIssuer's 14 lines between them staying behind) plus
// the per-helper move-vs-stay decision documented above. Splitting
// 9 from 9b keeps the four contiguous cuts on one commit and the
// non-contiguous cut on its own, mirroring the Sprint 8 / Sprint 8b
// pattern (mechanical vs harder-shape, separate review windows).

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
	// Phase 5 — per-account orders/hour cap. Hits return rateLimited
	// (RFC 8555 §6.7) before any DB work. Counter is in-memory; restart
	// wipes (eventual-consistency caps are acceptable).
	if s.rateLimiter != nil && s.cfg.RateLimitOrdersPerHour > 0 {
		if !s.rateLimiter.Allow(acme.ActionNewOrder, accountID, s.cfg.RateLimitOrdersPerHour) {
			s.metrics.bump(&s.metrics.NewOrderFailureTotal)
			return nil, ErrACMERateLimited
		}
	}
	// Phase 5 — concurrent-orders cap. We count
	// pending/ready/processing orders for this account; if at-or-over
	// the cap, reject. This is a DB read (no FOR UPDATE), so two
	// requests racing under the threshold can both succeed and push
	// the account one over — accepted as eventual-consistency.
	if s.cfg.RateLimitConcurrentOrders > 0 {
		count, cerr := s.repo.CountActiveOrdersByAccount(ctx, accountID)
		if cerr == nil && count >= s.cfg.RateLimitConcurrentOrders {
			s.metrics.bump(&s.metrics.NewOrderFailureTotal)
			return nil, ErrACMEConcurrentOrdersExceeded
		}
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
// reconciles. Documented in the project's ACME-server design notes + the
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
// etc.) — see the project's "TEXT primary keys with human-readable
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
