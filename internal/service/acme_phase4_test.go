// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/shankar0123/certctl/internal/api/acme"
	"github.com/shankar0123/certctl/internal/config"
	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// Phase 4 — service-layer tests for RotateAccountKey + RevokeCert +
// RenewalInfo against the in-memory fakeACMERepo. These exercise the
// service contract; full-stack JWS-flow tests live in the api/acme +
// handler test packages.

// --- RotateAccountKey ---------------------------------------------------

func newTestRSAJWKForSvc(t *testing.T) (*rsa.PrivateKey, *jose.JSONWebKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwk := &jose.JSONWebKey{Key: priv.Public(), Algorithm: string(jose.RS256), Use: "sig"}
	return priv, jwk
}

func newTestECDSAJWKForSvc(t *testing.T) (*ecdsa.PrivateKey, *jose.JSONWebKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	jwk := &jose.JSONWebKey{Key: priv.Public(), Algorithm: string(jose.ES256), Use: "sig"}
	return priv, jwk
}

func TestRotateAccountKey_HappyPath(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	profiles := map[string]*domain.CertificateProfile{"prof-corp": {ID: "prof-corp"}}
	svc, repo, _ := newSvcWithAudit(t, cfg, profiles)

	_, oldJWK := newTestRSAJWKForSvc(t)
	oldThumb, err := acme.JWKThumbprint(oldJWK)
	if err != nil {
		t.Fatalf("thumb: %v", err)
	}
	oldPEM, err := acme.JWKToPEM(oldJWK)
	if err != nil {
		t.Fatalf("pem: %v", err)
	}
	repo.accounts["acme-acc-test"] = &domain.ACMEAccount{
		AccountID:     "acme-acc-test",
		ProfileID:     "prof-corp",
		JWKThumbprint: oldThumb,
		JWKPEM:        oldPEM,
		Status:        domain.ACMEAccountStatusValid,
	}

	_, newJWK := newTestECDSAJWKForSvc(t)
	rolled, err := svc.RotateAccountKey(context.Background(), repo.accounts["acme-acc-test"], newJWK)
	if err != nil {
		t.Fatalf("RotateAccountKey: %v", err)
	}
	newThumb, _ := acme.JWKThumbprint(newJWK)
	if rolled.JWKThumbprint != newThumb {
		t.Errorf("rolled thumbprint = %q, want %q", rolled.JWKThumbprint, newThumb)
	}
	if repo.accounts["acme-acc-test"].JWKThumbprint != newThumb {
		t.Errorf("persisted thumbprint not updated")
	}
}

func TestRotateAccountKey_DuplicateNewKey(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	profiles := map[string]*domain.CertificateProfile{"prof-corp": {ID: "prof-corp"}}
	svc, repo, _ := newSvcWithAudit(t, cfg, profiles)

	_, oldJWK := newTestRSAJWKForSvc(t)
	_, newJWK := newTestECDSAJWKForSvc(t)
	oldThumb, _ := acme.JWKThumbprint(oldJWK)
	newThumb, _ := acme.JWKThumbprint(newJWK)
	oldPEM, _ := acme.JWKToPEM(oldJWK)
	newPEM, _ := acme.JWKToPEM(newJWK)

	// Account A holds the OLD key (will request rotation).
	repo.accounts["acme-acc-A"] = &domain.ACMEAccount{
		AccountID:     "acme-acc-A",
		ProfileID:     "prof-corp",
		JWKThumbprint: oldThumb,
		JWKPEM:        oldPEM,
		Status:        domain.ACMEAccountStatusValid,
	}
	// Account B already holds the NEW key — collision target.
	repo.accounts["acme-acc-B"] = &domain.ACMEAccount{
		AccountID:     "acme-acc-B",
		ProfileID:     "prof-corp",
		JWKThumbprint: newThumb,
		JWKPEM:        newPEM,
		Status:        domain.ACMEAccountStatusValid,
	}
	// Wire the thumbprint→account index that GetAccountByThumbprint
	// consults.
	repo.thumbToAccount["prof-corp|"+newThumb] = "acme-acc-B"

	_, err := svc.RotateAccountKey(context.Background(), repo.accounts["acme-acc-A"], newJWK)
	if !errors.Is(err, ErrACMEKeyRolloverDuplicateKey) {
		t.Errorf("got err=%v, want ErrACMEKeyRolloverDuplicateKey", err)
	}
}

// --- RevokeCert ---------------------------------------------------------

// stubRevoker captures the args RevokeCertificateWithActor receives.
type stubRevoker struct {
	calls []revokeCall
	err   error
}
type revokeCall struct {
	certID, reason, actor string
}

func (s *stubRevoker) RevokeCertificateWithActor(ctx context.Context, certID, reason, actor string) error {
	s.calls = append(s.calls, revokeCall{certID, reason, actor})
	return s.err
}

// stubCertRepo is a minimal CertificateRepository for revoke + renewal-info tests.
type stubCertRepo struct {
	repository.CertificateRepository
	cert    *domain.ManagedCertificate
	version *domain.CertificateVersion
	getErr  error
}

func (s *stubCertRepo) GetVersionBySerial(ctx context.Context, issuerID, serial string) (*domain.CertificateVersion, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	if s.version != nil && s.version.SerialNumber == serial {
		return s.version, nil
	}
	return nil, errors.New("not found")
}
func (s *stubCertRepo) Get(ctx context.Context, id string) (*domain.ManagedCertificate, error) {
	if s.cert != nil && s.cert.ID == id {
		return s.cert, nil
	}
	return nil, errors.New("not found")
}

// stubIssuerConn is a no-op IssuerConnector for firstAvailableIssuer().
// We don't need the connector itself to do anything; just that
// firstAvailableIssuer returns ok=true.

// stubRenewalPolicies is a minimal RenewalPolicyLookup.
type stubRenewalPolicies struct {
	pol *domain.RenewalPolicy
}

func (s *stubRenewalPolicies) Get(ctx context.Context, id string) (*domain.RenewalPolicy, error) {
	if s.pol != nil && s.pol.ID == id {
		return s.pol, nil
	}
	return nil, errors.New("not found")
}

func generateRevocationFixture(t *testing.T) (cert *domain.ManagedCertificate, version *domain.CertificateVersion, der []byte, certPriv *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0xabcdef12),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err = x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	parsed, _ := x509.ParseCertificate(der)
	serialHex := strings.ToLower(parsed.SerialNumber.Text(16))
	cert = &domain.ManagedCertificate{
		ID:        "mc-test-001",
		IssuerID:  "iss-test",
		ExpiresAt: parsed.NotAfter,
		Status:    domain.CertificateStatusActive,
	}
	version = &domain.CertificateVersion{
		CertificateID: cert.ID,
		SerialNumber:  serialHex,
		NotBefore:     parsed.NotBefore,
		NotAfter:      parsed.NotAfter,
	}
	return cert, version, der, priv
}

// minimalIssuerRegistryWithOne returns an IssuerRegistry that reports
// one available issuer so firstAvailableIssuer() is happy.
func minimalIssuerRegistryWithOne() *IssuerRegistry {
	r := NewIssuerRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.issuers["iss-test"] = nil // map entry is enough for first-available iteration
	return r
}

func TestRevokeCert_NotConfigured(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, _, _ := newSvcWithAudit(t, cfg, nil)
	err := svc.RevokeCert(context.Background(), &acme.VerifiedRequest{}, []byte{1, 2, 3}, 0)
	if !errors.Is(err, ErrACMERevocationUnconfigured) {
		t.Errorf("got err=%v, want ErrACMERevocationUnconfigured", err)
	}
}

func TestRevokeCert_KidPath_AccountDoesNotOwn(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, _, _ := newSvcWithAudit(t, cfg, nil)
	revoker := &stubRevoker{}
	cert, version, der, _ := generateRevocationFixture(t)
	certRepo := &stubCertRepo{cert: cert, version: version}
	svc.SetIssuancePipeline(nil, certRepo, minimalIssuerRegistryWithOne())
	svc.SetRevocationDelegate(revoker)

	verified := &acme.VerifiedRequest{
		Account: &domain.ACMEAccount{AccountID: "acme-acc-NotOwner"},
	}
	err := svc.RevokeCert(context.Background(), verified, der, 0)
	if !errors.Is(err, ErrACMERevocationUnauthorized) {
		t.Errorf("got err=%v, want ErrACMERevocationUnauthorized", err)
	}
	if len(revoker.calls) != 0 {
		t.Errorf("revoker should not have been called: %+v", revoker.calls)
	}
}

func TestRevokeCert_JWKPath_KeyMismatch(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, _, _ := newSvcWithAudit(t, cfg, nil)
	revoker := &stubRevoker{}
	cert, version, der, _ := generateRevocationFixture(t)
	certRepo := &stubCertRepo{cert: cert, version: version}
	svc.SetIssuancePipeline(nil, certRepo, minimalIssuerRegistryWithOne())
	svc.SetRevocationDelegate(revoker)

	// Different JWK than the cert's own pubkey → 401.
	_, otherJWK := newTestECDSAJWKForSvc(t)
	verified := &acme.VerifiedRequest{JWK: otherJWK}
	err := svc.RevokeCert(context.Background(), verified, der, 0)
	if !errors.Is(err, ErrACMERevocationUnauthorized) {
		t.Errorf("got err=%v, want ErrACMERevocationUnauthorized", err)
	}
}

func TestRevokeCert_JWKPath_HappyPath(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, _, _ := newSvcWithAudit(t, cfg, nil)
	revoker := &stubRevoker{}
	cert, version, der, certPriv := generateRevocationFixture(t)
	certRepo := &stubCertRepo{cert: cert, version: version}
	svc.SetIssuancePipeline(nil, certRepo, minimalIssuerRegistryWithOne())
	svc.SetRevocationDelegate(revoker)

	// JWK == cert's own pubkey.
	jwk := &jose.JSONWebKey{Key: certPriv.Public(), Algorithm: string(jose.ES256)}
	verified := &acme.VerifiedRequest{JWK: jwk}
	if err := svc.RevokeCert(context.Background(), verified, der, 1 /*keyCompromise*/); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	if len(revoker.calls) != 1 {
		t.Fatalf("revoker calls = %d, want 1", len(revoker.calls))
	}
	got := revoker.calls[0]
	if got.certID != cert.ID {
		t.Errorf("certID = %q, want %q", got.certID, cert.ID)
	}
	if got.reason != string(domain.RevocationReasonKeyCompromise) {
		t.Errorf("reason = %q, want keyCompromise", got.reason)
	}
	if !strings.HasPrefix(got.actor, "acme-cert-key:") {
		t.Errorf("actor = %q, want prefix acme-cert-key:", got.actor)
	}
}

func TestRevokeCert_AlreadyRevoked(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, _, _ := newSvcWithAudit(t, cfg, nil)
	revoker := &stubRevoker{}
	cert, version, der, certPriv := generateRevocationFixture(t)
	cert.Status = domain.CertificateStatusRevoked
	certRepo := &stubCertRepo{cert: cert, version: version}
	svc.SetIssuancePipeline(nil, certRepo, minimalIssuerRegistryWithOne())
	svc.SetRevocationDelegate(revoker)

	jwk := &jose.JSONWebKey{Key: certPriv.Public(), Algorithm: string(jose.ES256)}
	err := svc.RevokeCert(context.Background(), &acme.VerifiedRequest{JWK: jwk}, der, 0)
	if !errors.Is(err, ErrACMERevocationAlreadyRevoked) {
		t.Errorf("got err=%v, want ErrACMERevocationAlreadyRevoked", err)
	}
}

func TestRevokeCert_ReasonClamping(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{0, "unspecified"},
		{1, "keyCompromise"},
		{4, "superseded"},
		{8, "unspecified"},  // out-of-range RFC 5280 code
		{99, "unspecified"}, // out-of-range
		{-1, "unspecified"}, // negative
	}
	for _, c := range cases {
		got := mapACMERevocationReason(c.code)
		if got != c.want {
			t.Errorf("code=%d: got %q, want %q", c.code, got, c.want)
		}
	}
}

// --- RenewalInfo --------------------------------------------------------

func TestRenewalInfo_Disabled(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute, ARIEnabled: false}
	svc, _, _ := newSvcWithAudit(t, cfg, nil)
	_, _, err := svc.RenewalInfo(context.Background(), "prof-corp", "abc.def")
	if !errors.Is(err, ErrACMEARIDisabled) {
		t.Errorf("got err=%v, want ErrACMEARIDisabled", err)
	}
}

func TestRenewalInfo_BadCertID(t *testing.T) {
	cfg := config.ACMEServerConfig{
		NonceTTL:        5 * time.Minute,
		ARIEnabled:      true,
		ARIPollInterval: 6 * time.Hour,
	}
	profiles := map[string]*domain.CertificateProfile{"prof-corp": {ID: "prof-corp"}}
	svc, _, _ := newSvcWithAudit(t, cfg, profiles)
	_, _, err := svc.RenewalInfo(context.Background(), "prof-corp", "not-a-valid-cert-id")
	if !errors.Is(err, ErrACMEARIBadCertID) {
		t.Errorf("got err=%v, want ErrACMEARIBadCertID", err)
	}
}
