// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/certctl-io/certctl/internal/config"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// fakeACMERepo is an in-memory ACMERepo for tests. It tracks issued
// nonces in a map; Consume removes the entry to model one-shot use.
// Phase 1b extends with account state.
type fakeACMERepo struct {
	issued   map[string]time.Time // nonce → expires_at
	issueErr error

	// Phase 1b — account state.
	accounts         map[string]*domain.ACMEAccount // account_id → row
	thumbToAccount   map[string]string              // (profile|thumbprint) → account_id
	createAccountErr error
}

func newFakeACMERepo() *fakeACMERepo {
	return &fakeACMERepo{
		issued:         make(map[string]time.Time),
		accounts:       make(map[string]*domain.ACMEAccount),
		thumbToAccount: make(map[string]string),
	}
}

func (f *fakeACMERepo) IssueNonce(ctx context.Context, nonce string, ttl time.Duration) error {
	if f.issueErr != nil {
		return f.issueErr
	}
	f.issued[nonce] = time.Now().Add(ttl)
	return nil
}

func (f *fakeACMERepo) ConsumeNonce(ctx context.Context, nonce string) error {
	exp, ok := f.issued[nonce]
	if !ok {
		return errors.New("not found")
	}
	if time.Now().After(exp) {
		return errors.New("expired")
	}
	delete(f.issued, nonce)
	return nil
}

func (f *fakeACMERepo) CreateAccountWithTx(ctx context.Context, q repository.Querier, acct *domain.ACMEAccount) error {
	if f.createAccountErr != nil {
		return f.createAccountErr
	}
	key := acct.ProfileID + "|" + acct.JWKThumbprint
	if _, exists := f.thumbToAccount[key]; exists {
		return errors.New("duplicate")
	}
	cp := *acct
	cp.CreatedAt = time.Now()
	cp.UpdatedAt = cp.CreatedAt
	f.accounts[acct.AccountID] = &cp
	f.thumbToAccount[key] = acct.AccountID
	return nil
}

func (f *fakeACMERepo) GetAccountByID(ctx context.Context, accountID string) (*domain.ACMEAccount, error) {
	acct, ok := f.accounts[accountID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	cp := *acct
	return &cp, nil
}

func (f *fakeACMERepo) GetAccountByThumbprint(ctx context.Context, profileID, thumbprint string) (*domain.ACMEAccount, error) {
	id, ok := f.thumbToAccount[profileID+"|"+thumbprint]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return f.GetAccountByID(ctx, id)
}

func (f *fakeACMERepo) UpdateAccountContactWithTx(ctx context.Context, q repository.Querier, accountID string, contact []string) error {
	acct, ok := f.accounts[accountID]
	if !ok {
		return repository.ErrNotFound
	}
	acct.Contact = contact
	acct.UpdatedAt = time.Now()
	return nil
}

func (f *fakeACMERepo) UpdateAccountStatusWithTx(ctx context.Context, q repository.Querier, accountID string, status domain.ACMEAccountStatus) error {
	acct, ok := f.accounts[accountID]
	if !ok {
		return repository.ErrNotFound
	}
	acct.Status = status
	acct.UpdatedAt = time.Now()
	return nil
}

// Phase 2 — order / authz / challenge state. Phase 1b tests don't use
// these; the no-op stubs keep the *fakeACMERepo type satisfying the
// extended ACMERepo interface. Phase 2's tests overwrite these as
// needed.
func (f *fakeACMERepo) CreateOrderWithTx(ctx context.Context, q repository.Querier, order *domain.ACMEOrder) error {
	return nil
}
func (f *fakeACMERepo) GetOrderByID(ctx context.Context, orderID string) (*domain.ACMEOrder, error) {
	return nil, repository.ErrNotFound
}
func (f *fakeACMERepo) UpdateOrderWithTx(ctx context.Context, q repository.Querier, order *domain.ACMEOrder) error {
	return nil
}
func (f *fakeACMERepo) CreateAuthzWithTx(ctx context.Context, q repository.Querier, authz *domain.ACMEAuthorization) error {
	return nil
}
func (f *fakeACMERepo) GetAuthzByID(ctx context.Context, authzID string) (*domain.ACMEAuthorization, error) {
	return nil, repository.ErrNotFound
}
func (f *fakeACMERepo) ListAuthzsByOrder(ctx context.Context, orderID string) ([]*domain.ACMEAuthorization, error) {
	return nil, nil
}
func (f *fakeACMERepo) CreateChallengeWithTx(ctx context.Context, q repository.Querier, ch *domain.ACMEChallenge) error {
	return nil
}
func (f *fakeACMERepo) GetChallengeByID(ctx context.Context, challengeID string) (*domain.ACMEChallenge, error) {
	return nil, repository.ErrNotFound
}
func (f *fakeACMERepo) UpdateChallengeWithTx(ctx context.Context, q repository.Querier, ch *domain.ACMEChallenge) error {
	return nil
}
func (f *fakeACMERepo) UpdateAuthzStatusWithTx(ctx context.Context, q repository.Querier, authzID string, status domain.ACMEAuthzStatus) error {
	return nil
}
func (f *fakeACMERepo) UpdateAccountJWKWithTx(ctx context.Context, q repository.Querier, accountID, expectedOldThumbprint, newThumbprint, newJWKPEM string) error {
	for _, acct := range f.accounts {
		if acct.AccountID != accountID {
			continue
		}
		if acct.JWKThumbprint != expectedOldThumbprint {
			return fmt.Errorf("acme: account key was rotated concurrently; retry")
		}
		acct.JWKThumbprint = newThumbprint
		acct.JWKPEM = newJWKPEM
		return nil
	}
	return repository.ErrNotFound
}
func (f *fakeACMERepo) AccountOwnsCertificate(ctx context.Context, accountID, certificateID string) (bool, error) {
	return false, nil
}
func (f *fakeACMERepo) CountActiveOrdersByAccount(ctx context.Context, accountID string) (int, error) {
	return 0, nil
}
func (f *fakeACMERepo) GCExpiredNonces(ctx context.Context) (int64, error) {
	n := int64(0)
	for nonce, exp := range f.issued {
		if time.Now().After(exp) {
			delete(f.issued, nonce)
			n++
		}
	}
	return n, nil
}
func (f *fakeACMERepo) GCExpireAuthorizations(ctx context.Context) (int64, error) { return 0, nil }
func (f *fakeACMERepo) GCInvalidateExpiredOrders(ctx context.Context) (int64, error) {
	return 0, nil
}

// fakeTransactor is the repository.Transactor stand-in: runs fn
// against the supplied querier (we just pass nil — fakes ignore it).
// Mirrors how production transactor works without an actual DB.
type fakeTransactor struct{}

func (f *fakeTransactor) WithinTx(ctx context.Context, fn func(q repository.Querier) error) error {
	return fn(nil)
}

// fakeAuditRepo records the audit events fakeAuditService emits so
// tests can assert on the audit row count + shape.
type fakeAuditRepo struct {
	events []*domain.AuditEvent
}

func (f *fakeAuditRepo) Create(ctx context.Context, event *domain.AuditEvent) error {
	return f.CreateWithTx(ctx, nil, event)
}

func (f *fakeAuditRepo) CreateWithTx(ctx context.Context, q repository.Querier, event *domain.AuditEvent) error {
	cp := *event
	f.events = append(f.events, &cp)
	return nil
}

func (f *fakeAuditRepo) List(ctx context.Context, filter *repository.AuditFilter) ([]*domain.AuditEvent, error) {
	return f.events, nil
}

// fakeProfileLookup is an in-memory profileLookup that returns the
// profile by ID. Unknown IDs return repository.ErrNotFound (the
// canonical sentinel ACMEService maps to ErrACMEProfileNotFound).
type fakeProfileLookup struct {
	profiles map[string]*domain.CertificateProfile
}

func (f *fakeProfileLookup) Get(ctx context.Context, id string) (*domain.CertificateProfile, error) {
	p, ok := f.profiles[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return p, nil
}

func newSvc(t *testing.T, cfg config.ACMEServerConfig, profiles map[string]*domain.CertificateProfile) (*ACMEService, *fakeACMERepo) {
	t.Helper()
	repo := newFakeACMERepo()
	pl := &fakeProfileLookup{profiles: profiles}
	return NewACMEService(repo, pl, cfg), repo
}

// newSvcWithAudit returns a service wired with the transactor + audit
// service required by the JWS-authenticated POST endpoints.
func newSvcWithAudit(t *testing.T, cfg config.ACMEServerConfig, profiles map[string]*domain.CertificateProfile) (*ACMEService, *fakeACMERepo, *fakeAuditRepo) {
	t.Helper()
	repo := newFakeACMERepo()
	pl := &fakeProfileLookup{profiles: profiles}
	auditRepo := &fakeAuditRepo{}
	auditSvc := NewAuditService(auditRepo)
	svc := NewACMEService(repo, pl, cfg)
	svc.SetTransactor(&fakeTransactor{})
	svc.SetAuditService(auditSvc)
	return svc, repo, auditRepo
}

func TestBuildDirectory_HappyPath(t *testing.T) {
	cfg := config.ACMEServerConfig{
		NonceTTL: 5 * time.Minute,
	}
	cfg.DirectoryMeta.TermsOfService = "https://example.com/tos"
	cfg.DirectoryMeta.Website = "https://example.com"
	svc, _ := newSvc(t, cfg, map[string]*domain.CertificateProfile{
		"prof-corp": {ID: "prof-corp", Name: "corp"},
	})
	dir, err := svc.BuildDirectory(context.Background(), "prof-corp", "https://server/acme/profile/prof-corp")
	if err != nil {
		t.Fatalf("BuildDirectory: %v", err)
	}
	if dir == nil {
		t.Fatal("dir is nil")
	}
	if dir.NewNonce != "https://server/acme/profile/prof-corp/new-nonce" {
		t.Errorf("NewNonce = %q", dir.NewNonce)
	}
	if dir.Meta == nil || dir.Meta.TermsOfService != "https://example.com/tos" {
		t.Errorf("meta tos = %+v", dir.Meta)
	}
	if got := svc.Metrics().DirectoryTotal.Load(); got != 1 {
		t.Errorf("DirectoryTotal = %d, want 1", got)
	}
}

func TestBuildDirectory_UnknownProfile(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, _ := newSvc(t, cfg, nil)
	_, err := svc.BuildDirectory(context.Background(), "prof-missing", "https://server/acme/profile/prof-missing")
	if !errors.Is(err, ErrACMEProfileNotFound) {
		t.Errorf("err = %v, want ErrACMEProfileNotFound", err)
	}
	if got := svc.Metrics().DirectoryFailureTotal.Load(); got != 1 {
		t.Errorf("DirectoryFailureTotal = %d, want 1", got)
	}
}

func TestBuildDirectory_EmptyProfileNoDefault(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, _ := newSvc(t, cfg, nil)
	_, err := svc.BuildDirectory(context.Background(), "", "https://server/acme")
	if !errors.Is(err, ErrACMEUserActionRequired) {
		t.Errorf("err = %v, want ErrACMEUserActionRequired", err)
	}
}

func TestBuildDirectory_EmptyProfileWithDefault(t *testing.T) {
	cfg := config.ACMEServerConfig{
		NonceTTL:         5 * time.Minute,
		DefaultProfileID: "prof-default",
	}
	svc, _ := newSvc(t, cfg, map[string]*domain.CertificateProfile{
		"prof-default": {ID: "prof-default", Name: "default"},
	})
	dir, err := svc.BuildDirectory(context.Background(), "", "https://server/acme")
	if err != nil {
		t.Fatalf("BuildDirectory: %v", err)
	}
	if dir.NewNonce != "https://server/acme/new-nonce" {
		t.Errorf("NewNonce = %q (shorthand path)", dir.NewNonce)
	}
}

func TestIssueNonce_HappyPath(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, repo := newSvc(t, cfg, nil)
	n, err := svc.IssueNonce(context.Background())
	if err != nil {
		t.Fatalf("IssueNonce: %v", err)
	}
	if len(n) != 43 {
		t.Errorf("nonce length = %d, want 43 (base64url-no-pad of 32 bytes)", len(n))
	}
	if _, ok := repo.issued[n]; !ok {
		t.Errorf("issued nonce was not persisted")
	}
	if got := svc.Metrics().NewNonceTotal.Load(); got != 1 {
		t.Errorf("NewNonceTotal = %d, want 1", got)
	}
}

func TestIssueNonce_RepoFailure(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, repo := newSvc(t, cfg, nil)
	repo.issueErr = errors.New("disk full")
	_, err := svc.IssueNonce(context.Background())
	if err == nil {
		t.Fatal("expected error from IssueNonce when repo fails")
	}
	if got := svc.Metrics().NewNonceFailureTotal.Load(); got != 1 {
		t.Errorf("NewNonceFailureTotal = %d, want 1", got)
	}
}

func TestACMEMetrics_Snapshot(t *testing.T) {
	m := NewACMEMetrics()
	m.DirectoryTotal.Store(7)
	m.NewNonceTotal.Store(11)
	m.NewNonceFailureTotal.Store(2)
	m.NewAccountTotal.Store(3)
	m.NewAccountIdempotentTotal.Store(1)
	snap := m.Snapshot()
	if snap["certctl_acme_directory_total"] != 7 {
		t.Errorf("directory_total = %d", snap["certctl_acme_directory_total"])
	}
	if snap["certctl_acme_new_nonce_total"] != 11 {
		t.Errorf("new_nonce_total = %d", snap["certctl_acme_new_nonce_total"])
	}
	if snap["certctl_acme_new_nonce_failures_total"] != 2 {
		t.Errorf("new_nonce_failures_total = %d", snap["certctl_acme_new_nonce_failures_total"])
	}
	if snap["certctl_acme_new_account_total"] != 3 {
		t.Errorf("new_account_total = %d", snap["certctl_acme_new_account_total"])
	}
	if snap["certctl_acme_new_account_idempotent_total"] != 1 {
		t.Errorf("new_account_idempotent_total = %d", snap["certctl_acme_new_account_idempotent_total"])
	}
}

// --- Phase 1b — account management -------------------------------------

func mustGenJWK(t *testing.T) *jose.JSONWebKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	return &jose.JSONWebKey{Key: &k.PublicKey}
}

func TestNewAccount_HappyPath(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, repo, auditRepo := newSvcWithAudit(t, cfg, map[string]*domain.CertificateProfile{
		"prof-corp": {ID: "prof-corp", Name: "corp"},
	})
	jwk := mustGenJWK(t)

	acct, isNew, err := svc.NewAccount(context.Background(), "prof-corp", jwk, []string{"mailto:a@example.com"}, false, true)
	if err != nil {
		t.Fatalf("NewAccount: %v", err)
	}
	if !isNew {
		t.Errorf("isNew = false; want true")
	}
	if acct == nil || acct.AccountID == "" || acct.JWKThumbprint == "" {
		t.Fatalf("account row is malformed: %+v", acct)
	}
	if got := svc.Metrics().NewAccountTotal.Load(); got != 1 {
		t.Errorf("NewAccountTotal = %d, want 1", got)
	}
	if got := len(auditRepo.events); got != 1 {
		t.Errorf("audit events = %d, want 1", got)
	}
	if got := auditRepo.events[0].Action; got != "acme_account_created" {
		t.Errorf("audit action = %q", got)
	}
	if _, ok := repo.accounts[acct.AccountID]; !ok {
		t.Errorf("account row not in repo")
	}
}

func TestNewAccount_Idempotent_ExistingJWKReturnsExistingRow(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, _, auditRepo := newSvcWithAudit(t, cfg, map[string]*domain.CertificateProfile{
		"prof-corp": {ID: "prof-corp", Name: "corp"},
	})
	jwk := mustGenJWK(t)

	first, _, err := svc.NewAccount(context.Background(), "prof-corp", jwk, []string{"mailto:a@example.com"}, false, true)
	if err != nil {
		t.Fatalf("first NewAccount: %v", err)
	}
	second, isNew, err := svc.NewAccount(context.Background(), "prof-corp", jwk, []string{"mailto:b@example.com"}, false, true)
	if err != nil {
		t.Fatalf("second NewAccount: %v", err)
	}
	if isNew {
		t.Errorf("isNew = true on idempotent re-registration; want false")
	}
	if second.AccountID != first.AccountID {
		t.Errorf("second account ID = %q; want first %q", second.AccountID, first.AccountID)
	}
	// Idempotent re-registration MUST NOT update contact / write a
	// second audit row (RFC 8555 §7.3.1 says return the existing row
	// unmodified).
	if got := len(auditRepo.events); got != 1 {
		t.Errorf("audit events = %d after idempotent call; want 1", got)
	}
	if got := svc.Metrics().NewAccountIdempotentTotal.Load(); got != 1 {
		t.Errorf("NewAccountIdempotentTotal = %d, want 1", got)
	}
}

func TestNewAccount_OnlyReturnExisting_NoMatch(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, _, _ := newSvcWithAudit(t, cfg, map[string]*domain.CertificateProfile{
		"prof-corp": {ID: "prof-corp", Name: "corp"},
	})
	jwk := mustGenJWK(t)

	_, _, err := svc.NewAccount(context.Background(), "prof-corp", jwk, nil, true /*onlyReturnExisting*/, false)
	if !errors.Is(err, ErrACMEAccountDoesNotExist) {
		t.Errorf("err = %v; want ErrACMEAccountDoesNotExist", err)
	}
}

func TestNewAccount_OnlyReturnExisting_Match(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, _, _ := newSvcWithAudit(t, cfg, map[string]*domain.CertificateProfile{
		"prof-corp": {ID: "prof-corp", Name: "corp"},
	})
	jwk := mustGenJWK(t)

	first, _, err := svc.NewAccount(context.Background(), "prof-corp", jwk, nil, false, false)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, isNew, err := svc.NewAccount(context.Background(), "prof-corp", jwk, nil, true, false)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if isNew {
		t.Errorf("isNew = true; want false")
	}
	if second.AccountID != first.AccountID {
		t.Errorf("ids differ")
	}
}

func TestUpdateAccount_HappyPath(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, _, auditRepo := newSvcWithAudit(t, cfg, map[string]*domain.CertificateProfile{
		"prof-corp": {ID: "prof-corp", Name: "corp"},
	})
	jwk := mustGenJWK(t)
	acct, _, err := svc.NewAccount(context.Background(), "prof-corp", jwk, []string{"mailto:old@example.com"}, false, false)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	updated, err := svc.UpdateAccount(context.Background(), acct.AccountID, []string{"mailto:new@example.com"})
	if err != nil {
		t.Fatalf("UpdateAccount: %v", err)
	}
	if len(updated.Contact) != 1 || updated.Contact[0] != "mailto:new@example.com" {
		t.Errorf("contact = %v", updated.Contact)
	}
	// Two audit rows: the create + the update.
	if got := len(auditRepo.events); got != 2 {
		t.Errorf("audit events = %d, want 2", got)
	}
	if got := auditRepo.events[1].Action; got != "acme_account_updated" {
		t.Errorf("update audit action = %q", got)
	}
}

func TestDeactivateAccount_HappyPath(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, _, auditRepo := newSvcWithAudit(t, cfg, map[string]*domain.CertificateProfile{
		"prof-corp": {ID: "prof-corp", Name: "corp"},
	})
	jwk := mustGenJWK(t)
	acct, _, err := svc.NewAccount(context.Background(), "prof-corp", jwk, nil, false, false)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	deactivated, err := svc.DeactivateAccount(context.Background(), acct.AccountID)
	if err != nil {
		t.Fatalf("DeactivateAccount: %v", err)
	}
	if deactivated.Status != domain.ACMEAccountStatusDeactivated {
		t.Errorf("status = %q, want %q", deactivated.Status, domain.ACMEAccountStatusDeactivated)
	}
	if got := svc.Metrics().DeactivateAccountTotal.Load(); got != 1 {
		t.Errorf("DeactivateAccountTotal = %d, want 1", got)
	}
	if got := auditRepo.events[len(auditRepo.events)-1].Action; got != "acme_account_deactivated" {
		t.Errorf("last audit action = %q", got)
	}
}

func TestLookupAccount_NotFound(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	svc, _ := newSvc(t, cfg, nil)
	_, err := svc.LookupAccount(context.Background(), "acme-acc-missing")
	if !errors.Is(err, ErrACMEAccountNotFound) {
		t.Errorf("err = %v; want ErrACMEAccountNotFound", err)
	}
}

func TestNewAccount_RequiresTransactor(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute}
	// Use newSvc (no transactor wired) — NewAccount should refuse.
	svc, _ := newSvc(t, cfg, map[string]*domain.CertificateProfile{
		"prof-corp": {ID: "prof-corp", Name: "corp"},
	})
	jwk := mustGenJWK(t)
	_, _, err := svc.NewAccount(context.Background(), "prof-corp", jwk, nil, false, false)
	if err == nil {
		t.Fatal("expected error when transactor is unset")
	}
}

// --- Phase 2 — order creation in trust_authenticated mode -------------

// orderTrackingRepo wraps fakeACMERepo so CreateOrder + CreateAuthz +
// CreateChallenge persistence is observable in tests. The fakeACMERepo's
// stubs no-op; this overrides them.
type orderTrackingRepo struct {
	*fakeACMERepo
	orders     map[string]*domain.ACMEOrder
	authzs     map[string][]*domain.ACMEAuthorization // orderID → authzs
	challenges map[string][]domain.ACMEChallenge      // authzID → challenges
}

func newOrderTrackingRepo() *orderTrackingRepo {
	return &orderTrackingRepo{
		fakeACMERepo: newFakeACMERepo(),
		orders:       map[string]*domain.ACMEOrder{},
		authzs:       map[string][]*domain.ACMEAuthorization{},
		challenges:   map[string][]domain.ACMEChallenge{},
	}
}

func (r *orderTrackingRepo) CreateOrderWithTx(ctx context.Context, q repository.Querier, order *domain.ACMEOrder) error {
	cp := *order
	r.orders[order.OrderID] = &cp
	return nil
}
func (r *orderTrackingRepo) GetOrderByID(ctx context.Context, orderID string) (*domain.ACMEOrder, error) {
	o, ok := r.orders[orderID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	cp := *o
	return &cp, nil
}
func (r *orderTrackingRepo) UpdateOrderWithTx(ctx context.Context, q repository.Querier, order *domain.ACMEOrder) error {
	cp := *order
	r.orders[order.OrderID] = &cp
	return nil
}
func (r *orderTrackingRepo) CreateAuthzWithTx(ctx context.Context, q repository.Querier, authz *domain.ACMEAuthorization) error {
	cp := *authz
	r.authzs[authz.OrderID] = append(r.authzs[authz.OrderID], &cp)
	return nil
}
func (r *orderTrackingRepo) ListAuthzsByOrder(ctx context.Context, orderID string) ([]*domain.ACMEAuthorization, error) {
	return r.authzs[orderID], nil
}
func (r *orderTrackingRepo) CreateChallengeWithTx(ctx context.Context, q repository.Querier, ch *domain.ACMEChallenge) error {
	r.challenges[ch.AuthzID] = append(r.challenges[ch.AuthzID], *ch)
	return nil
}

func TestCreateOrder_TrustAuthenticated_AutoReady(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute, OrderTTL: 24 * time.Hour, AuthzTTL: 24 * time.Hour}
	repo := newOrderTrackingRepo()
	pl := &fakeProfileLookup{profiles: map[string]*domain.CertificateProfile{
		"prof-corp": {ID: "prof-corp", Name: "corp", ACMEAuthMode: "trust_authenticated"},
	}}
	auditRepo := &fakeAuditRepo{}
	auditSvc := NewAuditService(auditRepo)
	svc := NewACMEService(repo, pl, cfg)
	svc.SetTransactor(&fakeTransactor{})
	svc.SetAuditService(auditSvc)

	order, err := svc.CreateOrder(context.Background(), "acme-acc-X", "prof-corp",
		[]domain.ACMEIdentifier{{Type: "dns", Value: "example.com"}}, nil, nil)
	if err != nil {
		t.Fatalf("CreateOrder: %v", err)
	}
	if order.Status != domain.ACMEOrderStatusReady {
		t.Errorf("order status = %q, want ready (trust_authenticated)", order.Status)
	}
	authzs := repo.authzs[order.OrderID]
	if len(authzs) != 1 {
		t.Fatalf("authzs = %d, want 1", len(authzs))
	}
	if authzs[0].Status != domain.ACMEAuthzStatusValid {
		t.Errorf("authz status = %q, want valid (trust_authenticated)", authzs[0].Status)
	}
	chs := repo.challenges[authzs[0].AuthzID]
	if len(chs) != 1 {
		t.Fatalf("challenges = %d, want 1", len(chs))
	}
	if chs[0].Status != domain.ACMEChallengeStatusValid {
		t.Errorf("challenge status = %q, want valid (trust_authenticated)", chs[0].Status)
	}
	// Audit row written.
	if got := len(auditRepo.events); got != 1 {
		t.Errorf("audit events = %d, want 1", got)
	}
	if auditRepo.events[0].Action != "acme_order_created" {
		t.Errorf("audit action = %q", auditRepo.events[0].Action)
	}
	if got := svc.Metrics().NewOrderTotal.Load(); got != 1 {
		t.Errorf("NewOrderTotal = %d, want 1", got)
	}
}

func TestCreateOrder_ChallengeMode_StaysPending(t *testing.T) {
	cfg := config.ACMEServerConfig{NonceTTL: 5 * time.Minute, OrderTTL: 24 * time.Hour, AuthzTTL: 24 * time.Hour}
	repo := newOrderTrackingRepo()
	pl := &fakeProfileLookup{profiles: map[string]*domain.CertificateProfile{
		"prof-corp": {ID: "prof-corp", Name: "corp", ACMEAuthMode: "challenge"},
	}}
	auditSvc := NewAuditService(&fakeAuditRepo{})
	svc := NewACMEService(repo, pl, cfg)
	svc.SetTransactor(&fakeTransactor{})
	svc.SetAuditService(auditSvc)

	order, err := svc.CreateOrder(context.Background(), "acme-acc-X", "prof-corp",
		[]domain.ACMEIdentifier{{Type: "dns", Value: "example.com"}}, nil, nil)
	if err != nil {
		t.Fatalf("CreateOrder: %v", err)
	}
	if order.Status != domain.ACMEOrderStatusPending {
		t.Errorf("order status = %q, want pending (challenge mode)", order.Status)
	}
	authzs := repo.authzs[order.OrderID]
	if authzs[0].Status != domain.ACMEAuthzStatusPending {
		t.Errorf("authz status = %q, want pending (challenge mode)", authzs[0].Status)
	}
	chs := repo.challenges[authzs[0].AuthzID]
	if chs[0].Status != domain.ACMEChallengeStatusPending {
		t.Errorf("challenge status = %q, want pending (challenge mode)", chs[0].Status)
	}
}
