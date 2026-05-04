package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/certctl-io/certctl/internal/crypto/signer"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// fakeIntermediateCARepo is an in-memory IntermediateCARepository for
// service-layer tests. WalkAncestry mirrors the recursive-CTE
// semantics shipped by the postgres adapter: leaf-first ordering,
// terminating at the row whose parent_ca_id IS NULL. The AssembleChain
// pin only carries weight if this fake produces the same shape the
// production adapter would.
type fakeIntermediateCARepo struct {
	mu   sync.Mutex
	rows map[string]*domain.IntermediateCA
	seq  int
}

func newFakeIntermediateCARepo() *fakeIntermediateCARepo {
	return &fakeIntermediateCARepo{rows: make(map[string]*domain.IntermediateCA)}
}

func (f *fakeIntermediateCARepo) Create(ctx context.Context, ca *domain.IntermediateCA) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ca.ID == "" {
		f.seq++
		ca.ID = "ica-fake-" + strings.ToLower(stringn(f.seq))
	}
	if _, exists := f.rows[ca.ID]; exists {
		return repository.ErrAlreadyExists
	}
	if ca.CreatedAt.IsZero() {
		ca.CreatedAt = time.Now().UTC()
	}
	if ca.UpdatedAt.IsZero() {
		ca.UpdatedAt = ca.CreatedAt
	}
	cp := *ca
	f.rows[ca.ID] = &cp
	return nil
}

func (f *fakeIntermediateCARepo) Get(ctx context.Context, id string) (*domain.IntermediateCA, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rows[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	cp := *r
	return &cp, nil
}

func (f *fakeIntermediateCARepo) ListByIssuer(ctx context.Context, issuerID string) ([]*domain.IntermediateCA, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*domain.IntermediateCA
	for _, r := range f.rows {
		if r.OwningIssuerID == issuerID {
			cp := *r
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (f *fakeIntermediateCARepo) ListChildren(ctx context.Context, parentCAID string) ([]*domain.IntermediateCA, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*domain.IntermediateCA
	for _, r := range f.rows {
		if r.ParentCAID != nil && *r.ParentCAID == parentCAID {
			cp := *r
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (f *fakeIntermediateCARepo) UpdateState(ctx context.Context, id string, state domain.IntermediateCAState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rows[id]
	if !ok {
		return repository.ErrNotFound
	}
	r.State = state
	r.UpdatedAt = time.Now().UTC()
	return nil
}

func (f *fakeIntermediateCARepo) GetActiveRoot(ctx context.Context, issuerID string) (*domain.IntermediateCA, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.rows {
		if r.OwningIssuerID == issuerID && r.ParentCAID == nil && r.State == domain.IntermediateCAStateActive {
			cp := *r
			return &cp, nil
		}
	}
	return nil, repository.ErrNotFound
}

// WalkAncestry mirrors the postgres recursive-CTE: anchor on leafID,
// then iteratively follow parent_ca_id to the root. Ordering is
// leaf-first. Returns ErrNotFound when leafID does not exist (matching
// the postgres adapter's contract).
func (f *fakeIntermediateCARepo) WalkAncestry(ctx context.Context, leafID string) ([]*domain.IntermediateCA, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.rows[leafID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	var out []*domain.IntermediateCA
	visited := map[string]bool{}
	for cur != nil {
		if visited[cur.ID] {
			// Defense in depth: refuse cycles. Production schema's
			// no-self-parent CHECK + the parent_ca_id FK make this
			// unreachable; the fake is paranoid by construction.
			break
		}
		visited[cur.ID] = true
		cp := *cur
		out = append(out, &cp)
		if cur.ParentCAID == nil {
			break
		}
		cur = f.rows[*cur.ParentCAID]
	}
	return out, nil
}

func stringn(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	var b []byte
	for n > 0 {
		b = append([]byte{digits[n%10]}, b...)
		n /= 10
	}
	return string(b)
}

// Compile-time interface guard.
var _ repository.IntermediateCARepository = (*fakeIntermediateCARepo)(nil)

// testCAFixture is a one-shot helper that builds a self-signed root
// cert + key in process memory and adopts the key into a MemoryDriver
// under a stable ref. Returns the PEM-encoded cert, the
// signer.MemoryDriver, and the keyDriverID the service can pass to
// CreateRoot.
func testCAFixture(t *testing.T, drv *signer.MemoryDriver, ref string, subject pkix.Name, pathLen *int, ncs []domain.NameConstraint) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	if err := drv.Adopt(ref, key); err != nil {
		t.Fatalf("adopt key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		Issuer:                subject, // self-signed
		NotBefore:             time.Now().Add(-time.Hour).UTC(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour).UTC(),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if pathLen != nil {
		tmpl.MaxPathLen = *pathLen
		tmpl.MaxPathLenZero = (*pathLen == 0)
	}
	if len(ncs) > 0 {
		var permitted, excluded []string
		for _, nc := range ncs {
			permitted = append(permitted, nc.Permitted...)
			excluded = append(excluded, nc.Excluded...)
		}
		tmpl.PermittedDNSDomains = permitted
		tmpl.ExcludedDNSDomains = excluded
		tmpl.PermittedDNSDomainsCritical = true
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// newTestService spins up an IntermediateCAService backed by the
// in-memory repo + MemoryDriver + a no-op audit service.
func newTestService(t *testing.T) (*IntermediateCAService, *fakeIntermediateCARepo, *signer.MemoryDriver, *IntermediateCAMetrics) {
	t.Helper()
	repo := newFakeIntermediateCARepo()
	drv := signer.NewMemoryDriver()
	auditRepo := &mockAuditRepo{}
	auditSvc := NewAuditService(auditRepo)
	metrics := NewIntermediateCAMetrics()
	svc := NewIntermediateCAService(repo, nil, drv, auditSvc, metrics)
	return svc, repo, drv, metrics
}

// ==== Tests ====

// TestIntermediateCA_CreateRoot_RegistersOperatorSuppliedSelfSigned
// pins the happy-path: a valid self-signed root cert + matching key
// gets persisted with parent_ca_id = NULL and state=active.
func TestIntermediateCA_CreateRoot_RegistersOperatorSuppliedSelfSigned(t *testing.T) {
	svc, repo, drv, _ := newTestService(t)
	pem := testCAFixture(t, drv, "root-key", pkix.Name{CommonName: "Acme Root"}, nil, nil)

	id, err := svc.CreateRoot(context.Background(), "iss-acme", "Acme Root", "user-admin",
		pem, "root-key", nil)
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}
	if !strings.HasPrefix(id, "ica-") {
		t.Fatalf("expected ica- prefix, got %q", id)
	}
	got, err := repo.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ParentCAID != nil {
		t.Fatalf("expected ParentCAID nil for root, got %v", *got.ParentCAID)
	}
	if got.State != domain.IntermediateCAStateActive {
		t.Fatalf("expected state=active, got %v", got.State)
	}
	if got.KeyDriverID != "root-key" {
		t.Fatalf("expected KeyDriverID=root-key, got %q", got.KeyDriverID)
	}
}

// TestIntermediateCA_CreateRoot_RejectsNonSelfSigned pins RFC 5280
// §3.2: a cert whose issuer ≠ subject (or whose signature does not
// verify under its own public key) MUST NOT be registered as a root.
func TestIntermediateCA_CreateRoot_RejectsNonSelfSigned(t *testing.T) {
	svc, _, drv, _ := newTestService(t)

	// Build a cert whose issuer differs from subject — the validator
	// in CreateRoot relies on cert.CheckSignatureFrom(cert), which fails
	// when the embedded issuer DN doesn't match the cert's own public
	// key. We achieve that by signing a "child" template with a DIFFERENT
	// key under the same subject — so the public key the verifier loads
	// from the cert (cert.PublicKey) does not match the actual signer.
	signerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	embeddedKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := drv.Adopt("mismatched-key", signerKey); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Imposter Root"},
		Issuer:                pkix.Name{CommonName: "Imposter Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &embeddedKey.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	_, err = svc.CreateRoot(context.Background(), "iss-acme", "Bad Root", "user-admin",
		pemBytes, "mismatched-key", nil)
	if !errors.Is(err, ErrCANotSelfSigned) {
		t.Fatalf("expected ErrCANotSelfSigned, got %v", err)
	}
}

// TestIntermediateCA_CreateRoot_RejectsKeyMismatch pins the second
// gate: cert is well-formed self-signed, but the operator-supplied
// keyDriverID resolves to a DIFFERENT key. CreateRoot must refuse
// before persisting the row.
func TestIntermediateCA_CreateRoot_RejectsKeyMismatch(t *testing.T) {
	svc, _, drv, _ := newTestService(t)
	pemBytes := testCAFixture(t, drv, "real-root-key", pkix.Name{CommonName: "Acme Root"}, nil, nil)
	// Adopt an unrelated key under a different ref.
	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := drv.Adopt("stranger-key", stranger); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	_, err := svc.CreateRoot(context.Background(), "iss-acme", "Acme Root", "user-admin",
		pemBytes, "stranger-key", nil)
	if !errors.Is(err, ErrCAKeyMismatch) {
		t.Fatalf("expected ErrCAKeyMismatch, got %v", err)
	}
}

// TestIntermediateCA_CreateChild_PathLenTighteningEnforced pins RFC
// 5280 §4.2.1.9: a child whose requested PathLenConstraint equals or
// exceeds the parent's MUST be rejected.
func TestIntermediateCA_CreateChild_PathLenTighteningEnforced(t *testing.T) {
	svc, _, drv, _ := newTestService(t)
	parentPathLen := 1
	rootPEM := testCAFixture(t, drv, "root-key", pkix.Name{CommonName: "Acme Root"}, &parentPathLen, nil)
	rootID, err := svc.CreateRoot(context.Background(), "iss-acme", "Acme Root", "user-admin", rootPEM, "root-key", nil)
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}

	// Child requests path-len 1, parent has path-len 1 → child >= parent → reject.
	requested := 1
	_, err = svc.CreateChild(context.Background(), rootID, "Acme Policy CA", "user-admin",
		&CreateChildOptions{
			Subject:           pkix.Name{CommonName: "Acme Policy CA"},
			Algorithm:         signer.AlgorithmECDSAP256,
			TTL:               365 * 24 * time.Hour,
			PathLenConstraint: &requested,
		})
	if !errors.Is(err, ErrPathLenExceeded) {
		t.Fatalf("expected ErrPathLenExceeded, got %v", err)
	}

	// Child requests path-len 0 (strictly less), under parent path-len 1 → ok.
	tighter := 0
	if _, err := svc.CreateChild(context.Background(), rootID, "Acme Issuing CA", "user-admin",
		&CreateChildOptions{
			Subject:           pkix.Name{CommonName: "Acme Issuing CA"},
			Algorithm:         signer.AlgorithmECDSAP256,
			TTL:               365 * 24 * time.Hour,
			PathLenConstraint: &tighter,
		}); err != nil {
		t.Fatalf("expected tightening to succeed, got %v", err)
	}
}

// TestIntermediateCA_CreateChild_NameConstraintsSubset pins RFC 5280
// §4.2.1.10 enforcement at service layer. Parent permits "example.com";
// child trying to widen with "evil.com" must be rejected, while a
// subdomain "internal.example.com" must succeed.
func TestIntermediateCA_CreateChild_NameConstraintsSubset(t *testing.T) {
	svc, _, drv, _ := newTestService(t)
	parentNCs := []domain.NameConstraint{{Permitted: []string{"example.com"}}}
	rootPEM := testCAFixture(t, drv, "root-key", pkix.Name{CommonName: "Acme Root"}, nil, parentNCs)
	rootID, err := svc.CreateRoot(context.Background(), "iss-acme", "Acme Root", "user-admin", rootPEM, "root-key", nil)
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}

	// Widening is rejected.
	_, err = svc.CreateChild(context.Background(), rootID, "Bad Child", "user-admin",
		&CreateChildOptions{
			Subject:         pkix.Name{CommonName: "Bad Child"},
			Algorithm:       signer.AlgorithmECDSAP256,
			TTL:             365 * 24 * time.Hour,
			NameConstraints: []domain.NameConstraint{{Permitted: []string{"evil.com"}}},
		})
	if !errors.Is(err, ErrNameConstraintExceeded) {
		t.Fatalf("expected ErrNameConstraintExceeded, got %v", err)
	}

	// Subdomain narrowing succeeds.
	if _, err := svc.CreateChild(context.Background(), rootID, "Acme Internal CA", "user-admin",
		&CreateChildOptions{
			Subject:         pkix.Name{CommonName: "Acme Internal CA"},
			Algorithm:       signer.AlgorithmECDSAP256,
			TTL:             365 * 24 * time.Hour,
			NameConstraints: []domain.NameConstraint{{Permitted: []string{"internal.example.com"}}},
		}); err != nil {
		t.Fatalf("expected subdomain narrowing to succeed, got %v", err)
	}
}

// TestIntermediateCA_AssembleChain_4DeepHierarchy is the LOAD-BEARING
// pin for AssembleChain: a 4-level hierarchy (root → policy →
// issuing-A → issuing-B-leaf) must produce a leaf-to-root PEM bundle
// with exactly 4 CERTIFICATE blocks in the right order. This is what
// the local connector's tree-mode code-path delegates to at
// IssueCertificate time.
func TestIntermediateCA_AssembleChain_4DeepHierarchy(t *testing.T) {
	svc, _, drv, _ := newTestService(t)
	// Root with path-len 3 (allows 3 layers of sub-CAs).
	rootPathLen := 3
	rootPEM := testCAFixture(t, drv, "root-key", pkix.Name{CommonName: "Acme Root"}, &rootPathLen, nil)
	rootID, err := svc.CreateRoot(context.Background(), "iss-acme", "Acme Root", "user-admin", rootPEM, "root-key", nil)
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}

	policyID, err := svc.CreateChild(context.Background(), rootID, "Policy CA", "user-admin",
		&CreateChildOptions{
			Subject:   pkix.Name{CommonName: "Acme Policy CA"},
			Algorithm: signer.AlgorithmECDSAP256,
			TTL:       5 * 365 * 24 * time.Hour,
		})
	if err != nil {
		t.Fatalf("CreateChild policy: %v", err)
	}

	issuingAID, err := svc.CreateChild(context.Background(), policyID, "Issuing A", "user-admin",
		&CreateChildOptions{
			Subject:   pkix.Name{CommonName: "Acme Issuing A"},
			Algorithm: signer.AlgorithmECDSAP256,
			TTL:       2 * 365 * 24 * time.Hour,
		})
	if err != nil {
		t.Fatalf("CreateChild issuing A: %v", err)
	}

	issuingBID, err := svc.CreateChild(context.Background(), issuingAID, "Issuing B", "user-admin",
		&CreateChildOptions{
			Subject:   pkix.Name{CommonName: "Acme Issuing B"},
			Algorithm: signer.AlgorithmECDSAP256,
			TTL:       365 * 24 * time.Hour,
		})
	if err != nil {
		t.Fatalf("CreateChild issuing B: %v", err)
	}

	chain, err := svc.AssembleChain(context.Background(), issuingBID)
	if err != nil {
		t.Fatalf("AssembleChain: %v", err)
	}
	count := strings.Count(chain, "BEGIN CERTIFICATE")
	if count != 4 {
		t.Fatalf("expected 4 CERTIFICATE blocks, got %d:\n%s", count, chain)
	}

	// Verify each block parses + the chain is leaf → root by subject CN.
	rest := []byte(chain)
	wantSubjects := []string{"Acme Issuing B", "Acme Issuing A", "Acme Policy CA", "Acme Root"}
	for i := 0; i < 4; i++ {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			t.Fatalf("expected block %d, got nil", i)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse block %d: %v", i, err)
		}
		if cert.Subject.CommonName != wantSubjects[i] {
			t.Fatalf("block %d: expected CN=%q, got %q", i, wantSubjects[i], cert.Subject.CommonName)
		}
	}
}

// TestIntermediateCA_Retire_RefusesIfActiveChildren pins drain-first
// semantics: a CA in retiring state with active children cannot be
// terminalized — the caller must retire the children first.
func TestIntermediateCA_Retire_RefusesIfActiveChildren(t *testing.T) {
	svc, _, drv, _ := newTestService(t)
	rootPEM := testCAFixture(t, drv, "root-key", pkix.Name{CommonName: "Acme Root"}, nil, nil)
	rootID, err := svc.CreateRoot(context.Background(), "iss-acme", "Acme Root", "user-admin", rootPEM, "root-key", nil)
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}
	if _, err := svc.CreateChild(context.Background(), rootID, "Child", "user-admin",
		&CreateChildOptions{
			Subject:   pkix.Name{CommonName: "Child"},
			Algorithm: signer.AlgorithmECDSAP256,
			TTL:       365 * 24 * time.Hour,
		}); err != nil {
		t.Fatalf("CreateChild: %v", err)
	}

	// First call: active → retiring (no confirm needed).
	if err := svc.Retire(context.Background(), rootID, "user-admin", "drain start", false); err != nil {
		t.Fatalf("Retire (active→retiring): %v", err)
	}
	// Second call: retiring → retired with active child → must refuse.
	err = svc.Retire(context.Background(), rootID, "user-admin", "terminalize", true)
	if !errors.Is(err, ErrCAStillHasActiveChildren) {
		t.Fatalf("expected ErrCAStillHasActiveChildren, got %v", err)
	}
}

// TestIntermediateCA_Retire_TwoPhaseConfirm pins the two-phase
// transition: first call moves active→retiring without a confirm
// flag; the second retiring→retired transition requires confirm=true.
func TestIntermediateCA_Retire_TwoPhaseConfirm(t *testing.T) {
	svc, repo, drv, _ := newTestService(t)
	rootPEM := testCAFixture(t, drv, "root-key", pkix.Name{CommonName: "Acme Root"}, nil, nil)
	rootID, err := svc.CreateRoot(context.Background(), "iss-acme", "Acme Root", "user-admin", rootPEM, "root-key", nil)
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}

	// First call (no confirm, no children): active → retiring.
	if err := svc.Retire(context.Background(), rootID, "user-admin", "drain", false); err != nil {
		t.Fatalf("first retire: %v", err)
	}
	got, _ := repo.Get(context.Background(), rootID)
	if got.State != domain.IntermediateCAStateRetiring {
		t.Fatalf("expected retiring, got %v", got.State)
	}

	// Second call without confirm — must surface "pass confirm=true".
	err = svc.Retire(context.Background(), rootID, "user-admin", "terminalize?", false)
	if err == nil || !strings.Contains(err.Error(), "confirm=true") {
		t.Fatalf("expected confirm=true error, got %v", err)
	}

	// Second call with confirm: retiring → retired.
	if err := svc.Retire(context.Background(), rootID, "user-admin", "terminalize", true); err != nil {
		t.Fatalf("retire confirm: %v", err)
	}
	got, _ = repo.Get(context.Background(), rootID)
	if got.State != domain.IntermediateCAStateRetired {
		t.Fatalf("expected retired, got %v", got.State)
	}
}

// TestIntermediateCA_MetricsRecordedPerOutcome pins the metrics
// snapshot — every successful CreateRoot / CreateChild / Retire
// transition lands one row in the snapshot, dimensioned by
// (issuer_id, kind).
func TestIntermediateCA_MetricsRecordedPerOutcome(t *testing.T) {
	svc, _, drv, metrics := newTestService(t)

	rootPEM := testCAFixture(t, drv, "root-key", pkix.Name{CommonName: "Acme Root"}, nil, nil)
	rootID, err := svc.CreateRoot(context.Background(), "iss-acme", "Acme Root", "user-admin", rootPEM, "root-key", nil)
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}
	if _, err := svc.CreateChild(context.Background(), rootID, "Child", "user-admin",
		&CreateChildOptions{
			Subject:   pkix.Name{CommonName: "Child"},
			Algorithm: signer.AlgorithmECDSAP256,
			TTL:       365 * 24 * time.Hour,
		}); err != nil {
		t.Fatalf("CreateChild: %v", err)
	}
	if err := svc.Retire(context.Background(), rootID, "user-admin", "drain", false); err != nil {
		t.Fatalf("Retire: %v", err)
	}

	snap := metrics.SnapshotIntermediateCA()
	want := map[string]uint64{
		"iss-acme/create_root":     1,
		"iss-acme/create_child":    1,
		"iss-acme/retire_retiring": 1,
	}
	got := map[string]uint64{}
	for _, e := range snap {
		got[e.IssuerID+"/"+e.Kind] = e.Count
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("metric %s: expected %d, got %d (snapshot=%v)", k, v, got[k], got)
		}
	}
}

// TestIntermediateCA_LoadHierarchy_FlatList pins LoadHierarchy: it
// returns every CA for an issuer, irrespective of state, ordered by
// created_at. Caller renders the tree from parent_ca_id.
func TestIntermediateCA_LoadHierarchy_FlatList(t *testing.T) {
	svc, _, drv, _ := newTestService(t)
	rootPEM := testCAFixture(t, drv, "root-key", pkix.Name{CommonName: "Acme Root"}, nil, nil)
	rootID, err := svc.CreateRoot(context.Background(), "iss-acme", "Acme Root", "user-admin", rootPEM, "root-key", nil)
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}
	for i, name := range []string{"Policy CA", "Issuing CA"} {
		_ = i
		if _, err := svc.CreateChild(context.Background(), rootID, name, "user-admin",
			&CreateChildOptions{
				Subject:   pkix.Name{CommonName: name},
				Algorithm: signer.AlgorithmECDSAP256,
				TTL:       365 * 24 * time.Hour,
			}); err != nil {
			t.Fatalf("CreateChild %s: %v", name, err)
		}
	}

	hier, err := svc.LoadHierarchy(context.Background(), "iss-acme")
	if err != nil {
		t.Fatalf("LoadHierarchy: %v", err)
	}
	if len(hier) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(hier))
	}
}
