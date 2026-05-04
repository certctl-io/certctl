package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/certctl-io/certctl/internal/crypto/signer"
	"github.com/certctl-io/certctl/internal/domain"
	"github.com/certctl-io/certctl/internal/repository"
)

// IntermediateCAService manages first-class CA hierarchies for the
// local issuer's tree mode. Rank 8.
//
// Lifecycle: an admin-gated operator calls CreateRoot to register an
// operator-supplied root cert+key as the issuer's active root. They
// then chain CreateChild calls to build out the hierarchy — each
// child's cert is signed by its parent's signer. AssembleChain walks
// the tree at leaf-issuance time to produce the PEM bundle the local
// connector attaches to IssuanceResult.
//
// Defense in depth: NEVER persist CA private key bytes. Every
// IntermediateCA carries a key_driver_id pointing at the signer.Driver
// instance that owns its private key. The default driver is
// signer.FileDriver (matching the historical single-sub-CA mode); HSM-
// backed and KMS-backed drivers (PKCS#11, AWS KMS, Azure Key Vault HSM)
// plug in via the existing seam without touching this service.
//
// Concurrency: every CreateChild that touches a parent reads the
// parent's signer fresh from the driver — no shared in-memory parent-
// signer state. Callers should serialize CreateChild against the same
// parent at the API layer (admin-gated; not a hot path).
type IntermediateCAService struct {
	repo         repository.IntermediateCARepository
	issuerRepo   repository.IssuerRepository
	signerDriver signer.Driver
	auditService *AuditService
	metrics      *IntermediateCAMetrics
}

// NewIntermediateCAService constructs the service. metrics may be nil
// for tests; auditService should not be nil in production.
func NewIntermediateCAService(
	repo repository.IntermediateCARepository,
	issuerRepo repository.IssuerRepository,
	signerDriver signer.Driver,
	auditService *AuditService,
	metrics *IntermediateCAMetrics,
) *IntermediateCAService {
	return &IntermediateCAService{
		repo:         repo,
		issuerRepo:   issuerRepo,
		signerDriver: signerDriver,
		auditService: auditService,
		metrics:      metrics,
	}
}

// Sentinels for handler-side dispatch via errors.Is.
var (
	ErrIntermediateCANotFound   = errors.New("intermediate CA not found")
	ErrCANotSelfSigned          = errors.New("supplied root cert is not self-signed")
	ErrCAKeyMismatch            = errors.New("supplied CA key does not match the supplied cert")
	ErrParentCANotActive        = errors.New("parent CA is not in active state")
	ErrPathLenExceeded          = errors.New("requested path length exceeds parent's PathLenConstraint")
	ErrNameConstraintExceeded   = errors.New("child name constraints not a subset of parent's")
	ErrCAStillHasActiveChildren = errors.New("CA cannot retire: active children still issuing")
	ErrInvalidCertPEM           = errors.New("invalid cert PEM")
)

// CreateRootOptions are the optional parameters for CreateRoot. The
// rootCert + rootKey are operator-supplied; this struct carries
// per-CA bookkeeping that doesn't live in the cert itself.
type CreateRootOptions struct {
	OCSPResponderURL string
	Metadata         map[string]string
}

// CreateChildOptions are the parameters for CreateChild — everything
// the service needs to build a fresh sub-CA cert under a parent.
type CreateChildOptions struct {
	Subject           pkix.Name
	Algorithm         signer.Algorithm
	TTL               time.Duration // child's validity window
	PathLenConstraint *int          // RFC 5280 §4.2.1.9; nil = inherit (parent - 1) or no constraint
	NameConstraints   []domain.NameConstraint
	OCSPResponderURL  string
	Metadata          map[string]string
}

// CreateRoot registers an operator-supplied root cert as the issuer's
// active root, paired with a pre-positioned signer.Driver reference
// (file path / HSM slot / KMS resource name) that the operator owns.
// Validates the cert is self-signed (subject == issuer per RFC 5280
// §3.2) AND that the signer.Driver-loadable key at keyDriverID has a
// public key matching the cert's public key (rejects mismatched
// bundles at the operator boundary, not just at signing time).
// Returns the new ica-<slug> ID.
func (s *IntermediateCAService) CreateRoot(ctx context.Context, issuerID, name, decidedBy string,
	rootCertPEM []byte, keyDriverID string, opts *CreateRootOptions) (string, error) {
	if opts == nil {
		opts = &CreateRootOptions{}
	}
	if keyDriverID == "" {
		return "", fmt.Errorf("CreateRoot: keyDriverID required")
	}

	cert, err := parseCertPEM(rootCertPEM)
	if err != nil {
		return "", fmt.Errorf("CreateRoot: %w", err)
	}

	// RFC 5280 §3.2: a root cert is self-signed (subject == issuer +
	// signature verifies under the cert's own public key).
	if !cert.IsCA {
		return "", fmt.Errorf("CreateRoot: %w: cert lacks BasicConstraints CA:TRUE", ErrCANotSelfSigned)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return "", fmt.Errorf("CreateRoot: %w: %v", ErrCANotSelfSigned, err)
	}

	// Verify the supplied keyDriverID resolves to a signer whose public
	// key matches the cert's public key. Defense-in-depth — catches
	// operator wiring errors at registration time rather than at first
	// CreateChild attempt.
	rootSigner, err := s.signerDriver.Load(ctx, keyDriverID)
	if err != nil {
		return "", fmt.Errorf("CreateRoot: load key: %w", err)
	}
	if !publicKeysEqual(rootSigner.Public(), cert.PublicKey) {
		return "", ErrCAKeyMismatch
	}

	ca := &domain.IntermediateCA{
		OwningIssuerID:    issuerID,
		ParentCAID:        nil, // root has no parent
		Name:              name,
		Subject:           cert.Subject.String(),
		State:             domain.IntermediateCAStateActive,
		CertPEM:           string(rootCertPEM),
		KeyDriverID:       keyDriverID,
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		PathLenConstraint: pathLenFromCert(cert),
		NameConstraints:   nameConstraintsFromCert(cert),
		OCSPResponderURL:  opts.OCSPResponderURL,
		Metadata:          opts.Metadata,
	}
	if err := s.repo.Create(ctx, ca); err != nil {
		return "", fmt.Errorf("CreateRoot: %w", err)
	}

	s.recordAudit(ctx, decidedBy, domain.ActorTypeUser, "intermediate_ca_root_created", ca, nil)
	if s.metrics != nil {
		s.metrics.RecordCreate(ca.OwningIssuerID, "root")
	}
	return ca.ID, nil
}

// CreateChild signs a new sub-CA cert under the given parent.
// Enforces RFC 5280 §4.2.1.9 (PathLenConstraint must not exceed
// parent's) + §4.2.1.10 (NameConstraints must be a subset of
// parent's). Generates the child's key via the signer.Driver; signs
// the cert via the parent's signer (loaded by the parent's
// KeyDriverID).
func (s *IntermediateCAService) CreateChild(ctx context.Context, parentCAID, name, decidedBy string,
	opts *CreateChildOptions) (string, error) {
	if opts == nil {
		return "", fmt.Errorf("CreateChild: opts required")
	}

	parent, err := s.repo.Get(ctx, parentCAID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", ErrIntermediateCANotFound
		}
		return "", fmt.Errorf("CreateChild: get parent: %w", err)
	}
	if parent.State != domain.IntermediateCAStateActive {
		return "", ErrParentCANotActive
	}

	parentCert, err := parseCertPEM([]byte(parent.CertPEM))
	if err != nil {
		return "", fmt.Errorf("CreateChild: parent cert: %w", err)
	}

	// RFC 5280 §4.2.1.9 enforcement.
	childPathLen := opts.PathLenConstraint
	if parent.PathLenConstraint != nil {
		if childPathLen != nil && *childPathLen >= *parent.PathLenConstraint {
			return "", ErrPathLenExceeded
		}
		// If unset, default to parent - 1 (or 0 if parent is 0).
		if childPathLen == nil {
			v := *parent.PathLenConstraint - 1
			if v < 0 {
				v = 0
			}
			childPathLen = &v
		}
	}

	// RFC 5280 §4.2.1.10 enforcement: child's permitted ⊆ parent's
	// permitted; child's excluded ⊇ parent's excluded.
	if err := validateNameConstraintsSubset(parent.NameConstraints, opts.NameConstraints); err != nil {
		return "", err
	}

	// Generate the child's key via the signer.Driver.
	childSigner, keyDriverID, err := s.signerDriver.Generate(ctx, opts.Algorithm)
	if err != nil {
		return "", fmt.Errorf("CreateChild: generate key: %w", err)
	}

	// Load the parent's signer to sign the child's cert.
	parentSigner, err := s.signerDriver.Load(ctx, parent.KeyDriverID)
	if err != nil {
		return "", fmt.Errorf("CreateChild: load parent signer: %w", err)
	}

	// Build the child cert template.
	now := time.Now().UTC()
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 5 * 365 * 24 * time.Hour // 5y default for sub-CAs
	}
	notBefore := now
	notAfter := now.Add(ttl)
	if notAfter.After(parentCert.NotAfter) {
		// Child must not outlive parent (RFC 5280 §4.1.2.5; cert chain
		// breaks at parent's expiry regardless).
		notAfter = parentCert.NotAfter
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", fmt.Errorf("CreateChild: serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               opts.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if childPathLen != nil {
		template.MaxPathLen = *childPathLen
		template.MaxPathLenZero = (*childPathLen == 0)
	}
	if len(opts.NameConstraints) > 0 {
		var permitted, excluded []string
		for _, nc := range opts.NameConstraints {
			permitted = append(permitted, nc.Permitted...)
			excluded = append(excluded, nc.Excluded...)
		}
		template.PermittedDNSDomains = permitted
		template.ExcludedDNSDomains = excluded
		template.PermittedDNSDomainsCritical = true
	}
	if opts.OCSPResponderURL != "" {
		template.OCSPServer = []string{opts.OCSPResponderURL}
	}

	childDER, err := x509.CreateCertificate(rand.Reader, template, parentCert, childSigner.Public(), parentSigner)
	if err != nil {
		return "", fmt.Errorf("CreateChild: sign cert: %w", err)
	}
	childPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: childDER})

	parentID := parent.ID
	ca := &domain.IntermediateCA{
		OwningIssuerID:    parent.OwningIssuerID,
		ParentCAID:        &parentID,
		Name:              name,
		Subject:           opts.Subject.String(),
		State:             domain.IntermediateCAStateActive,
		CertPEM:           string(childPEM),
		KeyDriverID:       keyDriverID,
		NotBefore:         notBefore,
		NotAfter:          notAfter,
		PathLenConstraint: childPathLen,
		NameConstraints:   opts.NameConstraints,
		OCSPResponderURL:  opts.OCSPResponderURL,
		Metadata:          opts.Metadata,
	}
	if err := s.repo.Create(ctx, ca); err != nil {
		return "", fmt.Errorf("CreateChild: create row: %w", err)
	}

	s.recordAudit(ctx, decidedBy, domain.ActorTypeUser, "intermediate_ca_child_created", ca,
		map[string]interface{}{"parent_ca_id": parent.ID})
	if s.metrics != nil {
		s.metrics.RecordCreate(parent.OwningIssuerID, "child")
	}
	return ca.ID, nil
}

// Retire transitions a CA's state. First call: active → retiring.
// Second call (with confirm=true): retiring → retired. Refuses retired
// transition if active children still exist (drain-first semantics).
func (s *IntermediateCAService) Retire(ctx context.Context, caID, decidedBy, note string, confirm bool) error {
	ca, err := s.repo.Get(ctx, caID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrIntermediateCANotFound
		}
		return fmt.Errorf("Retire: get: %w", err)
	}

	var newState domain.IntermediateCAState
	switch ca.State {
	case domain.IntermediateCAStateActive:
		newState = domain.IntermediateCAStateRetiring
	case domain.IntermediateCAStateRetiring:
		if !confirm {
			return fmt.Errorf("Retire: already retiring; pass confirm=true to terminalize")
		}
		// Verify no active children before terminalizing.
		children, err := s.repo.ListChildren(ctx, caID)
		if err != nil {
			return fmt.Errorf("Retire: list children: %w", err)
		}
		for _, ch := range children {
			if ch.State == domain.IntermediateCAStateActive {
				return ErrCAStillHasActiveChildren
			}
		}
		newState = domain.IntermediateCAStateRetired
	default:
		return fmt.Errorf("Retire: already retired")
	}

	if err := s.repo.UpdateState(ctx, caID, newState); err != nil {
		return fmt.Errorf("Retire: update state: %w", err)
	}

	s.recordAudit(ctx, decidedBy, domain.ActorTypeUser,
		"intermediate_ca_"+string(newState), ca,
		map[string]interface{}{"note": note})
	if s.metrics != nil {
		s.metrics.RecordRetire(ca.OwningIssuerID, string(newState))
	}
	return nil
}

// Get returns a single CA by ID.
func (s *IntermediateCAService) Get(ctx context.Context, id string) (*domain.IntermediateCA, error) {
	ca, err := s.repo.Get(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrIntermediateCANotFound
		}
		return nil, err
	}
	return ca, nil
}

// LoadHierarchy returns the flat list for an issuer; caller renders the
// tree from parent_ca_id.
func (s *IntermediateCAService) LoadHierarchy(ctx context.Context, issuerID string) ([]*domain.IntermediateCA, error) {
	return s.repo.ListByIssuer(ctx, issuerID)
}

// AssembleChain walks the ancestry of leafCAID and returns the PEM
// bundle (leaf CA included, ordered leaf → root). The local connector
// uses this at issue time to populate IssuanceResult.ChainPEM. The
// caller of IssueCertificate prepends the just-issued leaf cert to
// this bundle.
func (s *IntermediateCAService) AssembleChain(ctx context.Context, leafCAID string) (string, error) {
	chain, err := s.repo.WalkAncestry(ctx, leafCAID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", ErrIntermediateCANotFound
		}
		return "", fmt.Errorf("AssembleChain: %w", err)
	}
	var b strings.Builder
	for _, ca := range chain {
		b.WriteString(ca.CertPEM)
		if !strings.HasSuffix(ca.CertPEM, "\n") {
			b.WriteString("\n")
		}
	}
	return b.String(), nil
}

// publicKeysEqual reports whether two crypto.PublicKey values are
// byte-identical when serialized via PKIX. Cheaper alternative to
// reflect.DeepEqual that survives algorithm-specific oddities (RSA
// key Equal method, ECDSA curve pointer compare).
func publicKeysEqual(a, b interface{}) bool {
	aBytes, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bBytes, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return bytes.Equal(aBytes, bBytes)
}

// validateNameConstraintsSubset enforces RFC 5280 §4.2.1.10. The
// child's permitted set must be a subset of the parent's permitted
// set (a child cannot widen permitted scope); the child's excluded
// set must be a superset of the parent's excluded set (a child
// cannot remove an excluded subtree).
func validateNameConstraintsSubset(parent, child []domain.NameConstraint) error {
	flatParentPermitted := flattenPermitted(parent)
	flatParentExcluded := flattenExcluded(parent)
	flatChildPermitted := flattenPermitted(child)
	flatChildExcluded := flattenExcluded(child)

	if len(flatParentPermitted) > 0 {
		// If parent has a non-empty permitted set, every child permitted
		// MUST belong to (or be a subdomain of) some parent permitted
		// entry.
		for _, p := range flatChildPermitted {
			if !isPermittedUnderParent(p, flatParentPermitted) {
				return fmt.Errorf("%w: child permitted %q not under parent permitted set", ErrNameConstraintExceeded, p)
			}
		}
	}
	// Excluded: every parent-excluded entry MUST be present (or covered)
	// in the child's excluded set.
	for _, pe := range flatParentExcluded {
		if !isExcludedByChild(pe, flatChildExcluded) {
			return fmt.Errorf("%w: parent excluded %q not preserved in child", ErrNameConstraintExceeded, pe)
		}
	}
	return nil
}

func flattenPermitted(ncs []domain.NameConstraint) []string {
	var out []string
	for _, n := range ncs {
		out = append(out, n.Permitted...)
	}
	return out
}

func flattenExcluded(ncs []domain.NameConstraint) []string {
	var out []string
	for _, n := range ncs {
		out = append(out, n.Excluded...)
	}
	return out
}

// isPermittedUnderParent reports whether candidate is the parent's
// permitted entry exactly OR a subdomain of one.
func isPermittedUnderParent(candidate string, parentSet []string) bool {
	for _, p := range parentSet {
		if candidate == p || strings.HasSuffix(candidate, "."+p) {
			return true
		}
	}
	return false
}

// isExcludedByChild reports whether parentExcluded is in child's
// excluded set (exactly OR via a wider exclusion in the child).
func isExcludedByChild(parentExcluded string, childSet []string) bool {
	for _, c := range childSet {
		if parentExcluded == c || strings.HasSuffix(parentExcluded, "."+c) {
			return true
		}
	}
	return false
}

func parseCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block in cert", ErrInvalidCertPEM)
	}
	return x509.ParseCertificate(block.Bytes)
}

func pathLenFromCert(cert *x509.Certificate) *int {
	if !cert.BasicConstraintsValid {
		return nil
	}
	if cert.MaxPathLen == 0 && !cert.MaxPathLenZero {
		// Go's x509 uses MaxPathLen=0 + MaxPathLenZero=false to mean "no constraint";
		// MaxPathLen=0 + MaxPathLenZero=true to mean "constraint of 0".
		return nil
	}
	v := cert.MaxPathLen
	return &v
}

func nameConstraintsFromCert(cert *x509.Certificate) []domain.NameConstraint {
	if len(cert.PermittedDNSDomains) == 0 && len(cert.ExcludedDNSDomains) == 0 {
		return nil
	}
	return []domain.NameConstraint{{
		Permitted: append([]string(nil), cert.PermittedDNSDomains...),
		Excluded:  append([]string(nil), cert.ExcludedDNSDomains...),
	}}
}

// recordAudit is the shared audit-emission helper.
func (s *IntermediateCAService) recordAudit(ctx context.Context, actor string, actorType domain.ActorType,
	action string, ca *domain.IntermediateCA, extra map[string]interface{}) {
	if s.auditService == nil || ca == nil {
		return
	}
	details := map[string]interface{}{
		"intermediate_ca_id": ca.ID,
		"owning_issuer_id":   ca.OwningIssuerID,
		"name":               ca.Name,
		"subject":            ca.Subject,
		"state":              string(ca.State),
		"key_driver_id":      ca.KeyDriverID,
		"not_before":         ca.NotBefore.Format(time.RFC3339),
		"not_after":          ca.NotAfter.Format(time.RFC3339),
	}
	if ca.ParentCAID != nil {
		details["parent_ca_id"] = *ca.ParentCAID
	}
	for k, v := range extra {
		details[k] = v
	}
	_ = s.auditService.RecordEvent(ctx, actor, actorType, action,
		"intermediate_ca", ca.ID, details)
}
