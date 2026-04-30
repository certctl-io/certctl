package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/pkcs7"
	"github.com/shankar0123/certctl/internal/repository"
	"github.com/shankar0123/certctl/internal/trustanchor"
)

// ESTService implements the EST (RFC 7030) enrollment protocol.
// It delegates certificate operations to an existing IssuerConnector and records
// enrollment events in the audit trail.
type ESTService struct {
	issuer       IssuerConnector
	issuerID     string
	auditService *AuditService
	logger       *slog.Logger
	profileID    string // optional: constrain enrollments to a specific profile
	profileRepo  repository.CertificateProfileRepository

	// EST RFC 7030 hardening master bundle Phase 7.1: per-status atomic
	// counters surfaced by IndividualStats() / the AdminEST endpoint.
	// Created lazily by NewESTService so the dispatcher's hot path stays
	// nil-safe even if a future refactor forgets to wire the counters.
	counters *estCounterTab

	// estPathIDForLog / estMTLSConfigured / estBasicConfigured /
	// estServerKeygenEnabled / estTrustAnchor are observability metadata
	// the AdminEST handler reads via Stats(). They're populated once at
	// startup by SetESTAdminMetadata; the dispatcher hot path never
	// reads them (the hot path consults the typed config fields on the
	// HANDLER instance, not the service).
	estPathIDForLog        string
	estMTLSConfigured      bool
	estBasicConfigured     bool
	estServerKeygenEnabled bool
	estTrustAnchor         *trustanchor.Holder
}

// NewESTService creates a new ESTService for the given issuer connector.
func NewESTService(issuerID string, issuer IssuerConnector, auditService *AuditService, logger *slog.Logger) *ESTService {
	return &ESTService{
		issuer:       issuer,
		issuerID:     issuerID,
		auditService: auditService,
		logger:       logger,
		counters:     &estCounterTab{},
	}
}

// SetProfileID constrains EST enrollments to a specific certificate profile.
func (s *ESTService) SetProfileID(profileID string) {
	s.profileID = profileID
}

// SetProfileRepo sets the profile repository for crypto policy enforcement during enrollment.
func (s *ESTService) SetProfileRepo(repo repository.CertificateProfileRepository) {
	s.profileRepo = repo
}

// GetCACerts returns the PEM-encoded CA certificate chain for this EST server.
// RFC 7030 Section 4.1: /cacerts distributes the current CA certificates.
func (s *ESTService) GetCACerts(ctx context.Context) (string, error) {
	caPEM, err := s.issuer.GetCACertPEM(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get CA certificates from issuer %s: %w", s.issuerID, err)
	}
	if caPEM == "" {
		return "", fmt.Errorf("issuer %s does not provide CA certificates for EST", s.issuerID)
	}
	return caPEM, nil
}

// SimpleEnroll processes an initial enrollment request.
// RFC 7030 Section 4.2: /simpleenroll accepts a PKCS#10 CSR and returns a signed cert.
//
// Phase 11.3: typed audit codes — the inner processEnrollment emits
// `est_simple_enroll_success` on success + `est_simple_enroll_failed`
// on any rejection. The legacy bare `est_simple_enroll` is retained
// for back-compat (the GUI's activity-tab chip-filter matches by
// prefix so both shapes render under the same chip).
func (s *ESTService) SimpleEnroll(ctx context.Context, csrPEM string) (*domain.ESTEnrollResult, error) {
	return s.processEnrollment(ctx, csrPEM, "est_simple_enroll",
		AuditActionESTSimpleEnrollSuccess, AuditActionESTSimpleEnrollFailed)
}

// SimpleReEnroll processes a re-enrollment request.
// RFC 7030 Section 4.2.2: /simplereenroll is functionally identical to /simpleenroll
// but is used when renewing an existing certificate.
func (s *ESTService) SimpleReEnroll(ctx context.Context, csrPEM string) (*domain.ESTEnrollResult, error) {
	return s.processEnrollment(ctx, csrPEM, "est_simple_reenroll",
		AuditActionESTSimpleReEnrollSuccess, AuditActionESTSimpleReEnrollFailed)
}

// GetCSRAttrs returns the CSR attributes the server wants clients to include.
// RFC 7030 §4.5: /csrattrs tells clients what to put in their CSR. The
// response is base64(DER(SEQUENCE OF AttrOrOID)) where AttrOrOID is either
// a bare OID (an attribute the client SHOULD include) or an Attribute
// SEQUENCE { type OID, values SET OF ANY }. We emit the bare-OID form for
// every entry — the EST endpoint hint contract is "what attributes /
// EKUs to include in the CSR", not "what specific values to set".
//
// EST RFC 7030 hardening master bundle Phase 6.2: replaces the v2.0.x
// nil/204 stub with a profile-derived OID list. Sources:
//   - profile.AllowedEKUs → emitted as id-kp-* OIDs (RFC 5280 §4.2.1.12).
//     Clients use these to add the matching EKU OIDs to their CSR's
//     extensionRequest attribute.
//   - profile.RequiredCSRAttributes → emitted as the matching CSR
//     attribute / DN-attribute OIDs (e.g. serialNumber → 2.5.4.5).
//
// Returns nil when no profile is configured OR the resolved hint set is
// empty after dropping unknown entries — the handler then writes 204
// per RFC 7030 §4.5.2 (the original stub semantic). Unknown entries are
// dropped + warning-logged; any one typo'd EKU/attribute string
// shouldn't take down the entire csrattrs surface.
func (s *ESTService) GetCSRAttrs(ctx context.Context) ([]byte, error) {
	if s.profileID == "" || s.profileRepo == nil {
		// No bound profile = no hints. Maintains the v2.0.x behavior of
		// returning 204 to legacy deployments that haven't opted into a
		// CertificateProfile. The handler writes 204-No-Content when the
		// returned slice is empty.
		return nil, nil
	}
	profile, err := s.profileRepo.Get(ctx, s.profileID)
	if err != nil || profile == nil {
		// Profile lookup failure isn't fatal — we degrade to the
		// no-hints case + log so the operator can spot misconfig. Same
		// rationale as the audit-noop path in processEnrollment.
		s.logger.Warn("est csrattrs: profile lookup failed; degrading to no-hints",
			"profile_id", s.profileID,
			"error", err)
		return nil, nil
	}

	var oids []asn1.ObjectIdentifier
	// EKU hints first (RFC 5280 §4.2.1.12 OIDs). Skip serverAuth + clientAuth
	// when the profile only allows the default — those are well-known and
	// every modern client adds them by default; emitting them in csrattrs
	// is just noise. But if the operator narrowed AllowedEKUs to e.g.
	// `["clientAuth"]` for an mTLS-only profile, we DO want clients to
	// know to drop serverAuth — so we emit the EKU hints unconditionally
	// when the profile is narrower than the default. The narrowing check
	// is implicit: if AllowedEKUs is the default (just serverAuth), we
	// emit just serverAuth, which is what well-behaved clients do anyway.
	for _, eku := range profile.AllowedEKUs {
		if oid, ok := domain.EKUStringToOID(eku); ok {
			oids = append(oids, oid)
		} else {
			s.logger.Warn("est csrattrs: unknown EKU in profile; dropping",
				"profile_id", s.profileID, "eku", eku)
		}
	}
	// Required CSR attribute / DN-attribute hints.
	for _, attr := range profile.RequiredCSRAttributes {
		if oid, ok := domain.AttributeStringToOID(attr); ok {
			oids = append(oids, oid)
		} else {
			s.logger.Warn("est csrattrs: unknown CSR attribute in profile; dropping",
				"profile_id", s.profileID, "attribute", attr)
		}
	}
	if len(oids) == 0 {
		return nil, nil
	}
	// RFC 7030 §4.5.2: response body is the DER encoding of a SEQUENCE
	// of AttrOrOID. asn1.Marshal of []asn1.ObjectIdentifier produces
	// SEQUENCE OF OBJECT IDENTIFIER, which is the bare-OID form.
	der, err := asn1.Marshal(oids)
	if err != nil {
		return nil, fmt.Errorf("est csrattrs: marshal OID sequence: %w", err)
	}
	return der, nil
}

// processEnrollment handles the common enrollment logic for both simpleenroll and simplereenroll.
//
// Phase 11.3 split-emit: every audit RecordEvent call goes to BOTH the
// legacy bare action code (auditAction param, e.g. "est_simple_enroll")
// AND the typed success/failed code (typedSuccess / typedFailed params)
// so existing GUI activity-tab chip filters stay green while operators
// gain the typed grep surface.
func (s *ESTService) processEnrollment(ctx context.Context, csrPEM, auditAction, typedSuccess, typedFailed string) (*domain.ESTEnrollResult, error) {
	// emitFailed is the in-line helper that records BOTH the bare +
	// typed failed-event so every error path stays one-liner. Returns
	// the input err verbatim so call sites stay one-shot.
	emitFailed := func(reason string, err error) {
		if s.auditService == nil {
			return
		}
		details := map[string]interface{}{
			"reason":    reason,
			"error":     err.Error(),
			"protocol":  "EST",
			"issuer_id": s.issuerID,
		}
		if s.profileID != "" {
			details["profile_id"] = s.profileID
		}
		_ = s.auditService.RecordEvent(ctx, "est-client", "system", auditAction+"_failed", "certificate", "", details)
		_ = s.auditService.RecordEvent(ctx, "est-client", "system", typedFailed, "certificate", "", details)
	}
	_ = emitFailed // referenced inside the body below
	// Parse the CSR to extract CN and SANs
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		s.counters.inc(estCounterCSRInvalid)
		emitFailed("csr_pem_decode", fmt.Errorf("invalid CSR PEM"))
		return nil, fmt.Errorf("invalid CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		s.counters.inc(estCounterCSRInvalid)
		emitFailed("csr_parse", err)
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		s.counters.inc(estCounterCSRSignatureMismatch)
		emitFailed("csr_signature", err)
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	commonName := csr.Subject.CommonName
	if commonName == "" {
		s.counters.inc(estCounterCSRInvalid)
		emitFailed("csr_missing_cn", fmt.Errorf("missing CN"))
		return nil, fmt.Errorf("CSR must include a Common Name")
	}

	// Collect SANs
	var sans []string
	for _, dns := range csr.DNSNames {
		sans = append(sans, dns)
	}
	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, email := range csr.EmailAddresses {
		sans = append(sans, email)
	}
	for _, uri := range csr.URIs {
		sans = append(sans, uri.String())
	}

	// Validate CSR key algorithm/size against profile (crypto policy enforcement)
	var profile *domain.CertificateProfile
	var ekus []string
	if s.profileID != "" && s.profileRepo != nil {
		if p, profileErr := s.profileRepo.Get(ctx, s.profileID); profileErr == nil && p != nil {
			profile = p
			ekus = profile.AllowedEKUs
		}
	}
	if _, csrErr := ValidateCSRAgainstProfile(csrPEM, profile); csrErr != nil {
		s.counters.inc(estCounterCSRPolicyViolation)
		// Emit BOTH the typed-failed code (for the Activity tab) AND
		// the standalone est_csr_policy_violation code (for the
		// per-failure-mode counter that ops greppers prefer).
		emitFailed("csr_policy_violation", csrErr)
		if s.auditService != nil {
			_ = s.auditService.RecordEvent(ctx, "est-client", "system",
				AuditActionESTCSRPolicyViolation, "certificate", "",
				map[string]interface{}{"error": csrErr.Error(), "issuer_id": s.issuerID, "profile_id": s.profileID})
		}
		s.logger.Error("EST enrollment rejected: crypto policy violation",
			"action", auditAction,
			"common_name", commonName,
			"error", csrErr)
		return nil, fmt.Errorf("EST enrollment rejected: %w", csrErr)
	}

	s.logger.Info("EST enrollment request",
		"action", auditAction,
		"common_name", commonName,
		"sans", strings.Join(sans, ","),
		"issuer", s.issuerID)

	// Resolve MaxTTL + must-staple from profile.
	// SCEP RFC 8894 + Intune master bundle Phase 5.6 follow-up: thread
	// profile.MustStaple through to the issuer so the local issuer can
	// add the RFC 7633 id-pe-tlsfeature extension.
	var (
		maxTTLSeconds int
		mustStaple    bool
	)
	if profile != nil {
		maxTTLSeconds = profile.MaxTTLSeconds
		mustStaple = profile.MustStaple
	}

	// Issue the certificate via the configured issuer connector
	// EST enrollments use profile EKUs if available, otherwise default (serverAuth + clientAuth fallback)
	result, err := s.issuer.IssueCertificate(ctx, commonName, sans, csrPEM, ekus, maxTTLSeconds, mustStaple)
	if err != nil {
		s.counters.inc(estCounterIssuerError)
		emitFailed("issuer_error", err)
		s.logger.Error("EST enrollment failed",
			"action", auditAction,
			"common_name", commonName,
			"error", err)
		return nil, fmt.Errorf("certificate issuance failed: %w", err)
	}
	// Phase 7.1: tick success counter — distinguish initial vs renewal so
	// the admin GUI can show enrollment-mix at a glance.
	if auditAction == "est_simple_reenroll" {
		s.counters.inc(estCounterSuccessSimpleReEnroll)
	} else {
		s.counters.inc(estCounterSuccessSimpleEnroll)
	}

	// Audit the enrollment — split-emit per Phase 11.3: legacy bare
	// action code (back-compat for the GUI activity tab + existing
	// audit-log analysers) + typed _success suffix variant + the
	// canonical typed code from the AuditAction* constants.
	if s.auditService != nil {
		details := map[string]interface{}{
			"common_name": commonName,
			"sans":        sans,
			"issuer_id":   s.issuerID,
			"serial":      result.Serial,
			"protocol":    "EST",
		}
		if s.profileID != "" {
			details["profile_id"] = s.profileID
		}
		_ = s.auditService.RecordEvent(ctx, "est-client", "system", auditAction, "certificate", result.Serial, details)
		_ = s.auditService.RecordEvent(ctx, "est-client", "system", typedSuccess, "certificate", result.Serial, details)
	}

	s.logger.Info("EST enrollment successful",
		"action", auditAction,
		"common_name", commonName,
		"serial", result.Serial,
		"not_after", result.NotAfter)

	return &domain.ESTEnrollResult{
		CertPEM:  result.CertPEM,
		ChainPEM: result.ChainPEM,
	}, nil
}

// EST RFC 7030 hardening master bundle Phase 5 — serverkeygen.
//
// RFC 7030 §4.4: the client submits a CSR whose key may be a placeholder;
// the server generates the keypair, issues a cert with the SERVER-generated
// pubkey, then returns BOTH the cert AND the corresponding private key
// encrypted to the client's separately-supplied key-encipherment public
// key (RFC 7030 §4.4.2 mandates secure key delivery).
//
// Wire shape: multipart/mixed body assembled by the handler. The service
// returns the raw cert PEM + the RAW private key bytes (already CMS-
// EnvelopedData-wrapped); the handler composes the multipart envelope.

// ESTServerKeygenResult is an alias for the domain type so existing callers
// don't reach across packages — handlers + tests reference the alias here,
// the wire schema lives in internal/domain/est.go.
type ESTServerKeygenResult = domain.ESTServerKeygenResult

// ErrServerKeygenRequiresKeyEncipherment is returned when the client's
// CSR doesn't carry an RSA key-encipherment public key the server can
// use to wrap the generated private key. RFC 7030 §4.4.2 mandates an
// encryption mechanism; we do NOT support the plaintext-PKCS#8 fallback.
var ErrServerKeygenRequiresKeyEncipherment = errors.New("est serverkeygen: client CSR missing RSA key-encipherment public key")

// ErrServerKeygenUnsupportedAlgorithm is returned when the CSR pubkey
// algorithm isn't in the server's supported-keygen list. Currently
// supported: RSA-2048, RSA-3072, RSA-4096, ECDSA P-256, ECDSA P-384.
var ErrServerKeygenUnsupportedAlgorithm = errors.New("est serverkeygen: unsupported keygen algorithm requested by CSR")

// ErrServerKeygenDisabled signals the handler that the per-profile gate
// is off (CertCertConfig.ServerKeygenEnabled == false). Maps to HTTP
// 404 (the endpoint isn't routable for this profile) at the handler.
var ErrServerKeygenDisabled = errors.New("est serverkeygen: disabled for this profile")

// SimpleServerKeygen runs the RFC 7030 §4.4 server-driven key generation
// flow. The CSR's Subject + SANs drive the issued cert's identity; the
// CSR's pubkey (which the client supplies as the encryption target for
// the returned private key) MUST be RSA so we can wrap with PKCS#1 v1.5
// keyTrans (matches the BUILDER's algorithm choice). The newly-generated
// keypair's algorithm is picked to match the profile's
// AllowedKeyAlgorithms first entry (or RSA-2048 default when no profile
// constraint) — the server isn't trying to second-guess the operator's
// crypto policy.
//
// Returns ESTServerKeygenResult{CertPEM, ChainPEM, EncryptedKey} where
// EncryptedKey is the CMS EnvelopedData wrapping a PKCS#8 marshal of the
// freshly-minted private key. The plaintext private key bytes are
// zeroized inside the call before return — the handler never sees them.
func (s *ESTService) SimpleServerKeygen(ctx context.Context, csrPEM string) (*ESTServerKeygenResult, error) {
	// 1. Parse + signature-verify the CSR. We re-use processEnrollment's
	// gates verbatim so a misshapen CSR fails the same way it does on
	// the simpleenroll path.
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}
	commonName := csr.Subject.CommonName
	if commonName == "" {
		return nil, fmt.Errorf("CSR must include a Common Name")
	}
	// The CSR pubkey IS the encryption target for the returned private
	// key per RFC 7030 §4.4.2 — refuse non-RSA pubkeys at the door so
	// the BUILDER doesn't fail later with a less-actionable error.
	rsaPub, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok || rsaPub == nil {
		s.counters.inc(estCounterCSRPolicyViolation)
		return nil, ErrServerKeygenRequiresKeyEncipherment
	}

	// 2. Resolve profile (for AllowedKeyAlgorithms + AllowedEKUs +
	// MaxTTLSeconds + MustStaple — the same set the simpleenroll path
	// reads). When no profile is bound, fall back to RSA-2048 + the
	// issuer's defaults — same v2.0.x posture as a no-profile
	// simpleenroll.
	var profile *domain.CertificateProfile
	if s.profileID != "" && s.profileRepo != nil {
		if p, perr := s.profileRepo.Get(ctx, s.profileID); perr == nil && p != nil {
			profile = p
		}
	}

	// 3. Generate the server-side keypair matching the profile's first
	// AllowedKeyAlgorithms entry (or RSA-2048 default). The signer
	// abstraction's MemoryDriver is overkill here — we just need a
	// crypto.PrivateKey + matching crypto.PublicKey for one CSR
	// re-derivation + one PKCS#8 marshal. The plaintext key never hits
	// disk: it's allocated, marshaled, then explicitly zeroized below.
	freshPriv, freshPub, algoLabel, err := s.generateServerKeyForProfile(profile)
	if err != nil {
		return nil, err
	}

	// 4. Build a synthetic CSR carrying the original CSR's Subject +
	// SANs but the SERVER-generated pubkey. This is the CSR we hand to
	// the issuer connector — the issued cert binds the device identity
	// to the new keypair.
	serverCSR := &x509.CertificateRequest{
		Subject:            csr.Subject,
		DNSNames:           csr.DNSNames,
		IPAddresses:        csr.IPAddresses,
		EmailAddresses:     csr.EmailAddresses,
		URIs:               csr.URIs,
		SignatureAlgorithm: csrSignatureForKey(freshPriv),
	}
	serverCSRDER, err := x509.CreateCertificateRequest(rand.Reader, serverCSR, freshPriv)
	if err != nil {
		zeroizeKey(freshPriv)
		return nil, fmt.Errorf("est serverkeygen: build server CSR: %w", err)
	}
	serverCSRPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: serverCSRDER}))

	// 5. SAN list mirrors processEnrollment's collect-and-issue logic.
	var sans []string
	for _, dns := range csr.DNSNames {
		sans = append(sans, dns)
	}
	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, email := range csr.EmailAddresses {
		sans = append(sans, email)
	}
	for _, uri := range csr.URIs {
		sans = append(sans, uri.String())
	}

	// 6. Issuance gates: profile's AllowedEKUs / MaxTTLSeconds /
	// MustStaple. The crypto-policy validation runs against the SERVER
	// CSR (so the freshly-generated key is what's checked) — that's
	// what the operator's policy is meant to constrain.
	if _, csrErr := ValidateCSRAgainstProfile(serverCSRPEM, profile); csrErr != nil {
		zeroizeKey(freshPriv)
		s.logger.Error("EST serverkeygen rejected: crypto policy violation",
			"common_name", commonName, "algo", algoLabel, "error", csrErr)
		return nil, fmt.Errorf("EST serverkeygen rejected: %w", csrErr)
	}
	var (
		ekus          []string
		maxTTLSeconds int
		mustStaple    bool
	)
	if profile != nil {
		ekus = profile.AllowedEKUs
		maxTTLSeconds = profile.MaxTTLSeconds
		mustStaple = profile.MustStaple
	}

	// 7. Issue.
	issued, err := s.issuer.IssueCertificate(ctx, commonName, sans, serverCSRPEM, ekus, maxTTLSeconds, mustStaple)
	if err != nil {
		zeroizeKey(freshPriv)
		s.counters.inc(estCounterIssuerError)
		s.logger.Error("EST serverkeygen failed",
			"common_name", commonName, "algo", algoLabel, "error", err)
		return nil, fmt.Errorf("EST serverkeygen issuance failed: %w", err)
	}
	s.counters.inc(estCounterSuccessServerKeygen)

	// 8. Marshal the freshly-generated private key as PKCS#8 (RFC 5958).
	// PKCS#8 is the format both libest and openssl smime expect on the
	// other end of CMS EnvelopedData unwrap.
	pkcs8, err := x509.MarshalPKCS8PrivateKey(freshPriv)
	if err != nil {
		zeroizeKey(freshPriv)
		return nil, fmt.Errorf("est serverkeygen: marshal PKCS#8: %w", err)
	}

	// 9. Build a synthetic recipient cert wrapping the device's
	// CSR-supplied key-encipherment pubkey. The BUILDER expects a
	// *x509.Certificate so it can read RawIssuer + SerialNumber for
	// the IssuerAndSerial rid; we synth one with the device CN + a
	// stable serial. Real PKI shape but we never sign / publish it
	// — purely a carrier for the pubkey + issuer info inside the
	// CMS envelope.
	recipient, err := buildSyntheticRecipientCert(rsaPub, csr)
	if err != nil {
		zeroizeKey(freshPriv)
		zeroizeBytes(pkcs8)
		return nil, fmt.Errorf("est serverkeygen: synth recipient cert: %w", err)
	}

	// 10. Encrypt the PKCS#8 with the device's pubkey via CMS
	// EnvelopedData. AES-256-CBC content encryption + RSA PKCS#1 v1.5
	// keyTrans — same algorithm choices as the BUILDER's hard-coded
	// defaults.
	encryptedKey, err := pkcs7.BuildEnvelopedData(pkcs8, recipient, rand.Reader)
	if err != nil {
		zeroizeKey(freshPriv)
		zeroizeBytes(pkcs8)
		return nil, fmt.Errorf("est serverkeygen: build EnvelopedData: %w", err)
	}

	// 11. Zeroize the in-memory plaintext key + PKCS#8 bytes. Ciphertext
	// remains; the handler emits it then returns. Best-effort — Go's
	// GC may have copied the buffers around already, but this closes
	// the obvious leak path at handler return time.
	zeroizeKey(freshPriv)
	zeroizeBytes(pkcs8)
	_ = freshPub // referenced only at issuance time; nothing to zero

	// 12. Audit + return.
	if s.auditService != nil {
		details := map[string]interface{}{
			"common_name": commonName,
			"sans":        sans,
			"issuer_id":   s.issuerID,
			"serial":      issued.Serial,
			"protocol":    "EST",
			"keygen":      "server",
			"algorithm":   algoLabel,
		}
		if s.profileID != "" {
			details["profile_id"] = s.profileID
		}
		_ = s.auditService.RecordEvent(ctx, "est-client", "system", "est_server_keygen", "certificate", issued.Serial, details)
		// Phase 11.3: typed _success suffix for the operator grep surface.
		_ = s.auditService.RecordEvent(ctx, "est-client", "system", AuditActionESTServerKeygenSuccess, "certificate", issued.Serial, details)
	}
	s.logger.Info("EST serverkeygen successful",
		"common_name", commonName, "serial", issued.Serial,
		"algo", algoLabel, "issuer", s.issuerID)

	return &ESTServerKeygenResult{
		CertPEM:      issued.CertPEM,
		ChainPEM:     issued.ChainPEM,
		EncryptedKey: encryptedKey,
	}, nil
}

// generateServerKeyForProfile returns a freshly-minted (priv, pub, label)
// triple. The chosen algorithm matches profile.AllowedKeyAlgorithms[0]
// when the profile has constraints; otherwise RSA-2048 (the broadest
// compatibility default, matches what the local issuer self-bootstraps
// when the operator hasn't pinned a key algorithm).
func (s *ESTService) generateServerKeyForProfile(profile *domain.CertificateProfile) (priv interface{}, pub interface{}, label string, err error) {
	algo := "RSA"
	size := 2048
	if profile != nil && len(profile.AllowedKeyAlgorithms) > 0 {
		first := profile.AllowedKeyAlgorithms[0]
		algo = first.Algorithm
		if first.MinSize > 0 {
			size = first.MinSize
		}
	}
	switch algo {
	case domain.KeyAlgorithmRSA:
		k, kerr := rsa.GenerateKey(rand.Reader, size)
		if kerr != nil {
			return nil, nil, "", fmt.Errorf("est serverkeygen: rsa.GenerateKey size=%d: %w", size, kerr)
		}
		return k, &k.PublicKey, fmt.Sprintf("RSA-%d", size), nil
	case domain.KeyAlgorithmECDSA:
		var curve elliptic.Curve
		switch size {
		case 256:
			curve = elliptic.P256()
			label = "ECDSA-P256"
		case 384:
			curve = elliptic.P384()
			label = "ECDSA-P384"
		case 521:
			curve = elliptic.P521()
			label = "ECDSA-P521"
		default:
			return nil, nil, "", fmt.Errorf("%w: ECDSA size=%d (allowed: 256/384/521)", ErrServerKeygenUnsupportedAlgorithm, size)
		}
		k, kerr := ecdsa.GenerateKey(curve, rand.Reader)
		if kerr != nil {
			return nil, nil, "", fmt.Errorf("est serverkeygen: ecdsa.GenerateKey: %w", kerr)
		}
		return k, &k.PublicKey, label, nil
	default:
		return nil, nil, "", fmt.Errorf("%w: %q (allowed: RSA, ECDSA)", ErrServerKeygenUnsupportedAlgorithm, algo)
	}
}

// csrSignatureForKey picks a sane SignatureAlgorithm for x509.CreateCertificateRequest
// given a private key. Mirrors what the stdlib defaults to but pinning here
// avoids hitting the deprecated SHA1WithRSA on RSA keys (Go's stdlib still
// defaults to SHA-256 for RSA, so this is mostly belt-and-braces).
func csrSignatureForKey(k interface{}) x509.SignatureAlgorithm {
	switch k.(type) {
	case *rsa.PrivateKey:
		return x509.SHA256WithRSA
	case *ecdsa.PrivateKey:
		return x509.ECDSAWithSHA256 // P-256 + P-384 both default fine; P-521 will pick SHA-256 too
	default:
		return x509.UnknownSignatureAlgorithm // stdlib derives a sensible default
	}
}

// buildSyntheticRecipientCert wraps the device's CSR-supplied
// key-encipherment pubkey in a minimal *x509.Certificate so the
// pkcs7.BuildEnvelopedData function (which keys off RawIssuer +
// SerialNumber for the IssuerAndSerial rid) can address it. The cert
// is never signed or persisted — it lives only inside this function
// + the EnvelopedData blob produced.
//
// We pin the issuer DN to the device's own Subject DN so the rid is
// self-referential — a stable, reproducible identifier the device's
// EST client library can match against its own cert request when it
// decrypts the response. Serial number is the SHA-256 prefix of the
// CSR signature (deterministic per CSR; collisions across millions of
// CSRs are negligible).
func buildSyntheticRecipientCert(rsaPub *rsa.PublicKey, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	// Self-sign the synthetic cert with an EPHEMERAL key so it parses
	// cleanly via x509.CreateCertificate + ParseCertificate. The
	// signature is throwaway — no one verifies it — but x509 won't
	// build a cert without one.
	ephemKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("ephemeral signer: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:       deterministicSerial(csr.Signature),
		Subject:            csr.Subject,
		Issuer:             csr.Subject, // self-referential; never verified
		NotBefore:          serverKeygenSyntheticNotBefore,
		NotAfter:           serverKeygenSyntheticNotAfter,
		KeyUsage:           x509.KeyUsageKeyEncipherment,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, rsaPub, ephemKey)
	if err != nil {
		return nil, fmt.Errorf("create synth cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse synth cert: %w", err)
	}
	zeroizeKey(ephemKey) // burn the ephemeral signer immediately
	return cert, nil
}

// deterministicSerial picks a stable serial number from the first 16
// bytes of the CSR signature. Avoids a fresh CSPRNG draw per request +
// gives the device's client library a serial it can re-derive locally
// for diagnostic-log correlation.
func deterministicSerial(sig []byte) *big.Int {
	if len(sig) == 0 {
		// Defensive: an unsigned CSR shouldn't reach here (CheckSignature
		// gated upstream) but a deterministic fallback ensures the cert
		// builder never crashes on a zero-byte serial.
		return big.NewInt(1)
	}
	end := 16
	if len(sig) < end {
		end = len(sig)
	}
	return new(big.Int).SetBytes(sig[:end])
}

// serverKeygenSyntheticNotBefore / NotAfter are stable timestamps for
// the never-published synthetic recipient cert. Using fixed-far-past +
// fixed-far-future means the cert struct round-trips cleanly through
// x509 without any time-source plumbing.
var (
	serverKeygenSyntheticNotBefore = mustParseTime("2020-01-01T00:00:00Z")
	serverKeygenSyntheticNotAfter  = mustParseTime("2099-12-31T23:59:59Z")
)

func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(fmt.Sprintf("est: hard-coded time %q failed to parse: %v", s, err))
	}
	return t
}

// zeroizeKey overwrites the in-memory bytes of the private key with
// zeros. Best-effort: Go's GC may have copied the buffer; closures the
// math/big and crypto stdlib hold may keep their own copies. The
// canonical defense is "don't keep this key around for long" — we
// release the reference inside the calling function so GC reclaims it
// promptly.
func zeroizeKey(k interface{}) {
	switch v := k.(type) {
	case *rsa.PrivateKey:
		// Best-effort: zero the big.Int components. Calls to
		// SetBytes(nil) reset the underlying word slice.
		if v == nil {
			return
		}
		if v.D != nil {
			v.D.SetUint64(0)
		}
		for i := range v.Primes {
			if v.Primes[i] != nil {
				v.Primes[i].SetUint64(0)
			}
		}
	case *ecdsa.PrivateKey:
		if v == nil || v.D == nil {
			return
		}
		v.D.SetUint64(0)
	}
}

// zeroizeBytes overwrites a byte slice with zeros in place.
func zeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
