package service

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// SCEPService implements the SCEP (RFC 8894) enrollment protocol.
// It delegates certificate operations to an existing IssuerConnector and records
// enrollment events in the audit trail.
type SCEPService struct {
	issuer            IssuerConnector
	issuerID          string
	auditService      *AuditService
	logger            *slog.Logger
	profileID         string // optional: constrain enrollments to a specific profile
	profileRepo       repository.CertificateProfileRepository
	challengePassword string // shared secret for enrollment authentication
}

// NewSCEPService creates a new SCEPService for the given issuer connector.
func NewSCEPService(issuerID string, issuer IssuerConnector, auditService *AuditService, logger *slog.Logger, challengePassword string) *SCEPService {
	return &SCEPService{
		issuer:            issuer,
		issuerID:          issuerID,
		auditService:      auditService,
		logger:            logger,
		challengePassword: challengePassword,
	}
}

// SetProfileID constrains SCEP enrollments to a specific certificate profile.
func (s *SCEPService) SetProfileID(profileID string) {
	s.profileID = profileID
}

// SetProfileRepo sets the profile repository for crypto policy enforcement during enrollment.
func (s *SCEPService) SetProfileRepo(repo repository.CertificateProfileRepository) {
	s.profileRepo = repo
}

// GetCACaps returns the capabilities of this SCEP server.
// RFC 8894 Section 3.5.2: GetCACaps returns a list of capabilities, one per line.
//
// SCEP RFC 8894 + Intune master bundle Phase 5.1: extended from the
// initial value (POSTPKIOperation+SHA-256+AES+SCEPStandard) to additionally
// advertise SHA-512 (now-implemented modern digest alternative) and Renewal
// (the messageType-17 dispatch from Phase 4). ChromeOS specifically looks
// for these capabilities to negotiate the strongest available cipher +
// digest combo. Order is by historical convention; clients walk the list
// linearly.
func (s *SCEPService) GetCACaps(ctx context.Context) string {
	return "POSTPKIOperation\nSHA-256\nSHA-512\nAES\nSCEPStandard\nRenewal\n"
}

// GetCACert returns the PEM-encoded CA certificate chain for this SCEP server.
// RFC 8894 Section 3.5.1: GetCACert distributes the CA certificate(s).
func (s *SCEPService) GetCACert(ctx context.Context) (string, error) {
	caPEM, err := s.issuer.GetCACertPEM(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get CA certificates from issuer %s: %w", s.issuerID, err)
	}
	if caPEM == "" {
		return "", fmt.Errorf("issuer %s does not provide CA certificates for SCEP", s.issuerID)
	}
	return caPEM, nil
}

// PKCSReq processes a SCEP enrollment request.
// RFC 8894 Section 3.3.1: PKCSReq contains a PKCS#10 CSR for certificate enrollment.
// The CSR PEM and challenge password are extracted by the handler from the PKCS#7 envelope.
//
// H-2 fix (CWE-306): the previous implementation skipped the shared-secret
// check entirely when s.challengePassword was empty, meaning any unauthenticated
// client that could reach /scep could enroll a CSR against the configured
// issuer. Reject that configuration defense-in-depth even though main() already
// refuses to start in the same state (see preflightSCEPChallengePassword). The
// non-empty branch now uses crypto/subtle.ConstantTimeCompare to avoid leaking
// the shared secret through a response-time side channel.
func (s *SCEPService) PKCSReq(ctx context.Context, csrPEM string, challengePassword string, transactionID string) (*domain.SCEPEnrollResult, error) {
	// Defense-in-depth: refuse any enrollment when no shared secret is
	// configured. The server-level pre-flight check in cmd/server/main.go
	// normally prevents the service from being constructed in this state, but
	// this branch also protects future call sites (tests, library reuse, a
	// future REST-over-HTTPS wrapper) from silently accepting unauthenticated
	// CSRs.
	if s.challengePassword == "" {
		s.logger.Warn("SCEP enrollment rejected: server has no challenge password configured",
			"transaction_id", transactionID)
		return nil, fmt.Errorf("SCEP challenge password not configured on server")
	}
	// Constant-time compare avoids leaking the configured secret through
	// response-time variance. ConstantTimeCompare returns 1 only when both
	// slices have equal length AND equal content; a mismatched-length input
	// still takes the same path as a content mismatch.
	if subtle.ConstantTimeCompare([]byte(challengePassword), []byte(s.challengePassword)) != 1 {
		s.logger.Warn("SCEP enrollment rejected: invalid challenge password",
			"transaction_id", transactionID)
		return nil, fmt.Errorf("invalid challenge password")
	}

	return s.processEnrollment(ctx, csrPEM, transactionID, "scep_pkcsreq")
}

// processEnrollment handles the common enrollment logic.
func (s *SCEPService) processEnrollment(ctx context.Context, csrPEM string, transactionID string, auditAction string) (*domain.SCEPEnrollResult, error) {
	// Parse the CSR to extract CN and SANs
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
		s.logger.Error("SCEP enrollment rejected: crypto policy violation",
			"action", auditAction,
			"common_name", commonName,
			"transaction_id", transactionID,
			"error", csrErr)
		return nil, fmt.Errorf("SCEP enrollment rejected: %w", csrErr)
	}

	s.logger.Info("SCEP enrollment request",
		"action", auditAction,
		"common_name", commonName,
		"sans", strings.Join(sans, ","),
		"transaction_id", transactionID,
		"issuer", s.issuerID)

	// Resolve MaxTTL + must-staple from profile.
	// SCEP RFC 8894 + Intune master bundle Phase 5.6 follow-up: thread
	// profile.MustStaple through to the issuer so the local issuer can
	// add the RFC 7633 id-pe-tlsfeature extension. Without this read the
	// CertificateProfile.MustStaple field would be a stored-but-ignored
	// "lying field" that operators set without behavior change.
	var (
		maxTTLSeconds int
		mustStaple    bool
	)
	if profile != nil {
		maxTTLSeconds = profile.MaxTTLSeconds
		mustStaple = profile.MustStaple
	}

	// Issue the certificate via the configured issuer connector
	// SCEP enrollments use profile EKUs if available, otherwise default (serverAuth + clientAuth fallback)
	result, err := s.issuer.IssueCertificate(ctx, commonName, sans, csrPEM, ekus, maxTTLSeconds, mustStaple)
	if err != nil {
		s.logger.Error("SCEP enrollment failed",
			"action", auditAction,
			"common_name", commonName,
			"transaction_id", transactionID,
			"error", err)
		return nil, fmt.Errorf("certificate issuance failed: %w", err)
	}

	// Audit the enrollment
	if s.auditService != nil {
		details := map[string]interface{}{
			"common_name":    commonName,
			"sans":           sans,
			"issuer_id":      s.issuerID,
			"serial":         result.Serial,
			"transaction_id": transactionID,
			"protocol":       "SCEP",
		}
		if s.profileID != "" {
			details["profile_id"] = s.profileID
		}
		_ = s.auditService.RecordEvent(ctx, "scep-client", "system", auditAction, "certificate", result.Serial, details)
	}

	s.logger.Info("SCEP enrollment successful",
		"action", auditAction,
		"common_name", commonName,
		"serial", result.Serial,
		"transaction_id", transactionID,
		"not_after", result.NotAfter)

	return &domain.SCEPEnrollResult{
		CertPEM:  result.CertPEM,
		ChainPEM: result.ChainPEM,
	}, nil
}

// PKCSReqWithEnvelope processes a SCEP PKCSReq from the RFC 8894 path
// (where the handler successfully parsed an EnvelopedData + signerInfo
// instead of the MVP raw-CSR path).
//
// SCEP RFC 8894 + Intune master bundle Phase 2.4.
//
// Returns *SCEPResponseEnvelope (not error + *SCEPEnrollResult) because
// RFC 8894 mandates a CertRep PKIMessage on every PKIOperation request,
// even failure cases — the handler shouldn't have to translate Go errors
// into SCEP failInfo codes; the service does that mapping.
//
// Service-side error → failInfo mapping (from the prompt's exact table):
//
//	Invalid challenge password    → caller returns HTTP 403, NOT a PKIMessage
//	                                (RFC 8894 §3.3.1 silent on this; matches MVP precedent)
//	CSR parse failure             → BadRequest (2)
//	CSR signature invalid         → BadMessageCheck (1)
//	Crypto policy violation       → BadAlg (0)
//	Issuer connector failure      → BadRequest (2)
//	Audit-log write failure       → log + continue with success (best-effort)
//
// The challenge-password failure case returns nil to signal "let the caller
// translate to 403"; every other failure mode returns a populated envelope
// with FailInfo set so the handler can build a CertRep with pkiStatus=2.
func (s *SCEPService) PKCSReqWithEnvelope(ctx context.Context, csrPEM string, challengePassword string, envelope *domain.SCEPRequestEnvelope) *domain.SCEPResponseEnvelope {
	resp := &domain.SCEPResponseEnvelope{
		TransactionID:  envelope.TransactionID,
		RecipientNonce: envelope.SenderNonce,
	}

	// Defense-in-depth: refuse any enrollment when no shared secret is
	// configured. Mirrors PKCSReq's gate. Returning nil signals 'let the
	// caller translate to HTTP 403' — the existing PKCSReq path returns
	// an error string the handler matched on, but PKCSReqWithEnvelope
	// returns *SCEPResponseEnvelope so we use a nil sentinel.
	if s.challengePassword == "" {
		s.logger.Warn("SCEP enrollment rejected: server has no challenge password configured (RFC 8894 path)",
			"transaction_id", envelope.TransactionID)
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(challengePassword), []byte(s.challengePassword)) != 1 {
		s.logger.Warn("SCEP enrollment rejected: invalid challenge password (RFC 8894 path)",
			"transaction_id", envelope.TransactionID)
		return nil
	}

	// Reuse the existing processEnrollment for the actual issuance work.
	// Errors mapped to SCEP failInfo per the table above.
	result, err := s.processEnrollment(ctx, csrPEM, envelope.TransactionID, "scep_pkcsreq")
	if err != nil {
		resp.Status = domain.SCEPStatusFailure
		resp.FailInfo = mapServiceErrorToFailInfo(err)
		return resp
	}
	resp.Status = domain.SCEPStatusSuccess
	resp.Result = result
	return resp
}

// mapServiceErrorToFailInfo translates a service-layer error into the
// SCEP failInfo code RFC 8894 §3.2.1.4.5 enumerates. The mapping mirrors
// the table in PKCSReqWithEnvelope's docblock; defaults to BadRequest
// when the error doesn't match any specific category.
func mapServiceErrorToFailInfo(err error) domain.SCEPFailInfo {
	if err == nil {
		return domain.SCEPFailBadRequest
	}
	msg := err.Error()
	switch {
	case containsAnyOf(msg, "invalid CSR PEM", "failed to parse CSR"):
		return domain.SCEPFailBadRequest
	case containsAnyOf(msg, "CSR signature verification failed"):
		return domain.SCEPFailBadMessageCheck
	case containsAnyOf(msg, "key algorithm", "key size", "algorithm not allowed", "crypto policy"):
		return domain.SCEPFailBadAlg
	default:
		return domain.SCEPFailBadRequest
	}
}

func containsAnyOf(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// RenewalReqWithEnvelope processes a SCEP RenewalReq from the RFC 8894 path.
// RFC 8894 §3.3.1.2 — re-enrollment with an existing valid cert. Distinct
// from PKCSReq because the signerInfo is signed by the EXISTING cert
// (proving possession), not by a transient self-signed device key.
//
// SCEP RFC 8894 + Intune master bundle Phase 4.2.
//
// Functionally identical to PKCSReqWithEnvelope but with two differences:
//
//  1. Audit action is `scep_renewalreq` (vs `scep_pkcsreq`) — operators
//     can grep the audit log to distinguish initial enrollments from
//     renewals.
//
//  2. The signing cert presented as POPO MUST chain to the issuer's CA
//     (the cert was previously issued by THIS issuer, not a self-signed
//     throwaway). Verified against the issuer's GetCACertPEM chain via
//     x509.Certificate.Verify. A signing cert that doesn't chain is
//     mapped to BadMessageCheck per the same RFC 8894 §3.3.2.2 semantics
//     as an EnvelopedData decrypt failure (integrity-check failure).
//
// Returns *SCEPResponseEnvelope (same contract as PKCSReqWithEnvelope);
// nil signals 'invalid challenge password' for HTTP 403 translation.
func (s *SCEPService) RenewalReqWithEnvelope(ctx context.Context, csrPEM string, challengePassword string, envelope *domain.SCEPRequestEnvelope) *domain.SCEPResponseEnvelope {
	resp := &domain.SCEPResponseEnvelope{
		TransactionID:  envelope.TransactionID,
		RecipientNonce: envelope.SenderNonce,
	}

	// Same challenge-password gate as PKCSReqWithEnvelope. Defense in depth
	// even though the RenewalReq path additionally verifies the signing
	// cert chain — a stolen/leaked challenge password combined with a
	// previously-issued cert (e.g. from a compromised device) would still
	// allow renewal otherwise. The two checks are independent.
	if s.challengePassword == "" {
		s.logger.Warn("SCEP renewal rejected: server has no challenge password configured (RFC 8894 path)",
			"transaction_id", envelope.TransactionID)
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(challengePassword), []byte(s.challengePassword)) != 1 {
		s.logger.Warn("SCEP renewal rejected: invalid challenge password (RFC 8894 path)",
			"transaction_id", envelope.TransactionID)
		return nil
	}

	// Verify the signing cert chains to the issuer's CA. Without this gate
	// any self-signed cert with a valid challenge password could trigger a
	// renewal — defeating the 'proof of prior issuance' contract RenewalReq
	// is supposed to provide.
	if err := s.verifyRenewalSignerCertChain(ctx, envelope.SignerCert); err != nil {
		s.logger.Warn("SCEP renewal rejected: signer cert chain invalid",
			"transaction_id", envelope.TransactionID,
			"error", err.Error(),
		)
		resp.Status = domain.SCEPStatusFailure
		resp.FailInfo = domain.SCEPFailBadMessageCheck
		return resp
	}

	// Reuse the existing processEnrollment for the actual issuance work
	// — RenewalReq is functionally a re-issuance with a different audit
	// action and chain-validation precondition.
	result, err := s.processEnrollment(ctx, csrPEM, envelope.TransactionID, "scep_renewalreq")
	if err != nil {
		resp.Status = domain.SCEPStatusFailure
		resp.FailInfo = mapServiceErrorToFailInfo(err)
		return resp
	}
	resp.Status = domain.SCEPStatusSuccess
	resp.Result = result
	return resp
}

// verifyRenewalSignerCertChain confirms the device's signing cert (the cert
// presented as POPO in the SignerInfo) was previously issued by the
// configured issuer. Used by RenewalReqWithEnvelope to enforce the 'must
// have a previously-issued cert' contract RFC 8894 §3.3.1.2 implies.
//
// A self-signed throwaway cert (initial-enrollment shape) fails this check
// — that's an indicator the client meant to send PKCSReq, not RenewalReq.
// Operators see the audit-log entry; the client sees BadMessageCheck.
func (s *SCEPService) verifyRenewalSignerCertChain(ctx context.Context, signerCertDER []byte) error {
	if len(signerCertDER) == 0 {
		return fmt.Errorf("signer cert is empty (no POPO cert in SignerInfo)")
	}
	signerCert, err := x509.ParseCertificate(signerCertDER)
	if err != nil {
		return fmt.Errorf("parse signer cert: %w", err)
	}

	// Pull the issuer's CA chain via the existing IssuerConnector
	// surface. Failure here is a deploy bug (the issuer connector lost
	// its CA cert mid-flight) rather than a client error — surface as
	// the same generic failure to avoid leaking server state.
	caPEM, err := s.issuer.GetCACertPEM(ctx)
	if err != nil {
		return fmt.Errorf("get CA cert PEM: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return fmt.Errorf("CA cert PEM contains no parseable certs")
	}
	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := signerCert.Verify(opts); err != nil {
		return fmt.Errorf("signer cert chain validation failed: %w", err)
	}
	return nil
}

// GetCertInitialWithEnvelope handles SCEP polling requests. RFC 8894 §3.3.3
// — the client polls when the prior PKCSReq returned Status=Pending.
//
// SCEP RFC 8894 + Intune master bundle Phase 4.3.
//
// v1 of this bundle returns FAILURE+badCertID for all GetCertInitial
// requests since deferred-issuance isn't supported (every PKCSReq either
// succeeds or fails synchronously — no Pending state in the existing
// service-layer issuance pipeline). The wiring stays in place for a
// future enhancement (e.g. 'queue for manual approval' workflows).
func (s *SCEPService) GetCertInitialWithEnvelope(_ context.Context, envelope *domain.SCEPRequestEnvelope) *domain.SCEPResponseEnvelope {
	s.logger.Info("SCEP GetCertInitial received — deferred-issuance not supported in v1, returning badCertID",
		"transaction_id", envelope.TransactionID)
	return &domain.SCEPResponseEnvelope{
		Status:         domain.SCEPStatusFailure,
		FailInfo:       domain.SCEPFailBadCertID,
		TransactionID:  envelope.TransactionID,
		RecipientNonce: envelope.SenderNonce,
	}
}
