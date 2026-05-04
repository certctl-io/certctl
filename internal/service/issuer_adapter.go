package service

import (
	"context"
	"time"

	"github.com/certctl-io/certctl/internal/connector/issuer"
)

// IssuerConnectorAdapter bridges the connector-layer issuer.Connector interface with the
// service-layer IssuerConnector interface. This maintains dependency inversion: the service
// layer defines the interface it needs, and this adapter wraps the concrete connector.
//
// Metrics: when issuerType + metrics are set via SetMetrics, the adapter
// records every IssueCertificate / RenewCertificate call into the
// IssuanceMetrics tables (audit fix #4). Untyped or unmetricked
// adapters (test path) skip the recording — nil-guard everywhere.
type IssuerConnectorAdapter struct {
	connector  issuer.Connector
	issuerType string
	metrics    *IssuanceMetrics
}

// NewIssuerConnectorAdapter wraps an issuer.Connector to implement
// service.IssuerConnector. Existing call sites (28+) keep this
// signature; metrics are wired via SetMetrics post-construction by
// the production code path (issuer_registry.go) so test sites that
// don't care about metrics stay one-arg.
func NewIssuerConnectorAdapter(c issuer.Connector) IssuerConnector {
	return &IssuerConnectorAdapter{connector: c}
}

// SetMetrics wires per-issuer-type issuance metrics. issuerType is the
// factory key (e.g. "local", "acme", "digicert") — must match one of
// the closed-enum values the metrics doc references. metrics may be
// nil to disable recording. Closes the #4 audit-readiness blocker
// (per-issuer-type metrics).
func (a *IssuerConnectorAdapter) SetMetrics(issuerType string, metrics *IssuanceMetrics) {
	a.issuerType = issuerType
	a.metrics = metrics
}

// Underlying returns the wrapped issuer.Connector so registry-level
// machinery (StartLifecycles / StopLifecycles, Bundle G audit-row
// pairing, future feature-detect interfaces) can reach the concrete
// connector behind the adapter without duplicating the wiring at
// every call site. Returns interface{} rather than issuer.Connector
// so callers do their own type assertion against optional extension
// interfaces (issuer.Lifecycle, etc.) without an import dependency
// fan-out from this package.
func (a *IssuerConnectorAdapter) Underlying() interface{} {
	return a.connector
}

// recordIssuance is the metrics-recording side effect at the adapter
// boundary. Bumps the issuance counter (success/failure) and the
// duration histogram; on failure also bumps the failure-by-error-class
// counter via ClassifyError.
//
// nil-guarded: when metrics or issuerType are unset, it's a no-op.
func (a *IssuerConnectorAdapter) recordIssuance(start time.Time, err error) {
	if a.metrics == nil || a.issuerType == "" {
		return
	}
	duration := time.Since(start)
	if err != nil {
		a.metrics.RecordIssuance(a.issuerType, "failure", duration)
		a.metrics.RecordFailure(a.issuerType, ClassifyError(err))
	} else {
		a.metrics.RecordIssuance(a.issuerType, "success", duration)
	}
}

// IssueCertificate delegates to the underlying connector's IssueCertificate method,
// translating between service-layer and connector-layer types.
//
// SCEP RFC 8894 + Intune master bundle Phase 5.6 follow-up: mustStaple flows
// through to the IssuanceRequest.MustStaple field. Only the local issuer
// honors it (RFC 7633 id-pe-tlsfeature extension); upstream connectors
// silently ignore the field.
func (a *IssuerConnectorAdapter) IssueCertificate(ctx context.Context, commonName string, sans []string, csrPEM string, ekus []string, maxTTLSeconds int, mustStaple bool) (*IssuanceResult, error) {
	start := time.Now()
	result, err := a.connector.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName:    commonName,
		SANs:          sans,
		CSRPEM:        csrPEM,
		EKUs:          ekus,
		MaxTTLSeconds: maxTTLSeconds,
		MustStaple:    mustStaple,
	})
	a.recordIssuance(start, err)
	if err != nil {
		return nil, err
	}
	return &IssuanceResult{
		CertPEM:   result.CertPEM,
		ChainPEM:  result.ChainPEM,
		Serial:    result.Serial,
		NotBefore: result.NotBefore,
		NotAfter:  result.NotAfter,
	}, nil
}

// RenewCertificate delegates to the underlying connector's RenewCertificate method,
// translating between service-layer and connector-layer types. Metrics:
// renewal is recorded into the same certctl_issuance_* series as
// initial issuance — operationally, renewal IS issuance from the
// connector's perspective.
func (a *IssuerConnectorAdapter) RenewCertificate(ctx context.Context, commonName string, sans []string, csrPEM string, ekus []string, maxTTLSeconds int, mustStaple bool) (*IssuanceResult, error) {
	start := time.Now()
	result, err := a.connector.RenewCertificate(ctx, issuer.RenewalRequest{
		CommonName:    commonName,
		SANs:          sans,
		CSRPEM:        csrPEM,
		EKUs:          ekus,
		MaxTTLSeconds: maxTTLSeconds,
		MustStaple:    mustStaple,
	})
	a.recordIssuance(start, err)
	if err != nil {
		return nil, err
	}
	return &IssuanceResult{
		CertPEM:   result.CertPEM,
		ChainPEM:  result.ChainPEM,
		Serial:    result.Serial,
		NotBefore: result.NotBefore,
		NotAfter:  result.NotAfter,
	}, nil
}

// RevokeCertificate delegates to the underlying connector's RevokeCertificate method.
func (a *IssuerConnectorAdapter) RevokeCertificate(ctx context.Context, serial string, reason string) error {
	var reasonPtr *string
	if reason != "" {
		reasonPtr = &reason
	}
	return a.connector.RevokeCertificate(ctx, issuer.RevocationRequest{
		Serial: serial,
		Reason: reasonPtr,
	})
}

// GenerateCRL delegates to the underlying connector.
func (a *IssuerConnectorAdapter) GenerateCRL(ctx context.Context, entries []CRLEntry) ([]byte, error) {
	// Convert service-layer CRLEntry to connector-layer RevokedCertEntry
	connEntries := make([]issuer.RevokedCertEntry, len(entries))
	for i, e := range entries {
		connEntries[i] = issuer.RevokedCertEntry{
			SerialNumber: e.SerialNumber,
			RevokedAt:    e.RevokedAt,
			ReasonCode:   e.ReasonCode,
		}
	}
	return a.connector.GenerateCRL(ctx, connEntries)
}

// SignOCSPResponse delegates to the underlying connector.
func (a *IssuerConnectorAdapter) SignOCSPResponse(ctx context.Context, req OCSPSignRequest) ([]byte, error) {
	return a.connector.SignOCSPResponse(ctx, issuer.OCSPSignRequest{
		CertSerial:       req.CertSerial,
		CertStatus:       req.CertStatus,
		RevokedAt:        req.RevokedAt,
		RevocationReason: req.RevocationReason,
		ThisUpdate:       req.ThisUpdate,
		NextUpdate:       req.NextUpdate,
		Nonce:            req.Nonce, // RFC 6960 §4.4.1 echo (production hardening II Phase 1)
	})
}

// GetCACertPEM delegates to the underlying connector.
func (a *IssuerConnectorAdapter) GetCACertPEM(ctx context.Context) (string, error) {
	return a.connector.GetCACertPEM(ctx)
}

// GetRenewalInfo delegates to the underlying connector, translating between service-layer and connector-layer types.
func (a *IssuerConnectorAdapter) GetRenewalInfo(ctx context.Context, certPEM string) (*RenewalInfoResult, error) {
	result, err := a.connector.GetRenewalInfo(ctx, certPEM)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return &RenewalInfoResult{
		SuggestedWindowStart: result.SuggestedWindowStart,
		SuggestedWindowEnd:   result.SuggestedWindowEnd,
		RetryAfter:           result.RetryAfter,
		ExplanationURL:       result.ExplanationURL,
	}, nil
}
