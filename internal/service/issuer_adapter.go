package service

import (
	"context"

	"github.com/shankar0123/certctl/internal/connector/issuer"
)

// IssuerConnectorAdapter bridges the connector-layer issuer.Connector interface with the
// service-layer IssuerConnector interface. This maintains dependency inversion: the service
// layer defines the interface it needs, and this adapter wraps the concrete connector.
type IssuerConnectorAdapter struct {
	connector issuer.Connector
}

// NewIssuerConnectorAdapter wraps an issuer.Connector to implement service.IssuerConnector.
func NewIssuerConnectorAdapter(c issuer.Connector) IssuerConnector {
	return &IssuerConnectorAdapter{connector: c}
}

// IssueCertificate delegates to the underlying connector's IssueCertificate method,
// translating between service-layer and connector-layer types.
func (a *IssuerConnectorAdapter) IssueCertificate(ctx context.Context, commonName string, sans []string, csrPEM string, ekus []string) (*IssuanceResult, error) {
	result, err := a.connector.IssueCertificate(ctx, issuer.IssuanceRequest{
		CommonName: commonName,
		SANs:       sans,
		CSRPEM:     csrPEM,
		EKUs:       ekus,
	})
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
// translating between service-layer and connector-layer types.
func (a *IssuerConnectorAdapter) RenewCertificate(ctx context.Context, commonName string, sans []string, csrPEM string, ekus []string) (*IssuanceResult, error) {
	result, err := a.connector.RenewCertificate(ctx, issuer.RenewalRequest{
		CommonName: commonName,
		SANs:       sans,
		CSRPEM:     csrPEM,
		EKUs:       ekus,
	})
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
