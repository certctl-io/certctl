package main

import (
	"context"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/service"
)

// fakeIssuerConn implements service.IssuerConnector enough for preflight tests.
type fakeIssuerConn struct {
	caCertPEM string
	caCertErr error
}

func (f *fakeIssuerConn) IssueCertificate(ctx context.Context, commonName string, sans []string, csrPEM string, ekus []string, maxTTLSeconds int, mustStaple bool) (*service.IssuanceResult, error) {
	return nil, nil
}
func (f *fakeIssuerConn) RenewCertificate(ctx context.Context, commonName string, sans []string, csrPEM string, ekus []string, maxTTLSeconds int, mustStaple bool) (*service.IssuanceResult, error) {
	return nil, nil
}
func (f *fakeIssuerConn) RevokeCertificate(ctx context.Context, serial string, reason string) error {
	return nil
}
func (f *fakeIssuerConn) GenerateCRL(ctx context.Context, revokedCerts []service.CRLEntry) ([]byte, error) {
	return nil, nil
}
func (f *fakeIssuerConn) SignOCSPResponse(ctx context.Context, req service.OCSPSignRequest) ([]byte, error) {
	return nil, nil
}
func (f *fakeIssuerConn) GetCACertPEM(ctx context.Context) (string, error) {
	return f.caCertPEM, f.caCertErr
}
func (f *fakeIssuerConn) GetRenewalInfo(ctx context.Context, certPEM string) (*service.RenewalInfoResult, error) {
	return nil, nil
}

// TestPreflightEnrollmentIssuer covers Bundle-4 / L-005 startup validation
// for EST/SCEP issuer binding.
func TestPreflightEnrollmentIssuer(t *testing.T) {
	cases := []struct {
		name        string
		issuer      service.IssuerConnector
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil_connector_fails",
			issuer:      nil,
			wantErr:     true,
			errContains: "connector is nil",
		},
		{
			name: "issuer_returns_error_fails",
			issuer: &fakeIssuerConn{
				caCertErr: errStub("ACME issuers do not provide a static CA certificate"),
			},
			wantErr:     true,
			errContains: "cannot serve CA certificate",
		},
		{
			name: "issuer_returns_empty_pem_fails",
			issuer: &fakeIssuerConn{
				caCertPEM: "",
				caCertErr: nil,
			},
			wantErr:     true,
			errContains: "empty PEM",
		},
		{
			name: "issuer_returns_valid_pem_succeeds",
			issuer: &fakeIssuerConn{
				caCertPEM: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
				caCertErr: nil,
			},
			wantErr: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := preflightEnrollmentIssuer(context.Background(), "EST", "iss-test", tc.issuer)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr && tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
				t.Fatalf("error %q missing substring %q", err.Error(), tc.errContains)
			}
		})
	}
}

// errStub is a tiny error wrapper so test cases can use string literals
// without importing fmt in every test struct entry.
type errStub string

func (e errStub) Error() string { return string(e) }
