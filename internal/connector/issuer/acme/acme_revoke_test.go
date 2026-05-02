package acme

// Audit fix #7 — serial-only ACME revocation tests.
//
// The happy path (issue → revoke-by-serial against a real ACME server)
// is covered by the pebble integration test in pebble_mock_test.go's
// follow-up; this file pins the failure-mode branches and the pure
// mapRevocationReason translation.

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"golang.org/x/crypto/acme"

	"github.com/shankar0123/certctl/internal/connector/issuer"
	"github.com/shankar0123/certctl/internal/domain"
)

// fakeCertLookup implements CertificateLookupRepo for tests. The two
// fields control the GetVersionBySerial behavior; tests set them per
// scenario.
type fakeCertLookup struct {
	version *domain.CertificateVersion
	err     error
}

func (f *fakeCertLookup) GetVersionBySerial(ctx context.Context, issuerID, serial string) (*domain.CertificateVersion, error) {
	return f.version, f.err
}

// newConnectorForRevoke builds an ACME connector pre-wired for a
// revoke test. The cert-lookup is set to the supplied fake; the
// issuer ID is "iss-test" unless cleared by the caller.
func newConnectorForRevoke(t *testing.T, lookup CertificateLookupRepo) *Connector {
	t.Helper()
	c := New(&Config{
		DirectoryURL: "https://acme.example.test/dir",
		Email:        "ops@example.com",
	}, testLogger())
	c.SetIssuerID("iss-test")
	c.SetCertificateLookup(lookup)
	return c
}

func TestRevokeCertificate_NoCertLookupWired(t *testing.T) {
	c := New(&Config{DirectoryURL: "https://x.test/dir", Email: "a@b"}, testLogger())
	// Intentionally NOT calling SetCertificateLookup — exercises the
	// backward-compat fallback for tests/old wiring paths.
	err := c.RevokeCertificate(context.Background(), issuer.RevocationRequest{Serial: "AB:CD"})
	if err == nil {
		t.Fatal("expected error when CertificateLookup is unwired")
	}
	if !contains(err.Error(), "CertificateLookup") {
		t.Errorf("expected wiring-error message, got: %v", err)
	}
}

func TestRevokeCertificate_NoIssuerIDWired(t *testing.T) {
	c := New(&Config{DirectoryURL: "https://x.test/dir", Email: "a@b"}, testLogger())
	c.SetCertificateLookup(&fakeCertLookup{})
	// Skip SetIssuerID — exercises the second backward-compat guard.
	err := c.RevokeCertificate(context.Background(), issuer.RevocationRequest{Serial: "AB:CD"})
	if err == nil {
		t.Fatal("expected error when issuer ID is unwired")
	}
	if !contains(err.Error(), "issuer ID") {
		t.Errorf("expected issuer-ID-error message, got: %v", err)
	}
}

func TestRevokeCertificate_LookupReturnsNotFound(t *testing.T) {
	c := newConnectorForRevoke(t, &fakeCertLookup{err: sql.ErrNoRows})
	err := c.RevokeCertificate(context.Background(), issuer.RevocationRequest{Serial: "DEAD:BEEF"})
	if err == nil {
		t.Fatal("expected error when lookup returns ErrNoRows")
	}
	// Operator-facing error must mention serial + suggest the cert
	// wasn't issued through certctl.
	if !contains(err.Error(), "DEAD:BEEF") {
		t.Errorf("expected error to include serial, got: %v", err)
	}
	if !contains(err.Error(), "may not have been issued through certctl") {
		t.Errorf("expected operator-facing hint about cert not in local store, got: %v", err)
	}
}

func TestRevokeCertificate_LookupArbitraryError(t *testing.T) {
	c := newConnectorForRevoke(t, &fakeCertLookup{err: errors.New("connection refused")})
	err := c.RevokeCertificate(context.Background(), issuer.RevocationRequest{Serial: "AB:CD"})
	if err == nil {
		t.Fatal("expected error to propagate")
	}
	if !contains(err.Error(), "connection refused") {
		t.Errorf("expected wrapped repo error, got: %v", err)
	}
	if !contains(err.Error(), "lookup") {
		t.Errorf("expected 'lookup' framing in error, got: %v", err)
	}
}

func TestRevokeCertificate_VersionPEMEmpty(t *testing.T) {
	c := newConnectorForRevoke(t, &fakeCertLookup{
		version: &domain.CertificateVersion{
			SerialNumber: "AB:CD",
			PEMChain:     "",
		},
	})
	err := c.RevokeCertificate(context.Background(), issuer.RevocationRequest{Serial: "AB:CD"})
	if err == nil {
		t.Fatal("expected error when version row has empty PEMChain")
	}
	if !contains(err.Error(), "empty PEM chain") {
		t.Errorf("expected empty-PEM error, got: %v", err)
	}
}

func TestRevokeCertificate_PEMMalformed_NoBlock(t *testing.T) {
	c := newConnectorForRevoke(t, &fakeCertLookup{
		version: &domain.CertificateVersion{
			SerialNumber: "AB:CD",
			PEMChain:     "this is not a PEM block at all",
		},
	})
	err := c.RevokeCertificate(context.Background(), issuer.RevocationRequest{Serial: "AB:CD"})
	if err == nil {
		t.Fatal("expected error when PEM chain has no decodable block")
	}
	if !contains(err.Error(), "no PEM block") {
		t.Errorf("expected no-PEM-block error, got: %v", err)
	}
}

func TestRevokeCertificate_PEMMalformed_WrongType(t *testing.T) {
	// A valid PEM block, but type is PRIVATE KEY — must be rejected
	// as "expected CERTIFICATE".
	pemPrivKey := "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQE=\n-----END PRIVATE KEY-----\n"
	c := newConnectorForRevoke(t, &fakeCertLookup{
		version: &domain.CertificateVersion{
			SerialNumber: "AB:CD",
			PEMChain:     pemPrivKey,
		},
	})
	err := c.RevokeCertificate(context.Background(), issuer.RevocationRequest{Serial: "AB:CD"})
	if err == nil {
		t.Fatal("expected error when PEM block type is not CERTIFICATE")
	}
	if !contains(err.Error(), "PRIVATE KEY") {
		t.Errorf("expected error to mention the actual block type, got: %v", err)
	}
}

// TestMapRevocationReason_TableDriven covers the full RFC 5280 §5.3.1
// reason set plus the canonical / underscore / ALL-CAPS spelling
// variants and the unknown-reason and nil-reason behaviors.
func TestMapRevocationReason_TableDriven(t *testing.T) {
	str := func(s string) *string { return &s }
	cases := []struct {
		name    string
		reason  *string
		want    acme.CRLReasonCode
		wantErr bool
	}{
		// Nil → unspecified. RFC 5280 §5.3.1: "if the reason code
		// extension is absent the reason is unspecified".
		{"nil_reason_unspecified", nil, acme.CRLReasonUnspecified, false},
		{"empty_string_unspecified", str(""), acme.CRLReasonUnspecified, false},

		// Canonical RFC 5280 camelCase.
		{"camel_unspecified", str("unspecified"), acme.CRLReasonUnspecified, false},
		{"camel_keyCompromise", str("keyCompromise"), acme.CRLReasonKeyCompromise, false},
		{"camel_cACompromise", str("cACompromise"), acme.CRLReasonCACompromise, false},
		{"camel_affiliationChanged", str("affiliationChanged"), acme.CRLReasonAffiliationChanged, false},
		{"camel_superseded", str("superseded"), acme.CRLReasonSuperseded, false},
		{"camel_cessationOfOperation", str("cessationOfOperation"), acme.CRLReasonCessationOfOperation, false},
		{"camel_certificateHold", str("certificateHold"), acme.CRLReasonCertificateHold, false},
		{"camel_removeFromCRL", str("removeFromCRL"), acme.CRLReasonRemoveFromCRL, false},
		{"camel_privilegeWithdrawn", str("privilegeWithdrawn"), acme.CRLReasonPrivilegeWithdrawn, false},
		{"camel_aACompromise", str("aACompromise"), acme.CRLReasonAACompromise, false},

		// underscore_lower.
		{"underscore_key_compromise", str("key_compromise"), acme.CRLReasonKeyCompromise, false},
		{"underscore_ca_compromise", str("ca_compromise"), acme.CRLReasonCACompromise, false},

		// ALL_CAPS_UNDERSCORE.
		{"caps_KEY_COMPROMISE", str("KEY_COMPROMISE"), acme.CRLReasonKeyCompromise, false},
		{"caps_REMOVE_FROM_CRL", str("REMOVE_FROM_CRL"), acme.CRLReasonRemoveFromCRL, false},

		// Unknown — must error rather than silently demote.
		{"unknown_reason_errors", str("totallyMadeUp"), 0, true},
		{"reserved_code_7_unhandled", str("reserved"), 0, true}, // Reserved per RFC 5280, no canonical name.
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mapRevocationReason(tc.reason)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got code %d, want %d", got, tc.want)
			}
		})
	}
}

// contains is a tiny helper to avoid pulling strings into every test.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
