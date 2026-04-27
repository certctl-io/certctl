package domain

import (
	"reflect"
	"testing"
)

// Bundle C / Audit M-015: pin the renewal-flow cardinality invariant.
//
// The audit's claim is "renewal flow assumes single profile per certificate;
// no cardinality validation". Verified-already-clean: the certificate
// struct holds exactly one CertificateProfileID and one RenewalPolicyID
// as bare strings, not slices. There is literally no way to attach
// multiple profiles or policies to a managed certificate without changing
// the struct shape — which this test guards against.
//
// If a future schema change introduces N:N profiles or N:N renewal
// policies, this test fails and forces the change to be paired with
// a deliberate update of internal/service/renewal.go's iteration logic.

func TestManagedCertificate_SingleProfileCardinality(t *testing.T) {
	rt := reflect.TypeOf(ManagedCertificate{})
	cases := []struct {
		field    string
		wantKind reflect.Kind
	}{
		{"CertificateProfileID", reflect.String},
		{"RenewalPolicyID", reflect.String},
		{"IssuerID", reflect.String},
		{"OwnerID", reflect.String},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			f, ok := rt.FieldByName(tc.field)
			if !ok {
				t.Fatalf("ManagedCertificate.%s field missing", tc.field)
			}
			if f.Type.Kind() != tc.wantKind {
				t.Errorf("ManagedCertificate.%s kind = %s, want %s "+
					"(M-015 cardinality pin: 1:1 relationships only — "+
					"if you're changing this you must also update "+
					"internal/service/renewal.go's profile/policy lookup)",
					tc.field, f.Type.Kind(), tc.wantKind)
			}
		})
	}
}

func TestRenewalPolicy_SingleProfileCardinality(t *testing.T) {
	rt := reflect.TypeOf(RenewalPolicy{})
	f, ok := rt.FieldByName("CertificateProfileID")
	if !ok {
		t.Fatal("RenewalPolicy.CertificateProfileID field missing")
	}
	if f.Type.Kind() != reflect.String {
		t.Errorf("RenewalPolicy.CertificateProfileID kind = %s, want String "+
			"(M-015 cardinality pin)", f.Type.Kind())
	}
}
