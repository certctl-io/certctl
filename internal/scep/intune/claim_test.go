package intune

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
)

// Each TestDeviceMatchesCSR_* covers a single dimension (CN / SAN-DNS /
// SAN-RFC822 / SAN-UPN) with both happy-path and mismatch fixtures so the
// per-dimension typed errors stay wired up over future refactors.

func newCSRFixture(cn string, dns, email []string) *x509.CertificateRequest {
	return &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: cn},
		DNSNames:       dns,
		EmailAddresses: email,
	}
}

func TestDeviceMatchesCSR_HappyPath_AllDimensions(t *testing.T) {
	csr := newCSRFixture("DEVICE-001", []string{"a.example.com", "b.example.com"},
		[]string{"alice@example.com"})
	c := &ChallengeClaim{
		DeviceName: "DEVICE-001",
		SANDNS:     []string{"b.example.com", "a.example.com"}, // reversed; set-equality
		SANRFC822:  []string{"alice@example.com"},
	}
	if err := c.DeviceMatchesCSR(csr); err != nil {
		t.Fatalf("happy-path match should succeed: %v", err)
	}
}

func TestDeviceMatchesCSR_NilGuards(t *testing.T) {
	var nilClaim *ChallengeClaim
	if err := nilClaim.DeviceMatchesCSR(&x509.CertificateRequest{}); err == nil {
		t.Errorf("nil claim should error")
	}
	c := &ChallengeClaim{}
	if err := c.DeviceMatchesCSR(nil); err == nil {
		t.Errorf("nil CSR should error")
	}
}

func TestDeviceMatchesCSR_CNMismatch(t *testing.T) {
	csr := newCSRFixture("ATTACKER-DEVICE", nil, nil)
	c := &ChallengeClaim{DeviceName: "DEVICE-001"}
	if err := c.DeviceMatchesCSR(csr); !errors.Is(err, ErrClaimCNMismatch) {
		t.Fatalf("got %v, want ErrClaimCNMismatch", err)
	}
}

func TestDeviceMatchesCSR_EmptyClaimCN_NoConstraint(t *testing.T) {
	csr := newCSRFixture("any-cn-is-fine", nil, nil)
	c := &ChallengeClaim{} // no DeviceName pinned
	if err := c.DeviceMatchesCSR(csr); err != nil {
		t.Fatalf("empty claim CN must impose no constraint: %v", err)
	}
}

func TestDeviceMatchesCSR_SANDNSMismatch_Missing(t *testing.T) {
	csr := newCSRFixture("d", []string{"a.example.com"}, nil) // missing b
	c := &ChallengeClaim{SANDNS: []string{"a.example.com", "b.example.com"}}
	if err := c.DeviceMatchesCSR(csr); !errors.Is(err, ErrClaimSANDNSMismatch) {
		t.Fatalf("got %v, want ErrClaimSANDNSMismatch", err)
	}
}

func TestDeviceMatchesCSR_SANDNSMismatch_Extra(t *testing.T) {
	csr := newCSRFixture("d", []string{"a.example.com", "evil.example.com"}, nil)
	c := &ChallengeClaim{SANDNS: []string{"a.example.com"}}
	if err := c.DeviceMatchesCSR(csr); !errors.Is(err, ErrClaimSANDNSMismatch) {
		t.Fatalf("got %v, want ErrClaimSANDNSMismatch (CSR carries extra SAN)", err)
	}
}

func TestDeviceMatchesCSR_SANDNSMatch_CaseInsensitive(t *testing.T) {
	csr := newCSRFixture("d", []string{"A.Example.COM"}, nil)
	c := &ChallengeClaim{SANDNS: []string{"a.example.com"}}
	if err := c.DeviceMatchesCSR(csr); err != nil {
		t.Fatalf("DNS comparison must be case-insensitive (RFC 4343): %v", err)
	}
}

func TestDeviceMatchesCSR_SANDNSDedupe(t *testing.T) {
	// CSR with duplicate SAN entries should still match a claim that
	// only lists each unique value once. The "set" in set-equality is
	// the cert's effective SAN set, not the multiset.
	csr := newCSRFixture("d", []string{"a.example.com", "a.example.com"}, nil)
	c := &ChallengeClaim{SANDNS: []string{"a.example.com"}}
	if err := c.DeviceMatchesCSR(csr); err != nil {
		t.Fatalf("dedup-equality must hold: %v", err)
	}
}

func TestDeviceMatchesCSR_EmptyClaimSAN_NoConstraint(t *testing.T) {
	csr := newCSRFixture("d", []string{"any.example.com"}, nil)
	c := &ChallengeClaim{} // no SANDNS pinned
	if err := c.DeviceMatchesCSR(csr); err != nil {
		t.Fatalf("empty claim SANDNS must impose no constraint: %v", err)
	}
}

func TestDeviceMatchesCSR_SANRFC822Mismatch(t *testing.T) {
	csr := newCSRFixture("d", nil, []string{"bob@example.com"})
	c := &ChallengeClaim{SANRFC822: []string{"alice@example.com"}}
	if err := c.DeviceMatchesCSR(csr); !errors.Is(err, ErrClaimSANRFC822Mismatch) {
		t.Fatalf("got %v, want ErrClaimSANRFC822Mismatch", err)
	}
}

func TestDeviceMatchesCSR_SANUPNMismatch_NoExtractor(t *testing.T) {
	// extractUPNSans currently returns nil; any non-empty SANUPN claim
	// is therefore a guaranteed mismatch (correct fail-closed behavior).
	csr := newCSRFixture("d", nil, nil)
	c := &ChallengeClaim{SANUPN: []string{"alice@corp.example.com"}}
	if err := c.DeviceMatchesCSR(csr); !errors.Is(err, ErrClaimSANUPNMismatch) {
		t.Fatalf("got %v, want ErrClaimSANUPNMismatch (UPN extractor stubbed)", err)
	}
}

func TestNormaliseSet_EdgeCases(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"empty", nil, []string{}},
		{"trim space", []string{"  hello  "}, []string{"hello"}},
		{"drop empty after trim", []string{"   ", "x"}, []string{"x"}},
		{"lowercase", []string{"HELLO", "World"}, []string{"hello", "world"}},
		{"dedupe", []string{"a", "a", "b"}, []string{"a", "b"}},
		{"sort", []string{"c", "a", "b"}, []string{"a", "b", "c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normaliseSet(tc.in)
			if !equalSets(got, tc.want) {
				t.Errorf("normaliseSet(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestEqualSets_LengthMismatch(t *testing.T) {
	if equalSets([]string{"a", "b"}, []string{"a"}) {
		t.Errorf("different-length sets must not compare equal")
	}
}

func TestExtractUPNSans_StubReturnsEmpty(t *testing.T) {
	// Pin the documented stub behavior. If/when ExtractUPNSans is
	// implemented for real, this test is the canary that flags the
	// behavioral change.
	if got := extractUPNSans(&x509.CertificateRequest{}); len(got) != 0 {
		t.Errorf("extractUPNSans stub must return empty slice; got %v", got)
	}
}
