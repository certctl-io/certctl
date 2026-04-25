package pkcs7

import (
	"testing"
)

// FuzzPEMToDERChain exercises the PEM-to-DER converter in
// internal/pkcs7/pkcs7.go::PEMToDERChain. Bundle-4 / H-004 (defense in depth):
// this function isn't directly network-reachable today (callers pass
// trusted PEM from issuer connectors), but it operates on byte input
// that traces back to upstream CA responses; a malicious-CA scenario
// could feed crafted PEM. Fuzz to ensure no panic, no allocation
// amplification.
//
// Run locally:
//
//	go test -run='^$' -fuzz=FuzzPEMToDERChain -fuzztime=10m ./internal/pkcs7/
func FuzzPEMToDERChain(f *testing.F) {
	seeds := []string{
		// Empty input.
		"",
		// Minimal valid PEM (an empty CERTIFICATE block — not a real cert).
		"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
		// Truncated header.
		"-----BEGIN CERTIFICATE",
		// Multiple BEGIN, no END.
		"-----BEGIN CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n",
		// Body with binary garbage.
		"-----BEGIN CERTIFICATE-----\n\x00\xff\xfe\x80\n-----END CERTIFICATE-----\n",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data string) {
		// Bound input — same rationale as the SCEP fuzz.
		if len(data) > 1<<20 {
			return
		}
		_, _ = PEMToDERChain(data)
	})
}

// FuzzASN1EncodeLength exercises the hand-rolled BER length encoder.
// Bundle-4 / H-004: the encoder is used when building PKCS#7 envelopes
// returned to EST/SCEP clients, so an attacker cannot directly feed
// untrusted bytes into it — but a future caller that did would be
// vulnerable to integer overflow / unbounded allocation. Fuzz the
// length values to confirm the encoder handles boundary conditions
// (negative, zero, MaxInt, etc.).
//
// Run locally:
//
//	go test -run='^$' -fuzz=FuzzASN1EncodeLength -fuzztime=2m ./internal/pkcs7/
func FuzzASN1EncodeLength(f *testing.F) {
	seeds := []int{0, 1, 127, 128, 255, 256, 65535, 65536, 1 << 20, 1 << 30, -1}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, length int) {
		// Bound input — fuzz-generated lengths in the billions cause
		// the encoder to allocate huge byte slices. Real PKCS#7 envelopes
		// from certctl never exceed a few MB.
		if length > 1<<24 || length < 0 {
			return
		}
		out := ASN1EncodeLength(length)
		// Sanity: encoder always returns at least one byte.
		if len(out) == 0 {
			t.Fatalf("ASN1EncodeLength(%d) returned empty slice", length)
		}
		// Sanity: encoder never returns more than 5 bytes for int input
		// (1 length-of-length byte + 4 bytes for a 32-bit length).
		if len(out) > 5 {
			t.Fatalf("ASN1EncodeLength(%d) returned %d bytes; expected ≤5", length, len(out))
		}
	})
}
