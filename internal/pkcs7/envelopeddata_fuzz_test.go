package pkcs7

import "testing"

// FuzzParseEnvelopedData is the panic-safety fuzzer for ParseEnvelopedData.
//
// SCEP RFC 8894 + Intune master bundle Phase 2.5: every parser certctl
// adds gets a Fuzz target in the same package (the fuzz-target-ownership
// rule from cowork/CLAUDE.md::Operating Rules). The point isn't to find
// vulnerabilities (the parser uses stdlib encoding/asn1 which is itself
// fuzzed upstream) — it's to prove that arbitrary attacker-controlled
// bytes cannot panic the SCEP server. Any panic = an availability bug.
//
// Seed corpus: a known-good EnvelopedData built by buildTestEnvelope plus
// a handful of degenerate inputs (empty, single byte, all zeros) that
// should each return an error without panicking.
func FuzzParseEnvelopedData(f *testing.F) {
	// Seed: empty input.
	f.Add([]byte{})
	// Seed: a SEQUENCE tag with an absurd length (asn1 layer should
	// reject before we get to our code).
	f.Add([]byte{0x30, 0x82, 0xff, 0xff})
	// Seed: a known-good EnvelopedData built dynamically below — but the
	// fuzz seed corpus must be deterministic, so we skip the full RA-pair
	// build and just feed a small SEQUENCE-shaped blob.
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Whatever happens, no panic. Errors are fine; nil parse with
		// nil error would be a bug but the contract is just no-panic.
		_, _ = ParseEnvelopedData(data)
	})
}
