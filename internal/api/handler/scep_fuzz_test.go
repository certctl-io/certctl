package handler

import (
	"encoding/hex"
	"testing"
)

// FuzzExtractCSRFromPKCS7 exercises the SCEP PKCS#7 envelope parser at
// internal/api/handler/scep.go::extractCSRFromPKCS7. Bundle-4 / H-004:
// this parser is reachable by an anonymous network attacker via
// POST /scep?operation=PKIOperation. It calls into hand-written ASN.1
// unmarshaling logic in parseSignedDataForCSR (which uses encoding/asn1
// from stdlib but with manual structure layouts). Any panic, OOM, or
// allocation amplification surfaces here.
//
// Run locally:
//
//	go test -run='^$' -fuzz=FuzzExtractCSRFromPKCS7 -fuzztime=10m \
//	    ./internal/api/handler/
//
// CI gate (Bundle-4 added in .github/workflows/ci.yml): runs at
// -fuzztime=2m on every PR. The full 10m runs are reserved for the
// scheduled overnight job to keep PR latency reasonable.
func FuzzExtractCSRFromPKCS7(f *testing.F) {
	// Seed corpus: a few well-formed envelopes + a few deliberately
	// malformed ones to give the fuzzer mutational starting points.
	seeds := [][]byte{
		// Minimal PKCS#7 ContentInfo OID + empty content.
		mustHex("3013060B2A864886F70D010907020100"),
		// Empty input — fuzzer should return error, not panic.
		{},
		// Single zero byte — parses as ASN.1 boolean false.
		{0x00},
		// Truncated SEQUENCE with bogus length.
		{0x30, 0x81, 0xff},
		// Recursive SEQUENCE wrapping (fuzzer + parser depth check).
		{0x30, 0x80, 0x30, 0x80, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Bound input size — the fuzzer otherwise tends to chase
		// "find" rewards via 100MB inputs that aren't representative.
		// Real network input is bounded by MaxBytesReader (1MB default).
		if len(data) > 1<<20 {
			return
		}
		// extractCSRFromPKCS7 returns (csrDER, challengePassword, transactionID, error).
		// We don't care about the return values — we care that it doesn't
		// panic, OOM, or allocate unbounded memory. The Go test harness
		// reports panics as test failures.
		_, _, _, _ = extractCSRFromPKCS7(data)
	})
}

// FuzzParseSignedDataForCSR exercises the inner SignedData parser
// directly (the function extractCSRFromPKCS7 calls). Same scope as
// FuzzExtractCSRFromPKCS7 but narrower; helps the fuzzer find paths
// that the wrapping function's fallbacks would otherwise mask.
//
// Run locally:
//
//	go test -run='^$' -fuzz=FuzzParseSignedDataForCSR -fuzztime=10m \
//	    ./internal/api/handler/
func FuzzParseSignedDataForCSR(f *testing.F) {
	seeds := [][]byte{
		mustHex("3013060B2A864886F70D010907020100"),
		{},
		{0x00},
		{0x30, 0x80},
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		_, _ = parseSignedDataForCSR(data)
	})
}

// mustHex decodes a hex string for fuzz seeds. Panics on malformed
// hex — only used at test setup with hard-coded constants.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
