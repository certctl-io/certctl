package pkcs7

import (
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Bundle Q (L-003 closure): property-based test for ASN.1 length encoding.
//
// The pkcs7 package implements DER-encoded length under [ASN1EncodeLength];
// the inverse parser is provided here as `decodeLength` (tracked under the
// EST/SCEP code path that consumes the DER framing). The property is the
// classic encode/decode round-trip:
//
//	decodeLength(encodeLength(x)) == x  for all 0 ≤ x ≤ math.MaxInt32
//
// In addition, structural invariants are pinned:
//
//   - 0 ≤ x < 128 → output is 1 byte, equal to x
//   - x ≥ 128 → output[0] has the high bit set; output[0]&0x7f == len(rest)
//     and rest is big-endian
//
// These match X.690 §8.1.3.

// decodeLength is the inverse of ASN1EncodeLength, defined in this test file
// because the production code only needs the encoder. It returns the decoded
// length and the number of bytes consumed.
func decodeLength(b []byte) (int, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	first := b[0]
	if first < 0x80 {
		return int(first), 1, true
	}
	n := int(first & 0x7f)
	if n == 0 || n > 4 || len(b) < 1+n {
		return 0, 0, false
	}
	v := 0
	for i := 0; i < n; i++ {
		v = (v << 8) | int(b[1+i])
	}
	return v, 1 + n, true
}

func TestProperty_ASN1LengthRoundTrip(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 500
	properties := gopter.NewProperties(parameters)

	properties.Property("decodeLength(ASN1EncodeLength(x)) == x", prop.ForAll(
		func(x int32) bool {
			if x < 0 {
				return true // out of contract domain (lengths are non-negative)
			}
			encoded := ASN1EncodeLength(int(x))
			got, n, ok := decodeLength(encoded)
			if !ok {
				t.Logf("decodeLength failed on encoded form of %d: %x", x, encoded)
				return false
			}
			if n != len(encoded) {
				t.Logf("consumed %d bytes but encoded form is %d bytes (%d → %x)", n, len(encoded), x, encoded)
				return false
			}
			if got != int(x) {
				t.Logf("round-trip mismatch: %d → %x → %d", x, encoded, got)
				return false
			}
			return true
		},
		gen.Int32Range(0, 0x7fffffff),
	))

	properties.Property("short-form encoding for x < 128", prop.ForAll(
		func(x int8) bool {
			if x < 0 {
				return true
			}
			encoded := ASN1EncodeLength(int(x))
			return len(encoded) == 1 && encoded[0] == byte(x)
		},
		gen.Int8Range(0, 127),
	))

	properties.Property("long-form encoding sets high bit on first byte", prop.ForAll(
		func(x int32) bool {
			if x < 128 {
				return true
			}
			encoded := ASN1EncodeLength(int(x))
			if len(encoded) < 2 {
				return false
			}
			if encoded[0]&0x80 == 0 {
				t.Logf("long-form first byte %02x missing high bit for x=%d", encoded[0], x)
				return false
			}
			n := int(encoded[0] & 0x7f)
			return n == len(encoded)-1
		},
		gen.Int32Range(128, 0x7fffffff),
	))

	properties.TestingRun(t)
}
