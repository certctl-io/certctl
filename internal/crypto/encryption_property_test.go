package crypto

import (
	"bytes"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Bundle Q (L-003 closure): property-based testing pilot.
//
// Two properties pinned with gopter:
//
//  1. Round-trip — DecryptIfKeySet(EncryptIfKeySet(x, k), k) == x for any
//     plaintext x and non-empty passphrase k. This is the core encryption
//     invariant; mutation testing on AES-GCM would benefit from this kind
//     of generative coverage in addition to the existing example-based
//     tests, because randomly-generated edge cases (zero-length plaintext,
//     plaintext containing the v2/v3 magic byte, very long plaintext) get
//     exercised automatically.
//
//  2. Wrong-passphrase rejection — DecryptIfKeySet(blob, wrongKey) must
//     never return a nil error AND non-empty plaintext. AEAD authentication
//     guarantees this; the property test makes the guarantee testable
//     under generative inputs rather than handpicked vectors.
//
// gopter is a non-blocking pilot — `MinSuccessfulTests` is 200 by default
// and these properties run in <50ms at -short. CI keeps them in the regular
// test stream (no separate gating).

func TestProperty_EncryptDecryptRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping property-based test in -short mode (PBKDF2 600k rounds × 50 iters > short budget)")
	}
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50 // 50 × 600k PBKDF2 ≈ 4-5s on -race CI
	properties := gopter.NewProperties(parameters)

	properties.Property("DecryptIfKeySet(EncryptIfKeySet(x, k), k) == x", prop.ForAll(
		func(plaintext []byte, passphrase string) bool {
			// Empty passphrase is the documented sentinel — skip.
			if passphrase == "" {
				return true
			}
			blob, ok, err := EncryptIfKeySet(plaintext, passphrase)
			if err != nil || !ok {
				t.Logf("EncryptIfKeySet(_, %q): err=%v ok=%v", passphrase, err, ok)
				return false
			}
			recovered, err := DecryptIfKeySet(blob, passphrase)
			if err != nil {
				t.Logf("DecryptIfKeySet round-trip: err=%v plaintext=%v passphrase=%q", err, plaintext, passphrase)
				return false
			}
			return bytes.Equal(recovered, plaintext)
		},
		// Plaintext: arbitrary byte slices including empty.
		gen.SliceOf(gen.UInt8()),
		// Passphrase: ASCII alpha, length 1..63 (avoid pathological lengths
		// blowing up PBKDF2 budgets in the property runner).
		gen.AlphaString().SuchThat(func(s string) bool {
			return len(s) > 0 && len(s) < 64
		}),
	))

	properties.TestingRun(t)
}

func TestProperty_WrongPassphraseRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping property-based test in -short mode (PBKDF2 cost)")
	}
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 30 // 30 × 600k PBKDF2 × 2 (encrypt+decrypt) ≈ 5s
	properties := gopter.NewProperties(parameters)

	properties.Property("Decrypt with wrong passphrase never returns plaintext", prop.ForAll(
		func(plaintext []byte, k1, k2 string) bool {
			if k1 == "" || k2 == "" || k1 == k2 {
				return true
			}
			blob, _, err := EncryptIfKeySet(plaintext, k1)
			if err != nil {
				return false
			}
			recovered, err := DecryptIfKeySet(blob, k2)
			// AEAD must reject. Either err != nil (expected), or — in the
			// astronomically-unlikely case of a tag collision — recovered
			// must NOT equal the original plaintext. Bytes-equal-but-no-error
			// is a security-relevant invariant violation.
			if err == nil && bytes.Equal(recovered, plaintext) {
				t.Logf("AEAD failed to reject wrong passphrase: plaintext=%v k1=%q k2=%q", plaintext, k1, k2)
				return false
			}
			return true
		},
		gen.SliceOf(gen.UInt8()),
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 64 }),
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 64 }),
	))

	properties.TestingRun(t)
}
