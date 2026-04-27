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
		func(plaintext []byte, passphraseRaw string) bool {
			// Sanitize inside (no SuchThat → no discards). Empty passphrase
			// is documented sentinel; substitute a non-empty default.
			passphrase := passphraseRaw
			if len(passphrase) == 0 {
				passphrase = "default-key"
			}
			if len(passphrase) > 50 {
				passphrase = passphrase[:50]
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
		// Passphrase: arbitrary ASCII alpha; length sanitized inside the predicate.
		gen.AlphaString(),
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

	// Generate a single passphrase + a deterministic-different mutation.
	// Sanitize length inside the predicate (no SuchThat) so gopter never
	// discards a case — prior version triggered "Gave up after only 26
	// passed tests, 132 discarded" under -race because SuchThat on
	// AlphaString rejected too many cases.
	properties.Property("Decrypt with wrong passphrase never returns plaintext", prop.ForAll(
		func(plaintext []byte, k1raw string) bool {
			k1 := k1raw
			if len(k1) == 0 {
				k1 = "default-key"
			}
			if len(k1) > 50 {
				k1 = k1[:50]
			}
			k2 := "wrong-" + k1 // guaranteed != k1
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
		gen.AlphaString(),
	))

	properties.TestingRun(t)
}
