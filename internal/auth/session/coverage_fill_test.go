package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

// Coverage fill — v2.1.0 release gate Phase 3.
//
// Three previously-uncovered surfaces:
//
//   - SetTrustedProxies (cmd/server config wire)
//   - ComputeCookieHMAC (pre-login cookie verifier helper)
//   - DecryptKeyMaterial (pre-login HMAC-key derive)
//
// Each is a thin wrapper called by main.go or the pre-login flow that
// never exits through a unit-test fixture. The tests below run them
// directly so the coverage gate stops flagging the package.

func TestSetTrustedProxies_RoundTrip(t *testing.T) {
	t.Parallel() //nolint:paralleltest // shared package-level state
	// Snapshot + restore so concurrent tests don't observe the override.
	prev := trustedProxyCIDRs
	defer func() { trustedProxyCIDRs = prev }()

	want := []string{"10.0.0.0/8", "192.0.2.1"}
	SetTrustedProxies(want)
	if len(trustedProxyCIDRs) != len(want) {
		t.Fatalf("expected %d entries, got %d", len(want), len(trustedProxyCIDRs))
	}
	for i, c := range want {
		if trustedProxyCIDRs[i] != c {
			t.Errorf("entry %d: got %q, want %q", i, trustedProxyCIDRs[i], c)
		}
	}

	// Empty slice clears.
	SetTrustedProxies(nil)
	if len(trustedProxyCIDRs) != 0 {
		t.Errorf("expected nil/empty after clear; got %v", trustedProxyCIDRs)
	}
}

func TestComputeCookieHMAC_Deterministic(t *testing.T) {
	t.Parallel()
	key := []byte("a-32-byte-key-for-hmac-test-pad!")
	mac1 := ComputeCookieHMAC("ses-1", "actor-1", key)
	mac2 := ComputeCookieHMAC("ses-1", "actor-1", key)
	if !hmac.Equal(mac1, mac2) {
		t.Errorf("HMAC must be deterministic for the same inputs")
	}
	// Length is sha256.Size.
	if len(mac1) != sha256.Size {
		t.Errorf("expected len=%d (sha256), got %d", sha256.Size, len(mac1))
	}
	// Differing id2 changes the HMAC.
	if hmac.Equal(mac1, ComputeCookieHMAC("ses-1", "actor-2", key)) {
		t.Errorf("HMAC must differ when actor changes")
	}
	// Differing id1 changes the HMAC.
	if hmac.Equal(mac1, ComputeCookieHMAC("ses-2", "actor-1", key)) {
		t.Errorf("HMAC must differ when session changes")
	}
}

func TestDecryptKeyMaterial_RoundTrip(t *testing.T) {
	t.Parallel()
	// encryptKeyMaterial + decryptKeyMaterial are the pair; round-trip
	// asserts the public DecryptKeyMaterial wrapper does not bypass
	// the decryption path.
	plaintext := []byte("plain-32-byte-key-for-hmac-pad!!")
	const passphrase = "test-passphrase-for-key-encrypt"
	ct, err := encryptKeyMaterial(plaintext, passphrase)
	if err != nil {
		t.Fatalf("encryptKeyMaterial: %v", err)
	}
	got, err := DecryptKeyMaterial(ct, passphrase)
	if err != nil {
		t.Fatalf("DecryptKeyMaterial: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("decrypt mismatch: got %q, want %q", got, plaintext)
	}
	// Wrong passphrase → error (forwarded from decryptKeyMaterial).
	if _, err := DecryptKeyMaterial(ct, "wrong-passphrase"); err == nil {
		t.Errorf("expected error with wrong passphrase, got nil")
	}
}
