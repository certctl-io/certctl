// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"encoding/base64"
	"testing"
)

func TestGenerateNonce_LengthAndCharset(t *testing.T) {
	n, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	// base64.RawURLEncoding emits ceil(N*8/6) chars = ceil(32*8/6) = 43.
	if got, want := len(n), 43; got != want {
		t.Errorf("nonce length = %d, want %d", got, want)
	}
	// Charset must decode under base64url-no-padding.
	raw, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		t.Fatalf("nonce did not decode under base64url-no-padding: %v", err)
	}
	if len(raw) != nonceByteLen {
		t.Errorf("decoded nonce = %d bytes, want %d", len(raw), nonceByteLen)
	}
}

func TestGenerateNonce_Distinct(t *testing.T) {
	// Statistical sanity check, NOT cryptographic strength proof.
	// 256 bits of entropy means the probability of two consecutive
	// values colliding is ~2^-256 — well below the threshold for a
	// flaky-test-on-the-cosmos timeline.
	a, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce a: %v", err)
	}
	b, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce b: %v", err)
	}
	if a == b {
		t.Errorf("two consecutive nonces collided: %q", a)
	}
}
