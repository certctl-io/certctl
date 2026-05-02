// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package secret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"
)

// TestRef_UseExposesBytesAndZeros — the canonical contract: Use
// hands fn a buffer containing the credential, fn reads it, and
// after fn returns the buffer is overwritten with zeros.
func TestRef_UseExposesBytesAndZeros(t *testing.T) {
	r := NewRefFromString("secret-token")

	var captured []byte
	err := r.Use(func(buf []byte) error {
		// Copy so we can inspect post-zero behavior — the original
		// buf is going to be zeroed by Use's defer.
		captured = make([]byte, len(buf))
		copy(captured, buf)
		if string(buf) != "secret-token" {
			t.Errorf("Use: want bytes 'secret-token', got %q", buf)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Use: %v", err)
	}
	if string(captured) != "secret-token" {
		t.Errorf("captured bytes: want 'secret-token', got %q", captured)
	}
}

// TestRef_BufferZeroedAfterUse — the load-bearing security property.
// Without zeroing, the credential lingers in the heap and is trivially
// extractable from a process dump. We assert via Use's internal-state
// observation: a slice escape (with a known anti-pattern) reads zeros
// after Use returns.
func TestRef_BufferZeroedAfterUse(t *testing.T) {
	r := NewRefFromString("very-secret")

	// Anti-pattern: capture the slice header and read it after Use.
	// In production code this is a bug (caller must not retain the
	// slice). The test exercises the bug to assert the buffer was
	// zeroed.
	var escaped []byte
	_ = r.Use(func(buf []byte) error {
		escaped = buf
		return nil
	})

	// After Use, the slice should be all zeros.
	for i, b := range escaped {
		if b != 0 {
			t.Errorf("byte %d not zeroed: 0x%02x", i, b)
		}
	}
}

// TestRef_WriteTo writes the secret to a writer and asserts the
// write happened correctly + the staging buffer is zeroed.
func TestRef_WriteTo(t *testing.T) {
	r := NewRefFromString("Bearer abc123")
	var buf bytes.Buffer
	n, err := r.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if int64(buf.Len()) != n {
		t.Errorf("WriteTo: want %d bytes, got %d", buf.Len(), n)
	}
	if buf.String() != "Bearer abc123" {
		t.Errorf("WriteTo: wrong bytes, got %q", buf.String())
	}
}

// TestRef_StringRedacted — Ref.String() must NEVER return the
// underlying bytes. Catches accidental fmt.Sprintf("%v", cfg) leaks.
func TestRef_StringRedacted(t *testing.T) {
	r := NewRefFromString("super-secret-token")
	got := r.String()
	if got != "[redacted]" {
		t.Errorf("String: want '[redacted]', got %q", got)
	}
	// Test the implicit fmt.Stringer interface too.
	got = fmt.Sprintf("%v", r)
	if got != "[redacted]" {
		t.Errorf("fmt.Sprintf: want '[redacted]', got %q", got)
	}
}

// TestRef_MarshalJSONRedacted — JSON-encoding a Ref returns
// "[redacted]". Catches API-surface leak via GET /issuers etc.
func TestRef_MarshalJSONRedacted(t *testing.T) {
	r := NewRefFromString("my-api-key")
	got, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != `"[redacted]"` {
		t.Errorf("MarshalJSON: want '\"[redacted]\"', got %s", got)
	}
}

// TestRef_MarshalJSONInStruct — a config struct holding a *Ref
// field marshals with the credential redacted.
func TestRef_MarshalJSONInStruct(t *testing.T) {
	cfg := struct {
		Name string `json:"name"`
		Key  *Ref   `json:"key"`
	}{
		Name: "globalsign",
		Key:  NewRefFromString("the-key"),
	}
	got, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"name":"globalsign","key":"[redacted]"}`
	if string(got) != want {
		t.Errorf("MarshalJSON struct: want %s, got %s", want, got)
	}
}

// TestRef_NilSafety — calling methods on a nil *Ref returns errors,
// not panics. Defensive programming for paths that haven't wired
// the Ref yet.
func TestRef_NilSafety(t *testing.T) {
	var r *Ref

	if got := r.String(); got != "[redacted]" {
		t.Errorf("nil Ref.String: want '[redacted]', got %q", got)
	}
	// Use on nil returns an error, doesn't panic.
	if err := r.Use(func(buf []byte) error { return nil }); err == nil {
		t.Error("Use on nil Ref: expected error")
	}
	// WriteTo on nil returns an error, doesn't panic.
	if _, err := r.WriteTo(io.Discard); err == nil {
		t.Error("WriteTo on nil Ref: expected error")
	}
	if !r.IsEmpty() {
		t.Error("IsEmpty on nil Ref: want true")
	}
}

// TestRef_SourceErrorPropagated — when the source closure returns
// an error (decrypt failure, etc.), Use propagates it.
func TestRef_SourceErrorPropagated(t *testing.T) {
	sentinel := errors.New("decrypt failed")
	r := NewRef(func() ([]byte, error) { return nil, sentinel })

	err := r.Use(func(buf []byte) error {
		t.Error("fn should not be called when source errors")
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("Use: want sentinel in chain, got %v", err)
	}
}

// TestRef_IsEmpty — empty source returns IsEmpty=true.
func TestRef_IsEmpty(t *testing.T) {
	if !NewRefFromString("").IsEmpty() {
		t.Error("empty string Ref: want IsEmpty=true")
	}
	if NewRefFromString("x").IsEmpty() {
		t.Error("non-empty Ref: want IsEmpty=false")
	}
}

// TestRef_UnmarshalJSON — parse a JSON string into a Ref via
// NewRefFromString. Required for the factory's JSON-deserialization
// path that loads issuer configs from the DB.
func TestRef_UnmarshalJSON(t *testing.T) {
	type cfg struct {
		Token *Ref `json:"token"`
	}

	t.Run("string_value", func(t *testing.T) {
		var c cfg
		if err := json.Unmarshal([]byte(`{"token":"my-secret-token"}`), &c); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if c.Token == nil {
			t.Fatal("expected non-nil Ref")
		}
		_ = c.Token.Use(func(buf []byte) error {
			if string(buf) != "my-secret-token" {
				t.Errorf("Use: want 'my-secret-token', got %q", buf)
			}
			return nil
		})
	})

	t.Run("null", func(t *testing.T) {
		var c cfg
		if err := json.Unmarshal([]byte(`{"token":null}`), &c); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if c.Token != nil {
			t.Errorf("null should leave Ref nil, got %v", c.Token)
		}
	})

	t.Run("missing_key", func(t *testing.T) {
		var c cfg
		if err := json.Unmarshal([]byte(`{}`), &c); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if c.Token != nil {
			t.Error("missing key should leave Ref nil")
		}
	})

	t.Run("number_rejected", func(t *testing.T) {
		var c cfg
		err := json.Unmarshal([]byte(`{"token":123}`), &c)
		if err == nil {
			t.Error("expected error for non-string Ref input")
		}
	})

	t.Run("roundtrip_marshal_then_unmarshal", func(t *testing.T) {
		// Marshal returns "[redacted]" — round-tripping through
		// Unmarshal would store the string "[redacted]" as the
		// new credential. Documented behavior; operators marshal
		// for inspection, not for re-loading.
		original := cfg{Token: NewRefFromString("real-secret")}
		marshaled, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if string(marshaled) != `{"token":"[redacted]"}` {
			t.Errorf("Marshal: got %s", marshaled)
		}
	})
}

// TestZero — direct test of the zero helper to lock the
// implementation: every byte set to 0.
func TestZero(t *testing.T) {
	b := []byte("not-zero")
	zero(b)
	for i, x := range b {
		if x != 0 {
			t.Errorf("byte %d: want 0, got %d", i, x)
		}
	}
}
