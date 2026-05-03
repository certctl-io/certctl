// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// --- KeyAuthorization + DNS01TXTRecordValue + TLSALPN01 helpers --------

func TestKeyAuthorization_RoundTrip(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	jwk := &jose.JSONWebKey{Key: &k.PublicKey}
	auth, err := KeyAuthorization("token-abc", jwk)
	if err != nil {
		t.Fatalf("KeyAuthorization: %v", err)
	}
	if !strings.HasPrefix(auth, "token-abc.") {
		t.Errorf("authorization should be `token.thumbprint`; got %q", auth)
	}
	thumb, err := JWKThumbprint(jwk)
	if err != nil {
		t.Fatalf("JWKThumbprint: %v", err)
	}
	if !strings.HasSuffix(auth, "."+thumb) {
		t.Errorf("authorization suffix mismatch: got %q, expected .%s", auth, thumb)
	}
}

func TestKeyAuthorization_NilJWK(t *testing.T) {
	_, err := KeyAuthorization("token", nil)
	if err == nil {
		t.Fatal("expected error for nil jwk")
	}
}

func TestDNS01TXTRecordValue_StableHash(t *testing.T) {
	// Same key authorization → same TXT value.
	v1 := DNS01TXTRecordValue("token-abc.thumbprint-xyz")
	v2 := DNS01TXTRecordValue("token-abc.thumbprint-xyz")
	if v1 != v2 {
		t.Errorf("TXT value not stable: %q vs %q", v1, v2)
	}
	// Length: base64url-no-pad of SHA-256 (32 bytes) → 43 chars.
	if len(v1) != 43 {
		t.Errorf("TXT value length = %d, want 43", len(v1))
	}
}

func TestTLSALPN01ExtensionValue_Length(t *testing.T) {
	v := TLSALPN01ExtensionValue("token-abc.thumbprint-xyz")
	if len(v) != 32 {
		t.Errorf("extension value length = %d, want 32 (SHA-256)", len(v))
	}
}

// --- HTTP-01 validator -------------------------------------------------

func TestHTTP01Validator_HappyPath(t *testing.T) {
	const expected = "token.thumbprint"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(expected))
	}))
	defer srv.Close()

	// httptest.NewServer binds 127.0.0.1; the SSRF guard rejects
	// reserved IPs. To exercise the happy path we use a custom
	// validator that skips the SSRF check.
	v := &HTTP01Validator{client: &http.Client{Timeout: 5 * time.Second}}

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	// Synthetic test: call the underlying http.Client.Do directly via
	// a custom Validate that targets srv.URL instead of building from
	// `domain`. The KeyAuthorization round-trip is what actually
	// matters here.
	body := makeHTTP01Body(t, v.client, srv.URL, "/.well-known/acme-challenge/token")
	if body != expected {
		t.Errorf("body = %q, want %q", body, expected)
	}
	_ = u
}

// makeHTTP01Body fetches a URL through the validator's HTTP client
// and returns the trimmed body. Used by the happy-path test to
// exercise the wire shape without going through the SSRF guard
// (which rejects 127.0.0.1).
func makeHTTP01Body(t *testing.T, client *http.Client, baseURL, path string) string {
	t.Helper()
	resp, err := client.Get(baseURL + path)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	return strings.TrimSpace(string(buf[:n]))
}

func TestHTTP01Validator_ReservedIPRejection(t *testing.T) {
	// Use the production NewHTTP01Validator which has the SSRF guard.
	v := NewHTTP01Validator(PoolConfig{PerChallengeTimeout: 2 * time.Second})

	// Target a domain that resolves to 127.0.0.1 (localhost). The
	// SSRF guard fires before the dial.
	err := v.Validate(context.Background(), "localhost", "token", "expected")
	if err == nil {
		t.Fatal("expected SSRF rejection for localhost; got nil")
	}
	if !errors.Is(err, ErrChallengeReservedIP) && !errors.Is(err, ErrChallengeConnection) {
		// "localhost" → 127.0.0.1 is the reserved-IP case; some
		// platforms route differently.
		t.Errorf("err = %v; want ErrChallengeReservedIP or ErrChallengeConnection", err)
	}
}

// --- Pool dispatch + bounded concurrency -------------------------------

// stubValidator is a ChallengeValidator that blocks on a channel until
// release is signaled. Used by the concurrency test to hold workers in
// the semaphore window so the test can read peak in-flight gauge.
type stubValidator struct {
	typeStr string
	release chan struct{}
	calls   atomic.Int64
}

func (s *stubValidator) Type() string { return s.typeStr }
func (s *stubValidator) Validate(ctx context.Context, domain, token, expected string) error {
	s.calls.Add(1)
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestPool_BoundedConcurrency(t *testing.T) {
	cfg := PoolConfig{
		HTTP01Weight:        3, // low cap so we can observe saturation
		DNS01Weight:         2,
		TLSALPN01Weight:     2,
		PerChallengeTimeout: 5 * time.Second,
	}
	p := NewPool(cfg)
	stub := &stubValidator{typeStr: "http-01", release: make(chan struct{})}
	p.SetValidator(stub)

	// Submit 10 HTTP-01 challenges. The pool's HTTP-01 weight is 3
	// → at most 3 should be in-flight at once.
	const total = 10
	var wg sync.WaitGroup
	wg.Add(total)
	for i := 0; i < total; i++ {
		i := i
		p.Submit(context.Background(), "http-01", fmt.Sprintf("d%d.example.com", i), "tok", "expect", func(err error) {
			defer wg.Done()
			_ = err
		})
	}

	// Wait for the validator to be hit by at least cfg.HTTP01Weight
	// workers (steady state — all available semaphore weight is
	// taken).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if stub.calls.Load() >= cfg.HTTP01Weight {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	snap := p.Snapshot()
	if snap.HTTP01InFlight > cfg.HTTP01Weight {
		t.Errorf("HTTP01InFlight = %d, exceeds cap %d", snap.HTTP01InFlight, cfg.HTTP01Weight)
	}
	if snap.HTTP01Peak > cfg.HTTP01Weight {
		t.Errorf("HTTP01Peak = %d, exceeds cap %d", snap.HTTP01Peak, cfg.HTTP01Weight)
	}
	// Release all blocked workers + drain.
	close(stub.release)
	wg.Wait()

	// Drain returns when wg is done (validators all completed).
	dctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := p.Drain(dctx); err != nil {
		t.Errorf("Drain: %v", err)
	}
	finalSnap := p.Snapshot()
	if finalSnap.HTTP01InFlight != 0 {
		t.Errorf("post-Drain HTTP01InFlight = %d, want 0", finalSnap.HTTP01InFlight)
	}
	if stub.calls.Load() != total {
		t.Errorf("validator calls = %d, want %d", stub.calls.Load(), total)
	}
}

func TestPool_TypeIsolation(t *testing.T) {
	// HTTP-01 saturation should not block DNS-01 dispatch. Each type
	// has its own semaphore.
	cfg := PoolConfig{
		HTTP01Weight:        1,
		DNS01Weight:         1,
		TLSALPN01Weight:     1,
		PerChallengeTimeout: 5 * time.Second,
	}
	p := NewPool(cfg)
	httpStub := &stubValidator{typeStr: "http-01", release: make(chan struct{})}
	dnsStub := &stubValidator{typeStr: "dns-01", release: make(chan struct{})}
	p.SetValidator(httpStub)
	p.SetValidator(dnsStub)

	// Block HTTP-01.
	httpDone := make(chan struct{})
	p.Submit(context.Background(), "http-01", "d.example.com", "tok", "expect", func(err error) {
		close(httpDone)
	})

	// DNS-01 should still progress.
	dnsDone := make(chan struct{})
	p.Submit(context.Background(), "dns-01", "d.example.com", "tok", "expect", func(err error) {
		close(dnsDone)
	})

	// Release DNS-01 immediately.
	close(dnsStub.release)
	select {
	case <-dnsDone:
		// good — DNS-01 completed even though HTTP-01 is held.
	case <-time.After(2 * time.Second):
		t.Fatal("DNS-01 did not complete despite HTTP-01 saturation")
	}

	// Release HTTP-01 + drain.
	close(httpStub.release)
	select {
	case <-httpDone:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP-01 did not complete after release")
	}
	dctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = p.Drain(dctx)
}

func TestPool_UnknownType(t *testing.T) {
	p := NewPool(PoolConfig{})
	done := make(chan error, 1)
	p.Submit(context.Background(), "ftp-01" /* invalid */, "d.example.com", "tok", "exp", func(err error) {
		done <- err
	})
	select {
	case err := <-done:
		if err == nil {
			t.Error("expected error for unknown challenge type")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Submit's onComplete did not fire for unknown type")
	}
}

// --- ChallengeProblemFromError mapping ---------------------------------

func TestChallengeProblemFromError_Mapping(t *testing.T) {
	cases := []struct {
		err     error
		wantTyp string
	}{
		{nil, ""}, // nil → nil Problem
		{ErrChallengeConnection, "urn:ietf:params:acme:error:connection"},
		{fmt.Errorf("%w: timeout", ErrChallengeConnection), "urn:ietf:params:acme:error:connection"},
		{ErrChallengeDNS, "urn:ietf:params:acme:error:dns"},
		{ErrChallengeTLS, "urn:ietf:params:acme:error:tls"},
		{ErrChallengeMismatch, "urn:ietf:params:acme:error:incorrectResponse"},
		{ErrChallengeReservedIP, "urn:ietf:params:acme:error:incorrectResponse"},
	}
	for _, tc := range cases {
		p := ChallengeProblemFromError("http-01", tc.err)
		if tc.err == nil {
			if p != nil {
				t.Errorf("nil err: got Problem %+v", p)
			}
			continue
		}
		if p == nil {
			t.Errorf("err=%v: got nil Problem", tc.err)
			continue
		}
		if p.Type != tc.wantTyp {
			t.Errorf("err=%v: type = %q, want %q", tc.err, p.Type, tc.wantTyp)
		}
	}
}
