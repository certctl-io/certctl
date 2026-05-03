// Copyright (c) certctl
// SPDX-License-Identifier: BSL-1.1

package acme

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/shankar0123/certctl/internal/validation"
)

// ChallengeValidator is the surface a challenge-validation worker
// implements. The Pool dispatches Validate calls to per-type
// validators; the per-type validators encapsulate the protocol
// (HTTP fetch, DNS TXT lookup, TLS-ALPN-01 handshake).
//
// Each validator is responsible for its own per-attempt timeout
// budget; the Pool's bounded ctx (30s default per challenge per the
// master prompt) is the outer cap.
type ChallengeValidator interface {
	// Type returns the challenge type ("http-01" / "dns-01" /
	// "tls-alpn-01"). Used for Pool dispatch + metrics labels.
	Type() string
	// Validate performs the protocol-specific check. domain is the
	// identifier value (DNS name, with a possible leading "*." for
	// wildcards on DNS-01); token is the challenge.token; expected
	// is the result of KeyAuthorization() on (token, account-jwk).
	// Returns nil on validation success.
	Validate(ctx context.Context, domain, token, expected string) error
}

// PoolConfig configures the validator-pool's three semaphore weights
// + the shared HTTP / DNS dialing parameters. cmd/server/main.go
// builds this from cfg.ACMEServer.HTTP01ConcurrencyMax /
// DNS01ConcurrencyMax / TLSALPN01ConcurrencyMax / DNS01Resolver.
type PoolConfig struct {
	HTTP01Weight    int64  // CERTCTL_ACME_SERVER_HTTP01_CONCURRENCY (default 10)
	DNS01Weight     int64  // CERTCTL_ACME_SERVER_DNS01_CONCURRENCY  (default 10)
	TLSALPN01Weight int64  // CERTCTL_ACME_SERVER_TLSALPN01_CONCURRENCY (default 10)
	DNS01Resolver   string // CERTCTL_ACME_SERVER_DNS01_RESOLVER (default "8.8.8.8:53")

	// PerChallengeTimeout caps the total per-challenge validation
	// time. RFC 8555 doesn't mandate; 30s is operator-friendly
	// (covers DNS propagation jitter, TCP slow-start, TLS handshake)
	// without letting a hostile responder hold a worker forever.
	// Default 30s.
	PerChallengeTimeout time.Duration
}

// Pool is the dispatcher that owns the 3 per-type semaphores +
// per-type ChallengeValidator implementations + per-validator-type
// in-flight gauge for the chaos test. Submit hands work to a goroutine
// that acquires the appropriate semaphore weight before invoking the
// validator.
//
// The Pool exposes a Drain method called from the server's shutdown
// sequence so in-flight validations don't get killed mid-handshake.
type Pool struct {
	cfg PoolConfig

	http01Sem    *semaphore.Weighted
	dns01Sem     *semaphore.Weighted
	tlsALPN01Sem *semaphore.Weighted

	validators map[string]ChallengeValidator

	// Per-type in-flight gauges. Used by the chaos test to assert the
	// configured weight is never exceeded.
	http01InFlight    atomic.Int64
	dns01InFlight     atomic.Int64
	tlsALPN01InFlight atomic.Int64

	// Per-type peak gauges. Same use as in-flight; tests read peaks
	// post-run.
	http01Peak    atomic.Int64
	dns01Peak     atomic.Int64
	tlsALPN01Peak atomic.Int64

	wg sync.WaitGroup
}

// NewPool constructs a Pool with the supplied config + the 3 default
// validators. cmd/server/main.go calls this at startup once.
func NewPool(cfg PoolConfig) *Pool {
	if cfg.HTTP01Weight <= 0 {
		cfg.HTTP01Weight = 10
	}
	if cfg.DNS01Weight <= 0 {
		cfg.DNS01Weight = 10
	}
	if cfg.TLSALPN01Weight <= 0 {
		cfg.TLSALPN01Weight = 10
	}
	if cfg.DNS01Resolver == "" {
		cfg.DNS01Resolver = "8.8.8.8:53"
	}
	if cfg.PerChallengeTimeout <= 0 {
		cfg.PerChallengeTimeout = 30 * time.Second
	}

	p := &Pool{
		cfg:          cfg,
		http01Sem:    semaphore.NewWeighted(cfg.HTTP01Weight),
		dns01Sem:     semaphore.NewWeighted(cfg.DNS01Weight),
		tlsALPN01Sem: semaphore.NewWeighted(cfg.TLSALPN01Weight),
		validators:   make(map[string]ChallengeValidator, 3),
	}
	p.SetValidator(NewHTTP01Validator(cfg))
	p.SetValidator(NewDNS01Validator(cfg))
	p.SetValidator(NewTLSALPN01Validator(cfg))
	return p
}

// SetValidator registers (or replaces) the validator for a given
// challenge type. Tests inject mocks via this entry point.
func (p *Pool) SetValidator(v ChallengeValidator) {
	p.validators[v.Type()] = v
}

// Submit fires off a validation goroutine. Returns immediately. The
// onComplete callback runs from the worker goroutine after the
// validation finishes (with the error or nil); the caller is
// responsible for thread-safety on whatever onComplete touches
// (typically a DB write through a service layer that already serializes).
//
// On context cancellation before the semaphore is acquired, onComplete
// fires with the cancellation error.
func (p *Pool) Submit(ctx context.Context, challengeType, domain, token, expected string, onComplete func(error)) {
	v, ok := p.validators[challengeType]
	if !ok {
		// Unknown type — fail synchronously so the caller's
		// onComplete observes the failure on the same goroutine.
		go onComplete(fmt.Errorf("acme: no validator registered for type %q", challengeType))
		return
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		sem, inFlight, peak := p.semaphoreFor(challengeType)
		if err := sem.Acquire(ctx, 1); err != nil {
			onComplete(err)
			return
		}
		defer sem.Release(1)

		now := inFlight.Add(1)
		// Update peak monotonically — only swap upward.
		for {
			old := peak.Load()
			if now <= old || peak.CompareAndSwap(old, now) {
				break
			}
		}
		defer inFlight.Add(-1)

		cctx, cancel := context.WithTimeout(ctx, p.cfg.PerChallengeTimeout)
		defer cancel()

		err := v.Validate(cctx, domain, token, expected)
		onComplete(err)
	}()
}

// Drain waits for every in-flight validator to finish, bounded by
// ctx. Called from cmd/server/main.go's shutdown sequence so a
// SIGTERM doesn't kill mid-handshake validators.
func (p *Pool) Drain(ctx context.Context) error {
	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// PoolSnapshot is the per-type in-flight + peak observation set used by
// chaos / concurrency tests to verify the configured weights were never
// exceeded.
type PoolSnapshot struct {
	HTTP01InFlight    int64
	HTTP01Peak        int64
	DNS01InFlight     int64
	DNS01Peak         int64
	TLSALPN01InFlight int64
	TLSALPN01Peak     int64
}

// Snapshot returns the current per-type in-flight + peak counts.
func (p *Pool) Snapshot() PoolSnapshot {
	return PoolSnapshot{
		HTTP01InFlight:    p.http01InFlight.Load(),
		HTTP01Peak:        p.http01Peak.Load(),
		DNS01InFlight:     p.dns01InFlight.Load(),
		DNS01Peak:         p.dns01Peak.Load(),
		TLSALPN01InFlight: p.tlsALPN01InFlight.Load(),
		TLSALPN01Peak:     p.tlsALPN01Peak.Load(),
	}
}

// semaphoreFor returns the (semaphore, in-flight gauge, peak gauge)
// triple for a given challenge type. Centralized so the Submit
// goroutine can update peak from a single spot.
func (p *Pool) semaphoreFor(challengeType string) (*semaphore.Weighted, *atomic.Int64, *atomic.Int64) {
	switch challengeType {
	case "http-01":
		return p.http01Sem, &p.http01InFlight, &p.http01Peak
	case "dns-01":
		return p.dns01Sem, &p.dns01InFlight, &p.dns01Peak
	case "tls-alpn-01":
		return p.tlsALPN01Sem, &p.tlsALPN01InFlight, &p.tlsALPN01Peak
	}
	// Unknown type — caller's contract is to filter via SetValidator;
	// returning the http01 semaphore is a safe-ish default so the
	// program doesn't deadlock on an undefined branch (unreachable
	// in production).
	return p.http01Sem, &p.http01InFlight, &p.http01Peak
}

// --- HTTP-01 validator -------------------------------------------------

// HTTP01Validator implements RFC 8555 §8.3. The validator GETs
// http://<domain>/.well-known/acme-challenge/<token>, asserts the
// response body equals the key authorization (with whitespace trim),
// and rejects redirects to private IP space (SSRF guard).
type HTTP01Validator struct {
	client *http.Client
}

// NewHTTP01Validator constructs the validator with a hardened HTTP
// client: 5s connect timeout, 10s response-header timeout, IP-aware
// dial that refuses reserved IPs.
func NewHTTP01Validator(cfg PoolConfig) *HTTP01Validator {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("%w: %v", ErrChallengeConnection, err)
			}
			for _, ip := range ips {
				if validation.IsReservedIPForDial(ip) {
					return nil, fmt.Errorf("%w: %s resolves to reserved IP %s", ErrChallengeReservedIP, host, ip)
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		DisableKeepAlives:     true, // each challenge fetch is a one-shot
	}

	return &HTTP01Validator{
		client: &http.Client{
			Transport: transport,
			Timeout:   cfg.PerChallengeTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Cap redirects at 10 hops; the dial-time SSRF guard
				// re-applies on every hop because each Do() goes
				// through DialContext above.
				if len(via) >= 10 {
					return fmt.Errorf("%w: %d hops", ErrChallengeRedirect, len(via))
				}
				return nil
			},
		},
	}
}

func (v *HTTP01Validator) Type() string { return "http-01" }

func (v *HTTP01Validator) Validate(ctx context.Context, domain, token, expected string) error {
	url := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", domain, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrChallengeConnection, err)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		// Distinguish redirect-loop / SSRF errors (already wrapped
		// with the proper sentinel) from raw transport errors.
		if errors.Is(err, ErrChallengeReservedIP) ||
			errors.Is(err, ErrChallengeRedirect) ||
			errors.Is(err, ErrChallengeConnection) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrChallengeConnection, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP-01 endpoint returned status %d", ErrChallengeMismatch, resp.StatusCode)
	}

	// 16 KiB body cap per the master prompt (validators must not be
	// turnable into memory-exhaustion vectors against the certctl
	// server).
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024+1))
	if err != nil {
		return fmt.Errorf("%w: read body: %v", ErrChallengeConnection, err)
	}
	if len(body) > 16*1024 {
		return ErrChallengeBodyTooBig
	}
	got := strings.TrimSpace(string(body))
	if got != expected {
		return fmt.Errorf("%w: HTTP-01 body did not match key authorization", ErrChallengeMismatch)
	}
	return nil
}

// --- DNS-01 validator --------------------------------------------------

// DNS01Validator implements RFC 8555 §8.4. The validator queries
// `_acme-challenge.<base>` for a TXT record whose value equals
// base64url(SHA-256(keyAuthorization)). Wildcard identifiers
// (`*.example.com`) resolve against `_acme-challenge.example.com` per
// RFC 8555 §8.4.
type DNS01Validator struct {
	resolver *net.Resolver
}

// NewDNS01Validator constructs the validator with a custom resolver
// pointed at cfg.DNS01Resolver. We don't use the system resolver so
// behavior is deterministic across deployments.
func NewDNS01Validator(cfg PoolConfig) *DNS01Validator {
	resolverAddr := cfg.DNS01Resolver
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &DNS01Validator{
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, resolverAddr)
			},
		},
	}
}

func (v *DNS01Validator) Type() string { return "dns-01" }

func (v *DNS01Validator) Validate(ctx context.Context, domain, token, expected string) error {
	// Wildcard handling: `*.example.com` queries _acme-challenge.example.com.
	base := strings.TrimPrefix(domain, "*.")
	qname := "_acme-challenge." + base
	want := DNS01TXTRecordValue(expected)

	txts, err := v.resolver.LookupTXT(ctx, qname)
	if err != nil {
		return fmt.Errorf("%w: TXT lookup for %s: %v", ErrChallengeDNS, qname, err)
	}
	for _, t := range txts {
		if t == want {
			return nil
		}
	}
	return fmt.Errorf("%w: no TXT record at %s matched expected value", ErrChallengeMismatch, qname)
}

// --- TLS-ALPN-01 validator --------------------------------------------

// TLSALPN01Validator implements RFC 8737. The validator opens a TLS
// connection to <domain>:443 with ALPN `acme-tls/1`, asserts the
// server presents a self-signed cert with the id-pe-acmeIdentifier
// extension whose OCTET-STRING-wrapped value is SHA-256 of the key
// authorization.
//
// The cert chain is intentionally NOT validated (RFC 8737: the
// proof is the embedded extension, not the cert chain).
// InsecureSkipVerify is correct here.
type TLSALPN01Validator struct {
	timeout time.Duration
}

func NewTLSALPN01Validator(cfg PoolConfig) *TLSALPN01Validator {
	return &TLSALPN01Validator{timeout: cfg.PerChallengeTimeout}
}

func (v *TLSALPN01Validator) Type() string { return "tls-alpn-01" }

func (v *TLSALPN01Validator) Validate(ctx context.Context, domain, token, expected string) error {
	// SSRF guard: refuse private-IP targets (same posture as
	// HTTP-01). LookupIP runs on the configured DNS resolver via
	// net.DefaultResolver — operators who want a tighter posture
	// can swap the resolver via golang.org/net/dns config.
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("%w: %s LookupIP: %v", ErrChallengeConnection, domain, err)
	}
	for _, ip := range ips {
		if validation.IsReservedIPForDial(ip) {
			return fmt.Errorf("%w: %s resolves to reserved IP %s", ErrChallengeReservedIP, domain, ip)
		}
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{
			ServerName: domain,
			NextProtos: []string{"acme-tls/1"},
			//nolint:gosec // RFC 8737 §3 mandates this: the TLS-ALPN-01 proof lives in the cert's id-pe-acmeIdentifier extension, NOT the chain. Documented in docs/tls.md L-001 table; documented in docs/acme-server.md threat model.
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return fmt.Errorf("%w: %s:443: %v", ErrChallengeTLS, domain, err)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return fmt.Errorf("%w: dialer returned non-TLS connection", ErrChallengeTLS)
	}
	state := tlsConn.ConnectionState()

	if state.NegotiatedProtocol != "acme-tls/1" {
		return fmt.Errorf("%w: ALPN = %q", ErrChallengeWrongALPN, state.NegotiatedProtocol)
	}
	if len(state.PeerCertificates) == 0 {
		return ErrChallengeNoCert
	}
	cert := state.PeerCertificates[0]

	wantValue := TLSALPN01ExtensionValue(expected)
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(IDPEAcmeIdentifierOID) {
			continue
		}
		// RFC 8737: the extension value is an ASN.1 OCTET STRING
		// wrapping the 32-byte SHA-256 hash.
		var raw []byte
		if _, err := asn1.Unmarshal(ext.Value, &raw); err != nil {
			return fmt.Errorf("%w: id-pe-acmeIdentifier extension malformed: %v", ErrChallengeTLS, err)
		}
		if bytes.Equal(raw, wantValue) {
			return nil
		}
		return fmt.Errorf("%w: extension value did not match expected SHA-256(keyAuth)", ErrChallengeMismatch)
	}
	return ErrChallengeExtMissing
}
