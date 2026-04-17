package validation

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// IsReservedIP reports whether the given IP falls inside a range that
// outbound HTTP egress (and the network-scanner CIDR expander) MUST treat
// as unreachable: loopback, link-local (including cloud-provider metadata
// endpoints at 169.254.169.254), multicast, and broadcast.
//
// RFC 1918 ranges (10/8, 172.16/12, 192.168/16) are intentionally NOT
// treated as reserved. certctl is designed to manage certificates inside
// private networks and filtering private address space would break the
// primary use case. The threat model here is outbound HTTP to
// cloud-metadata or localhost services, not general network reachability.
//
// This function is byte-identical in behaviour to the previous unexported
// copy in internal/service/network_scan.go. It is exported here so both
// the network scanner and the webhook notifier share a single
// authoritative implementation. Broader IPv6 coverage and unspecified-
// address handling live in SafeHTTPDialContext, where stricter policy is
// appropriate for outbound HTTP egress.
func IsReservedIP(ip net.IP) bool {
	// Loopback: 127.0.0.0/8 (and ::1 via IsLoopback).
	if ip.IsLoopback() {
		return true
	}

	// Link-local: 169.254.0.0/16 (includes cloud metadata 169.254.169.254).
	if linkLocal := net.ParseIP("169.254.0.0"); linkLocal != nil {
		if _, linkLocalNet, _ := net.ParseCIDR("169.254.0.0/16"); linkLocalNet != nil {
			if linkLocalNet.Contains(ip) {
				return true
			}
		}
	}

	// Multicast: 224.0.0.0/4.
	if multicast := net.ParseIP("224.0.0.0"); multicast != nil {
		if _, multicastNet, _ := net.ParseCIDR("224.0.0.0/4"); multicastNet != nil {
			if multicastNet.Contains(ip) {
				return true
			}
		}
	}

	// Broadcast: 255.255.255.255.
	if ip.String() == "255.255.255.255" {
		return true
	}

	return false
}

// isReservedIPForDial applies IsReservedIP plus additional ranges that are
// meaningful for outbound HTTP egress but were not part of the original
// network-scanner filter: the unspecified address (0.0.0.0 / ::) and IPv6
// link-local / multicast ranges. Kept private so IsReservedIP stays
// byte-identical with the previous scanner behaviour.
func isReservedIPForDial(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if IsReservedIP(ip) {
		return true
	}
	if ip.IsUnspecified() {
		return true
	}
	// IPv6 link-local fe80::/10.
	if _, n, err := net.ParseCIDR("fe80::/10"); err == nil && n.Contains(ip) {
		return true
	}
	// IPv6 multicast ff00::/8.
	if _, n, err := net.ParseCIDR("ff00::/8"); err == nil && n.Contains(ip) {
		return true
	}
	return false
}

// ValidateSafeURL parses rawURL and rejects anything that would let an
// attacker aim an outbound HTTP client at a SSRF-sensitive destination
// (CWE-918). Guards enforced:
//
//  1. The scheme must be http or https. Schemes like file://, gopher://,
//     ftp://, data:, javascript:, ldap://, and dict:// are rejected outright;
//     webhook delivery only speaks HTTP(S).
//  2. A hostname must be present. Empty-host URLs like "http:///foo" are
//     rejected to prevent ambiguous defaulting.
//  3. If the host is a literal IP address, the IP must not be reserved
//     (see isReservedIPForDial). This stops the obvious 127.0.0.1 / ::1 /
//     169.254.169.254 / 0.0.0.0 attacks at config time.
//  4. If the host is a DNS name and resolution succeeds, every resolved
//     A/AAAA record must be non-reserved. A single reserved result is
//     enough to reject. Resolution failure is tolerated (offline CI
//     environments, short-lived test servers) — the authoritative
//     enforcement runs at dial time anyway.
//
// The DNS resolution check here is a best-effort early diagnostic. The
// authoritative, TOCTOU-safe enforcement is SafeHTTPDialContext, which
// re-checks after resolution at dial time and defeats DNS rebinding.
// Callers that need SSRF-safe HTTP egress should use BOTH
// ValidateSafeURL (at config ingestion) AND SafeHTTPDialContext
// (installed on http.Transport).
func ValidateSafeURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("url is required")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("url scheme %q is not allowed; only http and https are permitted", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("url must include a host")
	}

	// Literal IP? Reject if reserved (strict policy for outbound egress).
	if ip := net.ParseIP(host); ip != nil {
		if isReservedIPForDial(ip) {
			return fmt.Errorf("url host resolves to a reserved address and cannot be used")
		}
		return nil
	}

	// DNS name. Resolve and reject if any answer is reserved.
	ips, err := net.LookupIP(host)
	if err != nil {
		// Resolution failure is not itself a SSRF signal; let the dial-time
		// DialContext handle the final decision. This keeps the validator
		// tolerant of offline validation environments (CI, tests) while
		// still blocking clearly-bad literal-IP URLs above.
		return nil
	}
	for _, ip := range ips {
		if isReservedIPForDial(ip) {
			return fmt.Errorf("url host resolves to a reserved address and cannot be used")
		}
	}

	return nil
}

// SafeHTTPDialContext returns a DialContext function suitable for
// installing on an http.Transport. Every dial attempt resolves the host
// again and rejects any connection whose resolved IP lies inside a
// reserved range. This is the authoritative SSRF / DNS-rebinding guard:
// even if ValidateSafeURL was bypassed, or if DNS changed between
// validation and dial, the outbound connection will fail closed.
//
// The timeout argument bounds both the resolution and the underlying TCP
// dial. Pass 0 to use a sensible default (10s).
func SafeHTTPDialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid dial address %q: %w", addr, err)
		}

		// If the host is already a literal IP, check it directly.
		if ip := net.ParseIP(host); ip != nil {
			if isReservedIPForDial(ip) {
				return nil, fmt.Errorf("refusing to dial reserved address %s", ip.String())
			}
			return dialer.DialContext(ctx, network, addr)
		}

		// Resolve and reject any answer that lands in a reserved range.
		// We then dial an explicit resolved IP so a racing DNS change
		// cannot substitute a different (and possibly reserved) answer
		// between our check and the actual TCP dial.
		resCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		ips, err := (&net.Resolver{}).LookupIP(resCtx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses found for %s", host)
		}
		for _, ip := range ips {
			if isReservedIPForDial(ip) {
				return nil, fmt.Errorf("refusing to dial %s: resolves to reserved address %s", host, ip.String())
			}
		}

		// Dial the first non-reserved resolved IP directly, pinning the
		// target so later DNS changes cannot redirect us.
		pinned := net.JoinHostPort(ips[0].String(), port)
		return dialer.DialContext(ctx, network, pinned)
	}
}
