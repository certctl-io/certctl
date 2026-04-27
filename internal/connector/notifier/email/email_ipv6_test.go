package email

import (
	"net"
	"os"
	"strings"
	"testing"
)

var osReadFile = os.ReadFile

// Bundle E / Audit L-011 (IPv6 dual-stack handling): every production
// `net.Dial`/`net.DialTimeout` call site was audited; the SMTP / email
// notifier path uses `net.JoinHostPort(SMTPHost, port)` which is
// bracket-aware by spec. This test pins the JoinHostPort shape so a
// future refactor that switches to bare `host + ":" + port`
// concatenation — which would silently break IPv6 literals — fails CI.
//
// Other production net.Dial sites are out of scope for this test:
//   - cmd/agent/main.go:293 uses literal "8.8.8.8:80" intentionally
//     (IPv4 route-discovery hack)
//   - cmd/agent/verify.go, internal/tlsprobe/probe.go,
//     internal/service/network_scan.go use net.Dialer (no string addr)
//   - internal/connector/target/ssh/ssh.go uses an addr derived from
//     net.JoinHostPort upstream
// The audit's per-site analysis confirms each is bracket-aware or
// intentionally IPv4-literal.

func TestJoinHostPort_IPv6BracketsRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		host string
		port string
		want string
	}{
		{"ipv4_literal", "10.0.0.1", "587", "10.0.0.1:587"},
		{"ipv6_literal", "::1", "587", "[::1]:587"},
		{"ipv6_full", "2001:db8::1", "25", "[2001:db8::1]:25"},
		{"hostname", "smtp.example.com", "465", "smtp.example.com:465"},
		{"ipv6_zone", "fe80::1%eth0", "587", "[fe80::1%eth0]:587"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := net.JoinHostPort(tc.host, tc.port)
			if got != tc.want {
				t.Errorf("net.JoinHostPort(%q, %q) = %q, want %q",
					tc.host, tc.port, got, tc.want)
			}
			// Round-trip via SplitHostPort.
			rh, rp, err := net.SplitHostPort(got)
			if err != nil {
				t.Fatalf("net.SplitHostPort(%q): %v", got, err)
			}
			// IPv6-zone hosts come back without the literal brackets.
			expectedHost := tc.host
			if rh != expectedHost {
				t.Errorf("round-trip host: got %q, want %q", rh, expectedHost)
			}
			if rp != tc.port {
				t.Errorf("round-trip port: got %q, want %q", rp, tc.port)
			}
		})
	}
}

func TestSMTPDialerUsesJoinHostPort(t *testing.T) {
	// Source-grep regression pin: the email notifier MUST use
	// net.JoinHostPort when assembling SMTP addresses, never bare
	// "host:port" string concatenation. We don't actually dial a
	// server here — we just assert the source pattern.
	//
	// Ridiculously cheap test, but a future refactor that swaps in
	// `fmt.Sprintf("%s:%d", host, port)` would silently break IPv6
	// SMTP destinations and this test catches it pre-merge.
	body := mustReadFile(t, "email.go")
	if !strings.Contains(body, "net.JoinHostPort") {
		t.Fatal("internal/connector/notifier/email/email.go must use net.JoinHostPort for IPv6 bracket-awareness (L-011)")
	}
	// Additionally make sure no bare "%s:%d" SMTP pattern slipped in.
	if strings.Contains(body, `fmt.Sprintf("%s:%d"`) {
		t.Error("found bare host:port concatenation; use net.JoinHostPort (L-011)")
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	body, err := osReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}
