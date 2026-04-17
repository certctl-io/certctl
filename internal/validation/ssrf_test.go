package validation

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestIsReservedIP_ByteIdenticalWithNetworkScannerBehavior(t *testing.T) {
	// These expectations MUST NOT drift from the original unexported
	// isReservedIP in internal/service/network_scan.go. Any deviation here
	// is a behaviour change in the network scanner and requires a separate,
	// deliberate migration.
	cases := []struct {
		name     string
		ip       string
		reserved bool
	}{
		{"loopback v4", "127.0.0.1", true},
		{"loopback v4 range upper", "127.255.255.254", true},
		{"loopback v6", "::1", true},
		{"AWS metadata", "169.254.169.254", true},
		{"link-local range edge", "169.254.0.0", true},
		{"multicast 224", "224.0.0.1", true},
		{"multicast upper", "239.255.255.255", true},
		{"broadcast", "255.255.255.255", true},
		// The original network-scanner filter does NOT include unspecified
		// or IPv6 link-local, so these must remain non-reserved at this
		// layer. Stricter outbound-dial policy lives in SafeHTTPDialContext.
		{"unspecified v4", "0.0.0.0", false},
		{"IPv6 link-local", "fe80::1", false},
		{"IPv6 multicast", "ff00::1", false},
		// RFC 1918 is intentionally allowed (self-hosted design).
		{"RFC 1918 10/8", "10.0.0.1", false},
		{"RFC 1918 172.16/12", "172.16.0.1", false},
		{"RFC 1918 192.168/16", "192.168.1.1", false},
		// Ordinary public addresses pass.
		{"public v4", "8.8.8.8", false},
		{"public v6", "2606:4700:4700::1111", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("test setup: failed to parse %q", tc.ip)
			}
			if got := IsReservedIP(ip); got != tc.reserved {
				t.Errorf("IsReservedIP(%s)=%v, want %v", tc.ip, got, tc.reserved)
			}
		})
	}
}

func TestValidateSafeURL_AcceptsSafePublicURLs(t *testing.T) {
	cases := []string{
		"https://example.com/webhook",
		"http://example.com/hook",
		"https://example.com:8443/hook",
		"https://webhook.site/abc-123",
		"http://10.0.0.5/internal",         // RFC 1918 allowed
		"http://192.168.1.10:8080/webhook", // RFC 1918 allowed
		"http://172.16.5.1/intranet",       // RFC 1918 allowed
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if err := ValidateSafeURL(raw); err != nil {
				t.Errorf("ValidateSafeURL(%q) unexpectedly failed: %v", raw, err)
			}
		})
	}
}

func TestValidateSafeURL_RejectsReservedLiteralIPs(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"loopback v4", "http://127.0.0.1/x"},
		{"loopback v4 with port", "http://127.0.0.1:8080/"},
		{"loopback v6 bracketed", "http://[::1]/x"},
		{"AWS metadata endpoint", "http://169.254.169.254/latest/meta-data/"},
		{"link-local IP", "http://169.254.1.2/"},
		{"broadcast", "http://255.255.255.255/"},
		{"multicast", "https://224.0.0.5/"},
		{"unspecified v4", "http://0.0.0.0/"},
		{"unspecified v6", "http://[::]/"},
		{"IPv6 link-local", "http://[fe80::1]/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSafeURL(tc.url)
			if err == nil {
				t.Fatalf("ValidateSafeURL(%q) returned nil, want error", tc.url)
			}
			if !strings.Contains(err.Error(), "reserved") {
				t.Errorf("error should mention 'reserved' for operator diagnostics, got %q", err.Error())
			}
		})
	}
}

func TestValidateSafeURL_RejectsDangerousSchemes(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"file scheme", "file:///etc/passwd"},
		{"gopher scheme", "gopher://example.com/"},
		{"ftp scheme", "ftp://example.com/"},
		{"javascript scheme", "javascript:alert(1)"},
		{"data scheme", "data:text/plain;base64,SGVsbG8="},
		{"ldap scheme", "ldap://example.com/"},
		{"dict scheme", "dict://example.com:2628/d:foo"},
		{"jar scheme", "jar:http://example.com/foo.jar!/"},
		{"empty scheme", "example.com/hook"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSafeURL(tc.url)
			if err == nil {
				t.Fatalf("ValidateSafeURL(%q) returned nil, want error", tc.url)
			}
			if !strings.Contains(err.Error(), "scheme") && !strings.Contains(err.Error(), "host") {
				t.Errorf("error should mention scheme or host, got %q", err.Error())
			}
		})
	}
}

func TestValidateSafeURL_RejectsMissingHost(t *testing.T) {
	cases := []string{
		"http:///foo",
		"https://",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			err := ValidateSafeURL(raw)
			if err == nil {
				t.Fatalf("ValidateSafeURL(%q) returned nil, want error", raw)
			}
		})
	}
}

func TestValidateSafeURL_RejectsEmpty(t *testing.T) {
	if err := ValidateSafeURL(""); err == nil {
		t.Fatal("ValidateSafeURL(\"\") returned nil, want error")
	}
}

func TestValidateSafeURL_RejectsMalformed(t *testing.T) {
	// url.Parse is famously lax; we lean on the scheme/host checks to catch
	// malformed inputs that produce empty schemes or hosts.
	cases := []string{
		"://missing-scheme",
		"http//missing-colon.example.com",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			err := ValidateSafeURL(raw)
			if err == nil {
				t.Fatalf("ValidateSafeURL(%q) returned nil, want error", raw)
			}
		})
	}
}

func TestSafeHTTPDialContext_RejectsLiteralReservedAddress(t *testing.T) {
	dial := SafeHTTPDialContext(2 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cases := []string{
		"127.0.0.1:9",
		"169.254.169.254:80",
		"[::1]:22",
		"0.0.0.0:80",
	}
	for _, addr := range cases {
		t.Run(addr, func(t *testing.T) {
			conn, err := dial(ctx, "tcp", addr)
			if err == nil {
				_ = conn.Close()
				t.Fatalf("dial(%q) returned nil err, want reserved-address rejection", addr)
			}
			if !strings.Contains(err.Error(), "reserved") {
				t.Errorf("expected reserved-address rejection, got %q", err.Error())
			}
		})
	}
}

func TestSafeHTTPDialContext_RejectsHostResolvingToReservedAddress(t *testing.T) {
	// The stdlib resolver treats "localhost" as 127.0.0.1 / ::1 on every
	// platform we care about; this exercises the post-resolution check and
	// demonstrates that DNS-rebinding attacks (where a name points at a
	// reserved IP) are rejected at dial time rather than at validation time.
	dial := SafeHTTPDialContext(2 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dial(ctx, "tcp", "localhost:9")
	if err == nil {
		_ = conn.Close()
		t.Fatal("dial(localhost:9) returned nil err, want reserved-address rejection")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Errorf("expected reserved-address rejection for localhost, got %q", err.Error())
	}
}

func TestSafeHTTPDialContext_InvalidAddress(t *testing.T) {
	dial := SafeHTTPDialContext(1 * time.Second)
	_, err := dial(context.Background(), "tcp", "no-port")
	if err == nil {
		t.Fatal("expected error for invalid dial address, got nil")
	}
}

func TestSafeHTTPDialContext_DefaultTimeoutWhenZero(t *testing.T) {
	// Not directly observable, but we at least exercise the branch to
	// prevent a nil-ptr regression if the timeout default is dropped.
	dial := SafeHTTPDialContext(0)
	_, err := dial(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected reserved-address rejection")
	}
}
