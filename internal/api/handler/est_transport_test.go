package handler

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
)

// TestVerifyESTTransport_Bundle4_M021 covers the EST transport precondition
// added in Bundle-4 / M-021. See verifyESTTransport doc comment in est.go for
// scope rationale (RFC 7030 §3.2.3 channel binding is moot without EST mTLS;
// what we DO enforce is TLS pre-conditions).
func TestVerifyESTTransport_Bundle4_M021(t *testing.T) {
	cases := []struct {
		name        string
		req         *http.Request
		wantErr     bool
		errContains string
	}{
		{
			name:        "plaintext_request_rejected",
			req:         &http.Request{TLS: nil},
			wantErr:     true,
			errContains: "plaintext",
		},
		{
			name: "incomplete_handshake_rejected",
			req: &http.Request{TLS: &tls.ConnectionState{
				HandshakeComplete: false,
				Version:           tls.VersionTLS13,
			}},
			wantErr:     true,
			errContains: "handshake",
		},
		{
			name: "tls10_rejected",
			req: &http.Request{TLS: &tls.ConnectionState{
				HandshakeComplete: true,
				Version:           tls.VersionTLS10,
			}},
			wantErr:     true,
			errContains: "TLS 1.2 minimum",
		},
		{
			name: "tls12_accepted",
			req: &http.Request{TLS: &tls.ConnectionState{
				HandshakeComplete: true,
				Version:           tls.VersionTLS12,
			}},
			wantErr: false,
		},
		{
			name: "tls13_accepted",
			req: &http.Request{TLS: &tls.ConnectionState{
				HandshakeComplete: true,
				Version:           tls.VersionTLS13,
			}},
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyESTTransport(tc.req)
			if tc.wantErr && err == nil {
				t.Fatalf("verifyESTTransport(%s): expected error, got nil", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("verifyESTTransport(%s): unexpected error: %v", tc.name, err)
			}
			if tc.wantErr && tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
				t.Fatalf("verifyESTTransport(%s): error %q missing substring %q", tc.name, err.Error(), tc.errContains)
			}
		})
	}
}
