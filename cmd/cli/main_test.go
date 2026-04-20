package main

import (
	"strings"
	"testing"
)

// TestValidateHTTPSScheme pins the pre-flight URL-scheme guard that the
// HTTPS-Everywhere milestone (v2.2, §3.2) requires on the certctl-cli binary
// startup path. The CLI's diagnostic is distinct from the agent and MCP server
// because it surfaces the --server flag alongside CERTCTL_SERVER_URL — so the
// empty-URL case pins that flag-name substring separately. Every other case
// mirrors the dispatch arms in cmd/cli/main.go:validateHTTPSScheme; drifting
// the substrings is what this test is here to catch.
func TestValidateHTTPSScheme(t *testing.T) {
	tests := []struct {
		name       string
		serverURL  string
		wantErr    bool
		wantErrSub string // substring that MUST appear in the error message
	}{
		{
			name:      "https URL passes",
			serverURL: "https://certctl-server:8443",
			wantErr:   false,
		},
		{
			name:      "https URL with path passes",
			serverURL: "https://certctl.example.com/api/v1",
			wantErr:   false,
		},
		{
			name:      "uppercase HTTPS scheme passes (url.Parse lowercases)",
			serverURL: "HTTPS://certctl-server:8443",
			wantErr:   false,
		},
		{
			name:       "empty URL rejected mentions --server flag",
			serverURL:  "",
			wantErr:    true,
			wantErrSub: "--server",
		},
		{
			name:       "empty URL rejected also mentions CERTCTL_SERVER_URL",
			serverURL:  "",
			wantErr:    true,
			wantErrSub: "CERTCTL_SERVER_URL",
		},
		{
			name:       "plaintext http rejected",
			serverURL:  "http://certctl-server:8443",
			wantErr:    true,
			wantErrSub: "plaintext http://",
		},
		{
			name:       "bare host missing scheme rejected",
			serverURL:  "localhost:8443",
			wantErr:    true,
			// url.Parse treats "localhost:8443" as scheme=localhost, opaque=8443
			// — exercises the default arm (unsupported scheme) rather than the
			// empty-scheme arm. Both are fail-closed, which is what we care about.
			wantErrSub: "unsupported scheme",
		},
		{
			name:       "path-only URL rejected",
			serverURL:  "//certctl-server:8443",
			wantErr:    true,
			wantErrSub: "missing a scheme",
		},
		{
			name:       "unsupported scheme rejected",
			serverURL:  "ftp://certctl-server:8443",
			wantErr:    true,
			wantErrSub: "unsupported scheme",
		},
		{
			name:       "ws scheme rejected",
			serverURL:  "ws://certctl-server:8443",
			wantErr:    true,
			wantErrSub: "unsupported scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHTTPSScheme(tt.serverURL)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateHTTPSScheme(%q) err=%v wantErr=%v", tt.serverURL, err, tt.wantErr)
			}
			if tt.wantErr && tt.wantErrSub != "" && !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Errorf("validateHTTPSScheme(%q) err=%q must contain %q so operators see the right diagnostic",
					tt.serverURL, err.Error(), tt.wantErrSub)
			}
		})
	}
}
