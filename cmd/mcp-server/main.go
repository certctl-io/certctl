package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/certctl-io/certctl/internal/mcp"
)

// Version is set at build time via -ldflags.
var Version = "dev"

func main() {
	// HTTPS-Everywhere (v2.2): the server is HTTPS-only. The default URL
	// uses https://; plaintext http:// is rejected by validateHTTPSScheme
	// below with a fail-loud pre-flight diagnostic pointing at
	// docs/upgrade-to-tls.md, so operators never get a TCP-refused or
	// TLS-handshake-error downstream. See docs/tls.md for CA bundle and
	// insecure-skip-verify guidance.
	serverURL := os.Getenv("CERTCTL_SERVER_URL")
	if serverURL == "" {
		serverURL = "https://localhost:8443"
	}

	if err := validateHTTPSScheme(serverURL); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nThe certctl control plane is HTTPS-only as of v2.2.\n")
		fmt.Fprintf(os.Stderr, "See docs/upgrade-to-tls.md for the cutover walkthrough.\n")
		os.Exit(1)
	}

	apiKey := os.Getenv("CERTCTL_API_KEY")
	caBundlePath := os.Getenv("CERTCTL_SERVER_CA_BUNDLE_PATH")
	insecure := strings.EqualFold(os.Getenv("CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY"), "true")

	client, err := mcp.NewClient(serverURL, apiKey, caBundlePath, insecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	server := gomcp.NewServer(&gomcp.Implementation{
		Name:    "certctl",
		Version: Version,
	}, nil)

	mcp.RegisterTools(server, client)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Fprintf(os.Stderr, "certctl MCP server %s (backend: %s)\n", Version, serverURL)

	if err := server.Run(ctx, &gomcp.StdioTransport{}); err != nil {
		log.Fatalf("MCP server error: %v", err)
	}
}

// validateHTTPSScheme rejects plaintext and empty-scheme server URLs at
// startup so operators get a fail-loud diagnostic before any network call,
// not a TCP-refused or TLS-handshake-error downstream. See docs/upgrade-to-tls.md.
func validateHTTPSScheme(serverURL string) error {
	if serverURL == "" {
		return fmt.Errorf("server URL is empty — set CERTCTL_SERVER_URL to an https:// URL (e.g., https://certctl-server:8443)")
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("server URL %q is not a valid URL: %w", serverURL, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		return fmt.Errorf("server URL %q uses plaintext http:// — the certctl control plane is HTTPS-only", serverURL)
	case "":
		return fmt.Errorf("server URL %q is missing a scheme — expected https://", serverURL)
	default:
		return fmt.Errorf("server URL %q uses unsupported scheme %q — expected https://", serverURL, u.Scheme)
	}
}
