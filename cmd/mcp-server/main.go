package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shankar0123/certctl/internal/mcp"
)

// Version is set at build time via -ldflags.
var Version = "dev"

func main() {
	serverURL := os.Getenv("CERTCTL_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:8443"
	}

	apiKey := os.Getenv("CERTCTL_API_KEY")

	client := mcp.NewClient(serverURL, apiKey)

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
