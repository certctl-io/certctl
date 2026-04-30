package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/shankar0123/certctl/internal/cli"
)

func main() {
	// Parse global flags
	fs := flag.NewFlagSet("certctl-cli", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `certctl-cli — CLI for certificate lifecycle management

Usage:
  certctl-cli [global flags] <command> [command flags]

Global flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Commands:
  certs list       List certificates
  certs get ID     Get certificate details
  certs renew ID   Trigger certificate renewal
  certs revoke ID  Revoke a certificate

  agents list              List agents (add --retired to list soft-retired agents)
  agents get ID            Get agent details
  agents retire ID         Soft-retire an agent (add --force --reason "…" to cascade)

  jobs list        List jobs
  jobs get ID      Get job details
  jobs cancel ID   Cancel a pending job

  import FILE      Bulk import certificates from PEM file(s)
                   Required: --owner-id, --team-id, --renewal-policy-id, --issuer-id
                   Optional: --name-template (default {cn}), --environment (default imported)

  est cacerts      --profile <p>                 EST GET cacerts (RFC 7030 §4.1)
  est csrattrs     --profile <p>                 EST GET csrattrs (RFC 7030 §4.5)
  est enroll       --profile <p> --csr <path>    EST POST simpleenroll (RFC 7030 §4.2)
  est reenroll     --profile <p> --csr <path>    EST POST simplereenroll (RFC 7030 §4.2.2)
  est serverkeygen --profile <p> --csr <path> --out <prefix>
                                                 EST POST serverkeygen (RFC 7030 §4.4)
  est test         --profile <p>                 Smoke-test cacerts + csrattrs

  status           Show server health + summary stats
  version          Show CLI version

Examples:
  certctl-cli --server https://localhost:8443 --api-key mykey certs list
  certctl-cli certs renew mc-prod --format json
  certctl-cli import certs.pem
`)
	}

	// HTTPS-Everywhere (v2.2): the server is HTTPS-only. The default URL uses
	// https://; plaintext http:// is rejected by validateHTTPSScheme below.
	defaultServer := os.Getenv("CERTCTL_SERVER_URL")
	if defaultServer == "" {
		defaultServer = "https://localhost:8443"
	}
	serverURL := fs.String("server", defaultServer, "certctl server URL — must be https:// (env: CERTCTL_SERVER_URL)")

	apiKey := fs.String("api-key", os.Getenv("CERTCTL_API_KEY"), "API key for authentication (env: CERTCTL_API_KEY)")
	format := fs.String("format", "table", "Output format: table, json")
	caBundlePath := fs.String("ca-bundle", os.Getenv("CERTCTL_SERVER_CA_BUNDLE_PATH"), "Path to a PEM-encoded CA bundle that signed the server cert (env: CERTCTL_SERVER_CA_BUNDLE_PATH)")
	insecure := fs.Bool("insecure", strings.EqualFold(os.Getenv("CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY"), "true"), "Skip TLS certificate verification — dev only, never set in production (env: CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY)")

	fs.Parse(os.Args[1:])

	if err := validateHTTPSScheme(*serverURL); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nThe certctl control plane is HTTPS-only as of v2.2.\n")
		fmt.Fprintf(os.Stderr, "See docs/upgrade-to-tls.md for the cutover walkthrough.\n")
		os.Exit(1)
	}

	args := fs.Args()
	if len(args) == 0 {
		fs.Usage()
		os.Exit(1)
	}

	// Create client
	client, err := cli.NewClient(*serverURL, *apiKey, *format, *caBundlePath, *insecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Dispatch to appropriate command
	command := args[0]
	cmdArgs := args[1:]

	switch command {
	case "certs":
		err = handleCerts(client, cmdArgs)
	case "agents":
		err = handleAgents(client, cmdArgs)
	case "jobs":
		err = handleJobs(client, cmdArgs)
	case "import":
		err = handleImport(client, cmdArgs)
	case "est":
		err = handleEST(client, cmdArgs)
	case "status":
		err = handleStatus(client)
	case "version":
		fmt.Println("certctl-cli version 0.1.0")
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", command)
		fs.Usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func handleCerts(client *cli.Client, args []string) error {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: certs <list|get|renew|revoke> [options]\n")
		return nil
	}

	subcommand := args[0]
	subArgs := args[1:]

	switch subcommand {
	case "list":
		return client.ListCertificates(subArgs)
	case "get":
		if len(subArgs) == 0 {
			fmt.Fprintf(os.Stderr, "usage: certs get <id>\n")
			return nil
		}
		return client.GetCertificate(subArgs[0])
	case "renew":
		if len(subArgs) == 0 {
			fmt.Fprintf(os.Stderr, "usage: certs renew <id>\n")
			return nil
		}
		return client.RenewCertificate(subArgs[0])
	case "revoke":
		if len(subArgs) == 0 {
			fmt.Fprintf(os.Stderr, "usage: certs revoke <id> [--reason <reason>]\n")
			return nil
		}
		id := subArgs[0]
		reason := "unspecified"
		if len(subArgs) > 2 && subArgs[1] == "--reason" {
			reason = subArgs[2]
		}
		return client.RevokeCertificate(id, reason)
	case "bulk-revoke":
		return client.BulkRevokeCertificates(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: certs %s\n", subcommand)
		return nil
	}
}

// handleAgents dispatches the `agents` subcommands.
//
// I-004 additions:
//
//	agents list --retired      — hit the opt-in /agents/retired endpoint
//	                             instead of the default listing (which
//	                             filters retired rows out).
//	agents retire <id>         — soft-retire an agent (DELETE /agents/{id}).
//	                             --force cascades; --reason is required with
//	                             --force (mirrors ErrForceReasonRequired).
func handleAgents(client *cli.Client, args []string) error {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: agents <list|get|retire> [options]\n")
		return nil
	}

	subcommand := args[0]
	subArgs := args[1:]

	switch subcommand {
	case "list":
		// --retired flag splits to a separate endpoint. We intercept it
		// client-side and strip it before delegating, so both code paths
		// share the --page/--per-page flag parsing inside the client.
		retired := false
		rest := make([]string, 0, len(subArgs))
		for _, a := range subArgs {
			if a == "--retired" {
				retired = true
				continue
			}
			rest = append(rest, a)
		}
		if retired {
			return client.ListRetiredAgents(rest)
		}
		return client.ListAgents(rest)
	case "get":
		if len(subArgs) == 0 {
			fmt.Fprintf(os.Stderr, "usage: agents get <id>\n")
			return nil
		}
		return client.GetAgent(subArgs[0])
	case "retire":
		if len(subArgs) == 0 {
			fmt.Fprintf(os.Stderr, "usage: agents retire <id> [--force] [--reason <reason>]\n")
			return nil
		}
		return client.RetireAgent(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: agents %s\n", subcommand)
		return nil
	}
}

func handleJobs(client *cli.Client, args []string) error {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: jobs <list|get|cancel> [options]\n")
		return nil
	}

	subcommand := args[0]
	subArgs := args[1:]

	switch subcommand {
	case "list":
		return client.ListJobs(subArgs)
	case "get":
		if len(subArgs) == 0 {
			fmt.Fprintf(os.Stderr, "usage: jobs get <id>\n")
			return nil
		}
		return client.GetJob(subArgs[0])
	case "cancel":
		if len(subArgs) == 0 {
			fmt.Fprintf(os.Stderr, "usage: jobs cancel <id>\n")
			return nil
		}
		return client.CancelJob(subArgs[0])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: jobs %s\n", subcommand)
		return nil
	}
}

func handleImport(client *cli.Client, args []string) error {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: import <file> [file2 ...]\n")
		return nil
	}
	return client.ImportCertificates(args)
}

func handleStatus(client *cli.Client) error {
	return client.GetStatus()
}

// handleEST dispatches the `est` subcommands. Mirrors the existing
// handleCerts / handleAgents pattern verbatim. EST RFC 7030 hardening
// master bundle Phase 9.1.
func handleEST(client *cli.Client, args []string) error {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: est <cacerts|csrattrs|enroll|reenroll|serverkeygen|test> [options]\n")
		return nil
	}
	subcommand := args[0]
	subArgs := args[1:]
	switch subcommand {
	case "cacerts":
		return client.EstCacerts(subArgs)
	case "csrattrs":
		return client.EstCsrattrs(subArgs)
	case "enroll":
		return client.EstEnroll(subArgs)
	case "reenroll":
		return client.EstReEnroll(subArgs)
	case "serverkeygen":
		return client.EstServerKeygen(subArgs)
	case "test":
		return client.EstTest(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: est %s\n", subcommand)
		return nil
	}
}

// validateHTTPSScheme rejects plaintext and empty-scheme server URLs at
// startup so operators get a fail-loud diagnostic before any network call,
// not a TCP-refused or TLS-handshake-error downstream. See docs/upgrade-to-tls.md.
func validateHTTPSScheme(serverURL string) error {
	if serverURL == "" {
		return fmt.Errorf("server URL is empty — set --server (or CERTCTL_SERVER_URL) to an https:// URL (e.g., https://certctl-server:8443)")
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
