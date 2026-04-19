package main

import (
	"flag"
	"fmt"
	"os"

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

  status           Show server health + summary stats
  version          Show CLI version

Examples:
  certctl-cli --server http://localhost:8443 --api-key mykey certs list
  certctl-cli certs renew mc-prod --format json
  certctl-cli import certs.pem
`)
	}

	serverURL := fs.String("server", os.Getenv("CERTCTL_SERVER_URL"), "certctl server URL (env: CERTCTL_SERVER_URL)")
	if *serverURL == "" {
		*serverURL = "http://localhost:8443"
	}

	apiKey := fs.String("api-key", os.Getenv("CERTCTL_API_KEY"), "API key for authentication (env: CERTCTL_API_KEY)")
	format := fs.String("format", "table", "Output format: table, json")

	fs.Parse(os.Args[1:])

	args := fs.Args()
	if len(args) == 0 {
		fs.Usage()
		os.Exit(1)
	}

	// Create client
	client := cli.NewClient(*serverURL, *apiKey, *format)

	// Dispatch to appropriate command
	command := args[0]
	cmdArgs := args[1:]

	var err error
	switch command {
	case "certs":
		err = handleCerts(client, cmdArgs)
	case "agents":
		err = handleAgents(client, cmdArgs)
	case "jobs":
		err = handleJobs(client, cmdArgs)
	case "import":
		err = handleImport(client, cmdArgs)
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
