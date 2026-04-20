package cli

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"
)

// Client is the CLI HTTP client that communicates with the certctl server.
type Client struct {
	baseURL    string
	apiKey     string
	format     string
	httpClient *http.Client
}

// NewClient creates a new CLI client.
//
// HTTPS-Everywhere (v2.2): the certctl control plane is HTTPS-only. caBundlePath,
// when non-empty, points at a PEM bundle used to verify the server cert; otherwise
// the system trust store is used. insecure skips cert verification — dev only,
// never enable in production. The TLS config is attached to *http.Transport so
// every call goes through the same verified socket.
func NewClient(baseURL, apiKey, format, caBundlePath string, insecure bool) (*Client, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: insecure, //nolint:gosec // opt-in dev toggle, documented in docs/tls.md
	}
	if caBundlePath != "" {
		pemBytes, err := os.ReadFile(caBundlePath)
		if err != nil {
			return nil, fmt.Errorf("reading CA bundle at %q: %w", caBundlePath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("CA bundle at %q contains no valid PEM-encoded certificates", caBundlePath)
		}
		tlsConfig.RootCAs = pool
	}
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		format:  format,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:       tlsConfig,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          10,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
	}, nil
}

// do performs an HTTP request and returns the parsed JSON response.
func (c *Client) do(method, path string, query url.Values, body interface{}) (json.RawMessage, error) {
	u, err := url.JoinPath(c.baseURL, path)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if query != nil && len(query) > 0 {
		u = u + "?" + query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, u, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	// 204 No Content — return empty JSON object
	if resp.StatusCode == 204 {
		return json.RawMessage(`{"status":"deleted"}`), nil
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return json.RawMessage(respBody), nil
}

// ListCertificates lists all managed certificates with optional filters.
func (c *Client) ListCertificates(args []string) error {
	fs := flag.NewFlagSet("certs list", flag.ContinueOnError)
	status := fs.String("status", "", "Filter by status")
	page := fs.Int("page", 1, "Page number")
	perPage := fs.Int("per-page", 50, "Items per page")
	fs.Parse(args)

	query := url.Values{}
	if *status != "" {
		query.Set("status", *status)
	}
	query.Set("page", fmt.Sprintf("%d", *page))
	query.Set("per_page", fmt.Sprintf("%d", *perPage))

	resp, err := c.do("GET", "/api/v1/certificates", query, nil)
	if err != nil {
		return err
	}

	var result struct {
		Data  []map[string]interface{} `json:"data"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if c.format == "json" {
		return c.outputJSON(result)
	}

	return c.outputCertificatesTable(result.Data, result.Total)
}

// GetCertificate retrieves a single certificate by ID.
func (c *Client) GetCertificate(id string) error {
	resp, err := c.do("GET", fmt.Sprintf("/api/v1/certificates/%s", id), nil, nil)
	if err != nil {
		return err
	}

	var cert map[string]interface{}
	if err := json.Unmarshal(resp, &cert); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if c.format == "json" {
		return c.outputJSON(cert)
	}

	return c.outputCertificateDetail(cert)
}

// RenewCertificate triggers renewal for a certificate.
func (c *Client) RenewCertificate(id string) error {
	body := map[string]interface{}{
		"force": false,
	}

	resp, err := c.do("POST", fmt.Sprintf("/api/v1/certificates/%s/renew", id), nil, body)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if c.format == "json" {
		return c.outputJSON(result)
	}

	fmt.Printf("Renewal triggered for certificate %s\n", id)
	if jobID, ok := result["job_id"]; ok {
		fmt.Printf("Job ID: %v\n", jobID)
	}
	return nil
}

// RevokeCertificate revokes a certificate.
func (c *Client) RevokeCertificate(id, reason string) error {
	body := map[string]interface{}{
		"reason": reason,
	}

	resp, err := c.do("POST", fmt.Sprintf("/api/v1/certificates/%s/revoke", id), nil, body)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if c.format == "json" {
		return c.outputJSON(result)
	}

	fmt.Printf("Certificate %s revoked with reason: %s\n", id, reason)
	return nil
}

// BulkRevokeCertificates revokes certificates matching filter criteria.
func (c *Client) BulkRevokeCertificates(args []string) error {
	fs := flag.NewFlagSet("certs bulk-revoke", flag.ContinueOnError)
	reason := fs.String("reason", "unspecified", "RFC 5280 revocation reason")
	profileID := fs.String("profile-id", "", "Revoke certs matching this profile")
	ownerID := fs.String("owner-id", "", "Revoke certs owned by this owner")
	agentID := fs.String("agent-id", "", "Revoke certs deployed via this agent")
	issuerID := fs.String("issuer-id", "", "Revoke certs issued by this issuer")
	teamID := fs.String("team-id", "", "Revoke certs owned by team members")
	if err := fs.Parse(args); err != nil {
		return err
	}

	body := map[string]interface{}{
		"reason": *reason,
	}
	if *profileID != "" {
		body["profile_id"] = *profileID
	}
	if *ownerID != "" {
		body["owner_id"] = *ownerID
	}
	if *agentID != "" {
		body["agent_id"] = *agentID
	}
	if *issuerID != "" {
		body["issuer_id"] = *issuerID
	}
	if *teamID != "" {
		body["team_id"] = *teamID
	}

	// Remaining positional args are certificate IDs
	if fs.NArg() > 0 {
		body["certificate_ids"] = fs.Args()
	}

	resp, err := c.do("POST", "/api/v1/certificates/bulk-revoke", nil, body)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if c.format == "json" {
		return c.outputJSON(result)
	}

	fmt.Printf("Bulk revocation complete:\n")
	fmt.Printf("  Matched: %v\n", result["total_matched"])
	fmt.Printf("  Revoked: %v\n", result["total_revoked"])
	fmt.Printf("  Skipped: %v\n", result["total_skipped"])
	fmt.Printf("  Failed:  %v\n", result["total_failed"])
	return nil
}

// ListAgents lists all agents.
func (c *Client) ListAgents(args []string) error {
	fs := flag.NewFlagSet("agents list", flag.ContinueOnError)
	status := fs.String("status", "", "Filter by status")
	page := fs.Int("page", 1, "Page number")
	perPage := fs.Int("per-page", 50, "Items per page")
	fs.Parse(args)

	query := url.Values{}
	if *status != "" {
		query.Set("status", *status)
	}
	query.Set("page", fmt.Sprintf("%d", *page))
	query.Set("per_page", fmt.Sprintf("%d", *perPage))

	resp, err := c.do("GET", "/api/v1/agents", query, nil)
	if err != nil {
		return err
	}

	var result struct {
		Data  []map[string]interface{} `json:"data"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if c.format == "json" {
		return c.outputJSON(result)
	}

	return c.outputAgentsTable(result.Data, result.Total)
}

// ListRetiredAgents lists soft-retired agents from the dedicated endpoint.
//
// I-004: hits GET /api/v1/agents/retired which is a separate route from the
// default listing (the default hides retired rows). Supports --page and
// --per-page just like the active list. Output format mirrors ListAgents
// but prepends RETIRED_AT and RETIRED_REASON columns so the operator can
// forensic-grep the output.
func (c *Client) ListRetiredAgents(args []string) error {
	fs := flag.NewFlagSet("agents list --retired", flag.ContinueOnError)
	page := fs.Int("page", 1, "Page number")
	perPage := fs.Int("per-page", 50, "Items per page")
	fs.Parse(args)

	query := url.Values{}
	query.Set("page", fmt.Sprintf("%d", *page))
	query.Set("per_page", fmt.Sprintf("%d", *perPage))

	resp, err := c.do("GET", "/api/v1/agents/retired", query, nil)
	if err != nil {
		return err
	}

	var result struct {
		Data  []map[string]interface{} `json:"data"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if c.format == "json" {
		return c.outputJSON(result)
	}

	return c.outputRetiredAgentsTable(result.Data, result.Total)
}

// RetireAgent soft-retires an agent via DELETE /api/v1/agents/{id}.
//
// I-004: wraps the full status-code matrix pinned by the handler's
// agent_retire_handler_test.go:
//
//	200 clean retire — body: retired_at, already_retired=false, cascade=false, counts=0
//	200 force-cascade retire — body: cascade=true, counts=pre-cascade snapshot
//	204 idempotent retire — agent was already retired, NO body
//	403 sentinel — reserved agent (server-scanner / cloud-*), ErrAgentIsSentinel
//	404 not found — agent doesn't exist
//	409 blocked_by_dependencies — body: error, message, counts
//
// The default (force=false) flow refuses to retire agents with active
// downstream dependencies; the operator must re-run with --force and an
// explicit --reason to cascade. The handler rejects --force without
// --reason with a 400 — we mirror that contract client-side so the
// operator gets a clear error before the round trip.
func (c *Client) RetireAgent(args []string) error {
	// Convention: `agents retire <id> [--force] [--reason <reason>]` — the ID
	// is a positional arg that precedes the flags. Go's flag package stops
	// parsing at the first non-flag token, so we pull args[0] as the ID and
	// hand args[1:] to the flag parser. Without this split, `agents retire
	// ag-1 --force --reason "x"` would parse with force=false and reason=""
	// because the flags land in fs.Args() instead of being recognized.
	if len(args) == 0 {
		return fmt.Errorf("agent ID is required: agents retire <id> [--force] [--reason <reason>]")
	}
	id := args[0]

	fs := flag.NewFlagSet("agents retire", flag.ContinueOnError)
	force := fs.Bool("force", false, "Cascade-retire downstream targets, certs, and jobs")
	reason := fs.String("reason", "", "Human-readable reason (required with --force)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	// Mirror the handler's ErrForceReasonRequired contract client-side so
	// the operator gets a clear error before the round trip.
	if *force && strings.TrimSpace(*reason) == "" {
		return fmt.Errorf("--reason is required when --force is set")
	}

	// Build query string. Skip ?force=false; skip ?reason= when empty.
	query := url.Values{}
	if *force {
		query.Set("force", "true")
	}
	if *reason != "" {
		query.Set("reason", *reason)
	}

	u, err := url.JoinPath(c.baseURL, fmt.Sprintf("/api/v1/agents/%s", id))
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if len(query) > 0 {
		u = u + "?" + query.Encode()
	}

	req, err := http.NewRequest("DELETE", u, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusNoContent:
		// 204 idempotent — the agent was already retired. No body.
		if c.format == "json" {
			return c.outputJSON(map[string]interface{}{
				"agent_id":        id,
				"already_retired": true,
			})
		}
		fmt.Printf("Agent %s was already retired (idempotent)\n", id)
		return nil

	case http.StatusOK:
		var result struct {
			RetiredAt      string `json:"retired_at"`
			AlreadyRetired bool   `json:"already_retired"`
			Cascade        bool   `json:"cascade"`
			Counts         struct {
				ActiveTargets      int `json:"active_targets"`
				ActiveCertificates int `json:"active_certificates"`
				PendingJobs        int `json:"pending_jobs"`
			} `json:"counts"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return fmt.Errorf("parsing 200 response: %w", err)
		}

		if c.format == "json" {
			return c.outputJSON(json.RawMessage(body))
		}

		if result.Cascade {
			fmt.Printf("Agent %s retired (cascade). Retired at: %s\n", id, result.RetiredAt)
			fmt.Printf("  Cascaded: %d targets, %d certificates, %d jobs\n",
				result.Counts.ActiveTargets, result.Counts.ActiveCertificates, result.Counts.PendingJobs)
		} else {
			fmt.Printf("Agent %s retired. Retired at: %s\n", id, result.RetiredAt)
		}
		return nil

	case http.StatusConflict:
		// 409 blocked_by_dependencies. Parse the body so we can show the
		// operator which dependency counts are holding up the retire.
		var blocked struct {
			Error   string `json:"error"`
			Message string `json:"message"`
			Counts  struct {
				ActiveTargets      int `json:"active_targets"`
				ActiveCertificates int `json:"active_certificates"`
				PendingJobs        int `json:"pending_jobs"`
			} `json:"counts"`
		}
		if err := json.Unmarshal(body, &blocked); err != nil {
			return fmt.Errorf("agent has active dependencies (HTTP 409); raw body: %s", string(body))
		}
		return fmt.Errorf("blocked_by_dependencies: %s (targets=%d certificates=%d jobs=%d); re-run with --force --reason \"<reason>\" to cascade",
			blocked.Message, blocked.Counts.ActiveTargets, blocked.Counts.ActiveCertificates, blocked.Counts.PendingJobs)

	case http.StatusForbidden:
		return fmt.Errorf("agent %s is a reserved sentinel and cannot be retired (HTTP 403)", id)

	case http.StatusNotFound:
		return fmt.Errorf("agent %s not found (HTTP 404)", id)

	case http.StatusBadRequest:
		return fmt.Errorf("bad request (HTTP 400): %s", string(body))

	default:
		return fmt.Errorf("unexpected HTTP %d: %s", resp.StatusCode, string(body))
	}
}

// GetAgent retrieves a single agent by ID.
func (c *Client) GetAgent(id string) error {
	resp, err := c.do("GET", fmt.Sprintf("/api/v1/agents/%s", id), nil, nil)
	if err != nil {
		return err
	}

	var agent map[string]interface{}
	if err := json.Unmarshal(resp, &agent); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if c.format == "json" {
		return c.outputJSON(agent)
	}

	return c.outputAgentDetail(agent)
}

// ListJobs lists all jobs.
func (c *Client) ListJobs(args []string) error {
	fs := flag.NewFlagSet("jobs list", flag.ContinueOnError)
	status := fs.String("status", "", "Filter by status")
	jobType := fs.String("type", "", "Filter by type")
	page := fs.Int("page", 1, "Page number")
	perPage := fs.Int("per-page", 50, "Items per page")
	fs.Parse(args)

	query := url.Values{}
	if *status != "" {
		query.Set("status", *status)
	}
	if *jobType != "" {
		query.Set("type", *jobType)
	}
	query.Set("page", fmt.Sprintf("%d", *page))
	query.Set("per_page", fmt.Sprintf("%d", *perPage))

	resp, err := c.do("GET", "/api/v1/jobs", query, nil)
	if err != nil {
		return err
	}

	var result struct {
		Data  []map[string]interface{} `json:"data"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if c.format == "json" {
		return c.outputJSON(result)
	}

	return c.outputJobsTable(result.Data, result.Total)
}

// GetJob retrieves a single job by ID.
func (c *Client) GetJob(id string) error {
	resp, err := c.do("GET", fmt.Sprintf("/api/v1/jobs/%s", id), nil, nil)
	if err != nil {
		return err
	}

	var job map[string]interface{}
	if err := json.Unmarshal(resp, &job); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if c.format == "json" {
		return c.outputJSON(job)
	}

	return c.outputJobDetail(job)
}

// CancelJob cancels a pending job.
func (c *Client) CancelJob(id string) error {
	body := map[string]interface{}{}

	resp, err := c.do("POST", fmt.Sprintf("/api/v1/jobs/%s/cancel", id), nil, body)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if c.format == "json" {
		return c.outputJSON(result)
	}

	fmt.Printf("Job %s cancelled\n", id)
	return nil
}

// GetStatus retrieves server health and summary stats.
func (c *Client) GetStatus() error {
	resp, err := c.do("GET", "/api/v1/health", nil, nil)
	if err != nil {
		return err
	}

	var health map[string]interface{}
	if err := json.Unmarshal(resp, &health); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if c.format == "json" {
		return c.outputJSON(health)
	}

	fmt.Printf("Server Status: %v\n", health["status"])
	if ts, ok := health["timestamp"]; ok {
		fmt.Printf("Timestamp: %v\n", ts)
	}

	// Try to fetch summary stats
	statsResp, err := c.do("GET", "/api/v1/stats/summary", nil, nil)
	if err == nil {
		var stats map[string]interface{}
		if err := json.Unmarshal(statsResp, &stats); err == nil {
			fmt.Println("\nSummary Stats:")
			if data, ok := stats["data"].(map[string]interface{}); ok {
				for k, v := range data {
					fmt.Printf("  %s: %v\n", k, v)
				}
			}
		}
	}

	return nil
}

// ImportCertificates bulk imports certificates from PEM files.
//
// C-001 scope-expansion closure: the create-certificate handler's
// six-field required contract (name, common_name, renewal_policy_id,
// issuer_id, owner_id, team_id) is enforced server-side via
// ValidateRequired. The bulk importer must therefore be told which
// owner / team / renewal-policy / issuer to assign to every imported
// cert — otherwise every POST comes back 400. All four IDs are
// required flags; missing flags error out with a user-legible message
// before any files are read.
func (c *Client) ImportCertificates(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	ownerID := fs.String("owner-id", "", "Owner ID to assign to each imported certificate (required)")
	teamID := fs.String("team-id", "", "Team ID to assign to each imported certificate (required)")
	renewalPolicyID := fs.String("renewal-policy-id", "", "Renewal policy ID to assign to each imported certificate (required)")
	issuerID := fs.String("issuer-id", "", "Issuer ID to assign to each imported certificate (required)")
	nameTemplate := fs.String("name-template", "{cn}", "Template for the certificate name; {cn} is substituted with the cert's common name")
	environment := fs.String("environment", "imported", "Environment tag for each imported certificate")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate required flags up front — a clear error here beats six
	// parallel 400s from the server.
	missing := []string{}
	if *ownerID == "" {
		missing = append(missing, "--owner-id")
	}
	if *teamID == "" {
		missing = append(missing, "--team-id")
	}
	if *renewalPolicyID == "" {
		missing = append(missing, "--renewal-policy-id")
	}
	if *issuerID == "" {
		missing = append(missing, "--issuer-id")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required flag(s): %s", strings.Join(missing, ", "))
	}
	if *nameTemplate == "" {
		return fmt.Errorf("--name-template must be non-empty")
	}

	files := fs.Args()
	if len(files) == 0 {
		return fmt.Errorf("at least one PEM file path is required")
	}

	var imported, failed int

	for _, filePath := range files {
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read %s: %v\n", filePath, err)
			failed++
			continue
		}

		certs, err := parsePEMCertificates(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse %s: %v\n", filePath, err)
			failed++
			continue
		}

		for i, cert := range certs {
			total := len(certs)
			fmt.Printf("Importing %d/%d certificates from %s...\r", i+1, total, filepath.Base(filePath))

			name := strings.ReplaceAll(*nameTemplate, "{cn}", cert.Subject.CommonName)

			req := map[string]interface{}{
				"name":              name,
				"common_name":       cert.Subject.CommonName,
				"sans":              cert.DNSNames,
				"issuer_id":         *issuerID,
				"owner_id":          *ownerID,
				"team_id":           *teamID,
				"renewal_policy_id": *renewalPolicyID,
				"environment":       *environment,
				"status":            "Active",
			}

			if cert.SerialNumber != nil {
				req["serial_number"] = fmt.Sprintf("%x", cert.SerialNumber)
			}

			_, err := c.do("POST", "/api/v1/certificates", nil, req)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to import cert %s: %v\n", cert.Subject.CommonName, err)
				failed++
				continue
			}
			imported++
		}
		fmt.Printf("Importing %d/%d certificates from %s... done\n", len(certs), len(certs), filepath.Base(filePath))
	}

	fmt.Printf("\nImport Summary:\n")
	fmt.Printf("  Successfully imported: %d\n", imported)
	fmt.Printf("  Failed: %d\n", failed)

	return nil
}

// Output formatting functions

func (c *Client) outputJSON(data interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func (c *Client) outputCertificatesTable(certs []map[string]interface{}, total int) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tCOMMON NAME\tSTATUS\tEXPIRES\tISSUER")

	for _, cert := range certs {
		id := getString(cert, "id")
		cn := getString(cert, "common_name")
		status := getString(cert, "status")
		issuer := getString(cert, "issuer_id")

		expiresStr := ""
		if expires, ok := cert["expires_at"].(string); ok {
			if t, err := time.Parse(time.RFC3339, expires); err == nil {
				expiresStr = t.Format("2006-01-02")
			}
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", id, cn, status, expiresStr, issuer)
	}

	w.Flush()
	fmt.Printf("\nTotal: %d\n", total)
	return nil
}

func (c *Client) outputCertificateDetail(cert map[string]interface{}) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintf(w, "ID:\t%v\n", getString(cert, "id"))
	fmt.Fprintf(w, "Name:\t%v\n", getString(cert, "name"))
	fmt.Fprintf(w, "Common Name:\t%v\n", getString(cert, "common_name"))
	fmt.Fprintf(w, "Status:\t%v\n", getString(cert, "status"))
	fmt.Fprintf(w, "Issuer ID:\t%v\n", getString(cert, "issuer_id"))
	fmt.Fprintf(w, "Owner ID:\t%v\n", getString(cert, "owner_id"))

	if expires, ok := cert["expires_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, expires); err == nil {
			fmt.Fprintf(w, "Expires At:\t%s\n", t.Format("2006-01-02 15:04:05 MST"))
		}
	}

	if sans, ok := cert["sans"].([]interface{}); ok && len(sans) > 0 {
		fmt.Fprintf(w, "SANs:\t%v\n", sans)
	}

	w.Flush()
	return nil
}

func (c *Client) outputAgentsTable(agents []map[string]interface{}, total int) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tHOSTNAME\tSTATUS\tOS\tARCHITECTURE\tIP ADDRESS")

	for _, agent := range agents {
		id := getString(agent, "id")
		hostname := getString(agent, "hostname")
		status := getString(agent, "status")
		os := getString(agent, "os")
		arch := getString(agent, "architecture")
		ip := getString(agent, "ip_address")

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", id, hostname, status, os, arch, ip)
	}

	w.Flush()
	fmt.Printf("\nTotal: %d\n", total)
	return nil
}

// outputRetiredAgentsTable is the tab-writer view for the retired listing.
// I-004: adds RETIRED_AT + REASON columns so operators can forensic-grep.
func (c *Client) outputRetiredAgentsTable(agents []map[string]interface{}, total int) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tHOSTNAME\tOS\tARCHITECTURE\tRETIRED AT\tREASON")

	for _, agent := range agents {
		id := getString(agent, "id")
		hostname := getString(agent, "hostname")
		osName := getString(agent, "os")
		arch := getString(agent, "architecture")
		retiredAt := ""
		if raw, ok := agent["retired_at"].(string); ok && raw != "" {
			if t, err := time.Parse(time.RFC3339, raw); err == nil {
				retiredAt = t.Format("2006-01-02 15:04:05")
			} else {
				retiredAt = raw
			}
		}
		reason := getString(agent, "retired_reason")

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", id, hostname, osName, arch, retiredAt, reason)
	}

	w.Flush()
	fmt.Printf("\nTotal retired: %d\n", total)
	return nil
}

func (c *Client) outputAgentDetail(agent map[string]interface{}) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintf(w, "ID:\t%v\n", getString(agent, "id"))
	fmt.Fprintf(w, "Name:\t%v\n", getString(agent, "name"))
	fmt.Fprintf(w, "Hostname:\t%v\n", getString(agent, "hostname"))
	fmt.Fprintf(w, "Status:\t%v\n", getString(agent, "status"))
	fmt.Fprintf(w, "OS:\t%v\n", getString(agent, "os"))
	fmt.Fprintf(w, "Architecture:\t%v\n", getString(agent, "architecture"))
	fmt.Fprintf(w, "IP Address:\t%v\n", getString(agent, "ip_address"))
	fmt.Fprintf(w, "Version:\t%v\n", getString(agent, "version"))

	if lastHB, ok := agent["last_heartbeat_at"].(string); ok && lastHB != "" {
		if t, err := time.Parse(time.RFC3339, lastHB); err == nil {
			fmt.Fprintf(w, "Last Heartbeat:\t%s\n", t.Format("2006-01-02 15:04:05 MST"))
		}
	}

	w.Flush()
	return nil
}

func (c *Client) outputJobsTable(jobs []map[string]interface{}, total int) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTYPE\tCERTIFICATE\tSTATUS\tATTEMPTS")

	for _, job := range jobs {
		id := getString(job, "id")
		jobType := getString(job, "type")
		certID := getString(job, "certificate_id")
		status := getString(job, "status")
		attempts := getInt(job, "attempts")

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n", id, jobType, certID, status, attempts)
	}

	w.Flush()
	fmt.Printf("\nTotal: %d\n", total)
	return nil
}

func (c *Client) outputJobDetail(job map[string]interface{}) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintf(w, "ID:\t%v\n", getString(job, "id"))
	fmt.Fprintf(w, "Type:\t%v\n", getString(job, "type"))
	fmt.Fprintf(w, "Certificate ID:\t%v\n", getString(job, "certificate_id"))
	fmt.Fprintf(w, "Status:\t%v\n", getString(job, "status"))
	fmt.Fprintf(w, "Attempts:\t%d\n", getInt(job, "attempts"))
	fmt.Fprintf(w, "Max Attempts:\t%d\n", getInt(job, "max_attempts"))

	if lastErr, ok := job["last_error"].(string); ok && lastErr != "" {
		fmt.Fprintf(w, "Last Error:\t%s\n", lastErr)
	}

	w.Flush()
	return nil
}

// Helper functions

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

// parsePEMCertificates parses PEM-encoded certificates from data.
func parsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}

	return certs, nil
}
