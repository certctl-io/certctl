package cli

import (
	"bytes"
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
	"text/tabwriter"
	"time"
)

// Client is the CLI HTTP client that communicates with the certctl server.
type Client struct {
	baseURL   string
	apiKey    string
	format    string
	httpClient *http.Client
}

// NewClient creates a new CLI client.
func NewClient(baseURL, apiKey, format string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		format:  format,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
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
func (c *Client) ImportCertificates(files []string) error {
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

			req := map[string]interface{}{
				"common_name": cert.Subject.CommonName,
				"sans":        cert.DNSNames,
				"issuer_id":   "iss-local",
				"environment": "imported",
				"status":      "Active",
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
