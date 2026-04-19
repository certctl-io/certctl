package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client is a thin HTTP client that forwards requests to the certctl REST API.
// It handles auth, base URL resolution, and JSON marshaling.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new certctl API client.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Get performs an HTTP GET and returns the raw JSON response body.
func (c *Client) Get(path string, query url.Values) (json.RawMessage, error) {
	return c.do("GET", path, query, nil)
}

// Post performs an HTTP POST with a JSON body and returns the raw JSON response.
func (c *Client) Post(path string, body interface{}) (json.RawMessage, error) {
	return c.do("POST", path, nil, body)
}

// Put performs an HTTP PUT with a JSON body and returns the raw JSON response.
func (c *Client) Put(path string, body interface{}) (json.RawMessage, error) {
	return c.do("PUT", path, nil, body)
}

// Delete performs an HTTP DELETE and returns the raw JSON response (may be empty for 204).
func (c *Client) Delete(path string) (json.RawMessage, error) {
	return c.do("DELETE", path, nil, nil)
}

// DeleteWithQuery performs an HTTP DELETE with query parameters. I-004 adds
// this transport so MCP tools can target endpoints that carry flags in the
// query string (e.g. DELETE /api/v1/agents/{id}?force=true&reason=…). Client.Delete
// is path-only; without this method the retire tool silently drops force/reason,
// turning every cascade retire into a default soft-retire. Shares do()'s 204
// normalization and 4xx/5xx error propagation so tool authors get one contract.
func (c *Client) DeleteWithQuery(path string, query url.Values) (json.RawMessage, error) {
	return c.do("DELETE", path, query, nil)
}

// GetRaw performs an HTTP GET and returns the raw response body bytes and content type.
// Used for binary responses (DER CRL, OCSP).
func (c *Client) GetRaw(path string) ([]byte, string, error) {
	u, err := url.JoinPath(c.baseURL, path)
	if err != nil {
		return nil, "", fmt.Errorf("invalid URL: %w", err)
	}

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}

	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, "", fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(data))
	}

	return data, resp.Header.Get("Content-Type"), nil
}

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
