// Package validation provides security-focused input validation functions for certctl.
//
// This package enforces strict input validation to prevent injection attacks,
// including command injection in shell-based connectors and DNS injection in ACME handlers.
package validation

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidateShellCommand validates that a command string does not contain shell metacharacters
// that could enable command injection. Commands should not contain:
// - Shell operators: ; | & $ ` ( ) { } < > \\ "
// - Newlines or other control characters
//
// This validation is intentionally strict to prevent any possibility of
// shell injection, even in unexpected contexts. Commands should be simple,
// executable names or paths without complex shell syntax.
//
// Returns an error if metacharacters are detected.
func ValidateShellCommand(cmd string) error {
	if cmd == "" {
		return fmt.Errorf("command cannot be empty")
	}

	if len(cmd) > 1024 {
		return fmt.Errorf("command exceeds maximum length (1024 characters)")
	}

	// List of shell metacharacters that indicate potential injection
	dangerousChars := []string{
		";", "|", "&", "$", "`", "(", ")", "{", "}", "<", ">", "\\", "\"", "'", "\n", "\r", "\x00",
	}

	for _, char := range dangerousChars {
		if strings.Contains(cmd, char) {
			return fmt.Errorf("command contains shell metacharacter %q (potential injection)", char)
		}
	}

	return nil
}

// ValidateDomainName validates a domain name against RFC 1123 with support for wildcards.
// Valid domain names contain only:
// - Alphanumeric characters (a-z, A-Z, 0-9)
// - Hyphens (-)
// - Dots (.) as separators
// - Optional wildcard prefix: *.
//
// Examples of valid domains:
// - example.com
// - sub.example.com
// - *.example.com
// - example.co.uk
//
// Returns an error if the domain contains invalid characters or is malformed.
func ValidateDomainName(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	if len(domain) > 253 {
		return fmt.Errorf("domain exceeds maximum length (253 characters)")
	}

	// Regular expression for RFC 1123 domain names with wildcard support
	// Pattern explanation:
	// ^(\*\.)?           - Optional wildcard prefix
	// ([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)*  - Subdomains (labels separated by dots)
	// [a-zA-Z0-9](-?[a-zA-Z0-9])*$      - Top-level domain label
	domainRegex := regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)*[a-zA-Z0-9](-?[a-zA-Z0-9])*$`)

	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("domain %q is invalid (must match RFC 1123 format)", domain)
	}

	// Additional check: no double dots
	if strings.Contains(domain, "..") {
		return fmt.Errorf("domain %q contains consecutive dots", domain)
	}

	// Additional check: labels cannot start or end with hyphen
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		// Skip wildcard label
		if label == "*" {
			continue
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("domain label %q cannot start or end with hyphen", label)
		}
		if len(label) > 63 {
			return fmt.Errorf("domain label %q exceeds maximum length (63 characters)", label)
		}
	}

	return nil
}

// ValidateACMEToken validates that an ACME token contains only safe characters.
// ACME tokens should contain only base64url-safe characters:
// - Alphanumeric (a-z, A-Z, 0-9)
// - Hyphens (-)
// - Underscores (_)
//
// This prevents injection attacks if tokens are used in shell commands
// or other contexts where special characters could be interpreted.
//
// Returns an error if the token contains unsafe characters.
func ValidateACMEToken(token string) error {
	if token == "" {
		return fmt.Errorf("ACME token cannot be empty")
	}

	if len(token) > 512 {
		return fmt.Errorf("ACME token exceeds maximum length (512 characters)")
	}

	// Regular expression for base64url characters: [A-Za-z0-9_-]
	tokenRegex := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

	if !tokenRegex.MatchString(token) {
		return fmt.Errorf("ACME token contains invalid characters (must be base64url-safe)")
	}

	return nil
}

// SanitizeForShell escapes a string to make it safe for use in shell commands.
// This is a defense-in-depth measure for cases where shell execution cannot be avoided.
//
// The sanitization wraps the string in single quotes and escapes any embedded
// single quotes by closing the quote, adding an escaped quote, and reopening.
// This prevents the string from being interpreted as shell code.
//
// Example: "hello'world" becomes "'hello'\"'\"'world'"
//
// Note: This should only be used as a last resort. Prefer alternatives such as:
// - Passing arguments directly to exec.Command instead of via shell
// - Using environment variables instead of shell substitution
// - Validating input strictly with ValidateShellCommand, ValidateDomainName, etc.
func SanitizeForShell(s string) string {
	// Escape single quotes by closing the quote, adding an escaped quote, and reopening
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
