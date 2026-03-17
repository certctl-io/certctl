package handler

import (
	"fmt"
	"net"
	"strings"
)

// ValidationError represents a validation error with field-level details.
type ValidationError struct {
	Field   string
	Message string
}

// ValidateCommonName validates a certificate common name.
func ValidateCommonName(cn string) error {
	if cn == "" {
		return ValidationError{Field: "common_name", Message: "common_name is required"}
	}
	if len(cn) > 253 {
		return ValidationError{Field: "common_name", Message: "common_name must be 253 characters or fewer"}
	}
	// Basic hostname validation: allow alphanumeric, dots, hyphens
	if err := isValidHostname(cn); err != nil {
		return ValidationError{Field: "common_name", Message: fmt.Sprintf("invalid hostname format: %v", err)}
	}
	return nil
}

// ValidateRequired checks if a string field is present and non-empty.
func ValidateRequired(field, value string) error {
	if value == "" {
		return ValidationError{Field: field, Message: fmt.Sprintf("%s is required", field)}
	}
	return nil
}

// ValidateStringLength checks if a string is within acceptable length bounds.
func ValidateStringLength(field, value string, maxLen int) error {
	if len(value) > maxLen {
		return ValidationError{Field: field, Message: fmt.Sprintf("%s must be %d characters or fewer", field, maxLen)}
	}
	return nil
}

// ValidateCSRPEM validates a certificate signing request PEM block.
func ValidateCSRPEM(csrPEM string) error {
	if csrPEM == "" {
		return ValidationError{Field: "csr_pem", Message: "csr_pem is required"}
	}
	if !strings.HasPrefix(strings.TrimSpace(csrPEM), "-----BEGIN CERTIFICATE REQUEST-----") {
		return ValidationError{Field: "csr_pem", Message: "csr_pem must be a valid PEM-encoded certificate request"}
	}
	return nil
}

// ValidatePolicyType checks if a policy rule type is valid.
func ValidatePolicyType(policyType interface{}) error {
	validTypes := map[string]bool{
		"AllowedIssuers":      true,
		"AllowedDomains":      true,
		"RequiredMetadata":    true,
		"AllowedEnvironments": true,
		"RenewalLeadTime":     true,
	}
	typeStr := fmt.Sprintf("%v", policyType)
	if !validTypes[typeStr] {
		return ValidationError{Field: "type", Message: "type must be one of: AllowedIssuers, AllowedDomains, RequiredMetadata, AllowedEnvironments, RenewalLeadTime"}
	}
	return nil
}

// ValidatePolicySeverity checks if a severity level is valid.
func ValidatePolicySeverity(severity interface{}) error {
	validSeverities := map[string]bool{
		"Warning":  true,
		"Error":    true,
		"Critical": true,
	}
	sevStr := fmt.Sprintf("%v", severity)
	if !validSeverities[sevStr] {
		return ValidationError{Field: "severity", Message: "severity must be one of: Warning, Error, Critical"}
	}
	return nil
}

// isValidHostname performs basic validation on a hostname.
func isValidHostname(hostname string) error {
	// Use net.SplitHostPort-compatible check
	// Hostname can be an IP or domain name
	if ip := net.ParseIP(hostname); ip != nil {
		return nil // Valid IP address
	}

	// For domain names, check basic format
	if len(hostname) == 0 || len(hostname) > 253 {
		return fmt.Errorf("hostname length invalid")
	}

	// Check for invalid characters (very basic)
	for _, char := range hostname {
		if !isValidHostnameChar(char) {
			return fmt.Errorf("hostname contains invalid character: %c", char)
		}
	}

	// Labels must not start or end with hyphen
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return fmt.Errorf("hostname has empty label")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("hostname labels cannot start or end with hyphen")
		}
	}

	return nil
}

// isValidHostnameChar checks if a character is valid in a hostname.
func isValidHostnameChar(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		r == '.' ||
		r == '-' ||
		r == '_' || // Underscores are sometimes allowed
		r == '*' // Wildcard support
}

// Error method makes ValidationError satisfy the error interface.
func (e ValidationError) Error() string {
	return e.Message
}
