package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
)

// TestValidateCommonName_ValidInputs tests common names that should pass validation.
func TestValidateCommonName_ValidInputs(t *testing.T) {
	tests := []struct {
		name string
		cn   string
	}{
		{
			name: "simple hostname",
			cn:   "example.com",
		},
		{
			name: "wildcard domain",
			cn:   "*.example.com",
		},
		{
			name: "subdomain",
			cn:   "sub.deep.example.com",
		},
		{
			name: "IPv4 address",
			cn:   "192.168.1.1",
		},
		{
			name: "IPv6 address",
			cn:   "2001:db8::1",
		},
		{
			name: "email address (S/MIME)",
			cn:   "user@example.com",
		},
		{
			name: "hostname with hyphen",
			cn:   "my-host",
		},
		{
			name: "single character hostname",
			cn:   "a",
		},
		{
			name: "hostname with underscore",
			cn:   "my_host",
		},
		{
			name: "complex subdomain",
			cn:   "api.v1.internal.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommonName(tt.cn)
			if err != nil {
				t.Errorf("ValidateCommonName(%q) = %v, want nil", tt.cn, err)
			}
		})
	}
}

// TestValidateCommonName_InvalidInputs tests common names that should fail validation.
func TestValidateCommonName_InvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		cn      string
		wantErr bool
	}{
		{
			name:    "empty string",
			cn:      "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			cn:      "   ",
			wantErr: true,
		},
		{
			name:    "string exceeds 253 characters",
			cn:      strings.Repeat("a", 254),
			wantErr: true,
		},
		{
			name:    "path traversal attempt",
			cn:      "../etc/passwd",
			wantErr: true,
		},
		{
			name:    "label starts with hyphen",
			cn:      "-example.com",
			wantErr: true,
		},
		{
			name:    "label ends with hyphen",
			cn:      "example-.com",
			wantErr: true,
		},
		{
			name:    "empty label",
			cn:      "example..com",
			wantErr: true,
		},
		{
			name:    "invalid character space",
			cn:      "my host.com",
			wantErr: true,
		},
		{
			name:    "invalid character slash",
			cn:      "my/host.com",
			wantErr: true,
		},
		{
			name:    "malformed email",
			cn:      "notanemail@",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommonName(tt.cn)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCommonName(%q) error = %v, wantErr %v", tt.cn, err, tt.wantErr)
			}
		})
	}
}

// TestValidateRequired_EmptyAndWhitespace tests required field validation.
func TestValidateRequired_EmptyAndWhitespace(t *testing.T) {
	tests := []struct {
		name    string
		field   string
		value   string
		wantErr bool
	}{
		{
			name:    "empty value",
			field:   "test_field",
			value:   "",
			wantErr: true,
		},
		{
			name:    "valid value",
			field:   "test_field",
			value:   "value",
			wantErr: false,
		},
		{
			name:    "whitespace only value",
			field:   "another_field",
			value:   "   ",
			wantErr: false, // Whitespace is considered a value (not empty string)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRequired(tt.field, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRequired(%q, %q) error = %v, wantErr %v", tt.field, tt.value, err, tt.wantErr)
			}
			if err != nil {
				ve, ok := err.(ValidationError)
				if !ok {
					t.Errorf("Expected ValidationError, got %T", err)
				}
				if ve.Field != tt.field {
					t.Errorf("Expected field %q, got %q", tt.field, ve.Field)
				}
			}
		})
	}
}

// TestValidateStringLength_Boundary tests string length validation at boundaries.
func TestValidateStringLength_Boundary(t *testing.T) {
	tests := []struct {
		name    string
		field   string
		value   string
		maxLen  int
		wantErr bool
	}{
		{
			name:    "at max length",
			field:   "test",
			value:   "0123456789",
			maxLen:  10,
			wantErr: false,
		},
		{
			name:    "under max length",
			field:   "test",
			value:   "012345678",
			maxLen:  10,
			wantErr: false,
		},
		{
			name:    "exceeds max length",
			field:   "test",
			value:   "01234567890",
			maxLen:  10,
			wantErr: true,
		},
		{
			name:    "empty string",
			field:   "test",
			value:   "",
			maxLen:  10,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStringLength(tt.field, tt.value, tt.maxLen)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateStringLength(%q, %q, %d) error = %v, wantErr %v",
					tt.field, tt.value, tt.maxLen, err, tt.wantErr)
			}
			if err != nil {
				ve, ok := err.(ValidationError)
				if !ok {
					t.Errorf("Expected ValidationError, got %T", err)
				}
				if ve.Field != tt.field {
					t.Errorf("Expected field %q, got %q", tt.field, ve.Field)
				}
			}
		})
	}
}

// TestValidateCSRPEM_Valid tests validation of a real CSR PEM.
func TestValidateCSRPEM_Valid(t *testing.T) {
	// Generate a real CSR using crypto/x509
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkixName("example.com"),
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	err = ValidateCSRPEM(string(csrPEM))
	if err != nil {
		t.Errorf("ValidateCSRPEM() on valid CSR returned error: %v", err)
	}
}

// TestValidateCSRPEM_InvalidInputs tests CSR validation with invalid inputs.
func TestValidateCSRPEM_InvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		csrPEM  string
		wantErr bool
	}{
		{
			name:    "empty string",
			csrPEM:  "",
			wantErr: true,
		},
		{
			name:    "not PEM format",
			csrPEM:  "not-a-pem-block",
			wantErr: true,
		},
		{
			name:    "garbage data",
			csrPEM:  "asdfjkl;asdfjkl;",
			wantErr: true,
		},
		{
			name:    "certificate PEM (not CSR)",
			csrPEM:  "-----BEGIN CERTIFICATE-----\nMIIC",
			wantErr: true,
		},
		{
			name:    "PEM with wrong type",
			csrPEM:  "-----BEGIN PRIVATE KEY-----\ndata",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			csrPEM:  "   \n   ",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCSRPEM(tt.csrPEM)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCSRPEM(%q) error = %v, wantErr %v", tt.csrPEM, err, tt.wantErr)
			}
			if err != nil {
				ve, ok := err.(ValidationError)
				if !ok {
					t.Errorf("Expected ValidationError, got %T", err)
				}
				if ve.Field != "csr_pem" {
					t.Errorf("Expected field 'csr_pem', got %q", ve.Field)
				}
			}
		})
	}
}

// TestValidatePolicyType_ValidTypes tests valid policy types.
func TestValidatePolicyType_ValidTypes(t *testing.T) {
	validTypes := []struct {
		name string
		ptype interface{}
	}{
		{
			name:  "AllowedIssuers",
			ptype: "AllowedIssuers",
		},
		{
			name:  "AllowedDomains",
			ptype: "AllowedDomains",
		},
		{
			name:  "RequiredMetadata",
			ptype: "RequiredMetadata",
		},
		{
			name:  "AllowedEnvironments",
			ptype: "AllowedEnvironments",
		},
		{
			name:  "RenewalLeadTime",
			ptype: "RenewalLeadTime",
		},
	}

	for _, tt := range validTypes {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePolicyType(tt.ptype)
			if err != nil {
				t.Errorf("ValidatePolicyType(%v) = %v, want nil", tt.ptype, err)
			}
		})
	}
}

// TestValidatePolicyType_InvalidType tests invalid policy types.
func TestValidatePolicyType_InvalidType(t *testing.T) {
	tests := []struct {
		name    string
		ptype   interface{}
		wantErr bool
	}{
		{
			name:    "nonexistent type",
			ptype:   "NonexistentType",
			wantErr: true,
		},
		{
			name:    "empty string",
			ptype:   "",
			wantErr: true,
		},
		{
			name:    "lowercase type",
			ptype:   "allowedissuers",
			wantErr: true,
		},
		{
			name:    "integer type",
			ptype:   123,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePolicyType(tt.ptype)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePolicyType(%v) error = %v, wantErr %v", tt.ptype, err, tt.wantErr)
			}
			if err != nil {
				ve, ok := err.(ValidationError)
				if !ok {
					t.Errorf("Expected ValidationError, got %T", err)
				}
				if ve.Field != "type" {
					t.Errorf("Expected field 'type', got %q", ve.Field)
				}
			}
		})
	}
}

// TestValidatePolicySeverity_ValidSeverities tests valid severity levels.
func TestValidatePolicySeverity_ValidSeverities(t *testing.T) {
	validSeverities := []struct {
		name string
		sev  interface{}
	}{
		{
			name: "Warning",
			sev:  "Warning",
		},
		{
			name: "Error",
			sev:  "Error",
		},
		{
			name: "Critical",
			sev:  "Critical",
		},
	}

	for _, tt := range validSeverities {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePolicySeverity(tt.sev)
			if err != nil {
				t.Errorf("ValidatePolicySeverity(%v) = %v, want nil", tt.sev, err)
			}
		})
	}
}

// TestValidatePolicySeverity_InvalidSeverity tests invalid severity levels.
func TestValidatePolicySeverity_InvalidSeverity(t *testing.T) {
	tests := []struct {
		name    string
		sev     interface{}
		wantErr bool
	}{
		{
			name:    "lowercase warning",
			sev:     "warning",
			wantErr: true,
		},
		{
			name:    "nonexistent severity",
			sev:     "Severe",
			wantErr: true,
		},
		{
			name:    "empty string",
			sev:     "",
			wantErr: true,
		},
		{
			name:    "integer",
			sev:     1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePolicySeverity(tt.sev)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePolicySeverity(%v) error = %v, wantErr %v", tt.sev, err, tt.wantErr)
			}
			if err != nil {
				ve, ok := err.(ValidationError)
				if !ok {
					t.Errorf("Expected ValidationError, got %T", err)
				}
				if ve.Field != "severity" {
					t.Errorf("Expected field 'severity', got %q", ve.Field)
				}
			}
		})
	}
}

// TestValidationError_ErrorMessage tests ValidationError.Error() method.
func TestValidationError_ErrorMessage(t *testing.T) {
	tests := []struct {
		name    string
		err     ValidationError
		wantMsg string
	}{
		{
			name: "simple message",
			err: ValidationError{
				Field:   "common_name",
				Message: "common_name is required",
			},
			wantMsg: "common_name is required",
		},
		{
			name: "detailed message",
			err: ValidationError{
				Field:   "csr_pem",
				Message: "csr_pem must be a valid PEM-encoded certificate request",
			},
			wantMsg: "csr_pem must be a valid PEM-encoded certificate request",
		},
		{
			name: "error with field info",
			err: ValidationError{
				Field:   "test_field",
				Message: fmt.Sprintf("test_field must be 10 characters or fewer"),
			},
			wantMsg: "test_field must be 10 characters or fewer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := tt.err.Error()
			if errMsg != tt.wantMsg {
				t.Errorf("ValidationError.Error() = %q, want %q", errMsg, tt.wantMsg)
			}
		})
	}
}

// TestValidationError_IsError tests that ValidationError satisfies error interface.
func TestValidationError_IsError(t *testing.T) {
	var err error = ValidationError{
		Field:   "test",
		Message: "test error",
	}

	if err == nil {
		t.Error("ValidationError should satisfy error interface")
	}

	msg := err.Error()
	if msg != "test error" {
		t.Errorf("Expected error message 'test error', got %q", msg)
	}
}

// pkixName is a helper function to create PKIX name (used in CSR generation).
func pkixName(cn string) pkix.Name {
	return pkix.Name{
		CommonName: cn,
	}
}
