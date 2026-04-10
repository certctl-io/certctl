package service

import (
	"encoding/json"
	"testing"
)

func TestIsSensitiveConfigKey_KnownSensitiveKeys(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{"api_key", "api_key", true},
		{"password", "password", true},
		{"secret", "secret", true},
		{"token", "token", true},
		{"hmac", "hmac", true},
		{"private_key", "private_key", true},
		{"credentials", "credentials", true},
		{"winrm_password", "winrm_password", true},
		{"keystore_password", "keystore_password", true},
		// Variations with different casing
		{"API_KEY", "API_KEY", true},
		{"Password", "Password", true},
		{"SECRET", "SECRET", true},
		{"PrivateKey", "PrivateKey", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSensitiveConfigKey(tt.key)
			if got != tt.expected {
				t.Errorf("isSensitiveConfigKey(%q) = %v, want %v", tt.key, got, tt.expected)
			}
		})
	}
}

func TestIsSensitiveConfigKey_NonSensitiveKeys(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{"url", "url"},
		{"host", "host"},
		{"port", "port"},
		{"region", "region"},
		{"ca_pool", "ca_pool"},
		{"namespace", "namespace"},
		{"cert_path", "cert_path"},
		{"base_url", "base_url"},
		{"org_id", "org_id"},
		{"product_type", "product_type"},
		{"email", "email"},
		{"enabled", "enabled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSensitiveConfigKey(tt.key)
			if got != false {
				t.Errorf("isSensitiveConfigKey(%q) = %v, want false", tt.key, got)
			}
		})
	}
}

func TestIsSensitiveConfigKey_CaseInsensitivity(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{"api_key uppercase", "API_KEY"},
		{"api_key mixed", "Api_Key"},
		{"password uppercase", "PASSWORD"},
		{"password mixed", "PassWord"},
		{"secret uppercase", "SECRET"},
		{"token mixed", "ToKeN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSensitiveConfigKey(tt.key)
			if got != true {
				t.Errorf("isSensitiveConfigKey(%q) = %v, want true (case-insensitive)", tt.key, got)
			}
		})
	}
}

func TestRedactConfigJSON_HidesSensitiveFields(t *testing.T) {
	input := json.RawMessage(`{
		"api_key": "secret-key-123",
		"password": "my-password",
		"token": "bearer-token",
		"host": "example.com"
	}`)

	result := redactConfigJSON(input)

	var m map[string]interface{}
	if err := json.Unmarshal(result, &m); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	// Check sensitive fields are redacted
	if m["api_key"] != "********" {
		t.Errorf("api_key = %v, want ********", m["api_key"])
	}
	if m["password"] != "********" {
		t.Errorf("password = %v, want ********", m["password"])
	}
	if m["token"] != "********" {
		t.Errorf("token = %v, want ********", m["token"])
	}

	// Check non-sensitive field is preserved
	if m["host"] != "example.com" {
		t.Errorf("host = %v, want example.com", m["host"])
	}
}

func TestRedactConfigJSON_PassesThroughNonSensitive(t *testing.T) {
	input := json.RawMessage(`{
		"url": "https://api.example.com",
		"port": 443,
		"region": "us-east-1"
	}`)

	result := redactConfigJSON(input)

	var m map[string]interface{}
	if err := json.Unmarshal(result, &m); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	// All fields should be preserved as-is
	if m["url"] != "https://api.example.com" {
		t.Errorf("url = %v, want https://api.example.com", m["url"])
	}
	if m["port"] != float64(443) {
		t.Errorf("port = %v, want 443", m["port"])
	}
	if m["region"] != "us-east-1" {
		t.Errorf("region = %v, want us-east-1", m["region"])
	}
}

func TestRedactConfigJSON_EmptyConfig(t *testing.T) {
	input := json.RawMessage(`{}`)

	result := redactConfigJSON(input)

	var m map[string]interface{}
	if err := json.Unmarshal(result, &m); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if len(m) != 0 {
		t.Errorf("empty config should remain empty, got %v", m)
	}
}

func TestRedactConfigJSON_EmptyStringPassword(t *testing.T) {
	input := json.RawMessage(`{
		"password": "",
		"token": "my-token",
		"host": "example.com"
	}`)

	result := redactConfigJSON(input)

	var m map[string]interface{}
	if err := json.Unmarshal(result, &m); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	// Empty password should be left as-is (empty string)
	if m["password"] != "" {
		t.Errorf("empty password = %v, want empty string", m["password"])
	}

	// Non-empty sensitive field should be redacted
	if m["token"] != "********" {
		t.Errorf("token = %v, want ********", m["token"])
	}

	// Non-sensitive field preserved
	if m["host"] != "example.com" {
		t.Errorf("host = %v, want example.com", m["host"])
	}
}

func TestRedactConfigJSON_MalformedJSON(t *testing.T) {
	// Malformed JSON should be returned as-is
	input := json.RawMessage(`not valid json`)

	result := redactConfigJSON(input)

	// Should return the input unchanged when it can't be parsed as object
	if string(result) != string(input) {
		t.Errorf("malformed JSON not returned as-is: got %s, want %s", string(result), string(input))
	}
}

func TestRedactConfigJSON_JSONArray(t *testing.T) {
	// Array of objects should be returned as-is (not parsed as object)
	input := json.RawMessage(`[{"key": "value"}]`)

	result := redactConfigJSON(input)

	// Should return the input unchanged since it's an array, not an object
	if string(result) != string(input) {
		t.Errorf("JSON array not returned as-is: got %s, want %s", string(result), string(input))
	}
}

func TestRedactConfigJSON_NestedSensitiveFields(t *testing.T) {
	input := json.RawMessage(`{
		"outer_password": "should-be-redacted",
		"config": {"inner_key": "value"}
	}`)

	result := redactConfigJSON(input)

	var m map[string]interface{}
	if err := json.Unmarshal(result, &m); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	// Outer level sensitive field is redacted
	if m["outer_password"] != "********" {
		t.Errorf("outer_password = %v, want ********", m["outer_password"])
	}

	// Note: nested fields are NOT redacted (function only processes top-level)
	// This is the current behavior based on the implementation
	if nested, ok := m["config"].(map[string]interface{}); ok {
		if nested["inner_key"] != "value" {
			t.Errorf("nested inner_key = %v, want value (nested not processed)", nested["inner_key"])
		}
	}
}

func TestRedactConfigJSON_NonStringValues(t *testing.T) {
	input := json.RawMessage(`{
		"password": 123,
		"token": null,
		"secret": true,
		"api_key": ["list", "of", "values"]
	}`)

	result := redactConfigJSON(input)

	var m map[string]interface{}
	if err := json.Unmarshal(result, &m); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	// Non-string values should be left as-is (not redacted)
	if m["password"] != float64(123) {
		t.Errorf("password (number) = %v, want 123 (unchanged)", m["password"])
	}
	if m["token"] != nil {
		t.Errorf("token (null) = %v, want nil (unchanged)", m["token"])
	}
	if m["secret"] != true {
		t.Errorf("secret (bool) = %v, want true (unchanged)", m["secret"])
	}
	if _, ok := m["api_key"].([]interface{}); !ok {
		t.Errorf("api_key (array) should remain as array, got %T", m["api_key"])
	}
}
