package service

import (
	"encoding/json"
	"strings"
)

// sensitiveKeys are config key substrings that should be redacted in API responses.
var sensitiveKeys = []string{"password", "secret", "token", "key", "hmac", "private", "credentials"}

// isSensitiveConfigKey checks if a config key contains sensitive substrings.
func isSensitiveConfigKey(key string) bool {
	lower := strings.ToLower(key)
	for _, s := range sensitiveKeys {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// redactConfigJSON replaces sensitive values in a JSON config with "********".
func redactConfigJSON(configJSON json.RawMessage) json.RawMessage {
	var m map[string]interface{}
	if err := json.Unmarshal(configJSON, &m); err != nil {
		return configJSON // Not a JSON object, return as-is
	}

	for k, v := range m {
		if isSensitiveConfigKey(k) {
			if str, ok := v.(string); ok && str != "" {
				m[k] = "********"
			}
		}
	}

	redacted, err := json.Marshal(m)
	if err != nil {
		return configJSON
	}
	return json.RawMessage(redacted)
}
