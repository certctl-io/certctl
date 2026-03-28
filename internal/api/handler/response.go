package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// PagedResponse represents a paginated API response.
type PagedResponse struct {
	Data    interface{} `json:"data"`
	Total   int64       `json:"total"`
	Page    int         `json:"page"`
	PerPage int         `json:"per_page"`
}

// CursorPagedResponse represents a cursor-paginated API response.
type CursorPagedResponse struct {
	Data       interface{} `json:"data"`
	Total      int64       `json:"total"`
	NextCursor string      `json:"next_cursor,omitempty"`
	PageSize   int         `json:"page_size"`
}

// ErrorResponse represents a standard error response.
type ErrorResponse struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

// JSON writes a JSON response with the given status code and data.
func JSON(w http.ResponseWriter, status int, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

// Error writes a JSON error response with the given status code and message.
func Error(w http.ResponseWriter, status int, message string) error {
	errResp := ErrorResponse{
		Error:   http.StatusText(status),
		Message: message,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(errResp)
}

// ErrorWithRequestID writes a JSON error response including a request ID.
func ErrorWithRequestID(w http.ResponseWriter, status int, message, requestID string) error {
	errResp := ErrorResponse{
		Error:     http.StatusText(status),
		Message:   message,
		RequestID: requestID,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(errResp)
}

// encodeCursor creates an opaque cursor token from a timestamp and ID.
func encodeCursor(createdAt time.Time, id string) string {
	raw := createdAt.Format(time.RFC3339Nano) + ":" + id
	return base64.URLEncoding.EncodeToString([]byte(raw))
}

// decodeCursor extracts a timestamp and ID from a cursor token.
// Kept as var assignment to suppress unused lint — will be used when
// cursor-based pagination is wired into list handlers.
var _ = func(cursor string) (time.Time, string, error) {
	raw, err := base64.URLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid cursor: %w", err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return time.Time{}, "", fmt.Errorf("invalid cursor format")
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid cursor timestamp: %w", err)
	}
	return t, parts[1], nil
}

// filterFields removes fields not in the allowed list from the response data.
// Works with both single objects and slices.
func filterFields(data interface{}, fields []string) interface{} {
	if len(fields) == 0 {
		return data
	}

	// Create field set for O(1) lookup
	fieldSet := make(map[string]bool, len(fields))
	for _, f := range fields {
		fieldSet[f] = true
	}

	// Marshal to JSON, then unmarshal to generic structure
	bytes, err := json.Marshal(data)
	if err != nil {
		return data
	}

	// Try as array first
	var arr []map[string]interface{}
	if err := json.Unmarshal(bytes, &arr); err == nil {
		for i := range arr {
			for key := range arr[i] {
				if !fieldSet[key] {
					delete(arr[i], key)
				}
			}
		}
		return arr
	}

	// Try as object
	var obj map[string]interface{}
	if err := json.Unmarshal(bytes, &obj); err == nil {
		for key := range obj {
			if !fieldSet[key] {
				delete(obj, key)
			}
		}
		return obj
	}

	return data
}
