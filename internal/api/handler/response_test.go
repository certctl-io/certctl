package handler

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEncodeCursor_ProducesValidBase64(t *testing.T) {
	// Test that encodeCursor produces valid base64 with correct format
	originalTime := time.Date(2024, 3, 15, 10, 30, 45, 123456789, time.UTC)
	originalID := "cert-12345"

	// Encode
	encoded := encodeCursor(originalTime, originalID)

	// Verify it's valid base64
	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("encoded cursor is not valid base64: %v", err)
	}

	// Verify contains both timestamp and ID
	decodedStr := string(decoded)
	if !strings.Contains(decodedStr, originalID) {
		t.Errorf("decoded cursor doesn't contain ID %q, got %q", originalID, decodedStr)
	}

	// Verify it's not empty and has expected structure (timestamp:id)
	if !strings.Contains(decodedStr, ":") {
		t.Errorf("decoded cursor doesn't contain colon separator, got %q", decodedStr)
	}
}

func TestEncodeCursor_DifferentTimes(t *testing.T) {
	id := "test-id"
	time1 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	time2 := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)

	cursor1 := encodeCursor(time1, id)
	cursor2 := encodeCursor(time2, id)

	// Different times should produce different cursors
	if cursor1 == cursor2 {
		t.Error("Different times produced identical cursors")
	}
}

func TestEncodeCursor_DifferentIDs(t *testing.T) {
	now := time.Now()
	id1 := "cert-1"
	id2 := "cert-2"

	cursor1 := encodeCursor(now, id1)
	cursor2 := encodeCursor(now, id2)

	// Different IDs should produce different cursors
	if cursor1 == cursor2 {
		t.Error("Different IDs produced identical cursors")
	}
}

func TestDecodeCursor_InvalidBase64(t *testing.T) {
	// Create the decodeCursor function from the closure - matching actual behavior
	decodeCursor := func(cursor string) (time.Time, string, error) {
		raw, err := base64.URLEncoding.DecodeString(cursor)
		if err != nil {
			return time.Time{}, "", err
		}
		parts := strings.SplitN(string(raw), ":", 2)
		if len(parts) != 2 {
			return time.Time{}, "", fmt.Errorf("invalid cursor format")
		}
		t, err := time.Parse(time.RFC3339Nano, parts[0])
		if err != nil {
			return time.Time{}, "", err
		}
		return t, parts[1], nil
	}

	tests := []struct {
		name        string
		cursor      string
		expectError bool
	}{
		{"invalid base64", "!!!invalid!!!", true},
		{"empty string", "", true},
		{"no colon separator", base64.URLEncoding.EncodeToString([]byte("no-separator-here")), true},
		{"invalid timestamp", base64.URLEncoding.EncodeToString([]byte("not-a-timestamp:id-123")), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := decodeCursor(tt.cursor)
			if tt.expectError && err == nil {
				t.Error("expected error for invalid cursor, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestJSON_SetsContentType(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"key": "value"}

	JSON(w, http.StatusOK, data)

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
}

func TestJSON_SetsStatusCode(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"key": "value"}

	JSON(w, http.StatusCreated, data)

	if w.Code != http.StatusCreated {
		t.Errorf("Status code = %d, want %d", w.Code, http.StatusCreated)
	}
}

func TestJSON_EncodesData(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]interface{}{
		"string": "value",
		"number": 42,
		"bool":   true,
		"null":   nil,
	}

	JSON(w, http.StatusOK, data)

	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["string"] != "value" {
		t.Errorf("string = %v, want value", result["string"])
	}

	if result["number"] != float64(42) {
		t.Errorf("number = %v, want 42", result["number"])
	}

	if result["bool"] != true {
		t.Errorf("bool = %v, want true", result["bool"])
	}

	if result["null"] != nil {
		t.Errorf("null = %v, want nil", result["null"])
	}
}

func TestError_SetsStatusCode(t *testing.T) {
	w := httptest.NewRecorder()

	Error(w, http.StatusBadRequest, "Invalid input")

	if w.Code != http.StatusBadRequest {
		t.Errorf("Status code = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestError_SetsContentType(t *testing.T) {
	w := httptest.NewRecorder()

	Error(w, http.StatusBadRequest, "Invalid input")

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
}

func TestError_IncludesMessage(t *testing.T) {
	w := httptest.NewRecorder()
	message := "Something went wrong"

	Error(w, http.StatusInternalServerError, message)

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Message != message {
		t.Errorf("Message = %q, want %q", errResp.Message, message)
	}
}

func TestError_IncludesStatusText(t *testing.T) {
	w := httptest.NewRecorder()

	Error(w, http.StatusNotFound, "Resource not found")

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Error != http.StatusText(http.StatusNotFound) {
		t.Errorf("Error = %q, want %q", errResp.Error, http.StatusText(http.StatusNotFound))
	}
}

func TestErrorWithRequestID_SetsStatusCode(t *testing.T) {
	w := httptest.NewRecorder()

	ErrorWithRequestID(w, http.StatusBadRequest, "Invalid input", "req-123")

	if w.Code != http.StatusBadRequest {
		t.Errorf("Status code = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestErrorWithRequestID_IncludesRequestID(t *testing.T) {
	w := httptest.NewRecorder()
	requestID := "req-abc-def-ghi"

	ErrorWithRequestID(w, http.StatusInternalServerError, "Server error", requestID)

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.RequestID != requestID {
		t.Errorf("RequestID = %q, want %q", errResp.RequestID, requestID)
	}
}

func TestErrorWithRequestID_IncludesMessage(t *testing.T) {
	w := httptest.NewRecorder()
	message := "Database connection failed"

	ErrorWithRequestID(w, http.StatusServiceUnavailable, message, "req-123")

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Message != message {
		t.Errorf("Message = %q, want %q", errResp.Message, message)
	}
}

func TestPagedResponse_Structure(t *testing.T) {
	response := PagedResponse{
		Data:    []string{"item1", "item2"},
		Total:   100,
		Page:    2,
		PerPage: 50,
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if result["total"] != float64(100) {
		t.Errorf("total = %v, want 100", result["total"])
	}

	if result["page"] != float64(2) {
		t.Errorf("page = %v, want 2", result["page"])
	}

	if result["per_page"] != float64(50) {
		t.Errorf("per_page = %v, want 50", result["per_page"])
	}

	if result["data"] == nil {
		t.Error("data is nil")
	}
}

func TestCursorPagedResponse_Structure(t *testing.T) {
	response := CursorPagedResponse{
		Data:       []string{"item1", "item2"},
		Total:      100,
		NextCursor: "abc123def456",
		PageSize:   50,
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if result["total"] != float64(100) {
		t.Errorf("total = %v, want 100", result["total"])
	}

	if result["next_cursor"] != "abc123def456" {
		t.Errorf("next_cursor = %v, want abc123def456", result["next_cursor"])
	}

	if result["page_size"] != float64(50) {
		t.Errorf("page_size = %v, want 50", result["page_size"])
	}
}

func TestCursorPagedResponse_EmptyNextCursor(t *testing.T) {
	// When NextCursor is empty, it should be omitted from JSON
	response := CursorPagedResponse{
		Data:       []string{},
		Total:      0,
		NextCursor: "",
		PageSize:   50,
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	// Empty string for next_cursor should be omitted due to omitempty tag
	if bytes.Contains(data, []byte("next_cursor")) {
		t.Error("empty next_cursor should be omitted from JSON")
	}
}

func TestFilterFields_SingleObject(t *testing.T) {
	data := map[string]interface{}{
		"id":    "cert-123",
		"name":  "My Cert",
		"expiry": "2025-01-01",
		"status": "active",
	}

	result := filterFields(data, []string{"id", "name"})

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is not map[string]interface{}, got %T", result)
	}

	if resultMap["id"] != "cert-123" {
		t.Errorf("id = %v, want cert-123", resultMap["id"])
	}

	if resultMap["name"] != "My Cert" {
		t.Errorf("name = %v, want My Cert", resultMap["name"])
	}

	if _, hasExpiry := resultMap["expiry"]; hasExpiry {
		t.Error("expiry should be filtered out")
	}

	if _, hasStatus := resultMap["status"]; hasStatus {
		t.Error("status should be filtered out")
	}
}

func TestFilterFields_EmptyFields(t *testing.T) {
	// Empty fields list should return data unchanged
	data := map[string]interface{}{
		"id":    "cert-123",
		"name":  "My Cert",
	}

	result := filterFields(data, []string{})

	// Should return original data unchanged
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is not map[string]interface{}, got %T", result)
	}

	if len(resultMap) != 2 {
		t.Errorf("filtered result has %d fields, want 2", len(resultMap))
	}
}

func TestFilterFields_NoMatchingFields(t *testing.T) {
	data := map[string]interface{}{
		"id":    "cert-123",
		"name":  "My Cert",
	}

	result := filterFields(data, []string{"nonexistent", "also-not-there"})

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is not map[string]interface{}, got %T", result)
	}

	if len(resultMap) != 0 {
		t.Errorf("filtered result has %d fields, want 0", len(resultMap))
	}
}

func TestFilterFields_InvalidJSON(t *testing.T) {
	// Non-serializable data should be returned as-is
	data := make(chan int) // channels can't be marshaled to JSON

	result := filterFields(data, []string{"field"})

	// Should return original data unchanged
	if result != data {
		t.Error("invalid data should be returned unchanged")
	}
}
