package handler

import (
	"context"
	"encoding/json"
	"net/http"
)

// DigestServicer defines the interface for digest operations used by the handler.
type DigestServicer interface {
	PreviewDigest(ctx context.Context) (string, error)
	SendDigest(ctx context.Context) error
}

// DigestHandler provides HTTP endpoints for certificate digest operations.
type DigestHandler struct {
	service DigestServicer
}

// NewDigestHandler creates a new digest handler.
func NewDigestHandler(service DigestServicer) *DigestHandler {
	return &DigestHandler{service: service}
}

// PreviewDigest renders the digest HTML without sending it.
// GET /api/v1/digest/preview
func (h *DigestHandler) PreviewDigest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.service == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "digest service not configured"})
		return
	}

	html, err := h.service.PreviewDigest(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// SendDigest triggers an immediate digest send.
// POST /api/v1/digest/send
func (h *DigestHandler) SendDigest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.service == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "digest service not configured"})
		return
	}

	if err := h.service.SendDigest(r.Context()); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "sent"})
}
