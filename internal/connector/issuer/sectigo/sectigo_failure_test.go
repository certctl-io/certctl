package sectigo_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/issuer/sectigo"
)

// Bundle N.A/B-extended: sectigo failure-mode round-out (79.4% → ≥85%).
// Targets uncovered branches in IssueCertificate / GetOrderStatus /
// checkStatus / collectCertificate / parsePEMBundle.

func buildSectigoConnector(t *testing.T, baseURL string) *sectigo.Connector {
	t.Helper()
	c := sectigo.New(nil, slog.Default())
	cfg := sectigo.Config{
		BaseURL:     baseURL,
		CustomerURI: "tcust",
		Login:       "user",
		Password:    "pw",
		CertType:    1,
		OrgID:       2,
		Term:        365,
	}
	raw, _ := json.Marshal(cfg)
	if err := c.ValidateConfig(context.Background(), raw); err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}
	return c
}

// Sectigo's ValidateConfig hits /ssl/v1/types — need a valid response.
func sectigoValidateOK(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`[{"id":1,"name":"InstantSSL"}]`))
}

func TestSectigo_GetOrderStatus_InvalidSslId(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ssl/v1/types" {
			sectigoValidateOK(w)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := buildSectigoConnector(t, srv.URL)
	_, err := c.GetOrderStatus(context.Background(), "not-a-number")
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("expected 'invalid Sectigo ssl_id' error, got %v", err)
	}
}

func TestSectigo_CheckStatus_404_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ssl/v1/types" {
			sectigoValidateOK(w)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"description":"not found"}`))
	}))
	defer srv.Close()
	c := buildSectigoConnector(t, srv.URL)
	_, err := c.GetOrderStatus(context.Background(), "999")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("expected 404 status error, got %v", err)
	}
}

func TestSectigo_CheckStatus_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ssl/v1/types" {
			sectigoValidateOK(w)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()
	c := buildSectigoConnector(t, srv.URL)
	_, err := c.GetOrderStatus(context.Background(), "100")
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected parse error, got %v", err)
	}
}

func TestSectigo_GetOrderStatus_AppliedAndPending(t *testing.T) {
	cases := []struct {
		statusVal string
		want      string
	}{
		{"Applied", "pending"},
		{"Pending", "pending"},
		{"Rejected", "failed"},
		{"Revoked", "failed"},
		{"Expired", "failed"},
		{"Not Enrolled", "failed"},
		{"WeirdNewStatus", "pending"}, // unknown → default pending
	}
	for _, tc := range cases {
		t.Run(tc.statusVal, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/ssl/v1/types" {
					sectigoValidateOK(w)
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"` + tc.statusVal + `"}`))
			}))
			defer srv.Close()
			c := buildSectigoConnector(t, srv.URL)
			st, err := c.GetOrderStatus(context.Background(), "55001")
			if err != nil {
				t.Fatalf("GetOrderStatus: %v", err)
			}
			if st.Status != tc.want {
				t.Errorf("expected status=%q, got %q", tc.want, st.Status)
			}
		})
	}
}

func TestSectigo_CollectCertificate_BadRequest_TreatedAsPending(t *testing.T) {
	// Sectigo returns 400 with code -183 when cert approved but not yet generated.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/ssl/v1/types":
			sectigoValidateOK(w)
		case strings.HasPrefix(r.URL.Path, "/ssl/v1/collect/"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":-183,"description":"certificate not yet ready"}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"Issued"}`))
		}
	}))
	defer srv.Close()
	c := buildSectigoConnector(t, srv.URL)
	st, err := c.GetOrderStatus(context.Background(), "55001")
	if err != nil {
		t.Fatalf("GetOrderStatus: %v", err)
	}
	if st.Status != "pending" {
		t.Errorf("expected pending (cert not yet ready), got %q", st.Status)
	}
}

func TestSectigo_CollectCertificate_500_PropagatesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/ssl/v1/types":
			sectigoValidateOK(w)
		case strings.HasPrefix(r.URL.Path, "/ssl/v1/collect/"):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`internal error`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"Issued"}`))
		}
	}))
	defer srv.Close()
	c := buildSectigoConnector(t, srv.URL)
	_, err := c.GetOrderStatus(context.Background(), "55001")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("expected 500 error, got %v", err)
	}
}

func TestSectigo_CollectCertificate_MalformedPEM_FailsClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/ssl/v1/types":
			sectigoValidateOK(w)
		case strings.HasPrefix(r.URL.Path, "/ssl/v1/collect/"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not a pem"))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"Issued"}`))
		}
	}))
	defer srv.Close()
	c := buildSectigoConnector(t, srv.URL)
	_, err := c.GetOrderStatus(context.Background(), "55001")
	if err == nil {
		t.Errorf("expected error from malformed PEM bundle")
	}
}
