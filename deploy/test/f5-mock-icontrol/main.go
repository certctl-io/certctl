// Package main implements the f5-mock-icontrol sidecar — an in-tree
// Go server that implements the subset of F5's iControl REST API
// the certctl F5 connector exercises. Used by the deploy-hardening
// II Phase 10 vendor-edge tests as a CI-friendly alternative to a
// real F5 BIG-IP appliance.
//
// Per frozen decision 0.3 (deploy-hardening II): the operator-supplied
// real F5 vagrant box documented in docs/connector-f5.md is the
// validation tier above the mock. CI runs against this mock; paying-
// customer validation runs against the real F5.
//
// Implements:
//   - POST /mgmt/shared/authn/login (token-based auth)
//   - POST /mgmt/shared/file-transfer/uploads/<filename> (multi-chunk)
//   - POST /mgmt/tm/sys/crypto/cert (install cert)
//   - POST /mgmt/tm/sys/crypto/key (install key)
//   - POST /mgmt/tm/transaction (create txn)
//   - POST /mgmt/tm/transaction/<txn-id> (commit txn)
//   - PATCH /mgmt/tm/ltm/profile/client-ssl/<name> (update SSL profile)
//   - GET /mgmt/tm/ltm/profile/client-ssl/<name> (read SSL profile)
//   - DELETE /mgmt/tm/sys/crypto/cert/<name> (remove cert)
//   - DELETE /mgmt/tm/sys/crypto/key/<name> (remove key)
//
// State: in-memory map per running process. Lost on container restart.
// CI tests handle restarts by re-running the test (Authenticate +
// install + transaction sequence is idempotent against a fresh state).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// state is the mock server's in-memory view of an F5 BIG-IP.
type state struct {
	mu sync.RWMutex
	// uploads holds raw uploaded bytes keyed by filename.
	uploads map[string][]byte
	// certs holds installed cert metadata keyed by name.
	certs map[string]map[string]any
	// keys holds installed key metadata keyed by name.
	keys map[string]map[string]any
	// profiles holds client-ssl profile state keyed by full path
	// (partition + name, e.g., "~Common~my-ssl-profile").
	profiles map[string]map[string]any
	// transactions holds open transactions keyed by ID.
	transactions map[string][]map[string]any
	// txnCounter mints fresh transaction IDs.
	txnCounter atomic.Uint64
	// authToken is the singleton bearer token issued at /authn/login.
	// Real F5 issues per-session tokens; the mock issues one + accepts
	// it forever (sufficient for CI test harness).
	authToken string
}

func newState() *state {
	return &state{
		uploads:      make(map[string][]byte),
		certs:        make(map[string]map[string]any),
		keys:         make(map[string]map[string]any),
		profiles:     make(map[string]map[string]any),
		transactions: make(map[string][]map[string]any),
		authToken:    "mock-bearer-token-do-not-use-in-prod",
	}
}

func main() {
	s := newState()
	mux := http.NewServeMux()

	mux.HandleFunc("/mgmt/shared/authn/login", s.handleLogin)
	mux.HandleFunc("/mgmt/shared/file-transfer/uploads/", s.handleUpload)
	mux.HandleFunc("/mgmt/tm/sys/crypto/cert", s.handleInstallCert)
	mux.HandleFunc("/mgmt/tm/sys/crypto/cert/", s.handleDeleteCert)
	mux.HandleFunc("/mgmt/tm/sys/crypto/key", s.handleInstallKey)
	mux.HandleFunc("/mgmt/tm/sys/crypto/key/", s.handleDeleteKey)
	mux.HandleFunc("/mgmt/tm/transaction", s.handleCreateTxn)
	mux.HandleFunc("/mgmt/tm/transaction/", s.handleCommitTxn)
	mux.HandleFunc("/mgmt/tm/ltm/profile/client-ssl/", s.handleProfile)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	log.Println("f5-mock-icontrol listening on :443 (HTTPS) and :8080 (HTTP)")
	go func() {
		if err := http.ListenAndServe(":8080", mux); err != nil {
			log.Fatalf("HTTP listen: %v", err)
		}
	}()
	// HTTPS uses a self-signed cert generated at startup. Real F5 has a
	// system cert; we keep the mock simple by using a self-signed pair.
	cert, key := selfSignedCert()
	srv := &http.Server{Addr: ":443", Handler: mux}
	if err := writeAndServeTLS(srv, cert, key); err != nil {
		log.Fatalf("HTTPS listen: %v", err)
	}
}

func (s *state) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("bad body: %v", err), http.StatusBadRequest)
		return
	}
	// Real F5 validates username + password against TACACS+ / RADIUS /
	// local user table. Mock accepts any non-empty credentials.
	user, _ := req["username"].(string)
	pass, _ := req["password"].(string)
	if user == "" || pass == "" {
		http.Error(w, "missing credentials", http.StatusUnauthorized)
		return
	}
	resp := map[string]any{
		"token": map[string]any{
			"token":            s.authToken,
			"name":             user,
			"timeout":          3600,
			"expirationMicros": 9999999999,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *state) handleUpload(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	filename := strings.TrimPrefix(r.URL.Path, "/mgmt/shared/file-transfer/uploads/")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("read body: %v", err), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.uploads[filename] = append(s.uploads[filename], body...)
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"localFilePath": "/var/config/rest/downloads/" + filename})
}

func (s *state) handleInstallCert(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("bad body: %v", err), http.StatusBadRequest)
		return
	}
	name, _ := req["name"].(string)
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.certs[name] = req
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(req)
}

func (s *state) handleInstallKey(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("bad body: %v", err), http.StatusBadRequest)
		return
	}
	name, _ := req["name"].(string)
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.keys[name] = req
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(req)
}

func (s *state) handleCreateTxn(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := fmt.Sprintf("txn-%d", s.txnCounter.Add(1))
	s.mu.Lock()
	s.transactions[id] = []map[string]any{}
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"transId": id, "state": "STARTED"})
}

func (s *state) handleCommitTxn(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/mgmt/tm/transaction/")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.transactions[id]; !ok {
		http.Error(w, "transaction not found", http.StatusNotFound)
		return
	}
	delete(s.transactions, id)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"transId": id, "state": "COMPLETED"})
}

func (s *state) handleProfile(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/mgmt/tm/ltm/profile/client-ssl/")
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		p, ok := s.profiles[name]
		s.mu.RUnlock()
		if !ok {
			// Return an empty default profile (mock convenience).
			p = map[string]any{"name": name, "cert": "", "key": "", "chain": ""}
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(p)
	case http.MethodPatch, http.MethodPut:
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("bad body: %v", err), http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		if existing, ok := s.profiles[name]; ok {
			for k, v := range req {
				existing[k] = v
			}
		} else {
			req["name"] = name
			s.profiles[name] = req
		}
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(s.profiles[name])
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *state) handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/mgmt/tm/sys/crypto/cert/")
	s.mu.Lock()
	delete(s.certs, name)
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (s *state) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/mgmt/tm/sys/crypto/key/")
	s.mu.Lock()
	delete(s.keys, name)
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (s *state) authOK(r *http.Request) bool {
	tok := r.Header.Get("X-F5-Auth-Token")
	if tok == "" {
		// Fall back to bearer
		bearer := r.Header.Get("Authorization")
		tok = strings.TrimPrefix(bearer, "Bearer ")
	}
	return tok == s.authToken
}
