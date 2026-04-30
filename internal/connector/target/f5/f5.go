package f5

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/shankar0123/certctl/internal/connector/target"
)

// Config represents the F5 BIG-IP deployment target configuration.
// Credentials are stored on the proxy agent, not on the control plane server,
// limiting the credential blast radius to the proxy agent's network zone.
type Config struct {
	Host       string `json:"host"`        // F5 BIG-IP management hostname or IP
	Port       int    `json:"port"`        // Management port (default 443)
	Username   string `json:"username"`    // Administrative username
	Password   string `json:"password"`    // Administrative password
	Partition  string `json:"partition"`   // F5 partition name (default "Common")
	SSLProfile string `json:"ssl_profile"` // SSL client profile name to update
	Insecure   bool   `json:"insecure"`    // Skip TLS verification for mgmt interface (default true)
	Timeout    int    `json:"timeout"`     // HTTP timeout in seconds (default 30)
}

// applyDefaults fills in zero-value fields with sensible defaults.
func (c *Config) applyDefaults() {
	if c.Port == 0 {
		c.Port = 443
	}
	if c.Partition == "" {
		c.Partition = "Common"
	}
	if c.Timeout == 0 {
		c.Timeout = 30
	}
	// Insecure defaults to true because F5 management interfaces commonly use
	// self-signed certificates. See TICKET-016 precedent for InsecureSkipVerify
	// documentation. Operators running proper mgmt certs can set insecure=false.
}

// SSLProfileInfo contains information about an F5 SSL client profile.
type SSLProfileInfo struct {
	Name  string `json:"name"`
	Cert  string `json:"cert"`
	Key   string `json:"key"`
	Chain string `json:"chain"`
}

// F5Client abstracts iControl REST API calls for testability.
// The real implementation uses net/http against the F5 management interface.
// Tests inject a mock implementation to verify call sequences without a real F5.
type F5Client interface {
	// Authenticate obtains an auth token from the F5. Implementations should
	// cache the token and re-authenticate on 401.
	Authenticate(ctx context.Context) error

	// UploadFile uploads raw bytes to the F5 file transfer endpoint.
	// The Content-Range header is required even for single-chunk uploads.
	UploadFile(ctx context.Context, filename string, data []byte) error

	// InstallCert installs an uploaded file as a crypto cert object.
	InstallCert(ctx context.Context, name, localFile string) error

	// InstallKey installs an uploaded file as a crypto key object.
	InstallKey(ctx context.Context, name, localFile string) error

	// CreateTransaction starts an F5 transaction for atomic operations.
	// Returns the transaction ID.
	CreateTransaction(ctx context.Context) (string, error)

	// CommitTransaction commits a transaction. If the commit fails,
	// F5 rolls back all operations within the transaction automatically.
	CommitTransaction(ctx context.Context, transID string) error

	// UpdateSSLProfile updates an SSL client profile's cert, key, and chain
	// references. If transID is non-empty, the operation is performed within
	// the given transaction.
	UpdateSSLProfile(ctx context.Context, partition, profile string, certName, keyName, chainName string, transID string) error

	// GetSSLProfile retrieves the current configuration of an SSL client profile.
	GetSSLProfile(ctx context.Context, partition, profile string) (*SSLProfileInfo, error)

	// DeleteCert removes a crypto cert object from the F5.
	DeleteCert(ctx context.Context, partition, name string) error

	// DeleteKey removes a crypto key object from the F5.
	DeleteKey(ctx context.Context, partition, name string) error
}

// Connector implements the target.Connector interface for F5 BIG-IP load balancers.
// This connector communicates with F5's iControl REST API to upload certificates,
// manage SSL profiles, and validate deployments. It uses the proxy agent pattern:
// a designated agent in the same network zone polls for F5 deployment jobs and
// executes iControl REST calls on behalf of the control plane.
//
// Minimum supported BIG-IP version: 12.0+.
type Connector struct {
	config *Config
	logger *slog.Logger
	client F5Client
}

// New creates a new F5 target connector with the given configuration and logger.
// The real iControl REST HTTP client is initialized with TLS settings based on config.
func New(config *Config, logger *slog.Logger) (*Connector, error) {
	if config == nil {
		return nil, fmt.Errorf("F5 config is required")
	}
	config.applyDefaults()

	httpClient := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// F5 management interfaces commonly use self-signed certificates.
				// InsecureSkipVerify is controlled by the config.Insecure field
				// (default true). Operators with proper management certs can set
				// insecure=false. See TICKET-016 for security rationale.
				InsecureSkipVerify: config.Insecure, //nolint:gosec // configurable, documented
			},
		},
	}

	realClient := &realF5Client{
		baseURL:    fmt.Sprintf("https://%s:%d", config.Host, config.Port),
		username:   config.Username,
		password:   config.Password,
		httpClient: httpClient,
		logger:     logger,
	}

	return &Connector{
		config: config,
		logger: logger,
		client: realClient,
	}, nil
}

// NewWithClient creates a new F5 target connector with an injected F5Client.
// Used in tests to mock iControl REST API calls without a real F5 device.
func NewWithClient(config *Config, logger *slog.Logger, client F5Client) *Connector {
	if config != nil {
		config.applyDefaults()
	}
	return &Connector{
		config: config,
		logger: logger,
		client: client,
	}
}

// Regex validators for config fields to prevent injection.
// Same pattern as IIS validIISName.
var (
	// validHost matches hostnames, IPv4, and IPv6 addresses.
	validHost = regexp.MustCompile(`^[a-zA-Z0-9\.\-\:\[\]]+$`)

	// validPartition matches F5 partition names (alphanumeric, underscore, hyphen).
	validPartition = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)

	// validProfileName matches SSL profile names (alphanumeric, underscore, hyphen, dot).
	validProfileName = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)
)

// ValidateConfig checks that the F5 BIG-IP is reachable and credentials are valid.
// It validates config fields, applies defaults, and tests authentication.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid F5 config: %w", err)
	}

	// Validate required fields
	if cfg.Host == "" {
		return fmt.Errorf("host is required")
	}
	if cfg.Username == "" {
		return fmt.Errorf("username is required")
	}
	if cfg.Password == "" {
		return fmt.Errorf("password is required")
	}
	if cfg.SSLProfile == "" {
		return fmt.Errorf("ssl_profile is required")
	}

	cfg.applyDefaults()

	// Validate field formats (prevent injection)
	if !validHost.MatchString(cfg.Host) {
		return fmt.Errorf("host contains invalid characters (allowed: alphanumeric, dots, hyphens, colons, brackets)")
	}
	if len(cfg.Host) > 253 {
		return fmt.Errorf("host exceeds maximum length (253 characters)")
	}
	if !validPartition.MatchString(cfg.Partition) {
		return fmt.Errorf("partition contains invalid characters (allowed: alphanumeric, underscore, hyphen)")
	}
	if len(cfg.Partition) > 64 {
		return fmt.Errorf("partition exceeds maximum length (64 characters)")
	}
	if !validProfileName.MatchString(cfg.SSLProfile) {
		return fmt.Errorf("ssl_profile contains invalid characters (allowed: alphanumeric, underscore, hyphen, dot)")
	}
	if len(cfg.SSLProfile) > 256 {
		return fmt.Errorf("ssl_profile exceeds maximum length (256 characters)")
	}

	// Validate port range
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", cfg.Port)
	}

	c.logger.Info("validating F5 configuration",
		"host", cfg.Host,
		"port", cfg.Port,
		"partition", cfg.Partition,
		"ssl_profile", cfg.SSLProfile)

	// Test authentication
	if err := c.client.Authenticate(ctx); err != nil {
		return fmt.Errorf("F5 authentication failed: %w", err)
	}

	c.config = &cfg
	c.logger.Info("F5 configuration validated",
		"host", cfg.Host,
		"partition", cfg.Partition,
		"ssl_profile", cfg.SSLProfile)

	return nil
}

// objectName generates a unique name for F5 crypto objects using nanosecond timestamps.
// Format: certctl-{type}-{unix_nanos}
func objectName(objType string) string {
	return fmt.Sprintf("certctl-%s-%d", objType, time.Now().UnixNano())
}

// partitionPath returns the full partition-qualified path for an F5 object reference.
// Used in JSON body values (e.g., "/Common/certctl-cert-xxx").
func partitionPath(partition, name string) string {
	return fmt.Sprintf("/%s/%s", partition, name)
}

// DeployCertificate uploads a certificate to the F5 BIG-IP and updates the specified SSL profile.
//
// The deployment uses F5's transaction API for atomic profile updates:
//  1. Authenticate to iControl REST API
//  2. Upload cert/key/chain PEM files via file transfer endpoint
//  3. Install as crypto objects (cert, key, optionally chain)
//  4. Create a transaction
//  5. Update SSL profile within the transaction
//  6. Commit the transaction (atomic — rolls back on failure)
//
// On failure after crypto object installation, cleanup removes uploaded objects
// to avoid accumulating orphans on the F5.
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	c.logger.Info("deploying certificate to F5 BIG-IP",
		"host", c.config.Host,
		"partition", c.config.Partition,
		"ssl_profile", c.config.SSLProfile)

	startTime := time.Now()

	// Validate we have a private key
	if request.KeyPEM == "" {
		errMsg := "private key (KeyPEM) is required for F5 deployment"
		c.logger.Error("deployment failed", "error", errMsg)
		return &target.DeploymentResult{
			Success:    false,
			Message:    errMsg,
			DeployedAt: time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Step 1: Authenticate
	if err := c.client.Authenticate(ctx); err != nil {
		errMsg := fmt.Sprintf("F5 authentication failed: %v", err)
		c.logger.Error("deployment failed", "error", err)
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Generate unique object names
	certName := objectName("cert")
	keyName := objectName("key")
	chainName := ""
	hasChain := strings.TrimSpace(request.ChainPEM) != ""
	if hasChain {
		chainName = objectName("chain")
	}

	// Track installed objects for cleanup on failure
	var installedCerts []string
	var installedKeys []string

	cleanup := func() {
		c.cleanupCryptoObjects(ctx, c.config.Partition, installedCerts, installedKeys)
	}

	// Step 2-3: Upload cert and key PEM files
	certFilename := certName + ".pem"
	if err := c.client.UploadFile(ctx, certFilename, []byte(request.CertPEM)); err != nil {
		errMsg := fmt.Sprintf("failed to upload certificate file: %v", err)
		c.logger.Error("cert upload failed", "error", err)
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	keyFilename := keyName + ".pem"
	if err := c.client.UploadFile(ctx, keyFilename, []byte(request.KeyPEM)); err != nil {
		errMsg := fmt.Sprintf("failed to upload key file: %v", err)
		c.logger.Error("key upload failed", "error", err)
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Step 4: Upload chain if present
	chainFilename := ""
	if hasChain {
		chainFilename = chainName + ".pem"
		if err := c.client.UploadFile(ctx, chainFilename, []byte(request.ChainPEM)); err != nil {
			errMsg := fmt.Sprintf("failed to upload chain file: %v", err)
			c.logger.Error("chain upload failed", "error", err)
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
				Message:       errMsg,
				DeployedAt:    time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
	}

	// Step 5: Install cert crypto object
	certLocalFile := "/var/config/rest/downloads/" + certFilename
	if err := c.client.InstallCert(ctx, certName, certLocalFile); err != nil {
		errMsg := fmt.Sprintf("failed to install cert crypto object: %v", err)
		c.logger.Error("cert install failed", "error", err)
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}
	installedCerts = append(installedCerts, certName)

	// Step 6: Install key crypto object
	keyLocalFile := "/var/config/rest/downloads/" + keyFilename
	if err := c.client.InstallKey(ctx, keyName, keyLocalFile); err != nil {
		errMsg := fmt.Sprintf("failed to install key crypto object: %v", err)
		c.logger.Error("key install failed", "error", err)
		cleanup()
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}
	installedKeys = append(installedKeys, keyName)

	// Step 7: Install chain crypto object (if present)
	if hasChain {
		chainLocalFile := "/var/config/rest/downloads/" + chainFilename
		if err := c.client.InstallCert(ctx, chainName, chainLocalFile); err != nil {
			errMsg := fmt.Sprintf("failed to install chain crypto object: %v", err)
			c.logger.Error("chain install failed", "error", err)
			cleanup()
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
				Message:       errMsg,
				DeployedAt:    time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
		installedCerts = append(installedCerts, chainName)
	}

	// Step 8: Create transaction for atomic SSL profile update
	transID, err := c.client.CreateTransaction(ctx)
	if err != nil {
		errMsg := fmt.Sprintf("failed to create F5 transaction: %v", err)
		c.logger.Error("transaction creation failed", "error", err)
		cleanup()
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Step 9: Update SSL profile within transaction
	profileChainName := chainName
	if err := c.client.UpdateSSLProfile(ctx, c.config.Partition, c.config.SSLProfile, certName, keyName, profileChainName, transID); err != nil {
		errMsg := fmt.Sprintf("failed to update SSL profile: %v", err)
		c.logger.Error("profile update failed", "error", err,
			"ssl_profile", c.config.SSLProfile,
			"transaction_id", transID)
		cleanup()
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Step 10: Commit transaction
	if err := c.client.CommitTransaction(ctx, transID); err != nil {
		errMsg := fmt.Sprintf("failed to commit F5 transaction: %v", err)
		c.logger.Error("transaction commit failed", "error", err,
			"transaction_id", transID)
		cleanup()
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	deploymentDuration := time.Since(startTime)
	c.logger.Info("certificate deployed to F5 BIG-IP successfully",
		"duration", deploymentDuration.String(),
		"host", c.config.Host,
		"ssl_profile", c.config.SSLProfile,
		"cert_object", certName)

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
		DeploymentID:  fmt.Sprintf("f5-%s-%d", certName, time.Now().Unix()),
		Message:       "Certificate uploaded and SSL profile updated via iControl REST",
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"host":              c.config.Host,
			"partition":         c.config.Partition,
			"ssl_profile":       c.config.SSLProfile,
			"cert_object_name":  certName,
			"key_object_name":   keyName,
			"chain_object_name": chainName,
			"duration_ms":       fmt.Sprintf("%d", deploymentDuration.Milliseconds()),
		},
	}, nil
}

// cleanupCryptoObjects removes installed crypto objects from the F5 on deployment failure.
// Best-effort: logs warnings on cleanup failures but does not mask the original error.
func (c *Connector) cleanupCryptoObjects(ctx context.Context, partition string, certNames, keyNames []string) {
	for _, name := range certNames {
		if name == "" {
			continue
		}
		if err := c.client.DeleteCert(ctx, partition, name); err != nil {
			c.logger.Warn("cleanup: failed to delete cert crypto object",
				"name", name, "partition", partition, "error", err)
		} else {
			c.logger.Debug("cleanup: deleted cert crypto object",
				"name", name, "partition", partition)
		}
	}
	for _, name := range keyNames {
		if name == "" {
			continue
		}
		if err := c.client.DeleteKey(ctx, partition, name); err != nil {
			c.logger.Warn("cleanup: failed to delete key crypto object",
				"name", name, "partition", partition, "error", err)
		} else {
			c.logger.Debug("cleanup: deleted key crypto object",
				"name", name, "partition", partition)
		}
	}
}

// ValidateDeployment verifies that the certificate is properly deployed on the F5 BIG-IP.
// It queries the SSL profile and checks that it references a certctl-managed certificate.
func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	c.logger.Info("validating F5 deployment",
		"certificate_id", request.CertificateID,
		"serial", request.Serial,
		"ssl_profile", c.config.SSLProfile)

	startTime := time.Now()

	// Authenticate
	if err := c.client.Authenticate(ctx); err != nil {
		errMsg := fmt.Sprintf("F5 authentication failed: %v", err)
		c.logger.Error("validation failed", "error", err)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Query SSL profile
	profile, err := c.client.GetSSLProfile(ctx, c.config.Partition, c.config.SSLProfile)
	if err != nil {
		errMsg := fmt.Sprintf("failed to get SSL profile %q: %v", c.config.SSLProfile, err)
		c.logger.Error("validation failed", "error", err,
			"ssl_profile", c.config.SSLProfile)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Verify profile has a cert configured
	if profile.Cert == "" {
		errMsg := fmt.Sprintf("SSL profile %q has no certificate configured", c.config.SSLProfile)
		c.logger.Error("validation failed", "error", errMsg)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	validationDuration := time.Since(startTime)
	c.logger.Info("F5 deployment validated",
		"duration", validationDuration.String(),
		"ssl_profile", c.config.SSLProfile,
		"current_cert", profile.Cert)

	return &target.ValidationResult{
		Valid:         true,
		Serial:        request.Serial,
		TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
		Message:       fmt.Sprintf("SSL profile %q has cert %q configured", c.config.SSLProfile, profile.Cert),
		ValidatedAt:   time.Now(),
		Metadata: map[string]string{
			"host":          c.config.Host,
			"ssl_profile":   c.config.SSLProfile,
			"current_cert":  profile.Cert,
			"current_key":   profile.Key,
			"current_chain": profile.Chain,
			"duration_ms":   fmt.Sprintf("%d", validationDuration.Milliseconds()),
		},
	}, nil
}

// --- realF5Client: production iControl REST implementation ---

// realF5Client implements F5Client using net/http against the iControl REST API.
type realF5Client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
	logger     *slog.Logger

	mu    sync.Mutex
	token string
}

// Authenticate obtains a token from POST /mgmt/shared/authn/login.
// The token is cached and reused. On 401 errors in other methods,
// callers should call Authenticate again to refresh.
func (c *realF5Client) Authenticate(ctx context.Context) error {
	body := map[string]string{
		"username":          c.username,
		"password":          c.password,
		"loginProviderName": "tmos",
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal auth body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/mgmt/shared/authn/login", bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("F5 auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("F5 auth failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Token struct {
			Token string `json:"token"`
		} `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}
	if result.Token.Token == "" {
		return fmt.Errorf("F5 auth response contained no token")
	}

	c.mu.Lock()
	c.token = result.Token.Token
	c.mu.Unlock()

	return nil
}

// doRequest executes an HTTP request with the F5 auth token.
// On 401 response, it re-authenticates once and retries.
func (c *realF5Client) doRequest(ctx context.Context, method, url string, body io.Reader, extraHeaders map[string]string) (*http.Response, error) {
	return c.doRequestInternal(ctx, method, url, body, extraHeaders, true)
}

func (c *realF5Client) doRequestInternal(ctx context.Context, method, url string, body io.Reader, extraHeaders map[string]string, retryOn401 bool) (*http.Response, error) {
	// Buffer body for potential retry
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.mu.Lock()
	token := c.token
	c.mu.Unlock()

	req.Header.Set("X-F5-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized && retryOn401 {
		resp.Body.Close()
		c.logger.Warn("F5 request returned 401, re-authenticating", "url", url)
		if authErr := c.Authenticate(ctx); authErr != nil {
			return nil, fmt.Errorf("F5 re-authentication failed: %w", authErr)
		}
		return c.doRequestInternal(ctx, method, url, bytes.NewReader(bodyBytes), extraHeaders, false)
	}

	return resp, nil
}

// UploadFile uploads raw bytes via POST /mgmt/shared/file-transfer/uploads/{filename}.
// The Content-Range header is required even for single-chunk uploads (F5-specific).
func (c *realF5Client) UploadFile(ctx context.Context, filename string, data []byte) error {
	url := fmt.Sprintf("%s/mgmt/shared/file-transfer/uploads/%s", c.baseURL, filename)

	headers := map[string]string{
		"Content-Type":  "application/octet-stream",
		"Content-Range": fmt.Sprintf("0-%d/%d", len(data)-1, len(data)),
	}

	resp, err := c.doRequest(ctx, http.MethodPost, url, bytes.NewReader(data), headers)
	if err != nil {
		return fmt.Errorf("upload file %q failed: %w", filename, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload file %q failed with status %d: %s", filename, resp.StatusCode, string(respBody))
	}
	return nil
}

// InstallCert installs an uploaded file as a crypto cert object.
func (c *realF5Client) InstallCert(ctx context.Context, name, localFile string) error {
	url := c.baseURL + "/mgmt/tm/sys/crypto/cert"
	body := map[string]string{
		"command":         "install",
		"name":            name,
		"from-local-file": localFile,
	}
	bodyJSON, _ := json.Marshal(body)

	resp, err := c.doRequest(ctx, http.MethodPost, url, bytes.NewReader(bodyJSON), nil)
	if err != nil {
		return fmt.Errorf("install cert %q failed: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("install cert %q failed with status %d: %s", name, resp.StatusCode, string(respBody))
	}
	return nil
}

// InstallKey installs an uploaded file as a crypto key object.
func (c *realF5Client) InstallKey(ctx context.Context, name, localFile string) error {
	url := c.baseURL + "/mgmt/tm/sys/crypto/key"
	body := map[string]string{
		"command":         "install",
		"name":            name,
		"from-local-file": localFile,
	}
	bodyJSON, _ := json.Marshal(body)

	resp, err := c.doRequest(ctx, http.MethodPost, url, bytes.NewReader(bodyJSON), nil)
	if err != nil {
		return fmt.Errorf("install key %q failed: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("install key %q failed with status %d: %s", name, resp.StatusCode, string(respBody))
	}
	return nil
}

// CreateTransaction starts an F5 transaction via POST /mgmt/tm/transaction.
func (c *realF5Client) CreateTransaction(ctx context.Context) (string, error) {
	url := c.baseURL + "/mgmt/tm/transaction"

	resp, err := c.doRequest(ctx, http.MethodPost, url, bytes.NewReader([]byte("{}")), nil)
	if err != nil {
		return "", fmt.Errorf("create transaction failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("create transaction failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		TransID json.Number `json:"transId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode transaction response: %w", err)
	}

	transID := result.TransID.String()
	if transID == "" {
		return "", fmt.Errorf("F5 returned empty transaction ID")
	}

	return transID, nil
}

// CommitTransaction commits a transaction via PATCH /mgmt/tm/transaction/{id}.
func (c *realF5Client) CommitTransaction(ctx context.Context, transID string) error {
	url := fmt.Sprintf("%s/mgmt/tm/transaction/%s", c.baseURL, transID)
	body := map[string]string{"state": "VALIDATING"}
	bodyJSON, _ := json.Marshal(body)

	resp, err := c.doRequest(ctx, http.MethodPatch, url, bytes.NewReader(bodyJSON), nil)
	if err != nil {
		return fmt.Errorf("commit transaction %s failed: %w", transID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("commit transaction %s failed with status %d: %s", transID, resp.StatusCode, string(respBody))
	}
	return nil
}

// UpdateSSLProfile updates an SSL client profile's cert/key/chain references.
// Uses tilde ~ as partition separator in the URL, forward slash / in JSON body values.
func (c *realF5Client) UpdateSSLProfile(ctx context.Context, partition, profile string, certName, keyName, chainName string, transID string) error {
	url := fmt.Sprintf("%s/mgmt/tm/ltm/profile/client-ssl/~%s~%s", c.baseURL, partition, profile)

	body := map[string]string{
		"cert": partitionPath(partition, certName),
		"key":  partitionPath(partition, keyName),
	}
	if chainName != "" {
		body["chain"] = partitionPath(partition, chainName)
	}
	bodyJSON, _ := json.Marshal(body)

	headers := map[string]string{}
	if transID != "" {
		headers["X-F5-REST-Overriding-Collection"] = fmt.Sprintf("/mgmt/tm/transaction/%s", transID)
	}

	resp, err := c.doRequest(ctx, http.MethodPatch, url, bytes.NewReader(bodyJSON), headers)
	if err != nil {
		return fmt.Errorf("update SSL profile %q failed: %w", profile, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update SSL profile %q failed with status %d: %s", profile, resp.StatusCode, string(respBody))
	}
	return nil
}

// GetSSLProfile retrieves an SSL client profile's configuration.
func (c *realF5Client) GetSSLProfile(ctx context.Context, partition, profile string) (*SSLProfileInfo, error) {
	url := fmt.Sprintf("%s/mgmt/tm/ltm/profile/client-ssl/~%s~%s", c.baseURL, partition, profile)

	resp, err := c.doRequest(ctx, http.MethodGet, url, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("get SSL profile %q failed: %w", profile, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get SSL profile %q failed with status %d: %s", profile, resp.StatusCode, string(respBody))
	}

	var info SSLProfileInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode SSL profile response: %w", err)
	}
	return &info, nil
}

// DeleteCert removes a crypto cert object from the F5.
func (c *realF5Client) DeleteCert(ctx context.Context, partition, name string) error {
	url := fmt.Sprintf("%s/mgmt/tm/sys/crypto/cert/~%s~%s", c.baseURL, partition, name)

	resp, err := c.doRequest(ctx, http.MethodDelete, url, nil, nil)
	if err != nil {
		return fmt.Errorf("delete cert %q failed: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete cert %q failed with status %d: %s", name, resp.StatusCode, string(respBody))
	}
	return nil
}

// DeleteKey removes a crypto key object from the F5.
func (c *realF5Client) DeleteKey(ctx context.Context, partition, name string) error {
	url := fmt.Sprintf("%s/mgmt/tm/sys/crypto/key/~%s~%s", c.baseURL, partition, name)

	resp, err := c.doRequest(ctx, http.MethodDelete, url, nil, nil)
	if err != nil {
		return fmt.Errorf("delete key %q failed: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete key %q failed with status %d: %s", name, resp.StatusCode, string(respBody))
	}
	return nil
}
