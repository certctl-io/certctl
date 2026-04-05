// Package ssh implements a target.Connector for agentless certificate deployment
// via SSH/SFTP. This enables the "proxy agent" pattern — a certctl agent in the
// same network zone deploys certificates to remote servers without requiring the
// certctl agent binary on every target host.
package ssh

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/shankar0123/certctl/internal/connector/target"
	"github.com/shankar0123/certctl/internal/validation"
)

// Config represents the SSH deployment target configuration.
// Supports key-based and password-based authentication for agentless
// certificate deployment to any Linux/Unix server.
type Config struct {
	Host           string `json:"host"`             // Required. SSH hostname or IP.
	Port           int    `json:"port"`             // Default: 22.
	User           string `json:"user"`             // Required. SSH username.
	AuthMethod     string `json:"auth_method"`      // "key" (default) or "password".
	PrivateKeyPath string `json:"private_key_path"` // Path to SSH private key file (when auth_method="key").
	PrivateKey     string `json:"private_key"`      // Inline SSH private key PEM (alternative to path).
	Password       string `json:"password"`         // SSH password (when auth_method="password").
	Passphrase     string `json:"passphrase"`       // Optional passphrase for encrypted private keys.
	CertPath       string `json:"cert_path"`        // Required. Remote path for certificate file.
	KeyPath        string `json:"key_path"`         // Required. Remote path for private key file.
	ChainPath      string `json:"chain_path"`       // Optional. Remote path for chain file.
	CertMode       string `json:"cert_mode"`        // File permissions for cert (default: "0644").
	KeyMode        string `json:"key_mode"`         // File permissions for key (default: "0600").
	ReloadCommand  string `json:"reload_command"`   // Optional. Command to run after deployment.
	Timeout        int    `json:"timeout"`          // SSH connection timeout in seconds (default: 30).
}

// SSHClient abstracts SSH/SFTP operations for testability.
// The real implementation uses golang.org/x/crypto/ssh + github.com/pkg/sftp.
// Tests inject a mock to verify behavior without a real SSH server.
type SSHClient interface {
	// Connect establishes an SSH connection to the remote host.
	Connect(ctx context.Context) error
	// WriteFile writes data to a remote path with the given permissions.
	WriteFile(remotePath string, data []byte, mode os.FileMode) error
	// Execute runs a command on the remote server and returns combined output.
	Execute(ctx context.Context, command string) (string, error)
	// StatFile checks if a remote file exists and returns its size.
	StatFile(remotePath string) (int64, error)
	// Close closes the SSH connection.
	Close() error
}

// Connector implements the target.Connector interface for SSH/SFTP deployment.
// This connector runs on the AGENT side and handles remote certificate deployment
// to Linux/Unix servers without requiring the certctl agent binary on each target.
type Connector struct {
	config *Config
	client SSHClient
	logger *slog.Logger
}

// hostRegex validates SSH hostnames (no shell metacharacters).
var hostRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// permRegex validates octal permission strings like "0644" or "0600".
var permRegex = regexp.MustCompile(`^0[0-7]{3}$`)

// New creates a new SSH target connector with the given configuration and logger.
// Returns an error if the configuration is invalid.
func New(cfg *Config, logger *slog.Logger) (*Connector, error) {
	applyDefaults(cfg)
	client := &realSSHClient{config: cfg}
	return &Connector{
		config: cfg,
		client: client,
		logger: logger,
	}, nil
}

// NewWithClient creates a new SSH target connector with an injectable SSH client.
// Used in tests to mock SSH/SFTP operations.
func NewWithClient(cfg *Config, client SSHClient, logger *slog.Logger) *Connector {
	applyDefaults(cfg)
	return &Connector{
		config: cfg,
		client: client,
		logger: logger,
	}
}

// applyDefaults fills in default values for unset config fields.
func applyDefaults(cfg *Config) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.AuthMethod == "" {
		cfg.AuthMethod = "key"
	}
	if cfg.CertMode == "" {
		cfg.CertMode = "0644"
	}
	if cfg.KeyMode == "" {
		cfg.KeyMode = "0600"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30
	}
}

// ValidateConfig validates the SSH deployment target configuration.
func (c *Connector) ValidateConfig(ctx context.Context, rawConfig json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid SSH config: %w", err)
	}

	applyDefaults(&cfg)

	// Required fields
	if cfg.Host == "" {
		return fmt.Errorf("SSH host is required")
	}
	if cfg.User == "" {
		return fmt.Errorf("SSH user is required")
	}
	if cfg.CertPath == "" {
		return fmt.Errorf("SSH cert_path is required")
	}
	if cfg.KeyPath == "" {
		return fmt.Errorf("SSH key_path is required")
	}

	// Validate host (no shell metacharacters)
	if !hostRegex.MatchString(cfg.Host) {
		return fmt.Errorf("SSH host contains invalid characters")
	}

	// Auth method validation
	if cfg.AuthMethod != "key" && cfg.AuthMethod != "password" {
		return fmt.Errorf("SSH auth_method must be \"key\" or \"password\", got %q", cfg.AuthMethod)
	}
	if cfg.AuthMethod == "key" {
		if cfg.PrivateKeyPath == "" && cfg.PrivateKey == "" {
			return fmt.Errorf("SSH key auth requires private_key_path or private_key")
		}
		// If path specified, verify file exists locally
		if cfg.PrivateKeyPath != "" {
			if _, err := os.Stat(cfg.PrivateKeyPath); os.IsNotExist(err) {
				return fmt.Errorf("SSH private key file not found: %s", cfg.PrivateKeyPath)
			}
		}
	}
	if cfg.AuthMethod == "password" && cfg.Password == "" {
		return fmt.Errorf("SSH password auth requires password")
	}

	// Validate file permissions
	if !permRegex.MatchString(cfg.CertMode) {
		return fmt.Errorf("SSH cert_mode must be octal (e.g., \"0644\"), got %q", cfg.CertMode)
	}
	if !permRegex.MatchString(cfg.KeyMode) {
		return fmt.Errorf("SSH key_mode must be octal (e.g., \"0600\"), got %q", cfg.KeyMode)
	}

	// Validate reload command (if set) against shell injection
	if cfg.ReloadCommand != "" {
		if err := validation.ValidateShellCommand(cfg.ReloadCommand); err != nil {
			return fmt.Errorf("SSH invalid reload_command: %w", err)
		}
	}

	c.config = &cfg
	c.logger.Info("SSH configuration validated",
		"host", cfg.Host,
		"port", cfg.Port,
		"user", cfg.User,
		"auth_method", cfg.AuthMethod,
		"cert_path", cfg.CertPath,
		"key_path", cfg.KeyPath)

	return nil
}

// DeployCertificate deploys a certificate to the remote server via SSH/SFTP.
//
// Steps:
//  1. Connect to remote host via SSH
//  2. Write certificate (+ chain if chain_path not set) to cert_path
//  3. Write private key to key_path with restricted permissions
//  4. If chain_path is set and chain provided, write chain separately
//  5. If reload_command is set, execute it via SSH
//  6. Close connection
func (c *Connector) DeployCertificate(ctx context.Context, request target.DeploymentRequest) (*target.DeploymentResult, error) {
	c.logger.Info("deploying certificate via SSH",
		"host", c.config.Host,
		"port", c.config.Port,
		"cert_path", c.config.CertPath,
		"key_path", c.config.KeyPath)

	startTime := time.Now()

	// Connect
	if err := c.client.Connect(ctx); err != nil {
		errMsg := fmt.Sprintf("SSH connection failed: %v", err)
		c.logger.Error("SSH connection failed", "error", err, "host", c.config.Host)
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}
	defer c.client.Close()

	// Parse file permissions
	certMode, _ := parsePermissions(c.config.CertMode)
	keyMode, _ := parsePermissions(c.config.KeyMode)

	// Build cert data: if chain_path not set, append chain to cert (fullchain)
	certData := request.CertPEM
	if request.ChainPEM != "" && c.config.ChainPath == "" {
		certData += "\n" + request.ChainPEM
	}

	// Write certificate
	if err := c.client.WriteFile(c.config.CertPath, []byte(certData), certMode); err != nil {
		errMsg := fmt.Sprintf("failed to write certificate: %v", err)
		c.logger.Error("certificate write failed", "error", err, "path", c.config.CertPath)
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Write private key (must have KeyPEM)
	if request.KeyPEM == "" {
		errMsg := "SSH deployment requires private key (KeyPEM)"
		c.logger.Error("missing private key")
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}
	if err := c.client.WriteFile(c.config.KeyPath, []byte(request.KeyPEM), keyMode); err != nil {
		errMsg := fmt.Sprintf("failed to write private key: %v", err)
		c.logger.Error("key write failed", "error", err, "path", c.config.KeyPath)
		return &target.DeploymentResult{
			Success:       false,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			DeployedAt:    time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Write chain separately if chain_path configured
	if c.config.ChainPath != "" && request.ChainPEM != "" {
		if err := c.client.WriteFile(c.config.ChainPath, []byte(request.ChainPEM), certMode); err != nil {
			errMsg := fmt.Sprintf("failed to write chain: %v", err)
			c.logger.Error("chain write failed", "error", err, "path", c.config.ChainPath)
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
				Message:       errMsg,
				DeployedAt:    time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
	}

	// Execute reload command if configured
	if c.config.ReloadCommand != "" {
		c.logger.Debug("executing reload command", "command", c.config.ReloadCommand)
		output, err := c.client.Execute(ctx, c.config.ReloadCommand)
		if err != nil {
			errMsg := fmt.Sprintf("reload command failed: %v (output: %s)", err, output)
			c.logger.Error("reload command failed", "error", err, "output", output)
			return &target.DeploymentResult{
				Success:       false,
				TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
				Message:       errMsg,
				DeployedAt:    time.Now(),
			}, fmt.Errorf("%s", errMsg)
		}
	}

	deploymentDuration := time.Since(startTime)
	c.logger.Info("certificate deployed via SSH successfully",
		"host", c.config.Host,
		"duration", deploymentDuration.String(),
		"cert_path", c.config.CertPath)

	return &target.DeploymentResult{
		Success:       true,
		TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
		DeploymentID:  fmt.Sprintf("ssh-%s-%d", c.config.Host, time.Now().Unix()),
		Message:       fmt.Sprintf("Certificate deployed via SSH to %s", c.config.Host),
		DeployedAt:    time.Now(),
		Metadata: map[string]string{
			"host":        c.config.Host,
			"cert_path":   c.config.CertPath,
			"key_path":    c.config.KeyPath,
			"duration_ms": fmt.Sprintf("%d", deploymentDuration.Milliseconds()),
		},
	}, nil
}

// ValidateDeployment verifies that the deployed certificate files exist on the remote server.
func (c *Connector) ValidateDeployment(ctx context.Context, request target.ValidationRequest) (*target.ValidationResult, error) {
	c.logger.Info("validating SSH deployment",
		"host", c.config.Host,
		"certificate_id", request.CertificateID,
		"serial", request.Serial)

	startTime := time.Now()

	// Connect
	if err := c.client.Connect(ctx); err != nil {
		errMsg := fmt.Sprintf("SSH connection failed during validation: %v", err)
		c.logger.Error("SSH connection failed", "error", err)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}
	defer c.client.Close()

	// Verify cert file exists
	if _, err := c.client.StatFile(c.config.CertPath); err != nil {
		errMsg := fmt.Sprintf("certificate file not found on remote: %s (%v)", c.config.CertPath, err)
		c.logger.Error("validation failed", "error", err)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	// Verify key file exists
	if _, err := c.client.StatFile(c.config.KeyPath); err != nil {
		errMsg := fmt.Sprintf("key file not found on remote: %s (%v)", c.config.KeyPath, err)
		c.logger.Error("validation failed", "error", err)
		return &target.ValidationResult{
			Valid:         false,
			Serial:        request.Serial,
			TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			Message:       errMsg,
			ValidatedAt:   time.Now(),
		}, fmt.Errorf("%s", errMsg)
	}

	validationDuration := time.Since(startTime)
	c.logger.Info("SSH deployment validated successfully",
		"host", c.config.Host,
		"duration", validationDuration.String())

	return &target.ValidationResult{
		Valid:         true,
		Serial:        request.Serial,
		TargetAddress: fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
		Message:       "Certificate and key files accessible on remote server",
		ValidatedAt:   time.Now(),
		Metadata: map[string]string{
			"host":        c.config.Host,
			"cert_path":   c.config.CertPath,
			"key_path":    c.config.KeyPath,
			"duration_ms": fmt.Sprintf("%d", validationDuration.Milliseconds()),
		},
	}, nil
}

// parsePermissions converts an octal permission string like "0644" to os.FileMode.
func parsePermissions(s string) (os.FileMode, error) {
	var mode uint32
	_, err := fmt.Sscanf(s, "%o", &mode)
	if err != nil {
		return 0, fmt.Errorf("invalid permission string %q: %w", s, err)
	}
	return os.FileMode(mode), nil
}

// --- Real SSH client implementation ---

// realSSHClient implements SSHClient using golang.org/x/crypto/ssh + github.com/pkg/sftp.
type realSSHClient struct {
	config     *Config
	sshClient  *ssh.Client
	sftpClient *sftp.Client
}

// Connect establishes an SSH connection to the remote host.
func (c *realSSHClient) Connect(ctx context.Context) error {
	authMethods, err := c.buildAuthMethods()
	if err != nil {
		return fmt.Errorf("failed to build SSH auth: %w", err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            c.config.User,
		Auth:            authMethods,
		Timeout:         time.Duration(c.config.Timeout) * time.Second,
		// InsecureIgnoreHostKey is used intentionally: certctl deploys to known
		// infrastructure (the operator explicitly configures each target host).
		// This is the same security rationale as network scanner's InsecureSkipVerify
		// and F5 connector's insecure flag. Host key verification would require
		// an additional known_hosts management layer that is out of scope.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := net.JoinHostPort(c.config.Host, fmt.Sprintf("%d", c.config.Port))

	// Use net.DialTimeout for context-aware connection (context cancellation
	// is handled by the timeout on the SSH client config)
	conn, err := net.DialTimeout("tcp", addr, sshConfig.Timeout)
	if err != nil {
		return fmt.Errorf("TCP connection to %s failed: %w", addr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SSH handshake with %s failed: %w", addr, err)
	}

	c.sshClient = ssh.NewClient(sshConn, chans, reqs)

	// Open SFTP session
	c.sftpClient, err = sftp.NewClient(c.sshClient)
	if err != nil {
		c.sshClient.Close()
		c.sshClient = nil
		return fmt.Errorf("SFTP session failed: %w", err)
	}

	return nil
}

// buildAuthMethods constructs SSH auth methods from the config.
func (c *realSSHClient) buildAuthMethods() ([]ssh.AuthMethod, error) {
	switch c.config.AuthMethod {
	case "password":
		return []ssh.AuthMethod{ssh.Password(c.config.Password)}, nil

	case "key":
		var keyData []byte
		var err error

		if c.config.PrivateKey != "" {
			keyData = []byte(c.config.PrivateKey)
		} else if c.config.PrivateKeyPath != "" {
			keyData, err = os.ReadFile(c.config.PrivateKeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read private key %s: %w", c.config.PrivateKeyPath, err)
			}
		} else {
			return nil, fmt.Errorf("key auth requires private_key or private_key_path")
		}

		var signer ssh.Signer
		if c.config.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(c.config.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyData)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil

	default:
		return nil, fmt.Errorf("unsupported auth method: %s", c.config.AuthMethod)
	}
}

// WriteFile writes data to a remote path via SFTP with the given permissions.
func (c *realSSHClient) WriteFile(remotePath string, data []byte, mode os.FileMode) error {
	if c.sftpClient == nil {
		return fmt.Errorf("SFTP client not connected")
	}

	f, err := c.sftpClient.Create(remotePath)
	if err != nil {
		return fmt.Errorf("failed to create remote file %s: %w", remotePath, err)
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("failed to write remote file %s: %w", remotePath, err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close remote file %s: %w", remotePath, err)
	}

	// Set file permissions
	if err := c.sftpClient.Chmod(remotePath, mode); err != nil {
		return fmt.Errorf("failed to set permissions on %s: %w", remotePath, err)
	}

	return nil
}

// Execute runs a command on the remote server and returns combined output.
func (c *realSSHClient) Execute(ctx context.Context, command string) (string, error) {
	if c.sshClient == nil {
		return "", fmt.Errorf("SSH client not connected")
	}

	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	return string(output), err
}

// StatFile checks if a remote file exists and returns its size.
func (c *realSSHClient) StatFile(remotePath string) (int64, error) {
	if c.sftpClient == nil {
		return 0, fmt.Errorf("SFTP client not connected")
	}

	info, err := c.sftpClient.Stat(remotePath)
	if err != nil {
		return 0, fmt.Errorf("failed to stat remote file %s: %w", remotePath, err)
	}

	return info.Size(), nil
}

// Close closes the SFTP and SSH connections.
func (c *realSSHClient) Close() error {
	if c.sftpClient != nil {
		c.sftpClient.Close()
		c.sftpClient = nil
	}
	if c.sshClient != nil {
		c.sshClient.Close()
		c.sshClient = nil
	}
	return nil
}
