package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

// Bundle M.SSH-extended (H-002 closure): in-process SSH server fixture that
// exercises realSSHClient.Connect, Execute, WriteFile, StatFile, and Close
// end-to-end. Same pattern as M.Email's hand-rolled SMTP fixture — minimal
// in-process protocol server bound to net.Listen("tcp", "127.0.0.1:0") with
// t.Cleanup-driven shutdown.
//
// The SSH server uses Ed25519 host keys (lightest crypto for tests),
// password authentication (simplest auth), and supports two channel types:
//
//   - "session" with "exec" subsystem — used by realSSHClient.Execute
//   - "session" with "subsystem sftp" — used by realSSHClient.WriteFile,
//     StatFile (proxied through pkg/sftp.NewServer over the channel)
//
// The fixture lives in tests only; production code never imports it.

// fakeSSHServer is a minimal in-process SSH server bound to a random port.
type fakeSSHServer struct {
	t        *testing.T
	listener net.Listener
	addr     string
	user     string
	password string

	wg       sync.WaitGroup
	mu       sync.Mutex
	closed   bool

	// Optional behaviour toggles for failure-mode tests.
	rejectAuth      bool   // reject all auth attempts (auth failure path)
	dropOnHandshake bool   // close conn before SSH NewServerConn returns (handshake failure)
	failExec        bool   // exec sessions return non-zero exit (Execute error path)
	failSFTP        bool   // refuse sftp subsystem (SFTP failure path)
}

// startFakeSSHServer binds a fresh server on a random local port and returns
// it ready to accept Connect calls. t.Cleanup is wired to close the listener
// + drain in-flight handlers.
func startFakeSSHServer(t *testing.T, opts ...func(*fakeSSHServer)) *fakeSSHServer {
	t.Helper()

	srv := &fakeSSHServer{
		t:        t,
		user:     "testuser",
		password: "testpass",
	}
	for _, opt := range opts {
		opt(srv)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	srv.listener = listener
	srv.addr = listener.Addr().String()

	t.Cleanup(srv.Close)

	srv.wg.Add(1)
	go srv.acceptLoop()

	return srv
}

// host returns the host:port the listener is bound to. Splits via SplitHostPort
// so the test caller can pass them separately to Config.
func (s *fakeSSHServer) hostPort() (string, int) {
	host, portStr, err := net.SplitHostPort(s.addr)
	if err != nil {
		s.t.Fatalf("SplitHostPort: %v", err)
	}
	var port int
	for _, c := range portStr {
		if c >= '0' && c <= '9' {
			port = port*10 + int(c-'0')
		}
	}
	return host, port
}

func (s *fakeSSHServer) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()

	_ = s.listener.Close()
	s.wg.Wait()
}

func (s *fakeSSHServer) acceptLoop() {
	defer s.wg.Done()
	// Generate a fresh Ed25519 host key for this server instance.
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		s.t.Errorf("ed25519.GenerateKey: %v", err)
		return
	}
	signer, err := gossh.NewSignerFromKey(hostKey)
	if err != nil {
		s.t.Errorf("NewSignerFromKey: %v", err)
		return
	}

	cfg := &gossh.ServerConfig{
		PasswordCallback: func(c gossh.ConnMetadata, p []byte) (*gossh.Permissions, error) {
			if s.rejectAuth {
				return nil, errors.New("auth rejected (test fixture)")
			}
			if c.User() == s.user && string(p) == s.password {
				return &gossh.Permissions{}, nil
			}
			return nil, errors.New("invalid credentials")
		},
		PublicKeyCallback: func(c gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if s.rejectAuth {
				return nil, errors.New("auth rejected (test fixture)")
			}
			// Accept any pubkey; testers using key-auth don't need to also
			// configure trust, since this is a pure connectivity fixture.
			return &gossh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(signer)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// Listener closed — exit cleanly.
			return
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConn(c, cfg)
		}(conn)
	}
}

func (s *fakeSSHServer) handleConn(nConn net.Conn, cfg *gossh.ServerConfig) {
	defer nConn.Close()

	if s.dropOnHandshake {
		// Close immediately to surface a handshake error on the client side.
		return
	}

	_, chans, reqs, err := gossh.NewServerConn(nConn, cfg)
	if err != nil {
		// Common: closed connection during handshake (test cleanup, auth fail).
		return
	}
	go gossh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(gossh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleSession(ch, requests)
		}()
	}
}

func (s *fakeSSHServer) handleSession(ch gossh.Channel, reqs <-chan *gossh.Request) {
	defer ch.Close()

	for req := range reqs {
		switch req.Type {
		case "exec":
			if s.failExec {
				_ = req.Reply(true, nil)
				_, _ = ch.Write([]byte("exec failure (test fixture)\n"))
				_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 1}) // exit code 1
				return
			}
			// Echo back a canned success response so Execute returns without error.
			_ = req.Reply(true, nil)
			_, _ = ch.Write([]byte("exec ok\n"))
			_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0}) // exit code 0
			return

		case "subsystem":
			// Payload is the subsystem name in standard SSH wire form: 4-byte
			// length prefix + bytes. Look for "sftp".
			if len(req.Payload) >= 4 {
				name := string(req.Payload[4:])
				if name == "sftp" {
					if s.failSFTP {
						_ = req.Reply(false, nil)
						return
					}
					_ = req.Reply(true, nil)
					srv, err := sftp.NewServer(ch)
					if err != nil {
						return
					}
					_ = srv.Serve()
					return
				}
			}
			_ = req.Reply(false, nil)

		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Connect happy path / failure paths
// ─────────────────────────────────────────────────────────────────────────────

func TestRealSSHClient_Connect_Password_Success(t *testing.T) {
	srv := startFakeSSHServer(t)
	host, port := srv.hostPort()

	c := &realSSHClient{config: &Config{
		Host:       host,
		Port:       port,
		User:       srv.user,
		AuthMethod: "password",
		Password:   srv.password,
		Timeout:    5,
	}}

	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()

	if c.sshClient == nil {
		t.Errorf("expected sshClient to be set after Connect")
	}
	if c.sftpClient == nil {
		t.Errorf("expected sftpClient to be set after Connect")
	}
}

func TestRealSSHClient_Connect_Password_WrongPassword(t *testing.T) {
	srv := startFakeSSHServer(t)
	host, port := srv.hostPort()

	c := &realSSHClient{config: &Config{
		Host:       host,
		Port:       port,
		User:       srv.user,
		AuthMethod: "password",
		Password:   "wrong-password",
		Timeout:    5,
	}}

	if err := c.Connect(context.Background()); err == nil {
		t.Errorf("expected wrong-password to fail Connect")
		_ = c.Close()
	}
}

func TestRealSSHClient_Connect_AuthRejected_AllAttempts(t *testing.T) {
	srv := startFakeSSHServer(t, func(s *fakeSSHServer) { s.rejectAuth = true })
	host, port := srv.hostPort()

	c := &realSSHClient{config: &Config{
		Host:       host,
		Port:       port,
		User:       srv.user,
		AuthMethod: "password",
		Password:   srv.password,
		Timeout:    5,
	}}

	if err := c.Connect(context.Background()); err == nil {
		t.Errorf("expected auth rejection to fail Connect")
		_ = c.Close()
	} else if !strings.Contains(err.Error(), "SSH handshake") {
		t.Errorf("expected handshake error, got %v", err)
	}
}

func TestRealSSHClient_Connect_HandshakeDropped(t *testing.T) {
	srv := startFakeSSHServer(t, func(s *fakeSSHServer) { s.dropOnHandshake = true })
	host, port := srv.hostPort()

	c := &realSSHClient{config: &Config{
		Host:       host,
		Port:       port,
		User:       srv.user,
		AuthMethod: "password",
		Password:   srv.password,
		Timeout:    5,
	}}

	if err := c.Connect(context.Background()); err == nil {
		t.Errorf("expected handshake-drop to fail Connect")
		_ = c.Close()
	}
}

func TestRealSSHClient_Connect_TCPConnRefused(t *testing.T) {
	// Bind a listener, immediately close it — the port is still allocated
	// but no one is listening. Connect must return a TCP-connection error.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	for _, c := range portStr {
		if c >= '0' && c <= '9' {
			port = port*10 + int(c-'0')
		}
	}

	c := &realSSHClient{config: &Config{
		Host:       host,
		Port:       port,
		User:       "anyone",
		AuthMethod: "password",
		Password:   "anything",
		Timeout:    1, // 1-second timeout
	}}

	if err := c.Connect(context.Background()); err == nil {
		t.Errorf("expected TCP-refused, got nil")
		_ = c.Close()
	} else if !strings.Contains(err.Error(), "TCP connection") {
		t.Errorf("expected TCP-connection error, got %v", err)
	}
}

func TestRealSSHClient_Connect_KeyAuth_Success(t *testing.T) {
	srv := startFakeSSHServer(t)
	host, port := srv.hostPort()

	// Generate an ed25519 client key and serialize it to OpenSSH PEM.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	_ = pub
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	pemBlock, err := gossh.MarshalPrivateKey(priv, "test-key")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_test")
	if err := os.WriteFile(keyPath, encodePEMBlock(pemBlock.Type, pemBlock.Bytes), 0600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}

	c := &realSSHClient{config: &Config{
		Host:           host,
		Port:           port,
		User:           srv.user,
		AuthMethod:     "key",
		PrivateKeyPath: keyPath,
		Timeout:        5,
	}}

	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("Connect (key auth): %v", err)
	}
	defer c.Close()
}

// encodePEMBlock builds a minimal PEM-format block with the given type+bytes.
// (Avoids pulling in encoding/pem in the test header — it's already imported
// transitively but this keeps the import list minimal.)
func encodePEMBlock(blockType string, blockBytes []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("-----BEGIN ")
	buf.WriteString(blockType)
	buf.WriteString("-----\n")
	// Base64-encode in 64-char lines.
	enc := base64Encode(blockBytes)
	for i := 0; i < len(enc); i += 64 {
		end := i + 64
		if end > len(enc) {
			end = len(enc)
		}
		buf.Write(enc[i:end])
		buf.WriteByte('\n')
	}
	buf.WriteString("-----END ")
	buf.WriteString(blockType)
	buf.WriteString("-----\n")
	return buf.Bytes()
}

func base64Encode(in []byte) []byte {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := make([]byte, (len(in)+2)/3*4)
	j := 0
	for i := 0; i < len(in); i += 3 {
		var v uint32
		v = uint32(in[i]) << 16
		if i+1 < len(in) {
			v |= uint32(in[i+1]) << 8
		}
		if i+2 < len(in) {
			v |= uint32(in[i+2])
		}
		out[j] = enc[(v>>18)&0x3f]
		out[j+1] = enc[(v>>12)&0x3f]
		if i+1 < len(in) {
			out[j+2] = enc[(v>>6)&0x3f]
		} else {
			out[j+2] = '='
		}
		if i+2 < len(in) {
			out[j+3] = enc[v&0x3f]
		} else {
			out[j+3] = '='
		}
		j += 4
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Execute
// ─────────────────────────────────────────────────────────────────────────────

func TestRealSSHClient_Execute_Success(t *testing.T) {
	srv := startFakeSSHServer(t)
	host, port := srv.hostPort()

	c := &realSSHClient{config: &Config{
		Host: host, Port: port, User: srv.user,
		AuthMethod: "password", Password: srv.password, Timeout: 5,
	}}
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()

	out, err := c.Execute(context.Background(), "echo hello")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, "exec ok") {
		t.Errorf("expected canned 'exec ok' output, got %q", out)
	}
}

func TestRealSSHClient_Execute_NotConnected(t *testing.T) {
	c := &realSSHClient{config: &Config{}}
	if _, err := c.Execute(context.Background(), "anything"); err == nil {
		t.Errorf("expected error when sshClient is nil")
	}
}

func TestRealSSHClient_Execute_ExitCode1(t *testing.T) {
	srv := startFakeSSHServer(t, func(s *fakeSSHServer) { s.failExec = true })
	host, port := srv.hostPort()

	c := &realSSHClient{config: &Config{
		Host: host, Port: port, User: srv.user,
		AuthMethod: "password", Password: srv.password, Timeout: 5,
	}}
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()

	out, err := c.Execute(context.Background(), "anything")
	if err == nil {
		t.Errorf("expected non-zero exit code to surface as error; got out=%q", out)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// WriteFile / StatFile via SFTP
// ─────────────────────────────────────────────────────────────────────────────

func TestRealSSHClient_WriteFile_StatFile_RoundTrip(t *testing.T) {
	srv := startFakeSSHServer(t)
	host, port := srv.hostPort()

	c := &realSSHClient{config: &Config{
		Host: host, Port: port, User: srv.user,
		AuthMethod: "password", Password: srv.password, Timeout: 5,
	}}
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()

	// Use a temp path the in-process sftp server can write to. pkg/sftp's
	// default server uses the OS filesystem, so use a t.TempDir-derived path.
	dir := t.TempDir()
	target := filepath.Join(dir, "out.pem")
	payload := []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")

	if err := c.WriteFile(target, payload, 0640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	size, err := c.StatFile(target)
	if err != nil {
		t.Fatalf("StatFile: %v", err)
	}
	if size != int64(len(payload)) {
		t.Errorf("expected size %d, got %d", len(payload), size)
	}

	// Verify mode 0640 was set.
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	if info.Mode().Perm() != 0640 {
		t.Errorf("expected mode 0640, got %v", info.Mode().Perm())
	}

	// Verify content round-trips.
	gotBytes, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(gotBytes, payload) {
		t.Errorf("payload round-trip mismatch:\n  got:  %q\n  want: %q", gotBytes, payload)
	}
}

func TestRealSSHClient_WriteFile_NotConnected(t *testing.T) {
	c := &realSSHClient{config: &Config{}}
	if err := c.WriteFile("/tmp/x", []byte("y"), 0600); err == nil {
		t.Errorf("expected error when sftpClient is nil")
	}
}

func TestRealSSHClient_StatFile_NotConnected(t *testing.T) {
	c := &realSSHClient{config: &Config{}}
	if _, err := c.StatFile("/tmp/x"); err == nil {
		t.Errorf("expected error when sftpClient is nil")
	}
}

func TestRealSSHClient_StatFile_NotExist(t *testing.T) {
	srv := startFakeSSHServer(t)
	host, port := srv.hostPort()
	c := &realSSHClient{config: &Config{
		Host: host, Port: port, User: srv.user,
		AuthMethod: "password", Password: srv.password, Timeout: 5,
	}}
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()

	if _, err := c.StatFile("/nonexistent/path/to/file"); err == nil {
		t.Errorf("expected error stat'ing nonexistent file")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Close
// ─────────────────────────────────────────────────────────────────────────────

func TestRealSSHClient_Close_Idempotent(t *testing.T) {
	srv := startFakeSSHServer(t)
	host, port := srv.hostPort()
	c := &realSSHClient{config: &Config{
		Host: host, Port: port, User: srv.user,
		AuthMethod: "password", Password: srv.password, Timeout: 5,
	}}
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	// Second close — idempotent (should not panic, may return nil)
	if err := c.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestRealSSHClient_Close_NeverConnected(t *testing.T) {
	c := &realSSHClient{config: &Config{}}
	if err := c.Close(); err != nil {
		t.Errorf("Close on never-connected client should be nil, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Suppress unused-import warning under some Go versions.
// ─────────────────────────────────────────────────────────────────────────────

var _ = io.EOF
var _ = time.Second
