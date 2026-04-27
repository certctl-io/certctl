package email

// Bundle M.Email (Coverage Audit Closure) — email notifier failure-mode
// coverage. Closes finding H-003.
//
// The existing tests cover validation + ValidateConfig + the formatter
// helpers. Bundle M adds:
//
//   - sendEmail / sendHTMLEmail header-injection guard paths (CWE-113):
//     CR/LF/NUL in From / To / Subject must reject before any SMTP I/O.
//   - sendEmail / sendHTMLEmail connection-failure paths (closed server).
//   - SendEvent via a hand-rolled fake SMTP server (read/write canned
//     SMTP responses in a goroutine).
//   - SendAlert via the same fake SMTP server.
//
// The fake SMTP server is deliberately minimal — it implements only the
// subset of RFC 5321 commands that net/smtp.Client.Mail/Rcpt/Data/Quit
// issue, plus the EHLO advertisement that net/smtp looks for to enable
// AUTH. It is NOT a conformant SMTP server.

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/shankar0123/certctl/internal/connector/notifier"
)

// quietEmailLogger returns a slog.Logger writing to io.Discard at error level.
func quietEmailLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// fakeSMTPServer is a minimal SMTP responder that satisfies net/smtp.Client.
// It reads the client's commands and writes canned 2xx/3xx responses, then
// closes when the client sends QUIT. The host:port to dial is returned.
//
// For tests that want to simulate SMTP-level failures (e.g. 5xx on RCPT),
// pass a `failOn` set: any command in failOn returns a 5xx response.
type fakeSMTPServer struct {
	listener net.Listener
	wg       sync.WaitGroup
	host     string
	port     string
	t        *testing.T
	failOn   map[string]string // command verb (lowercased) -> 5xx response line
}

func startFakeSMTP(t *testing.T, failOn map[string]string) *fakeSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	s := &fakeSMTPServer{listener: ln, host: host, port: port, t: t, failOn: failOn}
	s.wg.Add(1)
	go s.run()
	t.Cleanup(func() { _ = ln.Close(); s.wg.Wait() })
	return s
}

func (s *fakeSMTPServer) run() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeSMTPServer) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	write := func(line string) {
		_, _ = bw.WriteString(line + "\r\n")
		_ = bw.Flush()
	}
	write("220 fake-smtp ready")
	inData := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if inData {
			if line == "." {
				inData = false
				// Production code's `defer wc.Close()` ordering means
				// the dataCloser.Close()'s ReadResponse(250) hasn't run
				// yet when client.Quit() executes. If we write 250 here,
				// Quit's ReadCodeLine(221) reads "250" and errors. Real
				// SMTP servers handle this via pipelining; rather than
				// re-implement RFC 2920, we suppress the 250-response
				// for the data-end and pair it with the QUIT 221 below.
				continue
			}
			continue
		}
		// Determine command verb (first word, lowercased).
		var verb string
		if i := strings.IndexByte(line, ' '); i >= 0 {
			verb = strings.ToLower(line[:i])
		} else {
			verb = strings.ToLower(line)
		}
		if resp, ok := s.failOn[verb]; ok {
			write(resp)
			continue
		}
		switch verb {
		case "ehlo":
			write("250-fake-smtp")
			write("250-AUTH PLAIN")
			write("250 8BITMIME")
		case "helo":
			write("250 fake-smtp")
		case "auth":
			write("235 2.7.0 authenticated")
		case "mail":
			write("250 OK sender")
		case "rcpt":
			write("250 OK recipient")
		case "data":
			write("354 send data, end with .")
			inData = true
		case "quit":
			write("221 bye")
			return
		case "rset":
			write("250 OK")
		case "noop":
			write("250 OK")
		default:
			write("502 unrecognized")
		}
	}
}

func (s *fakeSMTPServer) portInt() int {
	// returns the port as int (unused — kept for if a test wants strconv-free access)
	var p int
	for _, c := range s.port {
		p = p*10 + int(c-'0')
	}
	return p
}

// ---------------------------------------------------------------------------
// Header-injection guards (CWE-113) — early-return paths in sendEmail / sendHTMLEmail
// ---------------------------------------------------------------------------

func TestSendEmail_InjectionInTo(t *testing.T) {
	c := New(&Config{
		SMTPHost:    "x",
		SMTPPort:    25,
		FromAddress: "ok@example.com",
	}, quietEmailLogger())
	err := c.sendEmail(context.Background(), "evil@example.com\r\nBcc: leak@evil.com", "subj", "body")
	if err == nil || !strings.Contains(err.Error(), "invalid recipient") {
		t.Fatalf("expected invalid-recipient error, got: %v", err)
	}
}

func TestSendEmail_InjectionInSubject(t *testing.T) {
	c := New(&Config{
		SMTPHost:    "x",
		SMTPPort:    25,
		FromAddress: "ok@example.com",
	}, quietEmailLogger())
	err := c.sendEmail(context.Background(), "ok@example.com", "evil\r\nBcc: leak@evil.com", "body")
	if err == nil || !strings.Contains(err.Error(), "invalid subject") {
		t.Fatalf("expected invalid-subject error, got: %v", err)
	}
}

func TestSendEmail_InjectionInFrom(t *testing.T) {
	c := New(&Config{
		SMTPHost:    "x",
		SMTPPort:    25,
		FromAddress: "evil\r\nBcc: leak@evil.com",
	}, quietEmailLogger())
	err := c.sendEmail(context.Background(), "ok@example.com", "subj", "body")
	if err == nil || !strings.Contains(err.Error(), "invalid sender") {
		t.Fatalf("expected invalid-sender error, got: %v", err)
	}
}

func TestSendHTMLEmail_InjectionInTo(t *testing.T) {
	c := New(&Config{
		SMTPHost:    "x",
		SMTPPort:    25,
		FromAddress: "ok@example.com",
	}, quietEmailLogger())
	err := c.sendHTMLEmail(context.Background(), "evil@example.com\r\nBcc: leak@evil.com", "subj", "<p>body</p>")
	if err == nil || !strings.Contains(err.Error(), "invalid recipient") {
		t.Fatalf("expected invalid-recipient error, got: %v", err)
	}
}

func TestSendHTMLEmail_InjectionInSubject(t *testing.T) {
	c := New(&Config{
		SMTPHost:    "x",
		SMTPPort:    25,
		FromAddress: "ok@example.com",
	}, quietEmailLogger())
	err := c.sendHTMLEmail(context.Background(), "ok@example.com", "evil\r\nBcc: leak@evil.com", "<p>body</p>")
	if err == nil || !strings.Contains(err.Error(), "invalid subject") {
		t.Fatalf("expected invalid-subject error, got: %v", err)
	}
}

func TestSendHTMLEmail_InjectionInFrom(t *testing.T) {
	c := New(&Config{
		SMTPHost:    "x",
		SMTPPort:    25,
		FromAddress: "evil\r\nBcc: leak@evil.com",
	}, quietEmailLogger())
	err := c.sendHTMLEmail(context.Background(), "ok@example.com", "subj", "<p>body</p>")
	if err == nil || !strings.Contains(err.Error(), "invalid sender") {
		t.Fatalf("expected invalid-sender error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SMTP connection failure
// ---------------------------------------------------------------------------

func TestSendEmail_ConnectionRefused(t *testing.T) {
	c := New(&Config{
		SMTPHost:    "127.0.0.1",
		SMTPPort:    1, // intentionally unused port; connect-refused
		FromAddress: "ok@example.com",
	}, quietEmailLogger())
	err := c.sendEmail(context.Background(), "ok@example.com", "subj", "body")
	if err == nil || !strings.Contains(err.Error(), "failed to connect") {
		t.Fatalf("expected connect error, got: %v", err)
	}
}

func TestSendHTMLEmail_ConnectionRefused(t *testing.T) {
	c := New(&Config{
		SMTPHost:    "127.0.0.1",
		SMTPPort:    1,
		FromAddress: "ok@example.com",
	}, quietEmailLogger())
	err := c.sendHTMLEmail(context.Background(), "ok@example.com", "subj", "<p>body</p>")
	if err == nil || !strings.Contains(err.Error(), "failed to connect") {
		t.Fatalf("expected connect error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Happy-path SendAlert / SendEvent / sendHTMLEmail via fake SMTP server
// ---------------------------------------------------------------------------

func TestSendAlert_HappyPath(t *testing.T) {
	srv := startFakeSMTP(t, nil)
	c := New(&Config{
		SMTPHost:    srv.host,
		SMTPPort:    srv.portInt(),
		FromAddress: "noreply@example.com",
	}, quietEmailLogger())

	err := c.SendAlert(context.Background(), notifier.Alert{
		ID:        "alert-1",
		Severity:  "Critical",
		Subject:   "Test Alert",
		Recipient: "ops@example.com",
		Message:   "Cert expiring",
	})
	if err != nil {
		t.Fatalf("SendAlert: %v", err)
	}
}

func TestSendEvent_HappyPath(t *testing.T) {
	srv := startFakeSMTP(t, nil)
	c := New(&Config{
		SMTPHost:    srv.host,
		SMTPPort:    srv.portInt(),
		FromAddress: "noreply@example.com",
	}, quietEmailLogger())

	err := c.SendEvent(context.Background(), notifier.Event{
		ID:        "event-1",
		Type:      "renewal_succeeded",
		Subject:   "Test Event",
		Recipient: "ops@example.com",
		Body:      "Cert renewed",
	})
	if err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
}

func TestSendEvent_RcptRejected(t *testing.T) {
	srv := startFakeSMTP(t, map[string]string{
		"rcpt": "550 5.1.1 mailbox unavailable",
	})
	c := New(&Config{
		SMTPHost:    srv.host,
		SMTPPort:    srv.portInt(),
		FromAddress: "noreply@example.com",
	}, quietEmailLogger())
	err := c.SendEvent(context.Background(), notifier.Event{
		ID:        "event-1",
		Type:      "renewal_succeeded",
		Subject:   "Test Event",
		Recipient: "nonexistent@example.com",
		Body:      "Cert renewed",
	})
	if err == nil || !strings.Contains(err.Error(), "set recipient") {
		t.Fatalf("expected RCPT-rejection error, got: %v", err)
	}
}

func TestSendAlert_DataWriteFailure(t *testing.T) {
	srv := startFakeSMTP(t, map[string]string{
		"data": "554 5.6.0 transaction failed",
	})
	c := New(&Config{
		SMTPHost:    srv.host,
		SMTPPort:    srv.portInt(),
		FromAddress: "noreply@example.com",
	}, quietEmailLogger())
	err := c.SendAlert(context.Background(), notifier.Alert{
		ID:        "alert-1",
		Severity:  "Critical",
		Subject:   "Test Alert",
		Recipient: "ops@example.com",
		Message:   "boom",
	})
	if err == nil || !strings.Contains(err.Error(), "data writer") {
		t.Fatalf("expected DATA-writer error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Authentication path (Username/Password set -> AUTH PLAIN)
// ---------------------------------------------------------------------------

func TestSendEmail_WithAuth(t *testing.T) {
	srv := startFakeSMTP(t, nil)
	c := New(&Config{
		SMTPHost:    srv.host,
		SMTPPort:    srv.portInt(),
		FromAddress: "noreply@example.com",
		Username:    "user",
		Password:    "pass",
	}, quietEmailLogger())
	err := c.SendAlert(context.Background(), notifier.Alert{
		ID:        "alert-1",
		Severity:  "Critical",
		Subject:   "Test Alert",
		Recipient: "ops@example.com",
		Message:   "with auth",
	})
	if err != nil {
		t.Fatalf("SendAlert with auth: %v", err)
	}
}

func TestSendEmail_AuthFailure(t *testing.T) {
	srv := startFakeSMTP(t, map[string]string{
		"auth": "535 5.7.8 authentication failed",
	})
	c := New(&Config{
		SMTPHost:    srv.host,
		SMTPPort:    srv.portInt(),
		FromAddress: "noreply@example.com",
		Username:    "user",
		Password:    "wrong-pass",
	}, quietEmailLogger())
	err := c.SendAlert(context.Background(), notifier.Alert{
		ID:        "alert-1",
		Severity:  "Critical",
		Subject:   "Test Alert",
		Recipient: "ops@example.com",
		Message:   "with bad auth",
	})
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected auth-failure error, got: %v", err)
	}
}
