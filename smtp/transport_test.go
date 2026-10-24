package smtp

/*
MIT License

Copyright (c) 2026 Shane

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"net/textproto"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	email "github.com/Bugs5382/go-email"
)

// fakeSMTP is an in-process, minimal SMTP server used to observe what a
// Transport actually sends on the wire: the MAIL FROM address, the full RCPT
// TO set, the raw DATA blob, and -- for the relay path -- whether the
// connection was upgraded via STARTTLS and what AUTH PLAIN credentials were
// presented.
type fakeSMTP struct {
	Host string
	Port int

	tlsConfig *tls.Config

	mu          sync.Mutex
	MailFrom    string
	Rcpts       []string
	Data        string
	TLSUpgraded bool
	AuthUser    string
	AuthPass    string

	// queued holds canned replies per session stage (see failNext). Each
	// one is used once, in order, in place of the stage's normal reply.
	queued map[string][]string
}

// failNext makes the next session that reaches stage answer with line
// instead of the normal reply. Stages are GREETING, MAIL, RCPT, DATA, END
// (the reply after the terminating "."), AUTH and QUIT. A canned GREETING or
// QUIT reply also ends the session.
func (s *fakeSMTP) failNext(stage, line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.queued == nil {
		s.queued = make(map[string][]string)
	}
	s.queued[stage] = append(s.queued[stage], line)
}

// canned pops the next canned reply for stage, if any.
func (s *fakeSMTP) canned(stage string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.queued[stage]
	if len(q) == 0 {
		return "", false
	}
	s.queued[stage] = q[1:]
	return q[0], true
}

// startFakeSMTP starts a fake SMTP listener on an ephemeral localhost port
// and returns once it is ready to accept connections. It does not advertise
// STARTTLS, matching a plaintext local catcher (e.g. maildev). The server is
// closed automatically via t.Cleanup.
func startFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	return newFakeSMTP(t, nil)
}

// startFakeSMTPTLS starts a fake SMTP listener like startFakeSMTP, but one
// that advertises STARTTLS in its EHLO reply and can perform a real TLS
// handshake using a throwaway, self-signed certificate -- for exercising
// SMTPTransport's relay (STARTTLS + AUTH) path.
func startFakeSMTPTLS(t *testing.T) *fakeSMTP {
	t.Helper()
	cert := generateTestCert(t)
	return newFakeSMTP(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
}

// newFakeSMTP is the shared listener bootstrap for startFakeSMTP and
// startFakeSMTPTLS. When tlsConfig is non-nil the server advertises STARTTLS
// (and AUTH PLAIN) and can upgrade a connection with it; when nil it behaves
// like a plaintext, no-STARTTLS catcher.
func newFakeSMTP(t *testing.T, tlsConfig *tls.Config) *fakeSMTP {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	addr := ln.Addr().(*net.TCPAddr)
	srv := &fakeSMTP{
		Host:      addr.IP.String(),
		Port:      addr.Port,
		tlsConfig: tlsConfig,
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handle(conn)
		}
	}()

	return srv
}

// generateTestCert creates a throwaway, self-signed certificate (valid for
// 127.0.0.1/localhost) for the fake SMTP server's STARTTLS handshake. Tests
// that use it connect with Config.TLSInsecure so the self-signed cert is
// accepted without a trust chain.
func generateTestCert(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// handle speaks just enough SMTP to satisfy net/smtp: greet, echo EHLO/HELO
// advertising STARTTLS and AUTH PLAIN, accept MAIL/RCPT (recording each),
// stream DATA into srv.Data until the terminating "." line, perform a real
// STARTTLS upgrade (recording it), decode AUTH PLAIN credentials, reply to
// QUIT, and reject anything else it doesn't recognize.
func (s *fakeSMTP) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	r := bufio.NewReader(conn)
	if line, ok := s.canned("GREETING"); ok {
		writeLine(conn, line)
		return
	}
	writeLine(conn, "220 fake.local ESMTP ready")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			writeLine(conn, "250-fake.local greets you")
			if s.tlsConfig != nil {
				writeLine(conn, "250-STARTTLS")
				writeLine(conn, "250-AUTH PLAIN")
			}
			writeLine(conn, "250 8BITMIME")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			if reply, ok := s.canned("MAIL"); ok {
				writeLine(conn, reply)
				continue
			}
			s.mu.Lock()
			s.MailFrom = extractAddr(line[len("MAIL FROM:"):])
			s.mu.Unlock()
			writeLine(conn, "250 OK")
		case strings.HasPrefix(upper, "RCPT TO:"):
			if reply, ok := s.canned("RCPT"); ok {
				writeLine(conn, reply)
				continue
			}
			s.mu.Lock()
			s.Rcpts = append(s.Rcpts, extractAddr(line[len("RCPT TO:"):]))
			s.mu.Unlock()
			writeLine(conn, "250 OK")
		case upper == "DATA":
			if reply, ok := s.canned("DATA"); ok {
				writeLine(conn, reply)
				continue
			}
			writeLine(conn, "354 End data with <CR><LF>.<CR><LF>")
			var b strings.Builder
			for {
				dl, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dl, "\r\n") == "." {
					break
				}
				b.WriteString(dl)
			}
			s.mu.Lock()
			s.Data = b.String()
			s.mu.Unlock()
			if reply, ok := s.canned("END"); ok {
				writeLine(conn, reply)
				continue
			}
			writeLine(conn, "250 OK: queued")
		case upper == "QUIT":
			if reply, ok := s.canned("QUIT"); ok {
				writeLine(conn, reply)
				return
			}
			writeLine(conn, "221 Bye")
			return
		case upper == "STARTTLS" && s.tlsConfig != nil:
			writeLine(conn, "220 Ready to start TLS")
			tlsConn := tls.Server(conn, s.tlsConfig)
			conn = tlsConn
			r = bufio.NewReader(conn)
			s.mu.Lock()
			s.TLSUpgraded = true
			s.mu.Unlock()
		case strings.HasPrefix(upper, "AUTH PLAIN"):
			if reply, ok := s.canned("AUTH"); ok {
				writeLine(conn, reply)
				continue
			}
			s.recordAuthPlain(line)
			writeLine(conn, "235 Authentication successful")
		default:
			writeLine(conn, "502 5.5.2 command not recognized")
		}
	}
}

// recordAuthPlain decodes the base64 SASL PLAIN payload from an
// "AUTH PLAIN <base64>" command line (authzid\0authcid\0password) and
// records the username/password it carried.
func (s *fakeSMTP) recordAuthPlain(line string) {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return
	}
	parts := strings.SplitN(string(decoded), "\x00", 3)
	if len(parts) != 3 {
		return
	}
	s.mu.Lock()
	s.AuthUser = parts[1]
	s.AuthPass = parts[2]
	s.mu.Unlock()
}

func writeLine(conn net.Conn, s string) {
	_, _ = conn.Write([]byte(s + "\r\n"))
}

// extractAddr strips the "<...>" envelope wrapper (and any trailing
// parameters such as SIZE=) from a MAIL FROM / RCPT TO argument.
func extractAddr(arg string) string {
	arg = strings.TrimSpace(arg)
	start := strings.Index(arg, "<")
	end := strings.Index(arg, ">")
	if start >= 0 && end > start {
		return arg[start+1 : end]
	}
	return arg
}

// assertSameSet fails the test unless got and want contain the same elements
// (order-independent).
func assertSameSet(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("set size = %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	seen := make(map[string]bool, len(want))
	for _, w := range want {
		seen[w] = true
	}
	for _, g := range got {
		if !seen[g] {
			t.Fatalf("unexpected element %q in %v, want set %v", g, got, want)
		}
	}
}

func TestSMTPTransport_RecipientsAndEnvelope(t *testing.T) {
	srv := startFakeSMTP(t)
	tr := NewSMTPTransport(Config{Host: srv.Host, Port: srv.Port, From: "a@example.com"})
	err := tr.Send(context.Background(), email.Message{
		From: "a@example.com", EnvelopeFrom: "bounce@example.com",
		To: []string{"b@example.com"}, Cc: []string{"c@example.com"}, Bcc: []string{"secret@example.com"},
		Subject: "S", Text: "hi",
	})
	if err != nil {
		t.Fatal(err)
	}
	if srv.MailFrom != "bounce@example.com" {
		t.Errorf("MAIL FROM = %q", srv.MailFrom)
	}
	assertSameSet(t, srv.Rcpts, []string{"b@example.com", "c@example.com", "secret@example.com"})
	if strings.Contains(srv.Data, "secret@example.com") {
		t.Error("Bcc leaked into DATA/headers")
	}
}

func TestSMTPTransport_MaildevFastPath(t *testing.T) {
	srv := startFakeSMTP(t)
	tr := NewSMTPTransport(Config{Host: srv.Host, Port: srv.Port, From: "a@example.com"})
	err := tr.Send(context.Background(), email.Message{
		From: "a@example.com",
		To:   []string{"b@example.com"},
		Text: "hi",
	})
	if err != nil {
		t.Fatal(err)
	}
	if srv.MailFrom != "a@example.com" {
		t.Errorf("MAIL FROM = %q, want From default", srv.MailFrom)
	}
	assertSameSet(t, srv.Rcpts, []string{"b@example.com"})
}

func TestSMTPTransport_RelaySTARTTLSAndAuth(t *testing.T) {
	srv := startFakeSMTPTLS(t)
	tr := NewSMTPTransport(Config{
		Host: srv.Host, Port: srv.Port,
		User: "reluser", Pass: "relpass",
		TLS: true, TLSInsecure: true,
		From: "a@example.com",
	})

	err := tr.Send(context.Background(), email.Message{
		From:    "a@example.com",
		To:      []string{"b@example.com"},
		Subject: "S",
		Text:    "hi",
	})
	if err != nil {
		t.Fatal(err)
	}

	if !srv.TLSUpgraded {
		t.Error("expected the connection to be upgraded via STARTTLS")
	}
	if srv.AuthUser != "reluser" || srv.AuthPass != "relpass" {
		t.Errorf("AUTH PLAIN credentials = %q/%q, want reluser/relpass", srv.AuthUser, srv.AuthPass)
	}
	if srv.MailFrom != "a@example.com" {
		t.Errorf("MAIL FROM = %q", srv.MailFrom)
	}
	assertSameSet(t, srv.Rcpts, []string{"b@example.com"})
	if !strings.Contains(srv.Data, "Subject: S") {
		t.Error("expected the message to be delivered over the TLS-upgraded connection")
	}
}

// TestSMTPTransport_PlaintextPathUpgradesWhenOffered pins the plaintext
// path's opportunistic STARTTLS: with no TLS and no user configured, a server
// that offers STARTTLS is still upgraded, with full certificate verification,
// so a self-signed relay certificate is rejected rather than silently
// accepted.
func TestSMTPTransport_PlaintextPathUpgradesWhenOffered(t *testing.T) {
	srv := startFakeSMTPTLS(t)
	tr := NewSMTPTransport(Config{Host: srv.Host, Port: srv.Port, From: "a@example.com"})

	err := tr.Send(context.Background(), email.Message{From: "a@example.com", To: []string{"b@example.com"}, Text: "hi"})
	if err == nil {
		t.Fatal("expected the unverifiable STARTTLS certificate to fail the send")
	}
	var certErr *tls.CertificateVerificationError
	if !errors.As(err, &certErr) {
		t.Fatalf("err = %v, want a certificate verification failure", err)
	}
	if srv.MailFrom != "" {
		t.Errorf("MAIL FROM = %q, want nothing sent before the failed upgrade", srv.MailFrom)
	}
}

func TestSMTPTransport_ContextCancelled(t *testing.T) {
	srv := startFakeSMTP(t)
	tr := NewSMTPTransport(Config{Host: srv.Host, Port: srv.Port, From: "a@example.com"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := tr.Send(ctx, email.Message{From: "a@example.com", To: []string{"b@example.com"}, Text: "hi"})
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	t.Setenv("SMTP_HOST", "")
	t.Setenv("SMTP_PORT", "")
	t.Setenv("SMTP_USER", "")
	t.Setenv("SMTP_PASS", "")
	t.Setenv("SMTP_FROM", "")
	t.Setenv("SMTP_TLS", "")
	t.Setenv("SMTP_TLS_INSECURE", "")

	cfg := LoadConfig()
	if cfg.Host != "localhost" {
		t.Errorf("Host = %q, want localhost", cfg.Host)
	}
	if cfg.Port != 1025 {
		t.Errorf("Port = %d, want 1025", cfg.Port)
	}
	if cfg.User != "" || cfg.Pass != "" {
		t.Errorf("User/Pass = %q/%q, want empty", cfg.User, cfg.Pass)
	}
	if cfg.From != "no-reply@example.com" {
		t.Errorf("From = %q, want no-reply@example.com", cfg.From)
	}
	if cfg.TLS || cfg.TLSInsecure {
		t.Errorf("TLS = %v, TLSInsecure = %v, want both false", cfg.TLS, cfg.TLSInsecure)
	}
}

func TestLoadConfig_Overrides(t *testing.T) {
	t.Setenv("SMTP_HOST", "relay.example.com")
	t.Setenv("SMTP_PORT", "2525")
	t.Setenv("SMTP_USER", "user")
	t.Setenv("SMTP_PASS", "pass")
	t.Setenv("SMTP_FROM", "custom@example.com")
	t.Setenv("SMTP_TLS", "true")
	t.Setenv("SMTP_TLS_INSECURE", "true")

	cfg := LoadConfig()
	if cfg.Host != "relay.example.com" {
		t.Errorf("Host = %q", cfg.Host)
	}
	if cfg.Port != 2525 {
		t.Errorf("Port = %d", cfg.Port)
	}
	if cfg.User != "user" || cfg.Pass != "pass" {
		t.Errorf("User/Pass = %q/%q", cfg.User, cfg.Pass)
	}
	if cfg.From != "custom@example.com" {
		t.Errorf("From = %q", cfg.From)
	}
	if !cfg.TLS || !cfg.TLSInsecure {
		t.Errorf("TLS = %v, TLSInsecure = %v", cfg.TLS, cfg.TLSInsecure)
	}
}

// startScriptedSMTP starts a listener that greets (unless greet is empty),
// answers each command line with the next reply in script, and then stops
// answering while keeping the connection open: a relay that has hung.
func startScriptedSMTP(t *testing.T, greet string, script ...string) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	var conns []net.Conn
	var mu sync.Mutex
	t.Cleanup(func() {
		close(done)
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			go func(conn net.Conn) {
				if greet != "" {
					writeLine(conn, greet)
				}
				r := bufio.NewReader(conn)
				for _, reply := range script {
					if _, err := r.ReadString('\n'); err != nil {
						return
					}
					writeLine(conn, reply)
				}
				<-done
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

// sendWithin runs Send and fails the test if it hasn't returned within limit,
// so a missing timeout shows up as a test failure rather than a hung run.
func sendWithin(t *testing.T, ctx context.Context, tr *SMTPTransport, limit time.Duration) (time.Duration, error) {
	t.Helper()
	start := time.Now()
	errc := make(chan error, 1)
	go func() {
		errc <- tr.Send(ctx, email.Message{From: "a@example.com", To: []string{"b@example.com"}, Text: "hi"})
	}()
	select {
	case err := <-errc:
		return time.Since(start), err
	case <-time.After(limit):
		t.Fatalf("Send still blocked after %v", limit)
		return 0, nil
	}
}

func TestSMTPTransport_TimeoutOnSilentGreeting(t *testing.T) {
	host, port := startScriptedSMTP(t, "")
	tr := NewSMTPTransport(Config{Host: host, Port: port, Timeout: 200 * time.Millisecond})

	took, err := sendWithin(t, context.Background(), tr, 5*time.Second)
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("err = %v, want os.ErrDeadlineExceeded", err)
	}
	if took < 150*time.Millisecond {
		t.Errorf("returned after %v, before the 200ms timeout could have fired", took)
	}
}

func TestSMTPTransport_TimeoutMidSession(t *testing.T) {
	// Greets and answers EHLO, then never answers MAIL FROM.
	host, port := startScriptedSMTP(t, "220 hung.local ESMTP", "250 hung.local")
	tr := NewSMTPTransport(Config{Host: host, Port: port, Timeout: 200 * time.Millisecond})

	_, err := sendWithin(t, context.Background(), tr, 5*time.Second)
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("err = %v, want os.ErrDeadlineExceeded", err)
	}
	if !strings.Contains(err.Error(), "mail from") {
		t.Errorf("err = %v, want it to name the MAIL FROM stage", err)
	}
	var transient email.TransientError
	if errors.As(err, &transient) {
		t.Errorf("a mid-session timeout must not be transient: %v", err)
	}
}

func TestSMTPTransport_ContextEndsHungSession(t *testing.T) {
	cases := []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		want error
	}{
		{"cancel", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(150*time.Millisecond, cancel)
			return ctx, cancel
		}, context.Canceled},
		{"deadline", func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 150*time.Millisecond)
		}, context.DeadlineExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port := startScriptedSMTP(t, "220 hung.local ESMTP", "250 hung.local")
			// Timeout disabled: only the context can end the session.
			tr := NewSMTPTransport(Config{Host: host, Port: port, Timeout: -1})
			ctx, cancel := tc.ctx()
			defer cancel()

			_, err := sendWithin(t, ctx, tr, 5*time.Second)
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// replyCode returns the SMTP reply code carried by err, or 0 if err does not
// wrap a *textproto.Error.
func replyCode(err error) int {
	var tpErr *textproto.Error
	if errors.As(err, &tpErr) {
		return tpErr.Code
	}
	return 0
}

func isTransient(err error) bool {
	var transient email.TransientError
	return errors.As(err, &transient)
}

func TestSMTPTransport_ReplyClassification(t *testing.T) {
	cases := []struct {
		name      string
		relay     bool
		stage     string
		reply     string
		code      int
		transient bool
	}{
		{"greeting 421", false, "GREETING", "421 4.3.2 service shutting down", 421, true},
		{"mail 450", false, "MAIL", "450 4.2.1 mailbox busy", 450, true},
		{"rcpt 451 greylisted", false, "RCPT", "451 4.7.1 greylisted, try again later", 451, true},
		{"rcpt 452", false, "RCPT", "452 4.5.3 too many recipients", 452, true},
		{"data 451", false, "DATA", "451 4.3.0 local error", 451, true},
		{"end of data 452", false, "END", "452 4.3.1 insufficient storage", 452, true},
		{"auth 454", true, "AUTH", "454 4.7.0 temporary authentication failure", 454, true},
		{"rcpt 550", false, "RCPT", "550 5.1.1 no such user", 550, false},
		{"end of data 554", false, "END", "554 5.7.1 rejected as spam", 554, false},
		{"auth 535", true, "AUTH", "535 5.7.8 bad credentials", 535, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{From: "a@example.com"}
			var srv *fakeSMTP
			if tc.relay {
				srv = startFakeSMTPTLS(t)
				cfg.User, cfg.Pass, cfg.TLS, cfg.TLSInsecure = "u", "p", true, true
			} else {
				srv = startFakeSMTP(t)
			}
			cfg.Host, cfg.Port = srv.Host, srv.Port
			srv.failNext(tc.stage, tc.reply)

			err := NewSMTPTransport(cfg).Send(context.Background(), email.Message{
				From: "a@example.com", To: []string{"b@example.com"}, Text: "hi",
			})
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := isTransient(err); got != tc.transient {
				t.Errorf("transient = %v, want %v (err: %v)", got, tc.transient, err)
			}
			if got := replyCode(err); got != tc.code {
				t.Errorf("reply code = %d, want %d (err: %v)", got, tc.code, err)
			}
		})
	}
}

func TestSMTPTransport_DialTimeoutIsTransient(t *testing.T) {
	// 192.0.2.1 is TEST-NET-1 (RFC 5737): never assigned, so a SYN to it is
	// normally dropped and the dial can only end by timing out.
	tr := NewSMTPTransport(Config{Host: "192.0.2.1", Port: 25, DialTimeout: 200 * time.Millisecond})

	took, err := sendWithin(t, context.Background(), tr, 10*time.Second)
	if err == nil {
		t.Fatal("expected the dial to fail")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Skipf("this network rejected the dial at once (%v), so the timeout can't be observed here", err)
	}
	if took > 3*time.Second {
		t.Errorf("dial took %v, want it bounded by the 200ms DialTimeout", took)
	}
	var transient email.TransientError
	if !errors.As(err, &transient) {
		t.Errorf("a dial timeout should be transient (nothing was sent): %v", err)
	}
}

func TestLoadConfig_Timeouts(t *testing.T) {
	t.Setenv("SMTP_DIAL_TIMEOUT", "")
	t.Setenv("SMTP_TIMEOUT", "")
	cfg := LoadConfig()
	if cfg.DialTimeout != DefaultDialTimeout || cfg.Timeout != DefaultTimeout {
		t.Errorf("defaults = %v/%v, want %v/%v", cfg.DialTimeout, cfg.Timeout, DefaultDialTimeout, DefaultTimeout)
	}

	t.Setenv("SMTP_DIAL_TIMEOUT", "5s")
	t.Setenv("SMTP_TIMEOUT", "2m")
	cfg = LoadConfig()
	if cfg.DialTimeout != 5*time.Second || cfg.Timeout != 2*time.Minute {
		t.Errorf("overrides = %v/%v, want 5s/2m", cfg.DialTimeout, cfg.Timeout)
	}

	t.Setenv("SMTP_DIAL_TIMEOUT", "soon")
	t.Setenv("SMTP_TIMEOUT", "-1")
	cfg = LoadConfig()
	if cfg.DialTimeout != DefaultDialTimeout {
		t.Errorf("unparseable SMTP_DIAL_TIMEOUT = %v, want default %v", cfg.DialTimeout, DefaultDialTimeout)
	}
	if cfg.Timeout != DefaultTimeout {
		t.Errorf("unitless SMTP_TIMEOUT = %v, want default %v", cfg.Timeout, DefaultTimeout)
	}
}

// TestSMTPTransport_QuitFailureIsNotTransient covers a relay that accepts the
// message and then fails QUIT: the mail is already queued, so retrying would
// deliver it twice.
func TestSMTPTransport_QuitFailureIsNotTransient(t *testing.T) {
	srv := startFakeSMTP(t)
	srv.failNext("QUIT", "421 4.3.2 closing connection")
	tr := NewSMTPTransport(Config{Host: srv.Host, Port: srv.Port, From: "a@example.com"})

	err := tr.Send(context.Background(), email.Message{From: "a@example.com", To: []string{"b@example.com"}, Text: "hi"})
	if err == nil {
		t.Fatal("expected the QUIT failure to be reported")
	}
	if isTransient(err) {
		t.Errorf("QUIT failure after the message was accepted must not be transient: %v", err)
	}
	if replyCode(err) != 421 {
		t.Errorf("reply code = %d, want 421", replyCode(err))
	}
}

// TestSMTPTransport_RetryRecoversFromGreylisting wires the transport behind
// email.Retry the way the README does and checks that one 451 is retried.
func TestSMTPTransport_RetryRecoversFromGreylisting(t *testing.T) {
	srv := startFakeSMTP(t)
	srv.failNext("RCPT", "451 4.7.1 greylisted, try again later")
	tr := NewSMTPTransport(Config{Host: srv.Host, Port: srv.Port, From: "a@example.com"})
	sender := email.New(tr, email.WithMiddleware(email.Retry(3, time.Millisecond)))

	err := sender.Send(context.Background(), email.Message{From: "a@example.com", To: []string{"b@example.com"}, Text: "hi"})
	if err != nil {
		t.Fatalf("Send after one greylisting reply = %v, want nil", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.Rcpts) != 1 || srv.Rcpts[0] != "b@example.com" {
		t.Errorf("RCPT TO = %v, want [b@example.com]", srv.Rcpts)
	}
}
