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
	"math/big"
	"net"
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
			s.mu.Lock()
			s.MailFrom = extractAddr(line[len("MAIL FROM:"):])
			s.mu.Unlock()
			writeLine(conn, "250 OK")
		case strings.HasPrefix(upper, "RCPT TO:"):
			s.mu.Lock()
			s.Rcpts = append(s.Rcpts, extractAddr(line[len("RCPT TO:"):]))
			s.mu.Unlock()
			writeLine(conn, "250 OK")
		case upper == "DATA":
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
			writeLine(conn, "250 OK: queued")
		case upper == "QUIT":
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
