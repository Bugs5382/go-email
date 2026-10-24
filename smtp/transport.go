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
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"strconv"
	"time"

	email "github.com/Bugs5382/go-email"
	log "github.com/Bugs5382/go-log"
)

// SMTPTransport is an email.Transport backed by net/smtp. With no SMTP_USER
// and no TLS configured (the default, matching a local catcher like maildev)
// it does a bare, unauthenticated handshake, upgrading with STARTTLS only if
// the server offers it; otherwise it STARTTLS-upgrades and/or authenticates
// against a real relay.
//
// Every send is bounded in time: connecting by Config.DialTimeout, and each
// read or write on the connection by Config.Timeout (both have defaults, see
// DefaultDialTimeout and DefaultTimeout). The ctx passed to Send is honored
// for the whole session, so cancelling it or reaching its deadline ends a send
// that is waiting on the server, and the error matches ctx.Err() with
// errors.Is.
type SMTPTransport struct {
	cfg Config
}

// NewSMTPTransport returns an SMTPTransport for the given Config.
func NewSMTPTransport(cfg Config) *SMTPTransport {
	return &SMTPTransport{cfg: cfg}
}

// Send renders m via m.Bytes and delivers it to m.Recipients() (the To ∪ Cc
// ∪ Bcc set) using the SMTP envelope MAIL FROM of m.EnvelopeFrom, falling
// back to m.From when EnvelopeFrom is unset. Bcc addresses are only ever used
// for RCPT TO -- m.Bytes never writes them into the message headers.
//
// A 4xx reply from the server at any stage before the message is accepted
// (greeting, STARTTLS, AUTH, MAIL, RCPT, DATA or the end-of-data reply) is
// returned wrapped in email.TransientError, so email.Retry retries it; 5xx
// replies are permanent. A failed QUIT after the server accepted the message
// is reported but never transient, so a retry can't send it twice. The
// server's *textproto.Error is reachable with errors.As in every case.
func (t *SMTPTransport) Send(ctx context.Context, m email.Message) error {
	addr := net.JoinHostPort(t.cfg.Host, strconv.Itoa(t.cfg.Port))
	s := &session{log: t.logger().Ctx(ctx).With(log.F("send_id", newSendID()), log.F("relay", addr))}
	start := time.Now()

	if err := ctx.Err(); err != nil {
		err = fmt.Errorf("email: context: %w", err)
		s.stage = "start"
		s.finish(ctx, err, start)
		return err
	}

	from := m.EnvelopeFrom
	if from == "" {
		from = m.From
	}
	rcpts := m.Recipients()

	msg, err := m.Bytes()
	if err != nil {
		s.stage = "build"
		s.cause = err
		s.finish(ctx, err, start)
		return fmt.Errorf("build mime: %w", err)
	}

	s.log.Debug("smtp send starting",
		log.F("recipients", len(rcpts)),
		log.F("size_bytes", len(msg)),
		log.F("tls", t.tlsMode()),
		log.F("auth", t.cfg.User != ""),
	)
	err = classify(t.deliver(ctx, s, addr, from, rcpts, msg))
	s.finish(ctx, err, start)
	return err
}

// tlsMode names the STARTTLS policy for logging: "required" with TLS set,
// "opportunistic" for the local-catcher setup, "off" for a User without TLS.
func (t *SMTPTransport) tlsMode() string {
	switch {
	case t.cfg.TLS:
		return "required"
	case t.cfg.User == "":
		return "opportunistic"
	}
	return "off"
}

// deliver runs one SMTP session against addr: Dial, STARTTLS, optional Auth,
// then Mail/Rcpt/Data/Quit. Both the plaintext local-catcher setup and the
// relay setup go through it; they differ only in how STARTTLS and Auth are
// decided (see startTLS). Each stage runs through s, which records where a
// failure happened for the outcome log line.
func (t *SMTPTransport) deliver(ctx context.Context, s *session, addr, from string, rcpts []string, msg []byte) error {
	var client *smtp.Client
	if err := s.step("dial", func() (err error) {
		client, err = t.dial(ctx, addr)
		return err
	}); err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer func() { _ = client.Close() }()

	if err := s.step("starttls", func() error {
		upgraded, err := t.startTLS(client)
		if err == nil {
			s.log.Debug("smtp starttls", log.F("upgraded", upgraded), log.F("verified", upgraded && (!t.cfg.TLS || !t.cfg.TLSInsecure)))
		}
		return err
	}); err != nil {
		return fmt.Errorf("smtp starttls: %w", err)
	}
	if t.cfg.User != "" {
		auth := smtp.PlainAuth("", t.cfg.User, t.cfg.Pass, t.cfg.Host)
		if err := s.step("auth", func() error { return client.Auth(auth) }); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := s.step("mail", func() error { return client.Mail(from) }); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, rcpt := range rcpts {
		if err := s.step("rcpt", func() error { return client.Rcpt(rcpt) }); err != nil {
			s.rcptID = rcptID(rcpt)
			return fmt.Errorf("smtp rcpt to %q: %w", rcpt, err)
		}
	}
	var wc io.WriteCloser
	if err := s.step("data", func() (err error) {
		wc, err = client.Data()
		return err
	}); err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	var op string
	if err := s.step("message", func() error {
		if _, err := wc.Write(msg); err != nil {
			_ = wc.Close()
			op = "smtp write"
			return err
		}
		op = "smtp close data"
		return wc.Close()
	}); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if err := s.step("quit", func() error { return client.Quit() }); err != nil {
		return fmt.Errorf("smtp quit: %w", acceptedError{err: err})
	}
	return nil
}

// startTLS upgrades the session when the Config asks for it and reports
// whether it did. With TLS set it always upgrades, honoring TLSInsecure. With
// neither TLS nor a User set (the local-catcher setup) it upgrades only when
// the server offers STARTTLS, with full certificate verification, the same as
// net/smtp.SendMail. A User without TLS stays plaintext.
func (t *SMTPTransport) startTLS(client *smtp.Client) (bool, error) {
	switch {
	case t.cfg.TLS:
		// #nosec G402 -- InsecureSkipVerify is opt-in (Config.TLSInsecure,
		// default false/verified) for relays with a non-standard certificate;
		// the connection stays encrypted either way.
		return true, client.StartTLS(&tls.Config{ServerName: t.cfg.Host, InsecureSkipVerify: t.cfg.TLSInsecure}) //nolint:gosec
	case t.cfg.User == "":
		if ok, _ := client.Extension("STARTTLS"); ok {
			return true, client.StartTLS(&tls.Config{ServerName: t.cfg.Host})
		}
	}
	return false, nil
}

var _ email.Transport = (*SMTPTransport)(nil)
