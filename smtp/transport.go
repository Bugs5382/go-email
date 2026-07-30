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
	"net"
	"net/smtp"
	"strconv"

	email "github.com/Bugs5382/go-email"
)

// SMTPTransport is an email.Transport backed by net/smtp. With no SMTP_USER
// and no TLS configured (the default, matching a local catcher like maildev)
// it does a bare, unauthenticated handshake; otherwise it STARTTLS-upgrades
// and/or authenticates against a real relay.
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
func (t *SMTPTransport) Send(ctx context.Context, m email.Message) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("email: context: %w", err)
	}

	addr := net.JoinHostPort(t.cfg.Host, strconv.Itoa(t.cfg.Port))

	from := m.EnvelopeFrom
	if from == "" {
		from = m.From
	}
	rcpts := m.Recipients()

	msg, err := m.Bytes()
	if err != nil {
		return fmt.Errorf("build mime: %w", err)
	}

	if !t.cfg.TLS && t.cfg.User == "" {
		// Plaintext, no-auth path (e.g. a local catcher like maildev): use
		// SendMail with a nil auth.
		if err := smtp.SendMail(addr, nil, from, rcpts, msg); err != nil {
			return fmt.Errorf("smtp send: %w", err)
		}
		return nil
	}

	return t.sendViaRelay(addr, from, rcpts, msg)
}

// sendViaRelay authenticates and/or STARTTLS-upgrades against a real relay:
// Dial, optional StartTLS, optional Auth, then Mail/Rcpt/Data/Quit.
func (t *SMTPTransport) sendViaRelay(addr, from string, rcpts []string, msg []byte) error {
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer func() { _ = client.Close() }()

	if t.cfg.TLS {
		// #nosec G402 -- InsecureSkipVerify is opt-in (Config.TLSInsecure,
		// default false/verified) for relays with a non-standard certificate;
		// the connection stays encrypted either way.
		tlsCfg := &tls.Config{ServerName: t.cfg.Host, InsecureSkipVerify: t.cfg.TLSInsecure} //nolint:gosec
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if t.cfg.User != "" {
		auth := smtp.PlainAuth("", t.cfg.User, t.cfg.Pass, t.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, rcpt := range rcpts {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp rcpt to %q: %w", rcpt, err)
		}
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("smtp quit: %w", err)
	}
	return nil
}

var _ email.Transport = (*SMTPTransport)(nil)
