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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	email "github.com/Bugs5382/go-email"
	log "github.com/Bugs5382/go-log"
)

// lockedBuffer is a bytes.Buffer safe to share with a logger.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLogger returns a go-log Logger that writes JSON lines at trace level
// into the returned buffer.
func captureLogger(t *testing.T) (log.Logger, *lockedBuffer) {
	t.Helper()
	t.Setenv("LOG_LEVEL", "trace")
	t.Setenv("LOG_FORMAT", "json")
	buf := &lockedBuffer{}
	return log.NewLoggerWithOptions("smtp-test", log.WithOutput(buf)), buf
}

type logLine map[string]any

func parseLines(t *testing.T, raw string) []logLine {
	t.Helper()
	var out []logLine
	for _, l := range strings.Split(strings.TrimSpace(raw), "\n") {
		if l == "" {
			continue
		}
		var m logLine
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

// find returns the first line whose message is msg, failing the test if none.
func find(t *testing.T, lines []logLine, msg string) logLine {
	t.Helper()
	for _, l := range lines {
		if l["message"] == msg {
			return l
		}
	}
	t.Fatalf("no log line %q in:\n%v", msg, lines)
	return nil
}

func stagesTraced(lines []logLine) []string {
	var out []string
	for _, l := range lines {
		if l["message"] == "smtp stage done" {
			out = append(out, l["stage"].(string))
		}
	}
	return out
}

// assertNoLeaks fails if any of the secrets appears anywhere in the log.
func assertNoLeaks(t *testing.T, raw string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(raw, s) {
			t.Errorf("log contains %q:\n%s", s, raw)
		}
	}
}

func TestSMTPTransport_LogsSuccessfulRelaySend(t *testing.T) {
	logger, buf := captureLogger(t)
	srv := startFakeSMTPTLS(t)
	tr := NewSMTPTransport(Config{
		Host: srv.Host, Port: srv.Port,
		User: "reluser", Pass: "relpass",
		TLS: true, TLSInsecure: true,
		Logger: logger,
	})

	err := tr.Send(context.Background(), email.Message{
		From:    "sender@example.com",
		To:      []string{"to@example.com"},
		Cc:      []string{"cc@example.com"},
		Bcc:     []string{"hidden@example.com"},
		Subject: "Quarterly numbers",
		Text:    "the body text",
	})
	if err != nil {
		t.Fatal(err)
	}

	raw := buf.String()
	lines := parseLines(t, raw)
	relay := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))

	start := find(t, lines, "smtp send starting")
	if start["level"] != "debug" || start["relay"] != relay || start["recipients"] != float64(3) ||
		start["auth"] != true || start["tls"] != "required" {
		t.Errorf("start line = %v", start)
	}
	if _, ok := start["size_bytes"].(float64); !ok {
		t.Errorf("start line has no size_bytes: %v", start)
	}

	tlsLine := find(t, lines, "smtp starttls")
	if tlsLine["upgraded"] != true || tlsLine["verified"] != false {
		t.Errorf("starttls line = %v", tlsLine)
	}

	done := find(t, lines, "smtp send delivered")
	if done["level"] != "info" || done["outcome"] != "delivered" || done["relay"] != relay {
		t.Errorf("done line = %v", done)
	}
	if _, ok := done["duration_ms"].(float64); !ok {
		t.Errorf("done line has no duration_ms: %v", done)
	}

	want := []string{"dial", "starttls", "auth", "mail", "rcpt", "rcpt", "rcpt", "data", "message", "quit"}
	if got := stagesTraced(lines); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("stages = %v, want %v", got, want)
	}

	id, _ := start["send_id"].(string)
	if id == "" {
		t.Fatalf("start line has no send_id: %v", start)
	}
	for _, l := range lines {
		if l["send_id"] != id {
			t.Errorf("line without the send's id: %v", l)
		}
	}

	assertNoLeaks(t, raw, "reluser", "relpass", "sender@example.com", "to@example.com",
		"cc@example.com", "hidden@example.com", "Quarterly numbers", "the body text")
}

func TestSMTPTransport_LogsFailures(t *testing.T) {
	cases := []struct {
		name      string
		stage     string
		reply     string
		level     string
		msg       string
		outcome   string
		code      int
		transient bool
	}{
		{"rcpt greylisted", "RCPT", "451 4.7.1 <to@example.com> greylisted", "warn", "smtp send failed", "transient", 451, true},
		{"rcpt rejected", "RCPT", "550 5.1.1 <to@example.com> no such user", "error", "smtp send failed", "failed", 550, false},
		{"quit after accept", "QUIT", "421 4.3.2 closing", "warn", "smtp send accepted, quit failed", "accepted", 421, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger, buf := captureLogger(t)
			srv := startFakeSMTP(t)
			srv.failNext(tc.stage, tc.reply)
			tr := NewSMTPTransport(Config{Host: srv.Host, Port: srv.Port, Logger: logger})

			err := tr.Send(context.Background(), email.Message{
				From: "sender@example.com", To: []string{"to@example.com"}, Text: "the body text",
			})
			if err == nil {
				t.Fatal("expected an error")
			}

			raw := buf.String()
			l := find(t, parseLines(t, raw), tc.msg)
			if l["level"] != tc.level || l["outcome"] != tc.outcome ||
				l["reply_code"] != float64(tc.code) || l["transient"] != tc.transient ||
				l["stage"] != strings.ToLower(tc.stage) {
				t.Errorf("failure line = %v", l)
			}
			if _, ok := l["duration_ms"].(float64); !ok {
				t.Errorf("failure line has no duration_ms: %v", l)
			}
			if _, ok := l["error"].(string); !ok {
				t.Errorf("failure line has no error: %v", l)
			}
			if tc.stage == "RCPT" {
				if id, _ := l["rcpt_id"].(string); id == "" {
					t.Errorf("rcpt failure has no rcpt_id: %v", l)
				}
			}
			assertNoLeaks(t, raw, "sender@example.com", "to@example.com", "the body text", "greylisted", "no such user")
		})
	}
}

func TestSMTPTransport_LogsDialFailureAndCancel(t *testing.T) {
	t.Run("dial refused", func(t *testing.T) {
		logger, buf := captureLogger(t)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().(*net.TCPAddr)
		_ = ln.Close()

		tr := NewSMTPTransport(Config{Host: addr.IP.String(), Port: addr.Port, Logger: logger})
		if err := tr.Send(context.Background(), email.Message{From: "a@example.com", To: []string{"b@example.com"}, Text: "hi"}); err == nil {
			t.Fatal("expected the dial to fail")
		}
		l := find(t, parseLines(t, buf.String()), "smtp send failed")
		if l["level"] != "error" || l["stage"] != "dial" || l["outcome"] != "failed" {
			t.Errorf("dial failure line = %v", l)
		}
		if _, ok := l["reply_code"]; ok {
			t.Errorf("dial failure has a reply_code: %v", l)
		}
	})

	t.Run("context already cancelled", func(t *testing.T) {
		logger, buf := captureLogger(t)
		srv := startFakeSMTP(t)
		tr := NewSMTPTransport(Config{Host: srv.Host, Port: srv.Port, Logger: logger})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := tr.Send(ctx, email.Message{From: "a@example.com", To: []string{"b@example.com"}, Text: "hi"}); err == nil {
			t.Fatal("expected an error")
		}
		l := find(t, parseLines(t, buf.String()), "smtp send ended by context")
		if l["level"] != "warn" || l["outcome"] != "cancelled" {
			t.Errorf("cancel line = %v", l)
		}
	})
}

// TestSMTPTransport_NilLoggerIsSilent pins the default: with no Logger the
// transport writes nothing, even with LOG_LEVEL at trace.
func TestSMTPTransport_NilLoggerIsSilent(t *testing.T) {
	t.Setenv("LOG_LEVEL", "trace")
	srv := startFakeSMTP(t)
	tr := NewSMTPTransport(Config{Host: srv.Host, Port: srv.Port})

	out := captureStd(t, func() {
		if err := tr.Send(context.Background(), email.Message{From: "a@example.com", To: []string{"b@example.com"}, Text: "hi"}); err != nil {
			t.Fatal(err)
		}
		srv.failNext("RCPT", "550 no")
		_ = tr.Send(context.Background(), email.Message{From: "a@example.com", To: []string{"b@example.com"}, Text: "hi"})
	})
	if out != "" {
		t.Errorf("nil Logger wrote %q", out)
	}
}

// captureStd runs fn with stdout and stderr redirected and returns what was
// written to them.
func captureStd(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() {
		os.Stdout, os.Stderr = oldOut, oldErr
	}()
	fn()
	_ = w.Close()
	return <-done
}

// ExampleConfig_logger turns on the transport's logs with a go-log Logger.
func ExampleConfig_logger() {
	cfg := LoadConfig()
	cfg.Logger = log.NewLogger("billing")
	transport := NewSMTPTransport(cfg)
	_ = transport
}
