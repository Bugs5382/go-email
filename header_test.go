package email

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
	"errors"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

// baseMsg is a minimal valid message used as the starting point for header tests.
func baseMsg() Message {
	return Message{From: "a@example.com", To: []string{"b@example.com"}, Subject: "S", Text: "hi"}
}

// headerBlock returns the raw header block (everything before the first blank
// line) of a rendered message.
func headerBlock(t *testing.T, b []byte) string {
	t.Helper()
	i := bytes.Index(b, []byte("\r\n\r\n"))
	if i < 0 {
		t.Fatalf("no header/body separator in:\n%s", b)
	}
	return string(b[:i+2])
}

func TestBytes_RejectsCRLFInHeaders(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"x\r\nBcc: evil@example.com", "x\nBcc: evil@example.com", "x\rBcc: evil@example.com"} {
		cases := map[string]func(m *Message){
			"subject":          func(m *Message) { m.Subject = bad },
			"from":             func(m *Message) { m.From = bad },
			"reply-to":         func(m *Message) { m.ReplyTo = bad },
			"to":               func(m *Message) { m.To = []string{bad} },
			"cc":               func(m *Message) { m.Cc = []string{bad} },
			"list-unsubscribe": func(m *Message) { m.ListUnsubscribe = bad },
			"list-unsub-post":  func(m *Message) { m.ListUnsubscribePost = bad },
			"custom value":     func(m *Message) { m.Headers = map[string]string{"X-A": bad} },
			"custom key":       func(m *Message) { m.Headers = map[string]string{bad: "v"} },
			"attach filename":  func(m *Message) { m.Attachments = []Attachment{{Filename: bad, Content: []byte("x")}} },
			"attach type": func(m *Message) {
				m.Attachments = []Attachment{{Filename: "a", ContentType: bad, Content: []byte("x")}}
			},
			"inline content id": func(m *Message) {
				m.Attachments = []Attachment{{Filename: "a", Inline: true, ContentID: bad, Content: []byte("x")}}
			},
		}
		for name, mutate := range cases {
			m := baseMsg()
			mutate(&m)
			b, err := m.Bytes()
			if !errors.Is(err, ErrInvalidHeader) {
				t.Errorf("%s %q: err = %v, want ErrInvalidHeader", name, bad, err)
			}
			if b != nil {
				t.Errorf("%s %q: got bytes on error", name, bad)
			}
		}
	}
}

func TestBytes_RejectsBadCustomHeaderNames(t *testing.T) {
	t.Parallel()

	for _, k := range []string{"", "X A", "X:A", "X-é", "Content-Type", "content-transfer-encoding", "MIME-Version"} {
		m := baseMsg()
		m.Headers = map[string]string{k: "v"}
		if _, err := m.Bytes(); !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("header name %q: err = %v, want ErrInvalidHeader", k, err)
		}
	}
}

func TestValidate_RejectsHeaderInjection(t *testing.T) {
	t.Parallel()

	m := baseMsg()
	m.Subject = "hi\r\nBcc: evil@example.com"
	called := false
	send := Validate()(func(context.Context, *Message) error { called = true; return nil })
	err := send(context.Background(), &m)
	if !errors.Is(err, ErrValidation) || !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("err = %v, want ErrValidation and ErrInvalidHeader", err)
	}
	if called {
		t.Fatal("next must not run")
	}
}

func TestBytes_EncodesNonASCIISubject(t *testing.T) {
	t.Parallel()

	subj := "Grüße aus Köln — " + strings.Repeat("äöü ", 30)
	m := baseMsg()
	m.Subject = subj
	b, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	hb := headerBlock(t, b)
	assertASCII(t, hb)
	for _, line := range strings.Split(strings.TrimSuffix(hb, "\r\n"), "\r\n") {
		if len(line) > 78 {
			t.Errorf("header line longer than 78 chars (%d): %q", len(line), line)
		}
	}
	msg, err := mail.ReadMessage(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	got, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil {
		t.Fatal(err)
	}
	if got != subj {
		t.Errorf("decoded subject = %q, want %q", got, subj)
	}
}

func TestBytes_ASCIISubjectUnchanged(t *testing.T) {
	t.Parallel()

	m := baseMsg()
	m.Subject = "Plain =?subject?= here"
	b, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\r\nSubject: Plain =?subject?= here\r\n") {
		t.Errorf("ASCII subject rewritten:\n%s", b)
	}
}

func TestBytes_EncodesNonASCIIDisplayNames(t *testing.T) {
	t.Parallel()

	m := baseMsg()
	m.From = "Jörg Müller <jorg@example.com>"
	m.ReplyTo = "Zoë <zoe@example.com>"
	m.To = []string{"Renée <renee@example.com>", "Plain Name <p@example.com>"}
	m.Cc = []string{"张伟 <zhang@example.com>"}
	b, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	hb := headerBlock(t, b)
	assertASCII(t, hb)
	if !strings.Contains(hb, "Plain Name <p@example.com>") {
		t.Errorf("ASCII display name rewritten:\n%s", hb)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	check := func(key string, want ...string) {
		t.Helper()
		list, err := msg.Header.AddressList(key)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if len(list) != len(want) {
			t.Fatalf("%s: got %d addresses, want %d", key, len(list), len(want))
		}
		for i, w := range want {
			if list[i].Name != w {
				t.Errorf("%s[%d] name = %q, want %q", key, i, list[i].Name, w)
			}
		}
	}
	check("From", "Jörg Müller")
	check("Reply-To", "Zoë")
	check("To", "Renée", "Plain Name")
	check("Cc", "张伟")
}

func TestBytes_EncodesAttachmentFilenames(t *testing.T) {
	t.Parallel()

	names := []string{"r.pdf", `we"ird\name.txt`, "Résumé — 2026.pdf", "报告.docx"}
	m := baseMsg()
	for _, n := range names {
		m.Attachments = append(m.Attachments, Attachment{Filename: n, ContentType: "application/octet-stream", Content: []byte("x")})
	}
	b, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	assertASCII(t, string(b))
	if !strings.Contains(string(b), `filename="r.pdf"`) {
		t.Error("plain ASCII filename should stay a quoted filename parameter")
	}

	msg, err := mail.ReadMessage(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var got []string
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		if cd := p.Header.Get("Content-Disposition"); cd != "" {
			_, dp, err := mime.ParseMediaType(cd)
			if err != nil {
				t.Fatalf("parse %q: %v", cd, err)
			}
			got = append(got, dp["filename"])
		}
	}
	if strings.Join(got, "|") != strings.Join(names, "|") {
		t.Errorf("filenames = %q, want %q", got, names)
	}
}

func TestBytes_CustomHeadersSorted(t *testing.T) {
	t.Parallel()

	m := baseMsg()
	m.Headers = map[string]string{
		"X-Zeta": "z", "X-Alpha": "a", "X-Mid": "m", "X-Beta": "b", "X-Kappa": "k",
		"Date": "Sat, 26 Sep 2026 10:00:00 +0000", "Message-ID": "<fixed@example.com>",
	}
	first, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	hb := headerBlock(t, first)
	idx := func(s string) int { return strings.Index(hb, "\r\n"+s+":") }
	order := []string{"X-Alpha", "X-Beta", "X-Kappa", "X-Mid", "X-Zeta"}
	for i := 1; i < len(order); i++ {
		if idx(order[i-1]) < 0 || idx(order[i-1]) > idx(order[i]) {
			t.Fatalf("custom headers not sorted:\n%s", hb)
		}
	}
	for range 20 {
		again, err := m.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if headerBlock(t, again) != hb {
			t.Fatal("header block is not deterministic")
		}
	}
}

func TestBytes_GeneratesDateAndMessageID(t *testing.T) {
	t.Parallel()

	m := baseMsg()
	m.From = "Sender <sender@mail.example.com>"
	b, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := msg.Header.Date(); err != nil {
		t.Errorf("Date header missing or invalid: %v", err)
	}
	id := msg.Header.Get("Message-Id")
	if !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, "@mail.example.com>") || len(id) < len("<@mail.example.com>")+16 {
		t.Errorf("Message-ID = %q, want <random@mail.example.com>", id)
	}
	b2, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	msg2, err := mail.ReadMessage(bytes.NewReader(b2))
	if err != nil {
		t.Fatal(err)
	}
	if msg2.Header.Get("Message-Id") == id {
		t.Error("Message-ID must be unique per render")
	}
}

func TestBytes_KeepsCallerDateAndMessageID(t *testing.T) {
	t.Parallel()

	m := baseMsg()
	m.Headers = map[string]string{"date": "Sat, 26 Sep 2026 10:00:00 +0000", "Message-Id": "<fixed@example.com>"}
	b, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(msg.Header["Date"]); n != 1 {
		t.Errorf("want exactly one Date header, got %d", n)
	}
	if got := msg.Header["Message-Id"]; len(got) != 1 || got[0] != "<fixed@example.com>" {
		t.Errorf("Message-ID headers = %q, want the caller's one", got)
	}
}

func TestBytes_MessageIDFallbackDomain(t *testing.T) {
	t.Parallel()

	m := baseMsg()
	m.From = "not an address"
	b, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if id := msg.Header.Get("Message-Id"); !strings.HasSuffix(id, "@localhost>") {
		t.Errorf("Message-ID = %q, want @localhost fallback", id)
	}
}

func assertASCII(t *testing.T, s string) {
	t.Helper()
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			t.Errorf("non-ASCII byte at %d in:\n%s", i, s)
			return
		}
	}
}

// FuzzBytesHeaders checks that no caller-supplied header content can add a
// header line: Bytes either rejects the message with ErrInvalidHeader or
// renders a header block whose field names are exactly the expected set.
func FuzzBytesHeaders(f *testing.F) {
	f.Add("Hello", "a@example.com", "r.pdf", "v")
	f.Add("x\r\nBcc: evil@example.com", "Jörg <j@example.com>", "Résumé.pdf", "a\nb")
	f.Add("=?utf-8?q?x?=", "\"q\" <q@example.com>", `a"b\c`, "")
	f.Fuzz(func(t *testing.T, subject, from, filename, custom string) {
		m := Message{
			From: from, To: []string{"b@example.com"}, Subject: subject, Text: "hi",
			Headers:     map[string]string{"X-Custom": custom},
			Attachments: []Attachment{{Filename: filename, ContentType: "text/plain", Content: []byte("x")}},
		}
		b, err := m.Bytes()
		if err != nil {
			if !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		msg, err := mail.ReadMessage(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("rendered message does not parse: %v\n%q", err, b)
		}
		allowed := map[string]bool{
			"From": true, "To": true, "Subject": true, "X-Custom": true, "Date": true,
			"Message-Id": true, "Mime-Version": true, "Content-Type": true,
		}
		for k, v := range msg.Header {
			if !allowed[k] || len(v) != 1 {
				t.Fatalf("unexpected header %q (%d) in:\n%q", k, len(v), b)
			}
		}
	})
}
