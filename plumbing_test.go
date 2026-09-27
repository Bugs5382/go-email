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
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPartBytes(t *testing.T) {
	t.Parallel()

	p := Part{
		ContentType:      "text/plain; charset=utf-8",
		TransferEncoding: "quoted-printable",
		Headers:          []Header{{"Content-Disposition", "inline"}, {"Content-Description", "note"}},
		Body:             []byte("hi"),
	}
	want := "Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"Content-Disposition: inline\r\n" +
		"Content-Description: note\r\n" +
		"\r\n" +
		"hi"
	if got := string(p.Bytes()); got != want {
		t.Errorf("Part.Bytes() =\n%q\nwant\n%q", got, want)
	}
	mp := Part{ContentType: "multipart/mixed; boundary=b", Body: []byte("x")}
	if got := string(mp.Bytes()); got != "Content-Type: multipart/mixed; boundary=b\r\n\r\nx" {
		t.Errorf("multipart Part.Bytes() = %q", got)
	}
}

// TestEntityIsEmbeddedVerbatim checks the property a detached signature
// depends on: the bytes Entity returns appear unchanged in the rendered
// message, and nested parts are rendered by Part.Bytes too.
func TestEntityIsEmbeddedVerbatim(t *testing.T) {
	t.Parallel()

	m := baseMsg()
	m.HTML = `<p>hi <img src="cid:logo"></p>`
	m.Attachments = []Attachment{
		{Filename: "logo.png", ContentType: "image/png", Content: []byte("PNG"), Inline: true, ContentID: "logo"},
		{Filename: "r.pdf", ContentType: "application/pdf", Content: []byte("%PDF")},
	}
	ent, err := m.Entity()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ent.ContentType, "multipart/mixed; boundary=") {
		t.Fatalf("entity content type = %q", ent.ContentType)
	}
	b, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	// Boundaries are random per render, so compare an entity taken from a
	// message whose body is fixed.
	m2 := baseMsg()
	m2.Body = &ent
	b2, err := m2.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b2, ent.Bytes()) {
		t.Fatal("rendered message does not contain Entity().Bytes() verbatim")
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
	var n int
	for {
		if _, err := mr.NextPart(); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			break
		}
		n++
	}
	if n != 2 {
		t.Errorf("multipart/mixed has %d parts, want 2 (related + pdf)", n)
	}
}

func TestBodyOverridesContent(t *testing.T) {
	t.Parallel()

	m := baseMsg()
	m.HTML = "<p>ignored</p>"
	m.Attachments = []Attachment{{Filename: "a.txt", Content: []byte("ignored")}}
	m.Body = &Part{
		ContentType:      "application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m",
		TransferEncoding: "base64",
		Headers:          []Header{{"Content-Disposition", `attachment; filename="smime.p7m"`}},
		Body:             []byte("AAAA\r\n"),
	}
	b, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.Header.Get("Content-Type"); got != m.Body.ContentType {
		t.Errorf("Content-Type = %q", got)
	}
	if got := msg.Header.Get("Content-Disposition"); got != `attachment; filename="smime.p7m"` {
		t.Errorf("Content-Disposition = %q", got)
	}
	if got := msg.Header.Get("Subject"); got != "S" {
		t.Errorf("Subject = %q", got)
	}
	body, _ := io.ReadAll(msg.Body)
	if string(body) != "AAAA\r\n" {
		t.Errorf("body = %q", body)
	}
	if strings.Contains(string(b), "ignored") {
		t.Error("HTML/attachments must be ignored when Body is set")
	}
	ent, err := m.Entity()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ent.Bytes(), m.Body.Bytes()) {
		t.Error("Entity must return *Body when set")
	}
}

func TestBodyHeadersRejectCRLF(t *testing.T) {
	t.Parallel()

	for name, p := range map[string]Part{
		"content type": {ContentType: "text/plain\r\nBcc: x@example.com"},
		"cte":          {ContentType: "text/plain", TransferEncoding: "7bit\r\nX: y"},
		"header value": {ContentType: "text/plain", Headers: []Header{{"X-A", "a\nb"}}},
		"header name":  {ContentType: "text/plain", Headers: []Header{{"X A", "v"}}},
		"empty type":   {},
	} {
		m := baseMsg()
		m.Body = &p
		if _, err := m.Bytes(); !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("%s: err = %v, want ErrInvalidHeader", name, err)
		}
		if _, err := m.Entity(); !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("%s: Entity err = %v, want ErrInvalidHeader", name, err)
		}
	}
}

// TestRetryDoesNotResign is the regression test for the double-wrap bug:
// with Retry outside Sign, every attempt must see the original message
// signed exactly once.
func TestRetryDoesNotResign(t *testing.T) {
	t.Parallel()

	signer := signerFunc(func(_ context.Context, m *Message) error {
		ent, err := m.Entity()
		if err != nil {
			return err
		}
		m.Body = &Part{ContentType: "multipart/signed; boundary=s", Body: append([]byte("SIGNED:"), ent.Bytes()...)}
		m.Headers["X-Signed"] = "yes"
		return nil
	})
	var seen []string
	attempts := 0
	base := func(_ context.Context, m *Message) error {
		attempts++
		seen = append(seen, string(m.Body.Body))
		if attempts == 1 {
			return TransientError{Err: errors.New("try again")}
		}
		return nil
	}
	orig := baseMsg()
	orig.Headers = map[string]string{"X-A": "1"}
	m := orig
	if err := chain(base, Retry(3, time.Millisecond), Sign(signer))(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d", attempts)
	}
	for i, s := range seen {
		if n := strings.Count(s, "SIGNED:"); n != 1 {
			t.Errorf("attempt %d signed %d times", i+1, n)
		}
	}
	if m.Body != nil {
		t.Error("Sign must not mutate the caller's message")
	}
	if _, ok := orig.Headers["X-Signed"]; ok {
		t.Error("Sign must not mutate the caller's Headers map")
	}
}

func TestEncryptWorksOnCopy(t *testing.T) {
	t.Parallel()

	enc := encryptorFunc(func(_ context.Context, m *Message) error {
		m.Body = &Part{ContentType: "application/octet-stream", Body: []byte("x")}
		m.To[0] = "changed@example.com"
		return nil
	})
	var got *Message
	base := func(_ context.Context, m *Message) error { got = m; return nil }
	m := baseMsg()
	if err := chain(base, Encrypt(enc))(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	if got.Body == nil || got.To[0] != "changed@example.com" {
		t.Error("next must see the Encryptor's changes")
	}
	if m.Body != nil || m.To[0] != "b@example.com" {
		t.Error("Encrypt must not mutate the caller's message")
	}
}

type captured struct {
	mu   sync.Mutex
	msgs []Message
}

func (c *captured) send(_ context.Context, m *Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, *m)
	return nil
}

func TestSplitBcc(t *testing.T) {
	t.Parallel()

	var c captured
	m := baseMsg()
	m.Cc = []string{"c@example.com"}
	m.Bcc = []string{"x@example.com", "y@example.com"}
	m.Meta = map[string]any{"k": "v"}
	if err := chain(c.send, SplitBcc())(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	if len(c.msgs) != 3 {
		t.Fatalf("got %d copies, want 3", len(c.msgs))
	}
	main := c.msgs[0]
	if len(main.Bcc) != 0 || !slices.Equal(main.Recipients(), []string{"b@example.com", "c@example.com"}) {
		t.Errorf("main copy: Bcc=%v Recipients=%v", main.Bcc, main.Recipients())
	}
	for i, want := range []string{"x@example.com", "y@example.com"} {
		bc := c.msgs[i+1]
		if !slices.Equal(bc.Recipients(), []string{want}) {
			t.Errorf("bcc copy %d: Recipients = %v, want [%s]", i, bc.Recipients(), want)
		}
		if !slices.Equal(bc.Bcc, []string{want}) {
			t.Errorf("bcc copy %d: Bcc = %v", i, bc.Bcc)
		}
		if !slices.Equal(bc.To, m.To) || !slices.Equal(bc.Cc, m.Cc) {
			t.Errorf("bcc copy %d must keep To/Cc for its headers", i)
		}
		b, err := bc.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "y@example.com") && want == "x@example.com" {
			t.Error("one Bcc copy reveals another Bcc address")
		}
	}
	if len(m.Bcc) != 2 || m.EnvelopeTo != nil {
		t.Error("SplitBcc must not mutate the caller's message")
	}
}

func TestSplitBccOnlyBcc(t *testing.T) {
	t.Parallel()

	var c captured
	m := Message{From: "a@example.com", Bcc: []string{"x@example.com"}, Text: "hi"}
	if err := chain(c.send, SplitBcc())(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	if len(c.msgs) != 1 || !slices.Equal(c.msgs[0].Recipients(), []string{"x@example.com"}) {
		t.Fatalf("copies = %+v", c.msgs)
	}
}

func TestSplitBccNoBccPassesThrough(t *testing.T) {
	t.Parallel()

	var c captured
	m := baseMsg()
	if err := chain(c.send, SplitBcc())(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	if len(c.msgs) != 1 || c.msgs[0].EnvelopeTo != nil {
		t.Fatalf("copies = %+v", c.msgs)
	}
}

func TestSplitBccJoinsErrorsAndKeepsSending(t *testing.T) {
	t.Parallel()

	errX := errors.New("x failed")
	var sent []string
	base := func(_ context.Context, m *Message) error {
		sent = append(sent, strings.Join(m.Recipients(), ","))
		if slices.Contains(m.Recipients(), "x@example.com") {
			return errX
		}
		return nil
	}
	m := baseMsg()
	m.Bcc = []string{"x@example.com", "y@example.com"}
	err := chain(base, SplitBcc())(context.Background(), &m)
	if !errors.Is(err, errX) {
		t.Fatalf("err = %v, want errX", err)
	}
	if len(sent) != 3 {
		t.Errorf("sent %v, want all three copies attempted", sent)
	}
}

func TestEnvelopeToOverridesRecipients(t *testing.T) {
	t.Parallel()

	m := Message{To: []string{"a@example.com"}, Bcc: []string{"b@example.com"}, EnvelopeTo: []string{"b@example.com"}}
	if got := m.Recipients(); !slices.Equal(got, []string{"b@example.com"}) {
		t.Errorf("Recipients() = %v", got)
	}
}

func TestSuppressFiltersEnvelopeTo(t *testing.T) {
	t.Parallel()

	s := suppressorFunc(func(_ context.Context, a string) (bool, error) { return a == "x@example.com", nil })
	var c captured
	m := baseMsg()
	m.Bcc = []string{"x@example.com"}
	m.EnvelopeTo = []string{"x@example.com"}
	err := chain(c.send, Suppress(s))(context.Background(), &m)
	if !errors.Is(err, ErrSuppressed) {
		t.Fatalf("err = %v, want ErrSuppressed (only envelope recipient suppressed)", err)
	}
}

func TestQPEscapesFromAtLineStart(t *testing.T) {
	t.Parallel()

	text := "From the start\nsome text\r\nFrom here too\nnot From mid-line\n" +
		strings.Repeat("a", 75) + "From after a soft break\n" + "trailing space \nend\t"
	p := buildTextPart("text/plain", text)
	enc := string(p.Body)
	for i, line := range strings.Split(enc, "\r\n") {
		if strings.HasPrefix(line, "From ") {
			t.Errorf("line %d starts with an unescaped From: %q", i, line)
		}
		if len(line) > 76 {
			t.Errorf("line %d longer than 76: %q", i, line)
		}
		if strings.HasSuffix(line, " ") || strings.HasSuffix(line, "\t") {
			t.Errorf("line %d ends in whitespace: %q", i, line)
		}
	}
	if !strings.HasPrefix(enc, "=46rom the start") {
		t.Errorf("encoded = %q", enc)
	}
	dec, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(enc)))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n")
	if string(dec) != want {
		t.Errorf("round trip =\n%q\nwant\n%q", dec, want)
	}
}

// FuzzQuotedPrintable checks the QP encoder against the stdlib decoder: every
// input round-trips (with line breaks normalised to CRLF), every line fits in
// 76 characters, output is 7-bit, and no line starts with "From ".
func FuzzQuotedPrintable(f *testing.F) {
	f.Add("From me\nhello")
	f.Add("café = crème \r\n\tFrom ")
	f.Add(strings.Repeat("x", 74) + "From \n")
	f.Add("a\rb\r\r\n")
	f.Fuzz(func(t *testing.T, s string) {
		enc := encodeQP(s)
		for _, c := range enc {
			if c >= 0x80 {
				t.Fatalf("non-ASCII byte in %q", enc)
			}
		}
		for _, line := range strings.Split(string(enc), "\r\n") {
			if len(line) > 76 || strings.HasPrefix(line, "From ") {
				t.Fatalf("bad line %q", line)
			}
		}
		dec, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(enc)))
		if err != nil {
			t.Fatalf("decode %q: %v", enc, err)
		}
		if want := normaliseNewlines(s); string(dec) != want {
			t.Fatalf("round trip of %q =\n%q\nwant\n%q", s, dec, want)
		}
	})
}

// normaliseNewlines turns every LF (with or without a preceding CR) into CRLF,
// matching the encoder's treatment of hard line breaks.
func normaliseNewlines(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

// splitEnc is a SplitEncryptor test double: it returns one copy per
// recipient and fails the copy for fail@example.com at send time.
type splitEnc struct{ calls int }

func (s *splitEnc) Encrypt(context.Context, *Message) error {
	return errors.New("Encrypt must not be called when EncryptCopies exists")
}

func (s *splitEnc) EncryptCopies(_ context.Context, m *Message) ([]Message, error) {
	s.calls++
	var out []Message
	for _, r := range m.Recipients() {
		c := m.clone()
		c.EnvelopeTo = []string{r}
		c.Body = &Part{ContentType: "application/octet-stream", Body: []byte(r)}
		m.To[0] = "mutated@example.com" // must not reach the caller
		out = append(out, c)
	}
	return out, nil
}

func TestEncryptSendsEveryCopyOfASplitEncryptor(t *testing.T) {
	t.Parallel()

	errFail := errors.New("fail")
	var sent []string
	base := func(_ context.Context, m *Message) error {
		sent = append(sent, strings.Join(m.Recipients(), ","))
		if slices.Contains(m.Recipients(), "fail@example.com") {
			return errFail
		}
		return nil
	}
	m := baseMsg()
	m.Cc = []string{"fail@example.com", "c@example.com"}
	enc := &splitEnc{}
	err := chain(base, Encrypt(enc))(context.Background(), &m)
	if !errors.Is(err, errFail) {
		t.Fatalf("err = %v, want the failed copy's error", err)
	}
	if !slices.Equal(sent, []string{"b@example.com", "fail@example.com", "c@example.com"}) {
		t.Errorf("sent %v, want every copy attempted in order", sent)
	}
	if enc.calls != 1 || m.To[0] != "b@example.com" || m.Body != nil {
		t.Error("the caller's message must not change")
	}
}

func TestEncryptSplitEncryptorError(t *testing.T) {
	t.Parallel()

	boom := errors.New("boom")
	enc := struct {
		encryptorFunc
		copiesFunc
	}{
		encryptorFunc(func(context.Context, *Message) error { return nil }),
		copiesFunc(func(context.Context, *Message) ([]Message, error) { return nil, boom }),
	}
	called := false
	base := func(context.Context, *Message) error { called = true; return nil }
	m := baseMsg()
	if err := chain(base, Encrypt(enc))(context.Background(), &m); !errors.Is(err, boom) || called {
		t.Errorf("err = %v, called = %v", err, called)
	}
}

type copiesFunc func(context.Context, *Message) ([]Message, error)

func (f copiesFunc) EncryptCopies(ctx context.Context, m *Message) ([]Message, error) {
	return f(ctx, m)
}
