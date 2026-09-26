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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net/mail"
	"net/textproto"
	"strings"
	"time"
)

// ErrInvalidHeader is returned (wrapped) when a header name or value would
// corrupt the rendered message: a CR or LF in any value, or a custom header
// name that is empty, not printable ASCII, or reserved for the MIME
// structure. A CR or LF would let the value start a new header line (header
// injection), so these messages are rejected rather than repaired.
var ErrInvalidHeader = errors.New("email: invalid header")

// reservedHeaders are the MIME structure headers the renderer writes itself.
// A caller-supplied copy would conflict with the real body structure, so
// they cannot be set through Message.Headers.
var reservedHeaders = map[string]bool{
	"Content-Type":              true,
	"Content-Transfer-Encoding": true,
	"Mime-Version":              true,
}

// maxEncodedLine is the line length budget for a header line carrying
// RFC 2047 encoded-words (RFC 2047 section 2 caps such lines at 76).
const maxEncodedLine = 76

// checkHeaderValue rejects a value that contains CR or LF. The value itself
// is never echoed into the error, since it may carry recipient data.
func checkHeaderValue(field, v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return fmt.Errorf("%w: %s contains CR or LF", ErrInvalidHeader, field)
	}
	return nil
}

// checkHeaderName enforces RFC 5322 section 2.2: a field name is one or more
// printable US-ASCII characters other than colon.
func checkHeaderName(k string) error {
	if k == "" {
		return fmt.Errorf("%w: empty header name", ErrInvalidHeader)
	}
	for i := 0; i < len(k); i++ {
		if c := k[i]; c < 33 || c > 126 || c == ':' {
			return fmt.Errorf("%w: header name %q is not printable ASCII without colon", ErrInvalidHeader, k)
		}
	}
	if reservedHeaders[textproto.CanonicalMIMEHeaderKey(k)] {
		return fmt.Errorf("%w: header %q is set by the MIME builder and cannot be overridden", ErrInvalidHeader, k)
	}
	return nil
}

// checkHeaders validates every caller-supplied value that ends up in a
// header line, including attachment part headers.
func (m Message) checkHeaders() error {
	fields := []struct{ name, v string }{
		{"From", m.From},
		{"Reply-To", m.ReplyTo},
		{"Subject", m.Subject},
		{"List-Unsubscribe", m.ListUnsubscribe},
		{"List-Unsubscribe-Post", m.ListUnsubscribePost},
	}
	for _, f := range fields {
		if err := checkHeaderValue(f.name, f.v); err != nil {
			return err
		}
	}
	for i, a := range m.To {
		if err := checkHeaderValue(fmt.Sprintf("To[%d]", i), a); err != nil {
			return err
		}
	}
	for i, a := range m.Cc {
		if err := checkHeaderValue(fmt.Sprintf("Cc[%d]", i), a); err != nil {
			return err
		}
	}
	for k, v := range m.Headers {
		if err := checkHeaderName(k); err != nil {
			return err
		}
		if err := checkHeaderValue(fmt.Sprintf("header %q", k), v); err != nil {
			return err
		}
	}
	for i, a := range m.Attachments {
		if err := checkHeaderValue(fmt.Sprintf("attachment[%d] filename", i), a.Filename); err != nil {
			return err
		}
		if err := checkHeaderValue(fmt.Sprintf("attachment[%d] content type", i), a.ContentType); err != nil {
			return err
		}
		if err := checkHeaderValue(fmt.Sprintf("attachment[%d] content id", i), a.ContentID); err != nil {
			return err
		}
	}
	return nil
}

// isASCII reports whether s holds only 7-bit bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// encodeUnstructured RFC 2047 Q-encodes a non-ASCII unstructured header
// value (such as Subject), folding between encoded-words so that no line,
// including the "Name: " prefix, exceeds maxEncodedLine. ASCII values are
// returned unchanged.
func encodeUnstructured(name, v string) string {
	if isASCII(v) {
		return v
	}
	const prefix, suffix = "=?utf-8?q?", "?="
	budget := maxEncodedLine - len(name) - len(": ")
	var out, word strings.Builder
	flush := func() {
		if out.Len() > 0 {
			out.WriteString("\r\n ")
		}
		out.WriteString(prefix)
		out.WriteString(word.String())
		out.WriteString(suffix)
		word.Reset()
		budget = maxEncodedLine - 1 // continuation lines start with one space
	}
	for _, r := range v {
		enc := qEncodeRune(r)
		if word.Len() > 0 && len(prefix)+word.Len()+len(enc)+len(suffix) > budget {
			flush()
		}
		word.WriteString(enc)
	}
	flush()
	return out.String()
}

// qEncodeRune returns the RFC 2047 "Q" encoding of r. Only letters, digits
// and the characters RFC 2047 section 5(3) allows in any context pass
// through, so the result is safe in a Subject and in a display name.
func qEncodeRune(r rune) string {
	switch {
	case r == ' ':
		return "_"
	case r < 0x80 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!*+-/", r)):
		return string(r)
	}
	var b strings.Builder
	for _, c := range []byte(string(r)) {
		fmt.Fprintf(&b, "=%02X", c)
	}
	return b.String()
}

// encodeAddressList RFC 2047-encodes non-ASCII display names in an address
// or address list. ASCII input, and input that does not parse as an address
// list, is returned unchanged so existing output stays byte-for-byte stable.
func encodeAddressList(v string) string {
	if isASCII(v) {
		return v
	}
	list, err := mail.ParseAddressList(v)
	if err != nil {
		return v
	}
	parts := make([]string, len(list))
	for i, a := range list {
		// mail.Address.String encodes a non-ASCII name as an RFC 2047
		// encoded-word and quotes an ASCII one when it needs quoting.
		parts[i] = a.String()
	}
	return strings.Join(parts, ", ")
}

// encodeAddresses encodes each element of addrs and joins them for a To or
// Cc header.
func encodeAddresses(addrs []string) string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = encodeAddressList(a)
	}
	return strings.Join(out, ", ")
}

// dispositionValue renders a Content-Disposition value carrying filename.
// An ASCII name is a quoted-string with backslash escapes (RFC 2045). A
// non-ASCII name is written twice: as an RFC 2231 extended parameter, which
// conforming readers prefer, and as an RFC 2047 encoded-word in the plain
// parameter, which is what older clients such as Outlook read.
func dispositionValue(disposition, filename string) string {
	if isASCII(filename) {
		return fmt.Sprintf(`%s; filename="%s"`, disposition, quoteParam(filename))
	}
	return fmt.Sprintf(`%s; filename*=utf-8''%s; filename="%s"`,
		disposition, rfc2231Escape(filename), mime.QEncoding.Encode("utf-8", filename))
}

// quoteParam backslash-escapes the characters that would end or break a
// quoted-string.
func quoteParam(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

// rfc2231Escape percent-encodes s for an RFC 2231 extended value, keeping
// only attribute-chars literal.
func rfc2231Escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x80 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$&+-.^_`|~", c) >= 0) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// hasHeader reports whether the caller set header k (case-insensitively).
func (m Message) hasHeader(k string) bool {
	for hk := range m.Headers {
		if strings.EqualFold(hk, k) {
			return true
		}
	}
	return false
}

// generatedHeaders returns the Date and Message-ID headers the caller did
// not set. Relays add them when missing, but some reject mail without them.
func (m Message) generatedHeaders() ([]headerKV, error) {
	var h []headerKV
	if !m.hasHeader("Date") {
		h = append(h, headerKV{"Date", time.Now().Format(time.RFC1123Z)})
	}
	if !m.hasHeader("Message-ID") {
		id, err := newMessageID(m.From)
		if err != nil {
			return nil, err
		}
		h = append(h, headerKV{"Message-ID", id})
	}
	return h, nil
}

// newMessageID returns "<random@domain>", with the domain taken from the
// From address and "localhost" as the fallback when From has no usable
// ASCII domain.
func newMessageID(from string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("email: generate Message-ID: %w", err)
	}
	domain := "localhost"
	if a, err := mail.ParseAddress(from); err == nil {
		if at := strings.LastIndexByte(a.Address, '@'); at >= 0 {
			if d := a.Address[at+1:]; d != "" && isASCII(d) {
				domain = d
			}
		}
	}
	return "<" + hex.EncodeToString(raw[:]) + "@" + domain + ">", nil
}
