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
	"fmt"
)

// Header is one MIME header field of a Part, kept in order.
type Header struct {
	Key, Value string
}

// Part is a fully encoded MIME entity: its own header fields plus an
// already-encoded body. Part.Bytes is the canonical rendering of the entity,
// so these are exactly the bytes a detached signature covers.
//
// A Part is what Message.Entity returns and what Message.Body accepts, which
// lets a Signer or Encryptor replace a message's body with a signed or
// encrypted entity without reimplementing the MIME builder.
type Part struct {
	// ContentType is the full Content-Type value, parameters included.
	ContentType string
	// TransferEncoding is the Content-Transfer-Encoding value. It is empty
	// for multipart/* entities, whose parts carry their own encodings.
	TransferEncoding string
	// Headers are extra header fields written after Content-Type and
	// Content-Transfer-Encoding, in order (Content-Disposition, Content-ID,
	// and so on).
	Headers []Header
	// Body is the encoded body: CRLF line endings, 7-bit safe.
	Body []byte
}

// Bytes renders p's header block (Content-Type, Content-Transfer-Encoding
// when set, then Headers in order), a blank line, and its body, all with
// CRLF line endings.
func (p Part) Bytes() []byte {
	var buf bytes.Buffer
	p.writeHeader(&buf)
	buf.WriteString("\r\n")
	buf.Write(p.Body)
	return buf.Bytes()
}

// writeHeader writes p's header fields without the terminating blank line.
func (p Part) writeHeader(buf *bytes.Buffer) {
	fmt.Fprintf(buf, "Content-Type: %s\r\n", p.ContentType)
	if p.TransferEncoding != "" {
		fmt.Fprintf(buf, "Content-Transfer-Encoding: %s\r\n", p.TransferEncoding)
	}
	for _, h := range p.Headers {
		fmt.Fprintf(buf, "%s: %s\r\n", h.Key, h.Value)
	}
}

// check validates the header fields of a caller-supplied Part the same way
// Message header values are checked.
func (p Part) check(field string) error {
	if p.ContentType == "" {
		return fmt.Errorf("%w: %s has no content type", ErrInvalidHeader, field)
	}
	if err := checkHeaderValue(field+" content type", p.ContentType); err != nil {
		return err
	}
	if err := checkHeaderValue(field+" transfer encoding", p.TransferEncoding); err != nil {
		return err
	}
	for _, h := range p.Headers {
		if err := checkHeaderName(h.Key); err != nil {
			return err
		}
		if err := checkHeaderValue(fmt.Sprintf("%s header %q", field, h.Key), h.Value); err != nil {
			return err
		}
	}
	return nil
}

// qpLineLen is the longest encoded quoted-printable line, soft-break "="
// included (RFC 2045 section 6.7, rule 5).
const qpLineLen = 76

// encodeQP quoted-printable encodes text with CRLF hard line breaks. Unlike
// mime/quotedprintable it also encodes the "F" of a "From " at the start of
// any encoded line, as RFC 3156 section 3 asks: some MTAs rewrite such lines
// to ">From ", which would break a detached signature. LF and CRLF in text
// both become hard line breaks; a lone CR is encoded.
func encodeQP(text string) []byte {
	var out bytes.Buffer
	lines := splitLines(text)
	for li, line := range lines {
		if li > 0 {
			out.WriteString("\r\n")
		}
		col := 0
		for i := 0; i < len(line); i++ {
			c := line[i]
			last := i == len(line)-1
			var tok string
			switch {
			case col == 0 && c == 'F' && hasPrefixAt(line, i, "From "):
				tok = "=46"
			case (c == ' ' || c == '\t') && !last:
				tok = string(c)
			case c >= 33 && c <= 126 && c != '=':
				tok = string(c)
			default:
				tok = fmt.Sprintf("=%02X", c)
			}
			// Keep room for the soft-break "=" unless this is the line's
			// last token, which may use the full width.
			limit := qpLineLen - 1
			if last {
				limit = qpLineLen
			}
			if col > 0 && col+len(tok) > limit {
				out.WriteString("=\r\n")
				col = 0
				if c == 'F' && hasPrefixAt(line, i, "From ") {
					tok = "=46"
				}
			}
			out.WriteString(tok)
			col += len(tok)
		}
	}
	return out.Bytes()
}

// splitLines splits text on LF, dropping one CR that immediately precedes
// each LF, so both LF and CRLF count as a hard line break.
func splitLines(text string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] != '\n' {
			continue
		}
		end := i
		if end > start && text[end-1] == '\r' {
			end--
		}
		lines = append(lines, text[start:end])
		start = i + 1
	}
	return append(lines, text[start:])
}

// hasPrefixAt reports whether s[i:] starts with prefix.
func hasPrefixAt(s string, i int, prefix string) bool {
	return len(s)-i >= len(prefix) && s[i:i+len(prefix)] == prefix
}
