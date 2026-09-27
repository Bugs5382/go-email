// Package mimeparse is the small, strict raw-MIME reader the pgp and smime
// packages use to verify and decrypt inbound mail. Unlike mime/multipart it
// returns every part's exact bytes, which is what a detached signature
// covers, and it fails closed on anything it cannot split unambiguously.
package mimeparse

/*
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
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net/textproto"
)

// ErrMalformed reports MIME structure that cannot be parsed unambiguously.
var ErrMalformed = errors.New("mimeparse: malformed MIME structure")

// maxHeaderBytes caps the header block of one entity.
const maxHeaderBytes = 1 << 20

// maxBoundaryLen is the RFC 2046 section 5.1.1 limit.
const maxBoundaryLen = 70

// Canonical returns b with every bare LF turned into CRLF, so input that
// was stored with Unix line endings can still be verified. A lone CR is
// left as is.
func Canonical(b []byte) []byte {
	n := bytes.Count(b, []byte("\n"))
	if n == 0 {
		return b
	}
	out := make([]byte, 0, len(b)+n)
	for i, c := range b {
		if c == '\n' && (i == 0 || b[i-1] != '\r') {
			out = append(out, '\r')
		}
		out = append(out, c)
	}
	return out
}

// Entity is one parsed MIME entity.
type Entity struct {
	Header textproto.MIMEHeader
	// Body is the entity body exactly as it appeared, still transfer-encoded.
	Body []byte
}

// Parse splits raw (CRLF line endings) at the first empty line into a
// header block and a body. An entity must have that empty line; one that
// starts with it has no header fields.
func Parse(raw []byte) (*Entity, error) {
	var head, body []byte
	switch {
	case bytes.HasPrefix(raw, []byte("\r\n")):
		body = raw[2:]
	default:
		i := bytes.Index(raw, []byte("\r\n\r\n"))
		if i < 0 {
			return nil, fmt.Errorf("%w: no empty line after the header block", ErrMalformed)
		}
		head, body = raw[:i+2], raw[i+4:]
	}
	if len(head) > maxHeaderBytes {
		return nil, fmt.Errorf("%w: header block larger than %d bytes", ErrMalformed, maxHeaderBytes)
	}
	h := textproto.MIMEHeader{}
	if len(head) > 0 {
		r := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(head[:len(head):len(head)], '\r', '\n'))))
		var err error
		h, err = r.ReadMIMEHeader()
		if err != nil {
			return nil, fmt.Errorf("%w: header: %w", ErrMalformed, err)
		}
	}
	return &Entity{Header: h, Body: body}, nil
}

// MediaType parses the entity's Content-Type, defaulting to text/plain as
// RFC 2045 section 5.2 says. The media type is lower-cased.
func (e *Entity) MediaType() (string, map[string]string, error) {
	ct := e.Header.Get("Content-Type")
	if ct == "" {
		return "text/plain", map[string]string{"charset": "us-ascii"}, nil
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return "", nil, fmt.Errorf("%w: content type: %w", ErrMalformed, err)
	}
	return mt, params, nil
}

// SplitMultipart returns the raw bytes of each body part of a multipart
// body, per RFC 2046 section 5.1.1: the CRLF before each delimiter belongs
// to the delimiter, and the preamble and epilogue are dropped. It fails if
// the boundary is invalid or the close delimiter is missing.
func SplitMultipart(body []byte, boundary string) ([][]byte, error) {
	if boundary == "" || len(boundary) > maxBoundaryLen {
		return nil, fmt.Errorf("%w: boundary must be 1 to %d characters", ErrMalformed, maxBoundaryLen)
	}
	delim := []byte("--" + boundary)

	var parts [][]byte
	start := -1 // start of the current part; -1 while in the preamble
	for pos := 0; pos <= len(body); {
		end := bytes.Index(body[pos:], []byte("\r\n"))
		next := 0
		if end < 0 {
			end = len(body)
			next = len(body) + 1
		} else {
			end += pos
			next = end + 2
		}
		if isDelim, isClose := delimiterLine(body[pos:end], delim); isDelim {
			if start >= 0 {
				stop := max(start, pos-2)
				parts = append(parts, body[start:stop])
			}
			if isClose {
				if start < 0 {
					return nil, fmt.Errorf("%w: close delimiter before any part", ErrMalformed)
				}
				return parts, nil
			}
			if next > len(body) {
				break
			}
			start = next
		}
		pos = next
	}
	return nil, fmt.Errorf("%w: missing close delimiter", ErrMalformed)
}

// delimiterLine reports whether line is a boundary delimiter line, and
// whether it is the close delimiter. Trailing linear whitespace is allowed.
func delimiterLine(line, delim []byte) (isDelim, isClose bool) {
	if !bytes.HasPrefix(line, delim) {
		return false, false
	}
	rest := line[len(delim):]
	if bytes.HasPrefix(rest, []byte("--")) {
		isClose = true
		rest = rest[2:]
	}
	for _, c := range rest {
		if c != ' ' && c != '\t' {
			return false, false
		}
	}
	return true, isClose
}

// NewBoundary returns a random boundary made only of hex digits, so it can
// never collide with base64, armored or quoted-printable content.
func NewBoundary() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mimeparse: boundary: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// Join assembles parts into a multipart body with the given boundary, the
// inverse of SplitMultipart. It fails if any part contains the delimiter.
func Join(boundary string, parts ...[]byte) ([]byte, error) {
	delim := []byte("--" + boundary)
	var buf bytes.Buffer
	for i, p := range parts {
		if bytes.Contains(p, delim) {
			return nil, fmt.Errorf("%w: part %d contains the boundary", ErrMalformed, i)
		}
		if i > 0 {
			buf.WriteString("\r\n")
		}
		buf.Write(delim)
		buf.WriteString("\r\n")
		buf.Write(p)
	}
	buf.WriteString("\r\n")
	buf.Write(delim)
	buf.WriteString("--\r\n")
	return buf.Bytes(), nil
}
