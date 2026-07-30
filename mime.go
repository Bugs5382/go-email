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
	"encoding/base64"
	"fmt"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/textproto"
)

// base64LineLen is the maximum encoded line length for base64 body parts,
// per RFC 2045 section 6.8.
const base64LineLen = 76

// builtPart is an already-encoded MIME body fragment, together with the
// headers needed to describe it -- either as the sole top-level body of the
// message or as one nested layer inside an outer multipart/* container.
type builtPart struct {
	contentType      string
	transferEncoding string
	extraHeaders     []headerKV
	body             []byte
}

// buildMIME renders m into RFC 5322 message bytes (headers plus body) using
// CRLF line endings throughout. The body's MIME structure is derived from
// the message content:
//
//   - HTML and Text both set -> multipart/alternative (text part first, then
//     html, so plain-text stays a first-class fallback).
//   - only one of HTML/Text set -> a single text/plain or text/html part.
//   - neither set -> a single, empty text/plain part.
//
// Inline attachments (Attachment.Inline true) wrap that body in
// multipart/related so HTML can reference them via "cid:<ContentID>".
// Non-inline attachments then wrap the result (or the plain body, if there
// were no inline attachments) in multipart/mixed.
func buildMIME(m Message) ([]byte, error) {
	part, err := buildBodyPart(m)
	if err != nil {
		return nil, fmt.Errorf("build body part: %w", err)
	}

	var inline, attached []Attachment
	for _, a := range m.Attachments {
		if a.Inline {
			inline = append(inline, a)
		} else {
			attached = append(attached, a)
		}
	}

	if len(inline) > 0 {
		part, err = wrapMultipart("related", part, inline, "inline")
		if err != nil {
			return nil, fmt.Errorf("wrap multipart/related: %w", err)
		}
	}
	if len(attached) > 0 {
		part, err = wrapMultipart("mixed", part, attached, "attachment")
		if err != nil {
			return nil, fmt.Errorf("wrap multipart/mixed: %w", err)
		}
	}

	return renderMessage(m, part), nil
}

// buildBodyPart computes the innermost body layer: multipart/alternative
// when both HTML and Text are present, otherwise whichever single one of
// the two is set, falling back to an empty text/plain part.
func buildBodyPart(m Message) (builtPart, error) {
	switch {
	case m.HTML != "" && m.Text != "":
		return combineParts("alternative", []builtPart{
			buildTextPart("text/plain", m.Text),
			buildTextPart("text/html", m.HTML),
		})
	case m.Text != "":
		return buildTextPart("text/plain", m.Text), nil
	case m.HTML != "":
		return buildTextPart("text/html", m.HTML), nil
	default:
		return buildTextPart("text/plain", ""), nil
	}
}

// buildTextPart quoted-printable encodes text as a single part of the given
// media type (e.g. "text/plain", "text/html").
func buildTextPart(mediaType, text string) builtPart {
	var buf bytes.Buffer
	qw := quotedprintable.NewWriter(&buf)
	// bytes.Buffer never returns an error from Write/Close.
	_, _ = qw.Write([]byte(text))
	_ = qw.Close()
	return builtPart{
		contentType:      mediaType + "; charset=utf-8",
		transferEncoding: "quoted-printable",
		body:             buf.Bytes(),
	}
}

// buildAttachmentPart base64-encodes an attachment as a single part,
// sniffing its Content-Type when the caller left it empty and tagging it
// inline (with a Content-ID for "cid:" references) or as a regular
// attachment per disposition.
func buildAttachmentPart(a Attachment, disposition string) builtPart {
	ct := a.ContentType
	if ct == "" {
		ct = http.DetectContentType(a.Content)
	}

	var extra []headerKV
	if disposition == "inline" {
		extra = append(extra, headerKV{"Content-ID", "<" + a.ContentID + ">"})
	}
	extra = append(extra, headerKV{
		"Content-Disposition",
		fmt.Sprintf(`%s; filename="%s"`, disposition, a.Filename),
	})

	return builtPart{
		contentType:      ct,
		transferEncoding: "base64",
		extraHeaders:     extra,
		body:             encodeBase64Lines(a.Content),
	}
}

// encodeBase64Lines base64-encodes data and wraps it into CRLF-terminated
// lines no longer than base64LineLen, per RFC 2045 section 6.8.
func encodeBase64Lines(data []byte) []byte {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(encoded, data)

	var buf bytes.Buffer
	for i := 0; i < len(encoded); i += base64LineLen {
		end := min(i+base64LineLen, len(encoded))
		buf.Write(encoded[i:end])
		buf.WriteString("\r\n")
	}
	return buf.Bytes()
}

// wrapMultipart wraps body as the first part of a new multipart/subtype
// container, followed by one part per attachment (each tagged with
// disposition, "inline" or "attachment").
func wrapMultipart(subtype string, body builtPart, atts []Attachment, disposition string) (builtPart, error) {
	parts := make([]builtPart, 0, len(atts)+1)
	parts = append(parts, body)
	for _, a := range atts {
		parts = append(parts, buildAttachmentPart(a, disposition))
	}
	return combineParts(subtype, parts)
}

// combineParts assembles parts into a multipart/subtype body using
// mime/multipart, which produces RFC 2046 boundaries and CRLF line
// terminators. It returns the combined part, ready to be nested again or
// rendered as the top-level message body.
func combineParts(subtype string, parts []builtPart) (builtPart, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	for _, p := range parts {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Type", p.contentType)
		if p.transferEncoding != "" {
			h.Set("Content-Transfer-Encoding", p.transferEncoding)
		}
		for _, kv := range p.extraHeaders {
			h.Set(kv.K, kv.V)
		}

		pw, err := mw.CreatePart(h)
		if err != nil {
			return builtPart{}, fmt.Errorf("create part: %w", err)
		}
		if _, err := pw.Write(p.body); err != nil {
			return builtPart{}, fmt.Errorf("write part body: %w", err)
		}
	}

	if err := mw.Close(); err != nil {
		return builtPart{}, fmt.Errorf("close multipart writer: %w", err)
	}

	return builtPart{
		contentType: fmt.Sprintf("multipart/%s; boundary=%s", subtype, mw.Boundary()),
		body:        buf.Bytes(),
	}, nil
}

// renderMessage writes the full RFC 5322 message: the header lines derived
// from m, MIME-Version and Content-Type (plus Content-Transfer-Encoding when
// part is a single, non-multipart body), a blank line, and the body.
func renderMessage(m Message, part builtPart) []byte {
	var buf bytes.Buffer
	for _, kv := range m.headerLines() {
		fmt.Fprintf(&buf, "%s: %s\r\n", kv.K, kv.V)
	}
	buf.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&buf, "Content-Type: %s\r\n", part.contentType)
	if part.transferEncoding != "" {
		fmt.Fprintf(&buf, "Content-Transfer-Encoding: %s\r\n", part.transferEncoding)
	}
	buf.WriteString("\r\n")
	buf.Write(part.body)
	return buf.Bytes()
}
