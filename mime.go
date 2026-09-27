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
	"io"
	"mime/multipart"
	"net/http"
)

// base64LineLen is the maximum encoded line length for base64 body parts,
// per RFC 2045 section 6.8.
const base64LineLen = 76

// buildMIME renders m into RFC 5322 message bytes (headers plus body) using
// CRLF line endings throughout. The body is m.Entity(): m.Body when set,
// otherwise a MIME tree derived from the message content (see Entity).
func buildMIME(m Message) ([]byte, error) {
	part, err := m.Entity()
	if err != nil {
		return nil, err
	}
	generated, err := m.generatedHeaders()
	if err != nil {
		return nil, err
	}
	return renderMessage(append(generated, m.headerLines()...), part), nil
}

// Entity returns m's body as a single encoded MIME entity, without the
// RFC 5322 message headers. When m.Body is set it returns *m.Body. Otherwise
// the structure is derived from the message content:
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
//
// Every nested part is rendered with Part.Bytes, and Bytes embeds the
// returned entity verbatim, so a signature over Entity().Bytes() stays valid
// once the entity is placed in a message. Multipart boundaries are random,
// so two calls return different bytes.
func (m Message) Entity() (Part, error) {
	if err := m.checkHeaders(); err != nil {
		return Part{}, err
	}
	if m.Body != nil {
		return *m.Body, nil
	}

	part, err := buildBodyPart(m)
	if err != nil {
		return Part{}, fmt.Errorf("build body part: %w", err)
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
			return Part{}, fmt.Errorf("wrap multipart/related: %w", err)
		}
	}
	if len(attached) > 0 {
		part, err = wrapMultipart("mixed", part, attached, "attachment")
		if err != nil {
			return Part{}, fmt.Errorf("wrap multipart/mixed: %w", err)
		}
	}
	return part, nil
}

// buildBodyPart computes the innermost body layer: multipart/alternative
// when both HTML and Text are present, otherwise whichever single one of
// the two is set, falling back to an empty text/plain part.
func buildBodyPart(m Message) (Part, error) {
	switch {
	case m.HTML != "" && m.Text != "":
		return combineParts("alternative", []Part{
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
// media type (e.g. "text/plain", "text/html"). See encodeQP for why this
// does not use mime/quotedprintable.
func buildTextPart(mediaType, text string) Part {
	return Part{
		ContentType:      mediaType + "; charset=utf-8",
		TransferEncoding: "quoted-printable",
		Body:             encodeQP(text),
	}
}

// buildAttachmentPart base64-encodes an attachment as a single part,
// sniffing its Content-Type when the caller left it empty and tagging it
// inline (with a Content-ID for "cid:" references) or as a regular
// attachment per disposition.
func buildAttachmentPart(a Attachment, disposition string) Part {
	ct := a.ContentType
	if ct == "" {
		ct = http.DetectContentType(a.Content)
	}

	var extra []Header
	if disposition == "inline" {
		extra = append(extra, Header{"Content-ID", "<" + a.ContentID + ">"})
	}
	extra = append(extra, Header{"Content-Disposition", dispositionValue(disposition, a.Filename)})

	return Part{
		ContentType:      ct,
		TransferEncoding: "base64",
		Headers:          extra,
		Body:             encodeBase64Lines(a.Content),
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
func wrapMultipart(subtype string, body Part, atts []Attachment, disposition string) (Part, error) {
	parts := make([]Part, 0, len(atts)+1)
	parts = append(parts, body)
	for _, a := range atts {
		parts = append(parts, buildAttachmentPart(a, disposition))
	}
	return combineParts(subtype, parts)
}

// combineParts assembles parts into a multipart/subtype body per RFC 2046
// section 5.1.1, writing each part with Part.Bytes so its bytes are the
// canonical form a signature would cover. The boundary is random (the one
// mime/multipart generates).
func combineParts(subtype string, parts []Part) (Part, error) {
	boundary := multipart.NewWriter(io.Discard).Boundary()
	delim := []byte("--" + boundary)
	var buf bytes.Buffer
	for i, p := range parts {
		pb := p.Bytes()
		if bytes.Contains(pb, delim) {
			return Part{}, fmt.Errorf("part %d contains the multipart boundary", i)
		}
		if i > 0 {
			buf.WriteString("\r\n")
		}
		buf.Write(delim)
		buf.WriteString("\r\n")
		buf.Write(pb)
	}
	buf.WriteString("\r\n")
	buf.Write(delim)
	buf.WriteString("--\r\n")

	return Part{
		ContentType: fmt.Sprintf("multipart/%s; boundary=%s", subtype, boundary),
		Body:        buf.Bytes(),
	}, nil
}

// renderMessage writes the full RFC 5322 message: the given header lines,
// MIME-Version, the entity's own header fields (Content-Type, plus
// Content-Transfer-Encoding and extra headers when set), a blank line, and
// the entity body.
func renderMessage(headers []headerKV, part Part) []byte {
	var buf bytes.Buffer
	for _, kv := range headers {
		fmt.Fprintf(&buf, "%s: %s\r\n", kv.K, kv.V)
	}
	buf.WriteString("MIME-Version: 1.0\r\n")
	part.writeHeader(&buf)
	buf.WriteString("\r\n")
	buf.Write(part.Body)
	return buf.Bytes()
}
