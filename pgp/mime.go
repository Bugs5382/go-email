package pgp

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
	"bytes"
	"fmt"
	"maps"
	"mime"
	"slices"
	"strings"

	email "github.com/Bugs5382/go-email"
	"github.com/Bugs5382/go-email/internal/mimeparse"
)

// RFC 3156 protocol values.
const (
	protoSignature = "application/pgp-signature"
	protoEncrypted = "application/pgp-encrypted"
)

// signedEntity builds the RFC 3156 section 5 multipart/signed entity:
// content, then the armored detached signature. content is placed
// verbatim, so the signature over it stays valid.
func signedEntity(content, armoredSig []byte, micalg string) (*email.Part, error) {
	boundary, err := mimeparse.NewBoundary()
	if err != nil {
		return nil, err
	}
	sig := email.Part{
		ContentType: protoSignature + `; name="signature.asc"`,
		Headers: []email.Header{
			{Key: "Content-Description", Value: "OpenPGP digital signature"},
			{Key: "Content-Disposition", Value: `attachment; filename="signature.asc"`},
		},
		Body: armoredSig,
	}
	body, err := mimeparse.Join(boundary, content, sig.Bytes())
	if err != nil {
		return nil, fmt.Errorf("pgp: building multipart/signed: %w", err)
	}
	return &email.Part{
		ContentType: fmt.Sprintf(`multipart/signed; micalg=%s; protocol="%s"; boundary=%s`, micalg, protoSignature, boundary),
		Body:        body,
	}, nil
}

// encryptedEntity builds the RFC 3156 section 4 multipart/encrypted entity
// around an armored OpenPGP message.
func encryptedEntity(armoredMsg []byte) (*email.Part, error) {
	boundary, err := mimeparse.NewBoundary()
	if err != nil {
		return nil, err
	}
	control := email.Part{
		ContentType: protoEncrypted,
		Headers:     []email.Header{{Key: "Content-Description", Value: "PGP/MIME version identification"}},
		Body:        []byte("Version: 1\r\n"),
	}
	data := email.Part{
		ContentType: `application/octet-stream; name="encrypted.asc"`,
		Headers: []email.Header{
			{Key: "Content-Description", Value: "OpenPGP encrypted message"},
			{Key: "Content-Disposition", Value: `inline; filename="encrypted.asc"`},
		},
		Body: armoredMsg,
	}
	body, err := mimeparse.Join(boundary, control.Bytes(), data.Bytes())
	if err != nil {
		return nil, fmt.Errorf("pgp: building multipart/encrypted: %w", err)
	}
	return &email.Part{
		ContentType: fmt.Sprintf(`multipart/encrypted; protocol="%s"; boundary=%s`, protoEncrypted, boundary),
		Body:        body,
	}, nil
}

// isEncryptedBody reports whether p is already an encrypted entity, PGP/MIME
// or S/MIME.
func isEncryptedBody(p *email.Part) bool {
	if p == nil {
		return false
	}
	mt, params, err := mime.ParseMediaType(p.ContentType)
	if err != nil {
		// Unparseable: refuse to guess that it is safe to sign.
		return true
	}
	switch mt {
	case "multipart/encrypted", protoEncrypted:
		return true
	case "application/pkcs7-mime", "application/x-pkcs7-mime":
		st := strings.ToLower(params["smime-type"])
		return st != "signed-data" && st != "certs-only"
	}
	return false
}

// cloneMessage copies m so that its slices, maps and Body are its own.
// Attachment contents and Body bytes are shared, never edited in place.
func cloneMessage(m email.Message) email.Message {
	c := m
	c.To = slices.Clone(m.To)
	c.Cc = slices.Clone(m.Cc)
	c.Bcc = slices.Clone(m.Bcc)
	c.EnvelopeTo = slices.Clone(m.EnvelopeTo)
	c.Attachments = slices.Clone(m.Attachments)
	c.Headers = maps.Clone(m.Headers)
	c.Meta = maps.Clone(m.Meta)
	if m.Body != nil {
		b := *m.Body
		b.Headers = slices.Clone(m.Body.Headers)
		c.Body = &b
	}
	return c
}

// setEncryptedBody replaces m's body with the encrypted entity and drops
// the plaintext fields, so no middleware further down the chain can read
// or record them by mistake.
func setEncryptedBody(m *email.Message, p *email.Part) {
	m.Body = p
	m.HTML, m.Text, m.Attachments = "", "", nil
}

// crlf converts the LF line endings go-crypto's armor writer uses to CRLF.
func crlf(b []byte) []byte {
	return mimeparse.Canonical(bytes.TrimRight(b, "\n"))
}
