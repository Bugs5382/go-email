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
	"context"
	"crypto"
	"fmt"
	"strings"
	"time"

	email "github.com/Bugs5382/go-email"
	log "github.com/Bugs5382/go-log"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

// signer is the email.Signer NewSigner returns.
type signer struct {
	key *Key
	o   *options
}

// NewSigner returns an email.Signer that replaces the message body with a
// PGP/MIME multipart/signed entity (RFC 3156 section 5): the original body
// entity, then a detached SHA-256 signature by k. k must be an unlocked
// private key, and the message's From address must be one of k's validly
// self-signed user IDs, or Sign returns ErrSignerMismatch.
//
// Use it with email.Sign. To sign and encrypt, use SignEncrypt instead,
// which hides the signature inside the ciphertext.
func NewSigner(k *Key, opts ...Option) (email.Signer, error) {
	o := buildOptions(opts)
	if k == nil || k.e == nil {
		return nil, ErrNoPrivateKey
	}
	if err := k.signingKey(o.now(), o.packetConfig()); err != nil {
		o.log.Warn("pgp: signing key rejected", k.LogField(), log.F("reason", err.Error()))
		return nil, err
	}
	o.log.Info("pgp: signer ready", k.LogField())
	return &signer{key: k, o: o}, nil
}

// Sign implements email.Signer.
func (s *signer) Sign(ctx context.Context, m *email.Message) error {
	l := s.o.log.Ctx(ctx).With(s.key.LogField())
	start := time.Now()
	l.Debug("pgp: signing message")
	if err := checkSignable(s.key, m, s.o); err != nil {
		l.Warn("pgp: message not signed", log.F("reason", err.Error()))
		return err
	}
	ent, err := m.Entity()
	if err != nil {
		l.Warn("pgp: building the body entity failed", log.F("reason", err.Error()))
		return fmt.Errorf("pgp: %w", err)
	}
	p, err := signPart(s.key, ent.Bytes(), s.o)
	if err != nil {
		l.Error(err, "pgp: signing failed")
		return err
	}
	m.Body = p
	l.Debug("pgp: message signed", since(start), log.F("signed_bytes", len(ent.Bytes())))
	return nil
}

// checkSignable enforces sign-then-encrypt and the From binding.
func checkSignable(k *Key, m *email.Message, o *options) error {
	if isEncryptedBody(m.Body) {
		return ErrAlreadyEncrypted
	}
	from := normalizeAddr(m.From)
	if from == "" || !k.hasValidEmail(from, o.now(), o.packetConfig()) {
		return ErrSignerMismatch
	}
	return nil
}

// signPart signs content with k and returns the multipart/signed entity.
func signPart(k *Key, content []byte, o *options) (*email.Part, error) {
	sig, hash, err := detachSign(k, content, o)
	if err != nil {
		return nil, err
	}
	return signedEntity(content, sig, micalg(hash))
}

// detachSign returns an armored (CRLF) detached binary signature over
// content, and the hash it used.
func detachSign(k *Key, content []byte, o *options) ([]byte, crypto.Hash, error) {
	cfg := o.packetConfig()
	var raw bytes.Buffer
	unlock := lockKeys(k)
	err := openpgp.DetachSign(&raw, []*openpgp.Entity{k.e}, bytes.NewReader(content), cfg)
	unlock()
	if err != nil {
		return nil, 0, fmt.Errorf("pgp: signing: %w", err)
	}
	p, err := packet.Read(bytes.NewReader(raw.Bytes()))
	if err != nil {
		return nil, 0, fmt.Errorf("pgp: reading our signature: %w", err)
	}
	sig, ok := p.(*packet.Signature)
	if !ok {
		return nil, 0, fmt.Errorf("pgp: signing produced a %T packet", p)
	}
	var out bytes.Buffer
	w, err := armor.Encode(&out, openpgp.SignatureType, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("pgp: armoring signature: %w", err)
	}
	if _, err := w.Write(raw.Bytes()); err != nil {
		return nil, 0, fmt.Errorf("pgp: armoring signature: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, 0, fmt.Errorf("pgp: armoring signature: %w", err)
	}
	return append(crlf(out.Bytes()), '\r', '\n'), sig.Hash, nil
}

// micalg returns the RFC 3156 micalg value for h, such as "pgp-sha256".
func micalg(h crypto.Hash) string {
	if id, ok := openpgp.HashToHashId(h); ok {
		if name, ok := openpgp.HashIdToString(id); ok {
			return "pgp-" + strings.ToLower(name)
		}
	}
	return "pgp-sha256"
}
