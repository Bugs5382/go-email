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
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"github.com/Bugs5382/go-email/internal/mimeparse"
	log "github.com/Bugs5382/go-log"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

// SignatureStatus is the outcome of signature checking in a Result.
type SignatureStatus int

const (
	// SignatureNone means the message carried no signature.
	SignatureNone SignatureStatus = iota
	// SignatureValid means the signature verified against a valid key
	// whose user ID matches the From address. Result.Signer is that key.
	SignatureValid
	// SignatureUnknownKey means the message is signed, but not by any
	// valid key the sender store holds for the From address, so it could
	// not be checked. Decrypt reports this rather than failing; treat the
	// content as unsigned.
	SignatureUnknownKey
)

func (s SignatureStatus) String() string {
	switch s {
	case SignatureValid:
		return "valid"
	case SignatureUnknownKey:
		return "unknown-key"
	default:
		return "none"
	}
}

// Result is a verified or decrypted message.
type Result struct {
	// Encrypted reports whether the message was encrypted.
	Encrypted bool
	// Signature is the signature outcome.
	Signature SignatureStatus
	// Signer is the key that made a valid signature, or nil.
	Signer *Key
	// SignedAt is the signature's creation time, when Signature is
	// SignatureValid.
	SignedAt time.Time
	// Entity is the inner MIME entity (its header fields, a blank line
	// and its body) with CRLF line endings: the signed content, or the
	// decrypted plaintext. For a decrypted multipart/signed entity (RFC
	// 3156 section 6.1) it is the signed content inside it.
	Entity []byte
}

// Verify checks a PGP/MIME multipart/signed message (RFC 3156 section 5).
// raw is the complete RFC 5322 message; LF line endings are accepted.
// senders supplies the sender's public keys: only valid, non-weak keys
// with a validly self-signed user ID matching the single From address are
// tried, so a valid signature by anyone else returns ErrUnknownSigner.
//
// It returns ErrNotSigned when the message is not PGP/MIME signed,
// ErrBadSignature when the signature does not verify, ErrMalformed for a
// broken structure, and ErrTooLarge above WithMaxSize. Only the body is
// signed: the headers, Subject and From included, are not.
func Verify(ctx context.Context, raw []byte, senders KeyStore, opts ...Option) (*Result, error) {
	o := buildOptions(opts)
	l := o.log.Ctx(ctx)
	start := time.Now()
	l.Debug("pgp: verifying message", log.F("bytes", len(raw)))
	res, err := verify(ctx, raw, senders, o)
	if err != nil {
		l.Warn("pgp: verification failed", log.F("reason", err.Error()), since(start))
		return nil, err
	}
	l.Debug("pgp: signature valid", res.Signer.LogField(), log.F("signed_at", res.SignedAt), since(start))
	return res, nil
}

func verify(ctx context.Context, raw []byte, senders KeyStore, o *options) (*Result, error) {
	top, err := parseTop(raw, o)
	if err != nil {
		return nil, err
	}
	mt, params, err := top.MediaType()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if mt != "multipart/signed" || !strings.EqualFold(params["protocol"], protoSignature) {
		return nil, ErrNotSigned
	}
	from, err := senderAddr(top.Header)
	if err != nil {
		return nil, err
	}
	content, sig, err := splitSigned(top.Body, params["boundary"])
	if err != nil {
		return nil, err
	}
	signer, at, err := verifyDetached(ctx, content, sig, from, senders, o)
	if err != nil {
		return nil, err
	}
	return &Result{Signature: SignatureValid, Signer: signer, SignedAt: at, Entity: content}, nil
}

// parseTop enforces the size cap, canonicalizes line endings and parses the
// top-level header block.
func parseTop(raw []byte, o *options) (*mimeparse.Entity, error) {
	if int64(len(raw)) > o.maxSize {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, len(raw), o.maxSize)
	}
	top, err := mimeparse.Parse(mimeparse.Canonical(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return top, nil
}

// senderAddr returns the lower-cased address of the single From header.
func senderAddr(h textproto.MIMEHeader) (string, error) {
	vals := h.Values("From")
	if len(vals) != 1 {
		return "", fmt.Errorf("%w: need exactly one From header, got %d", ErrUnknownSigner, len(vals))
	}
	list, err := mail.ParseAddressList(vals[0])
	if err != nil || len(list) != 1 {
		return "", fmt.Errorf("%w: From must hold exactly one address", ErrUnknownSigner)
	}
	return strings.ToLower(list[0].Address), nil
}

// splitSigned returns the signed content and the decoded signature data of
// a multipart/signed body. There must be exactly two parts, the second an
// application/pgp-signature.
func splitSigned(body []byte, boundary string) (content, sig []byte, err error) {
	parts, err := mimeparse.SplitMultipart(body, boundary)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("%w: multipart/signed has %d parts, want 2", ErrMalformed, len(parts))
	}
	se, err := mimeparse.Parse(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: signature part: %w", ErrMalformed, err)
	}
	if mt, _, err := se.MediaType(); err != nil || mt != protoSignature {
		return nil, nil, fmt.Errorf("%w: second part is not %s", ErrMalformed, protoSignature)
	}
	sig, err = decodeCTE(se)
	if err != nil {
		return nil, nil, err
	}
	return parts[0], sig, nil
}

// decodeCTE undoes a base64 transfer encoding; 7bit, 8bit and none are
// passed through. Anything else is refused.
func decodeCTE(e *mimeparse.Entity) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(e.Header.Get("Content-Transfer-Encoding"))) {
	case "", "7bit", "8bit":
		return e.Body, nil
	case "base64":
		b, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, newlineStripper(e.Body)))
		if err != nil {
			return nil, fmt.Errorf("%w: base64: %w", ErrMalformed, err)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("%w: unsupported transfer encoding", ErrMalformed)
	}
}

func newlineStripper(b []byte) io.Reader {
	return bytes.NewReader(bytes.NewBuffer(bytes.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, b)).Bytes())
}

// dearmor decodes one armored block of the given type. Binary data (as
// some clients send in a base64 part) is accepted as is.
func dearmor(b []byte, blockType string) (io.Reader, error) {
	if !bytes.HasPrefix(bytes.TrimSpace(b), []byte("-----BEGIN ")) {
		return bytes.NewReader(b), nil
	}
	block, err := armor.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%w: armor: %w", ErrMalformed, err)
	}
	if block.Type != blockType {
		return nil, fmt.Errorf("%w: armor block is %q, want %q", ErrMalformed, block.Type, blockType)
	}
	return block.Body, nil
}

// senderKeys returns the valid, non-weak keys in store bound to from.
func senderKeys(ctx context.Context, store KeyStore, from string, o *options) ([]*Key, error) {
	if store == nil {
		return nil, nil
	}
	l := o.log.Ctx(ctx)
	start := time.Now()
	cands, err := store.Keys(ctx, from)
	if err != nil {
		l.Error(err, "pgp: sender key lookup failed", log.F("addr_id", addrID(from)), since(start))
		return nil, fmt.Errorf("pgp: looking up sender key: %w", err)
	}
	now, cfg := o.now(), o.packetConfig()
	var out []*Key
	for _, k := range cands {
		if k == nil || k.e == nil {
			continue
		}
		if !k.hasValidEmail(from, now, cfg) {
			l.Warn("pgp: sender candidate has no valid user ID for From", k.LogField(), log.F("addr_id", addrID(from)))
			continue
		}
		if err := checkStrength(k.e.PrimaryKey); err != nil { // the primary key is immutable
			l.Warn("pgp: sender candidate rejected", k.LogField(), log.F("reason", err.Error()))
			continue
		}
		out = append(out, k)
	}
	l.Debug("pgp: sender keys", log.F("addr_id", addrID(from)), log.F("candidates", len(cands)), log.F("usable", fingerprints(out)), since(start))
	return out, nil
}

// keyFor returns the key in keys with the same primary key as e, or nil.
// It matches by fingerprint because the keyring may hold the recipient's
// private copy of a key that is also in keys as a public sender key.
func keyFor(keys []*Key, e *openpgp.Entity) *Key {
	if e == nil || e.PrimaryKey == nil {
		return nil
	}
	fp := (&Key{e: e}).Fingerprint()
	for _, k := range keys {
		if k.Fingerprint() == fp {
			return k
		}
	}
	return nil
}

// verifyDetached checks a detached signature over content by one of the
// sender's keys.
func verifyDetached(ctx context.Context, content, sigData []byte, from string, senders KeyStore, o *options) (*Key, time.Time, error) {
	keys, err := senderKeys(ctx, senders, from, o)
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(keys) == 0 {
		return nil, time.Time{}, ErrUnknownSigner
	}
	sigR, err := dearmor(sigData, openpgp.SignatureType)
	if err != nil {
		return nil, time.Time{}, err
	}
	unlock := lockKeys(keys...)
	sig, ent, err := openpgp.VerifyDetachedSignature(openpgp.EntityList(entities(keys)), bytes.NewReader(content), sigR, o.packetConfig())
	unlock()
	switch {
	case errors.Is(err, pgperrors.ErrUnknownIssuer):
		return nil, time.Time{}, ErrUnknownSigner
	case err != nil:
		return nil, time.Time{}, fmt.Errorf("%w: %w", ErrBadSignature, err)
	}
	if sig.SigType != packet.SigTypeBinary && sig.SigType != packet.SigTypeText {
		return nil, time.Time{}, fmt.Errorf("%w: signature type %d is not a document signature", ErrBadSignature, sig.SigType)
	}
	k := keyFor(keys, ent)
	if k == nil {
		return nil, time.Time{}, ErrUnknownSigner
	}
	return k, sig.CreationTime, nil
}

// Decrypt decrypts a PGP/MIME multipart/encrypted message (RFC 3156
// section 4) with the private key k, and checks any signature against the
// sender's keys in senders (which may be nil). raw is the complete RFC 5322
// message; LF line endings are accepted.
//
// Decrypt fails closed and never returns partial plaintext: a message that
// is not integrity protected (no MDC), fails its MDC or AEAD check, is
// truncated, or carries a signature that does not verify returns an error
// wrapping ErrDecrypt or ErrBadSignature and a nil Result. Every
// decryption failure returns the bare ErrDecrypt, whatever the cause, so
// the error cannot be used as an oracle; the cause is logged. Only a top-level
// multipart/encrypted body with exactly two parts and "Version: 1" is
// accepted, so an encrypted part embedded in other MIME structure (the
// EFAIL direct-exfiltration layout) returns ErrNotEncrypted.
//
// Signed-and-encrypted messages are accepted in both RFC 3156 forms: one
// OpenPGP message that is signed and encrypted (section 6.2), or an
// encrypted multipart/signed entity (section 6.1). A signature by a key
// that senders does not hold for the From address is reported as
// SignatureUnknownKey, not as an error.
func Decrypt(ctx context.Context, raw []byte, k *Key, senders KeyStore, opts ...Option) (*Result, error) {
	o := buildOptions(opts)
	l := o.log.Ctx(ctx)
	if k != nil && k.e != nil {
		l = l.With(k.LogField())
	}
	start := time.Now()
	l.Debug("pgp: decrypting message", log.F("bytes", len(raw)))
	res, err := decrypt(ctx, raw, k, senders, o)
	if err != nil {
		l.Warn("pgp: decryption failed", log.F("reason", err.Error()), since(start))
		return nil, err
	}
	f := []log.Field{log.F("signature", res.Signature.String()), log.F("plaintext_bytes", len(res.Entity)), since(start)}
	if res.Signer != nil {
		f = append(f, log.F("signer", res.Signer.Fingerprint()))
	}
	l.Debug("pgp: message decrypted", f...)
	return res, nil
}

func decrypt(ctx context.Context, raw []byte, k *Key, senders KeyStore, o *options) (*Result, error) {
	if k == nil || k.e == nil || !k.HasPrivate() {
		return nil, ErrNoPrivateKey
	}
	if k.Locked() {
		return nil, ErrKeyLocked
	}
	top, err := parseTop(raw, o)
	if err != nil {
		return nil, err
	}
	mt, params, err := top.MediaType()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if mt != "multipart/encrypted" || !strings.EqualFold(params["protocol"], protoEncrypted) {
		return nil, ErrNotEncrypted
	}
	ct, err := splitEncrypted(top.Body, params["boundary"])
	if err != nil {
		return nil, err
	}
	msgR, err := dearmor(ct, openpgp.MessageType)
	if err != nil {
		return nil, err
	}

	// The From address picks the sender keys; without a usable one the
	// message can still be decrypted, and a signature is then reported as
	// SignatureUnknownKey.
	var sender []*Key
	from, fromErr := senderAddr(top.Header)
	if fromErr == nil {
		if sender, err = senderKeys(ctx, senders, from, o); err != nil {
			return nil, err
		}
	}
	ring := openpgp.EntityList{k.e}
	for _, s := range sender {
		if s.e != k.e {
			ring = append(ring, s.e)
		}
	}

	md, plain, err := readMessage(msgR, ring, append([]*Key{k}, sender...), o)
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			return nil, err
		}
		// Every decryption failure looks the same to the caller, so the
		// error cannot serve as an oracle; the detail goes to the log.
		o.log.Ctx(ctx).Warn("pgp: decryption failed", k.LogField(), log.F("detail", err.Error()))
		return nil, ErrDecrypt
	}
	res := &Result{Encrypted: true, Entity: mimeparse.Canonical(plain)}

	if md.IsSigned {
		switch {
		case md.SignatureError == nil && md.SignedBy != nil && keyFor(sender, md.SignedBy.Entity) != nil:
			res.Signature = SignatureValid
			res.Signer = keyFor(sender, md.SignedBy.Entity)
			if md.Signature != nil {
				res.SignedAt = md.Signature.CreationTime
			}
		case md.SignatureError == nil, errors.Is(md.SignatureError, pgperrors.ErrUnknownIssuer):
			// Signed by a key that is not a sender key for From (possibly
			// the recipient's own key).
			res.Signature = SignatureUnknownKey
		default:
			clear(plain)
			return nil, fmt.Errorf("%w: %w", ErrBadSignature, md.SignatureError)
		}
		return res, nil
	}
	if md.SignatureError != nil {
		clear(plain)
		o.log.Ctx(ctx).Warn("pgp: integrity check failed", k.LogField(), log.F("detail", md.SignatureError.Error()))
		return nil, ErrDecrypt
	}
	return innerSigned(ctx, res, from, fromErr, senders, o)
}

// readMessage decrypts an OpenPGP message and reads all of it, holding the
// locks of every key in the keyring. Everything is read before anything is
// trusted: the MDC or AEAD tag and the signature are only checked at EOF,
// so on any error the partial plaintext is wiped and not returned. Errors
// other than ErrTooLarge carry go-crypto's detail for the log only.
func readMessage(r io.Reader, ring openpgp.EntityList, keys []*Key, o *options) (*openpgp.MessageDetails, []byte, error) {
	defer lockKeys(keys...)()
	md, err := openpgp.ReadMessage(r, ring, nil, o.packetConfig())
	if err != nil {
		return nil, nil, fmt.Errorf("reading message: %w", err)
	}
	if !md.IsEncrypted {
		return nil, nil, errors.New("OpenPGP message is not encrypted")
	}
	plain, err := io.ReadAll(io.LimitReader(md.UnverifiedBody, o.maxSize+1))
	if err != nil {
		clear(plain)
		return nil, nil, fmt.Errorf("reading plaintext: %w", err)
	}
	if int64(len(plain)) > o.maxSize {
		clear(plain)
		return nil, nil, fmt.Errorf("%w: plaintext over %d bytes", ErrTooLarge, o.maxSize)
	}
	return md, plain, nil
}

// splitEncrypted checks the two-part multipart/encrypted layout and returns
// the encrypted data.
func splitEncrypted(body []byte, boundary string) ([]byte, error) {
	parts, err := mimeparse.SplitMultipart(body, boundary)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: multipart/encrypted has %d parts, want 2", ErrMalformed, len(parts))
	}
	ctl, err := mimeparse.Parse(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: control part: %w", ErrMalformed, err)
	}
	if mt, _, err := ctl.MediaType(); err != nil || mt != protoEncrypted {
		return nil, fmt.Errorf("%w: first part is not %s", ErrMalformed, protoEncrypted)
	}
	if !hasVersion1(ctl.Body) {
		return nil, fmt.Errorf("%w: control part must say Version: 1", ErrMalformed)
	}
	data, err := mimeparse.Parse(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: data part: %w", ErrMalformed, err)
	}
	if mt, _, err := data.MediaType(); err != nil || mt != "application/octet-stream" {
		return nil, fmt.Errorf("%w: second part is not application/octet-stream", ErrMalformed)
	}
	return decodeCTE(data)
}

// hasVersion1 reports whether the control part's first non-empty line is
// "Version: 1".
func hasVersion1(body []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		name, val, ok := strings.Cut(line, ":")
		return ok && strings.EqualFold(strings.TrimSpace(name), "Version") && strings.TrimSpace(val) == "1"
	}
	return false
}

// innerSigned handles RFC 3156 section 6.1: when the decrypted entity is
// itself PGP/MIME multipart/signed, verify it and return the signed
// content. Any other entity is returned unsigned.
func innerSigned(ctx context.Context, res *Result, from string, fromErr error, senders KeyStore, o *options) (*Result, error) {
	inner, err := mimeparse.Parse(res.Entity)
	if err != nil {
		return res, nil //nolint:nilerr // not MIME we can inspect: return it as unsigned plaintext
	}
	mt, params, err := inner.MediaType()
	if err != nil || mt != "multipart/signed" || !strings.EqualFold(params["protocol"], protoSignature) {
		return res, nil //nolint:nilerr // an unparseable or non-signed type is plain content
	}
	content, sig, err := splitSigned(inner.Body, params["boundary"])
	if err != nil {
		clear(res.Entity)
		return nil, err
	}
	if fromErr != nil {
		res.Entity, res.Signature = content, SignatureUnknownKey
		return res, nil
	}
	signer, at, err := verifyDetached(ctx, content, sig, from, senders, o)
	switch {
	case errors.Is(err, ErrUnknownSigner):
		res.Entity, res.Signature = content, SignatureUnknownKey
	case err != nil:
		clear(res.Entity)
		return nil, err
	default:
		res.Entity, res.Signature, res.Signer, res.SignedAt = content, SignatureValid, signer, at
	}
	return res, nil
}
