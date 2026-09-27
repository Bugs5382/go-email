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
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	email "github.com/Bugs5382/go-email"
	log "github.com/Bugs5382/go-log"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

// encryptor is the email.SplitEncryptor NewEncryptor returns, and the engine
// behind SignEncrypt.
type encryptor struct {
	store KeyStore
	o     *options
}

// NewEncryptor returns an email.SplitEncryptor that replaces the message body
// with a PGP/MIME multipart/encrypted entity (RFC 3156 section 4), encrypted
// to one valid key per recipient in m.Recipients(), looked up in store, plus
// any WithEncryptToSelf keys.
//
// A recipient key is used only if it has a valid, unrevoked encryption
// subkey, a validly self-signed user ID matching the address, and is not
// weak. When several match, the newest is used. A recipient without one
// fails the message with a *MissingKeyError unless
// WithMissingKey(MissingKeyPlaintext) is set. In that case, used through
// email.Encrypt, recipients with keys get one encrypted copy and the rest
// get a separate plaintext copy (see EncryptCopies).
//
// The encrypted data is SEIPDv2 (AEAD) when every recipient key advertises
// support for it, and SEIPDv1 with a modification detection code otherwise.
// Nothing is compressed.
//
// One encrypted copy lists every recipient's key ID, so a message with Bcc
// recipients and more than one recipient returns ErrBccNotSplit, unless
// WithBccPolicy(BccAllow) is set. SignEncrypt splits Bcc copies itself.
func NewEncryptor(store KeyStore, opts ...Option) (email.SplitEncryptor, error) {
	return newEncryptor(store, opts)
}

func newEncryptor(store KeyStore, opts []Option) (*encryptor, error) {
	o := buildOptions(opts)
	if store == nil {
		return nil, errors.New("pgp: nil KeyStore")
	}
	if o.selfInvalid {
		return nil, errors.New("pgp: WithEncryptToSelf given a nil key")
	}
	for _, k := range o.self {
		if err := k.encryptionKey(o.now(), o.packetConfig()); err != nil {
			o.log.Warn("pgp: encrypt-to-self key rejected", k.LogField(), log.F("reason", err.Error()))
			return nil, fmt.Errorf("pgp: encrypt-to-self key %s: %w", k.Fingerprint(), err)
		}
	}
	o.log.Info("pgp: encryptor ready",
		log.F("cipher", o.cipher.String()),
		log.F("encrypt_to_self", fingerprints(o.self)),
		log.F("missing_key_policy", o.missing.String()),
		log.F("bcc_policy", o.bcc.String()))
	return &encryptor{store: store, o: o}, nil
}

// Encrypt implements email.Encryptor. It can only change m, so it cannot
// split a message: when WithMissingKey(MissingKeyPlaintext) is set and only
// some recipients lack a key, it returns a *MissingKeyError. Used through
// email.Encrypt, the Encryptor calls EncryptCopies instead, which splits.
func (e *encryptor) Encrypt(ctx context.Context, m *email.Message) error {
	start := time.Now()
	plan, err := e.prepare(ctx, m)
	if err != nil {
		return err
	}
	if len(plan.missing) > 0 && len(plan.keys) > 0 {
		e.o.log.Ctx(ctx).Warn("pgp: some recipients have no key and Encrypt cannot split; use email.Encrypt",
			log.F("missing", addrIDs(plan.missing)))
		return &MissingKeyError{Addrs: plan.missing}
	}
	return e.encryptWhole(ctx, m, plan, start)
}

// EncryptCopies implements email.SplitEncryptor, so email.Encrypt calls it
// instead of Encrypt. With WithMissingKey(MissingKeyPlaintext) and only
// some recipients lacking a key, it returns two copies: one encrypted to
// the recipients with keys, then one plaintext copy for the rest. Both
// keep the To and Cc headers, and EnvelopeTo limits delivery. Otherwise it
// returns the single copy Encrypt would produce.
func (e *encryptor) EncryptCopies(ctx context.Context, m *email.Message) ([]email.Message, error) {
	l := e.o.log.Ctx(ctx)
	start := time.Now()
	plan, err := e.prepare(ctx, m)
	if err != nil {
		return nil, err
	}
	if len(plan.missing) == 0 || len(plan.keys) == 0 {
		if err := e.encryptWhole(ctx, m, plan, start); err != nil {
			return nil, err
		}
		return []email.Message{*m}, nil
	}

	bcc := map[string]bool{}
	for _, a := range uniqueAddrs(m.Bcc) {
		bcc[a] = true
	}
	var keyed []string
	for _, a := range plan.addrs {
		if plan.keys[a] != nil {
			keyed = append(keyed, a)
		}
	}
	split := func(addrs []string) email.Message {
		c := cloneMessage(*m)
		c.EnvelopeTo = slices.Clone(addrs)
		c.Bcc = nil
		for _, a := range addrs {
			if bcc[a] {
				c.Bcc = append(c.Bcc, a)
			}
		}
		return c
	}

	ent, err := m.Entity()
	if err != nil {
		return nil, fmt.Errorf("pgp: %w", err)
	}
	p, err := e.encryptPart(ctx, ent.Bytes(), plan.keys, nil)
	if err != nil {
		return nil, err
	}
	encCopy := split(keyed)
	setEncryptedBody(&encCopy, p)
	plainCopy := split(plan.missing)
	l.Warn("pgp: sending a plaintext copy to recipients without a key",
		log.F("missing", addrIDs(plan.missing)), log.F("encrypted_recipients", len(keyed)))
	l.Debug("pgp: message split and encrypted", log.F("copies", 2), since(start))
	return []email.Message{encCopy, plainCopy}, nil
}

// encryptPlan is what prepare found: the unique recipient addresses, one
// key per address that has one, and the addresses without one.
type encryptPlan struct {
	addrs   []string
	keys    map[string]*Key
	missing []string
}

// prepare runs the checks shared by Encrypt and EncryptCopies and looks up
// every recipient's key. With MissingKeyFail, any missing key is an error.
func (e *encryptor) prepare(ctx context.Context, m *email.Message) (*encryptPlan, error) {
	l := e.o.log.Ctx(ctx)
	if isEncryptedBody(m.Body) {
		l.Warn("pgp: body already encrypted")
		return nil, ErrAlreadyEncrypted
	}
	rcpts := m.Recipients()
	l.Debug("pgp: encrypting message", log.F("recipients", len(rcpts)), log.F("bcc", len(m.Bcc)))
	if len(rcpts) == 0 {
		return nil, errors.New("pgp: message has no recipients")
	}
	if len(m.Bcc) > 0 && len(rcpts) > 1 && e.o.bcc != BccAllow {
		l.Warn("pgp: refusing to encrypt Bcc recipients into a shared copy", log.F("recipients", len(rcpts)))
		return nil, ErrBccNotSplit
	}
	addrs := uniqueAddrs(rcpts)
	keys, missing, err := e.resolve(ctx, addrs)
	if err != nil {
		return nil, err
	}
	if len(missing) > 0 && e.o.missing != MissingKeyPlaintext {
		l.Warn("pgp: recipients without a valid key", log.F("missing", addrIDs(missing)))
		return nil, &MissingKeyError{Addrs: missing}
	}
	return &encryptPlan{addrs: addrs, keys: keys, missing: missing}, nil
}

// encryptWhole encrypts m in place for every recipient, or leaves it in
// plaintext when no recipient has a key (only reachable with
// MissingKeyPlaintext).
func (e *encryptor) encryptWhole(ctx context.Context, m *email.Message, plan *encryptPlan, start time.Time) error {
	l := e.o.log.Ctx(ctx)
	if len(plan.keys) == 0 {
		l.Warn("pgp: no recipient has a key; sending plaintext as configured", log.F("missing", addrIDs(plan.missing)))
		return nil
	}
	ent, err := m.Entity()
	if err != nil {
		return fmt.Errorf("pgp: %w", err)
	}
	p, err := e.encryptPart(ctx, ent.Bytes(), plan.keys, nil)
	if err != nil {
		return err
	}
	setEncryptedBody(m, p)
	l.Debug("pgp: message encrypted", since(start))
	return nil
}

// uniqueAddrs normalizes addrs and drops duplicates, keeping order. An
// address that cannot be parsed is kept lower-cased, so it is reported as
// missing a key rather than dropped.
func uniqueAddrs(addrs []string) []string {
	var out []string
	for _, a := range addrs {
		n := normalizeAddr(a)
		if n == "" {
			n = strings.ToLower(strings.TrimSpace(a))
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// resolve finds one usable key per address. It returns the keys (one per
// address that has one, in order) and the addresses without one. A store
// error fails the lookup.
func (e *encryptor) resolve(ctx context.Context, addrs []string) (map[string]*Key, []string, error) {
	l := e.o.log.Ctx(ctx)
	now, cfg := e.o.now(), e.o.packetConfig()
	found := map[string]*Key{}
	var missing []string
	for _, addr := range addrs {
		start := time.Now()
		cands, err := e.store.Keys(ctx, addr)
		if err != nil {
			l.Error(err, "pgp: key store lookup failed", log.F("addr_id", addrID(addr)), since(start))
			return nil, nil, fmt.Errorf("pgp: looking up recipient key: %w", err)
		}
		var best *Key
		for _, k := range cands {
			if k == nil || k.e == nil {
				continue
			}
			if !k.hasValidEmail(addr, now, cfg) {
				l.Warn("pgp: candidate key has no valid user ID for the recipient", k.LogField(), log.F("addr_id", addrID(addr)))
				continue
			}
			if err := k.encryptionKey(now, cfg); err != nil {
				l.Warn("pgp: candidate key rejected", k.LogField(), log.F("addr_id", addrID(addr)), log.F("reason", err.Error()))
				continue
			}
			if best == nil || k.e.PrimaryKey.CreationTime.After(best.e.PrimaryKey.CreationTime) {
				best = k
			}
		}
		if best == nil {
			l.Debug("pgp: no usable key", log.F("addr_id", addrID(addr)), log.F("candidates", len(cands)), since(start))
			missing = append(missing, addr)
			continue
		}
		l.Debug("pgp: recipient key selected", best.LogField(), log.F("addr_id", addrID(addr)), log.F("candidates", len(cands)), since(start))
		found[addr] = best
	}
	return found, missing, nil
}

// encryptPart encrypts content to keys plus the encrypt-to-self keys,
// signing it in the same OpenPGP message when signer is non-nil (RFC 3156
// section 6.2), and returns the multipart/encrypted entity.
func (e *encryptor) encryptPart(ctx context.Context, content []byte, keys map[string]*Key, signer *Key) (*email.Part, error) {
	l := e.o.log.Ctx(ctx)
	start := time.Now()
	// One key per fingerprint, in a stable order.
	var to []*Key
	for _, k := range append(slices.Collect(maps.Values(keys)), e.o.self...) {
		if !slices.ContainsFunc(to, func(o *Key) bool { return o.Fingerprint() == k.Fingerprint() }) {
			to = append(to, k)
		}
	}
	slices.SortFunc(to, func(a, b *Key) int { return strings.Compare(a.Fingerprint(), b.Fingerprint()) })

	var out bytes.Buffer
	if err := encryptTo(&out, content, to, signer, e.o); err != nil {
		l.Error(err, "pgp: encryption failed", log.F("keys", fingerprints(to)))
		return nil, err
	}
	p, err := encryptedEntity(append(crlf(out.Bytes()), '\r', '\n'))
	if err != nil {
		return nil, err
	}
	f := []log.Field{log.F("keys", fingerprints(to)), log.F("plaintext_bytes", len(content)), log.F("ciphertext_bytes", out.Len()), since(start)}
	if signer != nil {
		f = append(f, log.F("signer", signer.Fingerprint()))
	}
	l.Debug("pgp: entity encrypted", f...)
	return p, nil
}

// encryptTo writes content as an armored OpenPGP message encrypted to the
// keys in to, and signed by signer when it is set, holding every key's
// lock throughout.
func encryptTo(out *bytes.Buffer, content []byte, to []*Key, signer *Key, o *options) error {
	defer lockKeys(append(slices.Clone(to), signer)...)()
	var signers []*openpgp.Entity
	if signer != nil {
		signers = []*openpgp.Entity{signer.e}
	}
	aw, err := armor.Encode(out, openpgp.MessageType, nil)
	if err != nil {
		return fmt.Errorf("pgp: armoring message: %w", err)
	}
	pw, err := openpgp.EncryptWithParams(aw, entities(to), nil, &openpgp.EncryptParams{
		Signers: signers,
		Config:  o.packetConfig(),
	})
	if err != nil {
		return fmt.Errorf("pgp: encrypting: %w", err)
	}
	if _, err := pw.Write(content); err != nil {
		return fmt.Errorf("pgp: encrypting: %w", err)
	}
	if err := pw.Close(); err != nil {
		return fmt.Errorf("pgp: encrypting: %w", err)
	}
	if err := aw.Close(); err != nil {
		return fmt.Errorf("pgp: armoring message: %w", err)
	}
	return nil
}

// SignEncrypt returns one middleware that signs with k and encrypts to the
// recipients' keys from store, always in that order. Signing and
// encryption happen in a single OpenPGP message (RFC 3156 section 6.2), so
// the signature is hidden inside the ciphertext. k may be nil for
// encryption only. It takes the same options as NewSigner and
// NewEncryptor.
//
// Each Bcc recipient gets a separate copy, encrypted to their key alone
// (plus any WithEncryptToSelf keys), so no reader learns who was Bcc'd. The
// To and Cc headers are the same on every copy. Every recipient's key is
// looked up before anything is sent: with the default MissingKeyFail
// policy a missing key fails the send and nothing goes out. With
// MissingKeyPlaintext, recipients without a key get a separate plaintext
// copy, which is still signed when k is set.
//
// The caller's message is never modified, so a Retry outside SignEncrypt
// re-signs and re-encrypts the original on every attempt. Every copy is
// attempted even if one fails, and the failures are joined, so a Retry
// outside it resends every copy: put Retry inside it when that matters.
func SignEncrypt(k *Key, store KeyStore, opts ...Option) (email.Middleware, error) {
	enc, err := newEncryptor(store, opts)
	if err != nil {
		return nil, err
	}
	if k != nil {
		if err := k.signingKey(enc.o.now(), enc.o.packetConfig()); err != nil {
			enc.o.log.Warn("pgp: signing key rejected", k.LogField(), log.F("reason", err.Error()))
			return nil, err
		}
		enc.o.log.Info("pgp: sign-and-encrypt ready", k.LogField())
	}
	se := &signEncrypt{key: k, enc: enc}
	return func(next email.SendFunc) email.SendFunc {
		return func(ctx context.Context, m *email.Message) error {
			return se.send(ctx, m, next)
		}
	}, nil
}

type signEncrypt struct {
	key *Key
	enc *encryptor
}

// delivery is one copy to send: its RCPT TO set, whether it is a Bcc copy,
// and whether it is encrypted.
type delivery struct {
	addrs   []string
	bcc     bool
	encrypt bool
}

func (se *signEncrypt) send(ctx context.Context, orig *email.Message, next email.SendFunc) error {
	o := se.enc.o
	l := o.log.Ctx(ctx)
	if se.key != nil {
		l = l.With(se.key.LogField())
	}
	start := time.Now()
	m := cloneMessage(*orig)
	if se.key != nil {
		if err := checkSignable(se.key, &m, o); err != nil {
			l.Warn("pgp: message not signed", log.F("reason", err.Error()))
			return err
		}
	} else if isEncryptedBody(m.Body) {
		return ErrAlreadyEncrypted
	}

	groups := recipientGroups(m)
	var all []string
	for _, g := range groups {
		all = append(all, g.addrs...)
	}
	all = uniqueAddrs(all)
	if len(all) == 0 {
		return errors.New("pgp: message has no recipients")
	}
	l.Debug("pgp: sign-and-encrypt started", log.F("recipients", len(all)), log.F("copies_planned", len(groups)))
	keys, missing, err := se.enc.resolve(ctx, all)
	if err != nil {
		return err
	}
	if len(missing) > 0 && o.missing != MissingKeyPlaintext {
		l.Warn("pgp: recipients without a valid key; nothing sent", log.F("missing", addrIDs(missing)))
		return &MissingKeyError{Addrs: missing}
	}

	var plan []delivery
	for _, g := range groups {
		var keyed, keyless []string
		for _, a := range g.addrs {
			if keys[a] != nil {
				keyed = append(keyed, a)
			} else {
				keyless = append(keyless, a)
			}
		}
		if len(keyed) > 0 {
			plan = append(plan, delivery{addrs: keyed, bcc: g.bcc, encrypt: true})
		}
		if len(keyless) > 0 {
			plan = append(plan, delivery{addrs: keyless, bcc: g.bcc})
		}
	}
	if len(missing) > 0 {
		l.Warn("pgp: sending plaintext copies to recipients without a key", log.F("missing", addrIDs(missing)))
	}

	ent, err := m.Entity()
	if err != nil {
		return fmt.Errorf("pgp: %w", err)
	}
	content := ent.Bytes()
	var signedPlain *email.Part // built once, only if needed

	var errs []error
	for i, d := range plan {
		c := cloneMessage(m)
		c.EnvelopeTo = d.addrs
		c.Bcc = nil
		if d.bcc {
			c.Bcc = slices.Clone(d.addrs)
		}
		switch {
		case d.encrypt:
			sub := map[string]*Key{}
			for _, a := range d.addrs {
				sub[a] = keys[a]
			}
			p, err := se.enc.encryptPart(ctx, content, sub, se.key)
			if err != nil {
				return errors.Join(append(errs, err)...)
			}
			setEncryptedBody(&c, p)
		case se.key != nil:
			if signedPlain == nil {
				if signedPlain, err = signPart(se.key, content, o); err != nil {
					l.Error(err, "pgp: signing plaintext copy failed")
					return errors.Join(append(errs, err)...)
				}
			}
			c.Body = signedPlain
		}
		copyStart := time.Now()
		err := next(ctx, &c)
		l.Debug("pgp: copy sent",
			log.F("copy", i+1), log.F("copies", len(plan)), log.F("recipients", len(d.addrs)),
			log.F("encrypted", d.encrypt), log.F("bcc", d.bcc), log.F("ok", err == nil), since(copyStart))
		if err != nil {
			errs = append(errs, err)
		}
	}
	err = errors.Join(errs...)
	if err != nil {
		l.Warn("pgp: sign-and-encrypt finished with errors", log.F("failed", len(errs)), log.F("copies", len(plan)), since(start))
	} else {
		l.Debug("pgp: sign-and-encrypt finished", log.F("copies", len(plan)), since(start))
	}
	return err
}

// group is the recipients of one copy, before keys are known.
type group struct {
	addrs []string
	bcc   bool
}

// recipientGroups splits m.Recipients() into the shared copy (To, Cc and
// any Bcc address that is also visible) and one group per Bcc-only
// recipient. Addresses are normalized and deduplicated.
func recipientGroups(m email.Message) []group {
	visible := map[string]bool{}
	for _, a := range uniqueAddrs(append(slices.Clone(m.To), m.Cc...)) {
		visible[a] = true
	}
	bccOnly := map[string]bool{}
	for _, a := range uniqueAddrs(m.Bcc) {
		if !visible[a] {
			bccOnly[a] = true
		}
	}
	var shared []string
	var bcc []group
	for _, a := range uniqueAddrs(m.Recipients()) {
		if bccOnly[a] {
			bcc = append(bcc, group{addrs: []string{a}, bcc: true})
		} else {
			shared = append(shared, a)
		}
	}
	if len(shared) == 0 {
		return bcc
	}
	return append([]group{{addrs: shared}}, bcc...)
}
