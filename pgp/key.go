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
	"cmp"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

// Key is an OpenPGP key: a public key, or a private key for signing and
// decryption. It is opaque so that no go-crypto type appears in this
// package's API. Formatting a Key with fmt, or logging it, shows only its
// fingerprint.
//
// A Key is safe for concurrent use. go-crypto caches signature checks
// inside the key as it uses it, so every operation holds the key's lock
// (see lockKeys) while it touches the key.
type Key struct {
	e *openpgp.Entity

	mu   sync.Mutex
	once sync.Once
	seq  uint64
}

// keySeq numbers keys in creation order of first use, which gives lockKeys
// a fixed lock order.
var keySeq atomic.Uint64

func (k *Key) order() uint64 {
	k.once.Do(func() { k.seq = keySeq.Add(1) })
	return k.seq
}

// lockKeys locks every distinct key in keys, always in the same order so
// two callers can never deadlock, and returns the function that unlocks
// them. Callers must not already hold any of the locks.
func lockKeys(keys ...*Key) func() {
	var uniq []*Key
	for _, k := range keys {
		if k != nil && !slices.Contains(uniq, k) {
			uniq = append(uniq, k)
		}
	}
	slices.SortFunc(uniq, func(a, b *Key) int { return cmp.Compare(a.order(), b.order()) })
	for _, k := range uniq {
		k.mu.Lock()
	}
	return func() {
		for i := len(uniq) - 1; i >= 0; i-- {
			uniq[i].mu.Unlock()
		}
	}
}

// maxKeyBytes caps how much ReadKeys and ReadArmoredKeys will read.
const maxKeyBytes = 16 << 20

// ReadArmoredKeys reads every key in an ASCII-armored key block (public or
// private). It fails if the input holds no key.
func ReadArmoredKeys(r io.Reader) ([]*Key, error) {
	el, err := openpgp.ReadArmoredKeyRing(io.LimitReader(r, maxKeyBytes))
	if err != nil {
		return nil, fmt.Errorf("pgp: reading armored keys: %w", err)
	}
	return wrapEntities(el)
}

// ReadKeys reads every key in binary (non-armored) OpenPGP data. It fails
// if the input holds no key.
func ReadKeys(r io.Reader) ([]*Key, error) {
	el, err := openpgp.ReadKeyRing(io.LimitReader(r, maxKeyBytes))
	if err != nil {
		return nil, fmt.Errorf("pgp: reading keys: %w", err)
	}
	return wrapEntities(el)
}

func wrapEntities(el openpgp.EntityList) ([]*Key, error) {
	if len(el) == 0 {
		return nil, errors.New("pgp: no keys found")
	}
	keys := make([]*Key, len(el))
	for i, e := range el {
		keys[i] = &Key{e: e}
	}
	return keys, nil
}

// Fingerprint returns the primary key's fingerprint in upper-case hex (40
// characters for a v4 key, 64 for a v6 key).
func (k *Key) Fingerprint() string {
	if k == nil || k.e == nil || k.e.PrimaryKey == nil {
		return ""
	}
	return strings.ToUpper(fmt.Sprintf("%x", k.e.PrimaryKey.Fingerprint))
}

// String returns the fingerprint, so a Key never prints key material.
func (k *Key) String() string { return "pgp.Key(" + k.Fingerprint() + ")" }

// GoString returns the same as String, for %#v.
func (k *Key) GoString() string { return k.String() }

// Format prints the fingerprint for every verb, so %+v and %#v cannot
// reach the private key through reflection.
func (k *Key) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }

// LogField returns a go-log field holding only the fingerprint.
func (k *Key) LogField() log.Field { return log.F("fingerprint", k.Fingerprint()) }

// Emails returns the lower-cased email addresses of the key's user IDs, in
// sorted order, without duplicates. It does not check the user IDs'
// self-signatures; the Signer and Encryptor only use user IDs that are
// validly self-signed and not revoked.
func (k *Key) Emails() []string {
	var out []string
	for _, id := range k.e.Identities {
		if id.UserId != nil && id.UserId.Email != "" {
			out = append(out, strings.ToLower(id.UserId.Email))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// HasPrivate reports whether k includes its private key.
func (k *Key) HasPrivate() bool { return k.e.PrivateKey != nil }

// Locked reports whether any private key in k is still protected by a
// passphrase.
func (k *Key) Locked() bool {
	defer lockKeys(k)()
	return k.locked()
}

func (k *Key) locked() bool {
	if k.e.PrivateKey != nil && k.e.PrivateKey.Encrypted {
		return true
	}
	for _, s := range k.e.Subkeys {
		if s.PrivateKey != nil && s.PrivateKey.Encrypted {
			return true
		}
	}
	return false
}

// Unlock decrypts k's private keys with passphrase. It wipes passphrase
// before returning, whether or not it succeeded. Unlocking a key that is
// not locked is a no-op.
func (k *Key) Unlock(passphrase []byte) error {
	defer clear(passphrase)
	if !k.HasPrivate() {
		return ErrNoPrivateKey
	}
	defer lockKeys(k)()
	if !k.locked() {
		return nil
	}
	if err := k.e.DecryptPrivateKeys(passphrase); err != nil {
		return fmt.Errorf("pgp: unlocking key %s: %w", k.Fingerprint(), err)
	}
	return nil
}

// ArmoredPublic returns the ASCII-armored public key, the form to hand to
// correspondents.
func (k *Key) ArmoredPublic() ([]byte, error) {
	defer lockKeys(k)()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, fmt.Errorf("pgp: armoring key: %w", err)
	}
	if err := k.e.Serialize(w); err != nil {
		return nil, fmt.Errorf("pgp: serializing key: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("pgp: armoring key: %w", err)
	}
	return buf.Bytes(), nil
}

// hasValidEmail reports whether addr (lower-cased) is one of k's user IDs
// with a valid, unrevoked self-signature at now.
func (k *Key) hasValidEmail(addr string, now time.Time, cfg *packet.Config) bool {
	defer lockKeys(k)()
	for _, id := range k.e.Identities {
		if id.UserId == nil || !strings.EqualFold(id.UserId.Email, addr) {
			continue
		}
		if _, err := id.Verify(now, cfg); err == nil {
			return true
		}
	}
	return false
}

// checkStrength rejects DSA, ElGamal and RSA keys under minRSABits.
func checkStrength(pk *packet.PublicKey) error {
	switch pk.PubKeyAlgo {
	case packet.PubKeyAlgoDSA, packet.PubKeyAlgoElGamal:
		return fmt.Errorf("%w: %s", ErrWeakKey, algoName(pk.PubKeyAlgo))
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly, packet.PubKeyAlgoRSAEncryptOnly:
		bits, err := pk.BitLength()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrWeakKey, err)
		}
		if bits < minRSABits {
			return fmt.Errorf("%w: RSA-%d is under %d bits", ErrWeakKey, bits, minRSABits)
		}
	}
	return nil
}

// encryptionKey returns an error unless k has a valid, strong encryption
// key at now. It does not check user IDs.
func (k *Key) encryptionKey(now time.Time, cfg *packet.Config) error {
	defer lockKeys(k)()
	if k.e.Revoked(now) {
		return fmt.Errorf("%w: key is revoked", ErrWeakKey)
	}
	if err := checkStrength(k.e.PrimaryKey); err != nil {
		return err
	}
	sub, err := k.e.EncryptionKeyWithError(now, cfg)
	if err != nil {
		return fmt.Errorf("%w: no valid encryption key: %w", ErrWeakKey, err)
	}
	return checkStrength(sub.PublicKey)
}

// signingKey returns an error unless k has a valid, strong, unlocked
// private signing key at now.
func (k *Key) signingKey(now time.Time, cfg *packet.Config) error {
	if !k.HasPrivate() {
		return ErrNoPrivateKey
	}
	defer lockKeys(k)()
	if k.locked() {
		return ErrKeyLocked
	}
	if k.e.Revoked(now) {
		return fmt.Errorf("%w: key is revoked", ErrWeakKey)
	}
	if err := checkStrength(k.e.PrimaryKey); err != nil {
		return err
	}
	sub, ok := k.e.SigningKey(now, cfg)
	if !ok {
		return fmt.Errorf("%w: no valid signing key", ErrWeakKey)
	}
	if sub.PrivateKey == nil {
		return ErrNoPrivateKey
	}
	return checkStrength(sub.PublicKey)
}

// algoName names a public-key algorithm for errors and logs.
func algoName(a packet.PublicKeyAlgorithm) string {
	switch a {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly, packet.PubKeyAlgoRSAEncryptOnly:
		return "RSA"
	case packet.PubKeyAlgoDSA:
		return "DSA"
	case packet.PubKeyAlgoElGamal:
		return "ElGamal"
	case packet.PubKeyAlgoECDSA:
		return "ECDSA"
	case packet.PubKeyAlgoECDH:
		return "ECDH"
	case packet.PubKeyAlgoEdDSA:
		return "EdDSA"
	case packet.PubKeyAlgoEd25519:
		return "Ed25519"
	case packet.PubKeyAlgoEd448:
		return "Ed448"
	case packet.PubKeyAlgoX25519:
		return "X25519"
	case packet.PubKeyAlgoX448:
		return "X448"
	default:
		return fmt.Sprintf("algorithm %d", a)
	}
}

// entities unwraps keys for go-crypto calls.
func entities(keys []*Key) []*openpgp.Entity {
	out := make([]*openpgp.Entity, len(keys))
	for i, k := range keys {
		out[i] = k.e
	}
	return out
}
