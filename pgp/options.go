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
	"crypto"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Cipher is the symmetric cipher for encrypted messages. It is used when
// every recipient key lists it as a preference; otherwise the best cipher
// all recipients share is used.
type Cipher int

const (
	// AES256 is the default.
	AES256 Cipher = iota
	// AES128 is supported by every OpenPGP implementation.
	AES128
)

func (c Cipher) String() string {
	if c == AES128 {
		return "AES-128"
	}
	return "AES-256"
}

// MissingKeyPolicy decides what happens when a recipient has no valid key.
type MissingKeyPolicy int

const (
	// MissingKeyFail fails the whole send with a *MissingKeyError before
	// anything is sent. It is the default.
	MissingKeyFail MissingKeyPolicy = iota
	// MissingKeyPlaintext sends recipients without a key a separate
	// plaintext copy (still signed when SignEncrypt has a signing key).
	// A bare Encryptor cannot split a message, so it only leaves the
	// message in plaintext when no recipient has a key at all.
	MissingKeyPlaintext
)

func (p MissingKeyPolicy) String() string {
	if p == MissingKeyPlaintext {
		return "plaintext"
	}
	return "fail"
}

// BccPolicy decides what a bare Encryptor does with Bcc recipients.
type BccPolicy int

const (
	// BccReject returns ErrBccNotSplit when a message with Bcc recipients
	// would go to more than one recipient in one encrypted copy. It is
	// the default.
	BccReject BccPolicy = iota
	// BccAllow encrypts to everyone in one copy, so every reader can see
	// the key IDs of the Bcc recipients.
	BccAllow
)

func (p BccPolicy) String() string {
	if p == BccAllow {
		return "allow"
	}
	return "reject"
}

// DefaultMaxSize is the default limit on the size of a message passed to
// Verify or Decrypt, and on the plaintext Decrypt produces.
const DefaultMaxSize = 64 << 20

// Option configures NewSigner, NewEncryptor, SignEncrypt, Verify and
// Decrypt. Options that do not apply to a function are ignored.
type Option func(*options)

type options struct {
	log         log.Logger
	now         func() time.Time
	cipher      Cipher
	self        []*Key
	missing     MissingKeyPolicy
	bcc         BccPolicy
	maxSize     int64
	selfInvalid bool
}

func buildOptions(opts []Option) *options {
	o := &options{log: nopLogger{}, now: time.Now, maxSize: DefaultMaxSize}
	for _, opt := range opts {
		if opt != nil {
			opt(o)
		}
	}
	return o
}

// WithLogger sends the package's logs to l. Without it nothing is logged.
// Per-message operations log at debug level, rejected keys and failed
// checks at warn, and unexpected failures at error. No key material,
// passphrase, message content or address is ever logged.
func WithLogger(l log.Logger) Option {
	return func(o *options) {
		if l != nil {
			o.log = l
		}
	}
}

// WithClock sets the clock used to check key validity and to time
// signatures. It defaults to time.Now.
func WithClock(now func() time.Time) Option {
	return func(o *options) {
		if now != nil {
			o.now = now
		}
	}
}

// WithCipher sets the preferred symmetric cipher. The default is AES256.
func WithCipher(c Cipher) Option {
	return func(o *options) { o.cipher = c }
}

// WithEncryptToSelf also encrypts every message to k, usually the sender's
// own public key, so the sender can read what it sent.
func WithEncryptToSelf(k *Key) Option {
	return func(o *options) {
		if k == nil {
			o.selfInvalid = true
			return
		}
		o.self = append(o.self, k)
	}
}

// WithMissingKey sets the policy for recipients without a valid key. The
// default is MissingKeyFail.
func WithMissingKey(p MissingKeyPolicy) Option {
	return func(o *options) { o.missing = p }
}

// WithBccPolicy sets how a bare Encryptor handles Bcc recipients. The
// default is BccReject. SignEncrypt always splits Bcc copies and ignores
// this option.
func WithBccPolicy(p BccPolicy) Option {
	return func(o *options) { o.bcc = p }
}

// WithMaxSize caps the size in bytes of a message given to Verify or
// Decrypt, and of the plaintext Decrypt produces. The default is
// DefaultMaxSize.
func WithMaxSize(n int64) Option {
	return func(o *options) {
		if n > 0 {
			o.maxSize = n
		}
	}
}

// minRSABits is the smallest RSA modulus accepted anywhere.
const minRSABits = 2048

// packetConfig returns the go-crypto configuration every operation uses:
// SHA-256, the chosen cipher, no compression, a 2048-bit RSA floor, and
// go-crypto's v2 rejection lists (DSA, ElGamal, MD5, RIPEMD-160, SHA-1
// message signatures, secp256k1).
func (o *options) packetConfig() *packet.Config {
	c := packet.CipherAES256
	if o.cipher == AES128 {
		c = packet.CipherAES128
	}
	return &packet.Config{
		DefaultHash:   crypto.SHA256,
		DefaultCipher: c,
		Time:          o.now,
		MinRSABits:    minRSABits,
	}
}
