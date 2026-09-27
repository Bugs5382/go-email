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
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrNoPrivateKey is returned when a signing or decryption key has no
	// private half.
	ErrNoPrivateKey = errors.New("pgp: key has no private part")
	// ErrKeyLocked is returned when a private key is still encrypted with a
	// passphrase. Call Key.Unlock first.
	ErrKeyLocked = errors.New("pgp: private key is locked")
	// ErrWeakKey is returned for keys this package refuses to use: RSA
	// under 2048 bits, DSA, ElGamal, or keys with no usable subkey.
	ErrWeakKey = errors.New("pgp: key is weak or unusable")
	// ErrSignerMismatch is returned when the message's From address is not
	// one of the signing key's user IDs.
	ErrSignerMismatch = errors.New("pgp: From address does not match the signing key")
	// ErrAlreadyEncrypted is returned when asked to sign or encrypt a body
	// that is already an encrypted entity. Sign first, then encrypt.
	ErrAlreadyEncrypted = errors.New("pgp: message body is already encrypted")
	// ErrNoRecipientKey is returned when a recipient has no valid
	// encryption key. The error is a *MissingKeyError listing them.
	ErrNoRecipientKey = errors.New("pgp: no valid key for recipient")
	// ErrBccNotSplit is returned by an Encryptor when a message with Bcc
	// recipients would be encrypted to more than one recipient in a single
	// copy, which would reveal the Bcc recipients' keys to everyone. Use
	// SignEncrypt or email.SplitBcc, or pass WithBccPolicy(BccAllow).
	ErrBccNotSplit = errors.New("pgp: Bcc recipients must get their own encrypted copy")

	// ErrMalformed reports a PGP/MIME structure that cannot be parsed
	// unambiguously.
	ErrMalformed = errors.New("pgp: malformed PGP/MIME message")
	// ErrTooLarge is returned when a message or its plaintext is larger
	// than the WithMaxSize limit.
	ErrTooLarge = errors.New("pgp: message too large")
	// ErrNotSigned is returned by Verify when the message is not a
	// PGP/MIME multipart/signed message.
	ErrNotSigned = errors.New("pgp: message is not PGP/MIME signed")
	// ErrNotEncrypted is returned by Decrypt when the top-level body is not
	// a PGP/MIME multipart/encrypted entity.
	ErrNotEncrypted = errors.New("pgp: message is not PGP/MIME encrypted")
	// ErrBadSignature is returned when a signature does not verify.
	ErrBadSignature = errors.New("pgp: bad signature")
	// ErrUnknownSigner is returned by Verify when the signature was not made
	// by any valid key the store holds for the From address.
	ErrUnknownSigner = errors.New("pgp: signature is not by a known key for the sender")
	// ErrDecrypt is returned when a message cannot be decrypted or fails
	// its integrity check. No plaintext is ever returned with it.
	ErrDecrypt = errors.New("pgp: decryption failed")
)

// MissingKeyError lists the recipients that have no valid encryption key.
// It matches ErrNoRecipientKey with errors.Is.
type MissingKeyError struct {
	// Addrs are the recipient addresses, lower-cased, in message order.
	Addrs []string
}

// Error implements error.
func (e *MissingKeyError) Error() string {
	return fmt.Sprintf("%v: %s", ErrNoRecipientKey, strings.Join(e.Addrs, ", "))
}

// Unwrap lets errors.Is match ErrNoRecipientKey.
func (e *MissingKeyError) Unwrap() error { return ErrNoRecipientKey }
