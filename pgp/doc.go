// Package pgp signs, encrypts, verifies and decrypts email with OpenPGP,
// using the PGP/MIME format of RFC 3156.
//
// Sending plugs into the email middleware chain. NewSigner returns an
// email.Signer that wraps the message body in multipart/signed with a
// detached signature. NewEncryptor returns an email.Encryptor that wraps it
// in multipart/encrypted. SignEncrypt returns one middleware that signs and
// encrypts in a single OpenPGP message (RFC 3156 section 6.2), always in
// that order, and gives every Bcc recipient a separate copy so no reader
// learns who else was Bcc'd:
//
//	mw, err := pgp.SignEncrypt(myKey, pgp.NewMemStore(recipientKeys...),
//		pgp.WithEncryptToSelf(myPublicKey))
//	sender := email.New(transport, email.WithMiddleware(email.Retry(3, time.Second), mw))
//
// Receiving is Verify, for a multipart/signed message, and Decrypt, for a
// multipart/encrypted one. Both take the raw RFC 5322 bytes and a KeyStore of
// sender keys. A signature only counts when it was made by a key whose user
// ID matches the From address. Decrypt fails closed: a message without
// integrity protection, a failed MDC or AEAD check, a truncated ciphertext or
// a bad signature returns an error and no plaintext at all, and only a
// top-level multipart/encrypted body is ever decrypted, which rules out the
// EFAIL direct-exfiltration layout.
//
// Headers are not protected. Subject, From, To and Cc stay outside the
// signed and encrypted entity, as they do in most PGP/MIME mail today.
//
// Keys are wrapped in the opaque Key type, so no go-crypto type appears in
// this package's API. Keys, stores, Signers, Encryptors and the SignEncrypt
// middleware are safe for concurrent use. Keys formatted with fmt or a logger show only their
// fingerprint. Weak keys are refused: RSA under 2048 bits, DSA and ElGamal.
// Logging goes through a github.com/Bugs5382/go-log Logger passed with
// WithLogger and is silent by default. It never includes key material,
// passphrases, message content or email addresses; addresses are logged as
// a keyed hash that only correlates lines within one process.
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
