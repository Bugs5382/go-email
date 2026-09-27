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
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	email "github.com/Bugs5382/go-email"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

func TestConstructorErrors(t *testing.T) {
	t.Parallel()

	store := NewMemStore()
	if _, err := NewEncryptor(nil); err == nil {
		t.Error("NewEncryptor(nil) succeeded")
	}
	if _, err := NewEncryptor(store, WithEncryptToSelf(nil)); err == nil {
		t.Error("WithEncryptToSelf(nil) accepted")
	}
	weak, err := openpgp.NewEntity("Weak", "", "weak@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoRSA, RSABits: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEncryptor(store, WithEncryptToSelf(&Key{e: weak})); !errors.Is(err, ErrWeakKey) {
		t.Errorf("weak encrypt-to-self key: err = %v", err)
	}
	if _, err := SignEncrypt(&Key{e: weak}, store); !errors.Is(err, ErrWeakKey) {
		t.Errorf("weak SignEncrypt key: err = %v", err)
	}
	if _, err := NewSigner(nil); !errors.Is(err, ErrNoPrivateKey) {
		t.Errorf("NewSigner(nil): err = %v", err)
	}
	if _, err := SignEncrypt(testKey(t, "Alice", "alice@example.com"), nil); err == nil {
		t.Error("SignEncrypt with a nil store succeeded")
	}
}

// TestExpiredKeyWithClock checks that WithClock drives key validity: a
// key that expires after an hour is refused two hours later.
func TestExpiredKeyWithClock(t *testing.T) {
	t.Parallel()

	e, err := openpgp.NewEntity("Erin", "", "erin@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, KeyLifetimeSecs: 3600})
	if err != nil {
		t.Fatal(err)
	}
	erin := &Key{e: e}
	later := WithClock(func() time.Time { return time.Now().Add(2 * time.Hour) })
	if _, err := NewSigner(erin, later); !errors.Is(err, ErrWeakKey) {
		t.Errorf("expired signing key: err = %v", err)
	}
	enc, err := NewEncryptor(NewMemStore(publicOnly(t, erin)), later)
	if err != nil {
		t.Fatal(err)
	}
	m := testMessage()
	m.To = []string{"erin@example.com"}
	if err := enc.Encrypt(context.Background(), &m); !errors.Is(err, ErrNoRecipientKey) {
		t.Errorf("expired recipient key: err = %v", err)
	}
	if _, err := NewSigner(erin); err != nil {
		t.Errorf("key is valid now: %v", err)
	}
}

func TestEncryptorRefusesEncryptedBody(t *testing.T) {
	t.Parallel()

	bob := publicOnly(t, testKey(t, "Bob", "bob@example.com"))
	enc, _ := NewEncryptor(NewMemStore(bob))
	for _, ct := range []string{
		`multipart/encrypted; protocol="application/pgp-encrypted"; boundary=x`,
		`application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m`,
		`application/pkcs7-mime; smime-type=authEnveloped-data`,
		`not a media type;;`,
	} {
		m := testMessage()
		m.Body = &email.Part{ContentType: ct, Body: []byte("x")}
		if err := enc.Encrypt(context.Background(), &m); !errors.Is(err, ErrAlreadyEncrypted) {
			t.Errorf("%s: err = %v", ct, err)
		}
	}
	// An S/MIME signed body may still be encrypted.
	m := testMessage()
	m.Body = &email.Part{ContentType: "application/pkcs7-mime; smime-type=signed-data", TransferEncoding: "base64", Body: []byte("AA==\r\n")}
	if err := enc.Encrypt(context.Background(), &m); err != nil {
		t.Errorf("S/MIME signed-data body: %v", err)
	}
	if m.Text != "" || m.HTML != "" || m.Attachments != nil {
		t.Error("Encrypt must drop the plaintext fields")
	}
}

func TestDecryptKeyChecksAndLimits(t *testing.T) {
	t.Parallel()

	bob := testKey(t, "Bob", "bob@example.com")
	enc, _ := NewEncryptor(NewMemStore(publicOnly(t, bob)))
	m := testMessage()
	if err := enc.Encrypt(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	raw := render(t, m)
	if _, err := Decrypt(context.Background(), raw, publicOnly(t, bob), nil); !errors.Is(err, ErrNoPrivateKey) {
		t.Errorf("public key: err = %v", err)
	}
	if _, err := Decrypt(context.Background(), raw, nil, nil); !errors.Is(err, ErrNoPrivateKey) {
		t.Errorf("nil key: err = %v", err)
	}
	locked, err := openpgp.NewEntity("Lou", "", "lou@example.com", edConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := locked.EncryptPrivateKeys([]byte("pw"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(context.Background(), raw, &Key{e: locked}, nil); !errors.Is(err, ErrKeyLocked) {
		t.Errorf("locked key: err = %v", err)
	}
	if _, err := Decrypt(context.Background(), raw, bob, nil, WithMaxSize(int64(len(raw)-1))); !errors.Is(err, ErrTooLarge) {
		t.Errorf("message cap: err = %v", err)
	}
	// A compressed message can expand far beyond its own size; the cap
	// also bounds the plaintext, so a decompression bomb is refused.
	var ct bytes.Buffer
	w, err := openpgp.EncryptWithParams(&ct, []*openpgp.Entity{publicOnly(t, bob).e}, nil, &openpgp.EncryptParams{
		Config: &packet.Config{DefaultCompressionAlgo: packet.CompressionZLIB},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(bytes.Repeat([]byte("a"), 1<<20)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	bomb := rebuildEncrypted(t, ct.Bytes())
	if res, err := Decrypt(context.Background(), bomb, bob, nil, WithMaxSize(64<<10)); !errors.Is(err, ErrTooLarge) || res != nil {
		t.Errorf("plaintext over the cap: res=%v err=%v", res != nil, err)
	}
	if res, err := Decrypt(context.Background(), bomb, bob, nil); err != nil || len(res.Entity) != 1<<20 {
		t.Errorf("under the default cap: %v", err)
	}
	if _, err := Verify(context.Background(), raw, NewMemStore()); !errors.Is(err, ErrNotSigned) {
		t.Errorf("Verify of an encrypted message: err = %v", err)
	}
	if _, err := Decrypt(context.Background(), render(t, testMessage()), bob, nil); !errors.Is(err, ErrNotEncrypted) {
		t.Errorf("Decrypt of a plain message: err = %v", err)
	}
}

// TestVerifyBase64SignaturePart accepts a signature part sent with a
// base64 transfer encoding, as some clients do.
func TestVerifyBase64SignaturePart(t *testing.T) {
	t.Parallel()

	alice := testKey(t, "Alice", "alice@example.com")
	s, _ := NewSigner(alice)
	m := testMessage()
	if err := s.Sign(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	raw := render(t, m)
	parts := splitTop(t, raw)
	sig := parts[1][bytes.Index(parts[1], []byte("-----BEGIN")):]
	b64 := base64.StdEncoding.EncodeToString(sig)
	var wrapped strings.Builder
	for len(b64) > 76 {
		wrapped.WriteString(b64[:76] + "\r\n")
		b64 = b64[76:]
	}
	wrapped.WriteString(b64 + "\r\n")
	part := []byte("Content-Type: application/pgp-signature\r\nContent-Transfer-Encoding: base64\r\n\r\n" + wrapped.String())
	res, err := Verify(context.Background(), rebuildWithParts(t, raw, parts[0], part), NewMemStore(publicOnly(t, alice)))
	if err != nil || res.Signature != SignatureValid {
		t.Fatalf("base64 signature part: %v", err)
	}
	bad := []byte("Content-Type: application/pgp-signature\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nzz\r\n")
	if _, err := Verify(context.Background(), rebuildWithParts(t, raw, parts[0], bad), NewMemStore(publicOnly(t, alice))); !errors.Is(err, ErrMalformed) {
		t.Errorf("unknown transfer encoding: err = %v", err)
	}
	one := rebuildWithParts(t, raw, parts[0])
	if _, err := Verify(context.Background(), one, NewMemStore(publicOnly(t, alice))); !errors.Is(err, ErrMalformed) {
		t.Errorf("one-part multipart/signed: err = %v", err)
	}
	wrongType := []byte("Content-Type: text/plain\r\n\r\n" + string(sig))
	if _, err := Verify(context.Background(), rebuildWithParts(t, raw, parts[0], wrongType), NewMemStore(publicOnly(t, alice))); !errors.Is(err, ErrMalformed) {
		t.Errorf("signature part of the wrong type: err = %v", err)
	}
}

// TestDecryptInnerSignedTampered covers RFC 3156 section 6.1 with a bad
// inner signature: Decrypt must fail closed, not return the content as
// unsigned.
func TestDecryptInnerSignedTampered(t *testing.T) {
	t.Parallel()

	alice := testKey(t, "Alice", "alice@example.com")
	bob := testKey(t, "Bob", "bob@example.com")
	s, _ := NewSigner(alice)
	m := testMessage()
	if err := s.Sign(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	signed := *m.Body
	signed.Body = bytes.Replace(signed.Body, []byte("numbers are in"), []byte("numbers are IN"), 1)
	m.Body = &signed
	enc, _ := NewEncryptor(NewMemStore(publicOnly(t, bob)))
	if err := enc.Encrypt(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	raw := render(t, m)
	if res, err := Decrypt(context.Background(), raw, bob, NewMemStore(publicOnly(t, alice))); !errors.Is(err, ErrBadSignature) || res != nil {
		t.Errorf("tampered inner signature: res=%v err=%v", res != nil, err)
	}
	// Without the sender's key it cannot be checked, which is reported,
	// not hidden.
	res, err := Decrypt(context.Background(), raw, bob, nil)
	if err != nil || res.Signature != SignatureUnknownKey {
		t.Errorf("unknown inner signer: %v %v", res, err)
	}
}

// TestVerifyRejectsAmbiguousFrom refuses to pick a sender when From holds
// more than one address.
func TestVerifyRejectsAmbiguousFrom(t *testing.T) {
	t.Parallel()

	alice := testKey(t, "Alice", "alice@example.com")
	s, _ := NewSigner(alice)
	m := testMessage()
	if err := s.Sign(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	raw := bytes.Replace(render(t, m), []byte("From: Alice <alice@example.com>"), []byte("From: alice@example.com, mallory@example.com"), 1)
	if _, err := Verify(context.Background(), raw, NewMemStore(publicOnly(t, alice))); !errors.Is(err, ErrUnknownSigner) {
		t.Errorf("two From addresses: err = %v", err)
	}
}

func TestStringers(t *testing.T) {
	t.Parallel()

	for s, want := range map[SignatureStatus]string{SignatureNone: "none", SignatureValid: "valid", SignatureUnknownKey: "unknown-key"} {
		if s.String() != want {
			t.Errorf("%d.String() = %q", s, s.String())
		}
	}
	if AES128.String() != "AES-128" || AES256.String() != "AES-256" {
		t.Error("Cipher.String")
	}
	if MissingKeyFail.String() != "fail" || MissingKeyPlaintext.String() != "plaintext" || BccReject.String() != "reject" || BccAllow.String() != "allow" {
		t.Error("policy String")
	}
	e := &MissingKeyError{Addrs: []string{"a@example.com", "b@example.com"}}
	if !strings.Contains(e.Error(), "a@example.com, b@example.com") || !errors.Is(e, ErrNoRecipientKey) {
		t.Errorf("MissingKeyError = %q", e.Error())
	}
	for _, a := range []packet.PublicKeyAlgorithm{packet.PubKeyAlgoRSA, packet.PubKeyAlgoDSA, packet.PubKeyAlgoElGamal, packet.PubKeyAlgoECDSA,
		packet.PubKeyAlgoECDH, packet.PubKeyAlgoEdDSA, packet.PubKeyAlgoEd25519, packet.PubKeyAlgoEd448, packet.PubKeyAlgoX25519, packet.PubKeyAlgoX448, 99} {
		if algoName(a) == "" {
			t.Errorf("algoName(%d) empty", a)
		}
	}
	k := testKey(t, "Alice", "alice@example.com")
	if s := k.GoString(); !strings.Contains(s, k.Fingerprint()) {
		t.Errorf("GoString = %q", s)
	}
	if micalg(0) != "pgp-sha256" {
		t.Error("unknown hash must fall back to pgp-sha256")
	}
}

func TestNormalizeAddr(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"Bob@Example.com":            "bob@example.com",
		"Bob <BOB@example.com>":      "bob@example.com",
		"  bob@example.com ":         "bob@example.com",
		"not an address":             "",
		"":                           "",
		"a@b@c":                      "",
		"=?utf-8?q?B=C3=B6b?= <b@x>": "b@x",
	} {
		if got := normalizeAddr(in); got != want {
			t.Errorf("normalizeAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestConcurrentUse shares one set of keys, one Signer and one SignEncrypt
// middleware across goroutines. go-crypto caches signature checks inside a
// key, so this fails under -race without the per-key locks.
func TestConcurrentUse(t *testing.T) {
	t.Parallel()

	alice := testKey(t, "Alice", "alice@example.com")
	bob := testKey(t, "Bob", "bob@example.com")
	pubAlice, pubBob := publicOnly(t, alice), publicOnly(t, bob)
	senders := NewMemStore(pubAlice)
	mw, err := SignEncrypt(alice, NewMemStore(pubBob), WithEncryptToSelf(pubAlice))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := NewSigner(alice)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for range 16 {
		wg.Go(func() {
			var out sink
			if err := mw(out.send)(context.Background(), new(testMessage())); err != nil {
				errs <- err
				return
			}
			raw := render(t, out.msgs[0])
			for _, k := range []*Key{bob, alice} {
				if res, err := Decrypt(context.Background(), raw, k, senders); err != nil || res.Signature != SignatureValid {
					errs <- fmt.Errorf("decrypt: %v %v", res, err)
				}
			}
			m := testMessage()
			if err := s.Sign(context.Background(), &m); err != nil {
				errs <- err
				return
			}
			if _, err := Verify(context.Background(), render(t, m), senders); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestDecryptErrorsAreUniform checks that different decryption failures
// (wrong key, tampered data, downgraded packet, truncation) all return the
// same bare ErrDecrypt, so the error is no oracle.
func TestDecryptErrorsAreUniform(t *testing.T) {
	t.Parallel()

	bob := testKey(t, "Bob", "bob@example.com")
	enc, _ := NewEncryptor(NewMemStore(publicOnly(t, bob)))
	m := testMessage()
	if err := enc.Encrypt(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	raw := render(t, m)
	ct := ciphertextOf(t, raw)
	flipped := append([]byte(nil), ct...)
	flipped[len(flipped)-3] ^= 1
	cases := map[string][]byte{
		"tampered":   rebuildEncrypted(t, flipped),
		"downgraded": rebuildEncrypted(t, downgradeToSED(t, ct)),
		"truncated":  rebuildEncrypted(t, ct[:len(ct)/2]),
	}
	for name, in := range cases {
		if _, err := Decrypt(context.Background(), in, bob, nil); err != ErrDecrypt { //nolint:errorlint // must be the bare sentinel
			t.Errorf("%s: err = %v, want bare ErrDecrypt", name, err)
		}
	}
	if _, err := Decrypt(context.Background(), raw, testKey(t, "Eve", "eve@example.com"), nil); err != ErrDecrypt { //nolint:errorlint // must be the bare sentinel
		t.Errorf("wrong key: err = %v, want bare ErrDecrypt", err)
	}
}

// TestEncryptorSplitsForMissingKeys covers MissingKeyPlaintext on a bare
// Encryptor used through email.Encrypt: recipients with keys get one
// encrypted copy, and only the recipients without a key get plaintext.
func TestEncryptorSplitsForMissingKeys(t *testing.T) {
	t.Parallel()

	alice := testKey(t, "Alice", "alice@example.com")
	bob := testKey(t, "Bob", "bob@example.com")
	dave := testKey(t, "Dave", "dave@example.com")
	store := NewMemStore(publicOnly(t, bob), publicOnly(t, dave))
	enc, err := NewEncryptor(store, WithMissingKey(MissingKeyPlaintext), WithEncryptToSelf(publicOnly(t, alice)))
	if err != nil {
		t.Fatal(err)
	}
	send := func(m email.Message) ([]email.Message, error) {
		var out sink
		err := email.Encrypt(enc)(out.send)(context.Background(), &m)
		return out.msgs, err
	}

	m := testMessage()
	m.To = []string{"bob@example.com", "carol@example.com"}
	m.Cc = []string{"Dave <dave@example.com>", "erin@example.com"}
	got, err := send(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d copies, want 2", len(got))
	}
	if r := got[0].Recipients(); !slices.Equal(r, []string{"bob@example.com", "dave@example.com"}) {
		t.Errorf("encrypted copy recipients = %v", r)
	}
	encRaw := render(t, got[0])
	for _, k := range []*Key{bob, dave, alice} {
		if _, err := Decrypt(context.Background(), encRaw, k, nil); err != nil {
			t.Errorf("encrypted copy unreadable by %s: %v", k.Emails()[0], err)
		}
	}
	if bytes.Contains(encRaw, []byte("numbers are in")) {
		t.Error("encrypted copy leaks the plaintext")
	}
	if r := got[1].Recipients(); !slices.Equal(r, []string{"carol@example.com", "erin@example.com"}) {
		t.Errorf("plaintext copy recipients = %v", r)
	}
	if got[1].Body != nil || got[1].Text != m.Text {
		t.Error("the plaintext copy must be the original, unencrypted message")
	}
	for _, c := range got {
		if !slices.Equal(c.To, m.To) || !slices.Equal(c.Cc, m.Cc) {
			t.Error("every copy keeps the visible To and Cc headers")
		}
	}
	if m.Body != nil || m.EnvelopeTo != nil {
		t.Error("the caller's message must not change")
	}

	// Every recipient has a key: one encrypted copy, as before.
	m = testMessage()
	m.To = []string{"bob@example.com", "dave@example.com"}
	if got, err := send(m); err != nil || len(got) != 1 || got[0].Body == nil {
		t.Errorf("all keyed: %d copies, %v", len(got), err)
	}
	// No recipient has a key: one plaintext copy.
	m = testMessage()
	m.To = []string{"carol@example.com"}
	if got, err := send(m); err != nil || len(got) != 1 || got[0].Body != nil {
		t.Errorf("none keyed: %d copies, %v", len(got), err)
	}

	// The default policy still fails closed and sends nothing.
	strict, _ := NewEncryptor(store)
	var out sink
	m = testMessage()
	m.To = []string{"bob@example.com", "carol@example.com"}
	if err := email.Encrypt(strict)(out.send)(context.Background(), &m); !errors.Is(err, ErrNoRecipientKey) || len(out.msgs) != 0 {
		t.Errorf("MissingKeyFail: err=%v sent=%d", err, len(out.msgs))
	}

	// Calling Encrypt directly cannot split, so a partial miss still fails.
	m = testMessage()
	m.To = []string{"bob@example.com", "carol@example.com"}
	var mk *MissingKeyError
	if err := enc.Encrypt(context.Background(), &m); !errors.As(err, &mk) || !slices.Equal(mk.Addrs, []string{"carol@example.com"}) {
		t.Errorf("direct Encrypt with a partial miss: err = %v", err)
	}
}

// TestEncryptorSplitKeepsBccRules checks that splitting for missing keys
// does not change the Bcc rules: a shared copy with Bcc is still refused,
// and with BccAllow the Bcc field follows each address to its copy.
func TestEncryptorSplitKeepsBccRules(t *testing.T) {
	t.Parallel()

	bob := testKey(t, "Bob", "bob@example.com")
	store := NewMemStore(publicOnly(t, bob))
	enc, _ := NewEncryptor(store, WithMissingKey(MissingKeyPlaintext))
	var out sink
	m := testMessage()
	m.To = []string{"bob@example.com"}
	m.Bcc = []string{"carol@example.com"}
	if err := email.Encrypt(enc)(out.send)(context.Background(), &m); !errors.Is(err, ErrBccNotSplit) || len(out.msgs) != 0 {
		t.Errorf("shared Bcc copy: err=%v sent=%d", err, len(out.msgs))
	}

	allow, _ := NewEncryptor(store, WithMissingKey(MissingKeyPlaintext), WithBccPolicy(BccAllow))
	out = sink{}
	if err := email.Encrypt(allow)(out.send)(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	if len(out.msgs) != 2 {
		t.Fatalf("got %d copies, want 2", len(out.msgs))
	}
	if c := out.msgs[0]; !slices.Equal(c.Recipients(), []string{"bob@example.com"}) || len(c.Bcc) != 0 || c.Body == nil {
		t.Errorf("encrypted copy: rcpt=%v bcc=%v", c.Recipients(), c.Bcc)
	}
	if c := out.msgs[1]; !slices.Equal(c.Recipients(), []string{"carol@example.com"}) || !slices.Equal(c.Bcc, []string{"carol@example.com"}) || c.Body != nil {
		t.Errorf("plaintext copy: rcpt=%v bcc=%v", c.Recipients(), c.Bcc)
	}
	if raw := render(t, out.msgs[1]); bytes.Contains(raw, []byte("carol@example.com")) {
		t.Error("a Bcc address must never be written to a header")
	}
}
