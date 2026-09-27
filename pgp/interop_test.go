//go:build interop

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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	email "github.com/Bugs5382/go-email"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

// These tests round-trip messages through GnuPG in both directions. They
// run with "go test -tags interop ./pgp/" and skip when gpg is missing.

// gpgHome is a throwaway GnuPG home with the given keys imported.
type gpgHome struct {
	t   *testing.T
	dir string
}

func newGPG(t *testing.T, publicKeys ...*Key) *gpgHome {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed; skipping GnuPG interop")
	}
	// A short path keeps the agent socket under the Unix socket limit.
	dir, err := os.MkdirTemp("", "gpg")
	if err != nil {
		t.Fatal(err)
	}
	g := &gpgHome{t: t, dir: dir}
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", dir, "--kill", "all").Run()
		_ = os.RemoveAll(dir)
	})
	out, _ := exec.Command("gpg", "--version").Output()
	t.Logf("%s", bytes.SplitN(out, []byte("\n"), 2)[0])
	// Only public keys are imported. Secret keys GnuPG needs are generated
	// by GnuPG itself (genKey), the way real users' keys are.
	for _, k := range publicKeys {
		var buf bytes.Buffer
		if err := k.e.Serialize(&buf); err != nil {
			t.Fatal(err)
		}
		g.run(buf.Bytes(), "--import")
	}
	return g
}

// run runs gpg with the status output on stdout and returns it.
func (g *gpgHome) run(stdin []byte, args ...string) string {
	g.t.Helper()
	base := []string{"--homedir", g.dir, "--batch", "--yes", "--no-tty", "--status-fd", "1",
		"--pinentry-mode", "loopback", "--passphrase", "", "--trust-model", "always"}
	cmd := exec.Command("gpg", append(base, args...)...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		g.t.Fatalf("gpg %v: %v\nstatus:\n%s\nstderr:\n%s", args, err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

func (g *gpgHome) write(name string, b []byte) string {
	g.t.Helper()
	p := filepath.Join(g.dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		g.t.Fatal(err)
	}
	return p
}

func (g *gpgHome) read(name string) []byte {
	g.t.Helper()
	b, err := os.ReadFile(filepath.Join(g.dir, name))
	if err != nil {
		g.t.Fatal(err)
	}
	return b
}

func requireStatus(t *testing.T, status string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(status, "[GNUPG:] "+w) {
			t.Errorf("gpg status lacks %s:\n%s", w, status)
		}
	}
	for _, bad := range []string{"BADSIG", "DECRYPTION_FAILED", "ERRSIG"} {
		if strings.Contains(status, "[GNUPG:] "+bad) {
			t.Errorf("gpg status has %s:\n%s", bad, status)
		}
	}
}

// genKey has GnuPG generate a key for uid ("Name <addr>"), of kind
// "ed25519" (with a cv25519 encryption subkey) or "rsa3072", protected by
// passphrase (empty for none), and returns its fingerprint.
func (g *gpgHome) genKey(uid, kind, passphrase string) string {
	g.t.Helper()
	pass := []string{"--passphrase", passphrase}
	switch kind {
	case "ed25519":
		g.runPass(pass, nil, "--quick-gen-key", uid, "ed25519", "sign,cert", "never")
		fpr := g.fingerprint(uid)
		g.runPass(pass, nil, "--quick-add-key", fpr, "cv25519", "encr", "never")
		return fpr
	default:
		g.runPass(pass, nil, "--quick-gen-key", uid, "rsa3072", "sign,cert,encr", "never")
		return g.fingerprint(uid)
	}
}

// runPass is run with a different passphrase.
func (g *gpgHome) runPass(pass []string, stdin []byte, args ...string) string {
	g.t.Helper()
	return g.run(stdin, append(pass, args...)...)
}

func (g *gpgHome) fingerprint(uid string) string {
	g.t.Helper()
	cmd := exec.Command("gpg", "--homedir", g.dir, "--batch", "--with-colons", "--list-keys", uid)
	out, err := cmd.Output()
	if err != nil {
		g.t.Fatal(err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Split(line, ":"); f[0] == "fpr" {
			return f[9]
		}
	}
	g.t.Fatalf("no fingerprint for %s", uid)
	return ""
}

// export reads a key back out of GnuPG: the public key, or the secret key
// (still protected by its passphrase) when secret is true.
func (g *gpgHome) export(fpr string, secret bool, passphrase string) *Key {
	g.t.Helper()
	op := "--export"
	if secret {
		op = "--export-secret-keys"
	}
	g.runPass([]string{"--passphrase", passphrase}, nil, "--armor", "--output", filepath.Join(g.dir, "key.asc"), op, fpr)
	keys, err := ReadArmoredKeys(bytes.NewReader(g.read("key.asc")))
	if err != nil {
		g.t.Fatal(err)
	}
	return keys[0]
}

var gpgKinds = []string{"ed25519", "rsa3072"}

// TestInteropGPGVerifiesOurSignature: we sign, gpg verifies.
func TestInteropGPGVerifiesOurSignature(t *testing.T) {
	for _, alice := range []*Key{testKey(t, "Alice", "alice@example.com"), rsaKey(t)} {
		g := newGPG(t, publicOnly(t, alice))
		s, err := NewSigner(alice)
		if err != nil {
			t.Fatal(err)
		}
		m := testMessage()
		m.From = alice.Emails()[0]
		if err := s.Sign(context.Background(), &m); err != nil {
			t.Fatal(err)
		}
		parts := splitTop(t, render(t, m))
		sig := parts[1][bytes.Index(parts[1], []byte("-----BEGIN")):]
		status := g.run(nil, "--verify", g.write("sig.asc", sig), g.write("content", parts[0]))
		requireStatus(t, status, "GOODSIG", "VALIDSIG "+alice.Fingerprint())
	}
}

// TestInteropGPGDecryptsOurMessage: we sign and encrypt to a GnuPG key,
// gpg decrypts and verifies.
func TestInteropGPGDecryptsOurMessage(t *testing.T) {
	alice := testKey(t, "Alice", "alice@example.com")
	for _, kind := range gpgKinds {
		g := newGPG(t, publicOnly(t, alice))
		bob := g.export(g.genKey("Bob <bob@example.com>", kind, ""), false, "")
		mw, err := SignEncrypt(alice, NewMemStore(bob))
		if err != nil {
			t.Fatal(err)
		}
		var out sink
		if err := mw(out.send)(context.Background(), new(testMessage())); err != nil {
			t.Fatal(err)
		}
		parts := splitTop(t, render(t, out.msgs[0]))
		enc := parts[1][bytes.Index(parts[1], []byte("-----BEGIN")):]
		status := g.run(nil, "--output", filepath.Join(g.dir, "plain"), "--decrypt", g.write("enc.asc", enc))
		requireStatus(t, status, "DECRYPTION_OKAY", "GOODSIG", "VALIDSIG "+alice.Fingerprint())
		if plain := g.read("plain"); !bytes.Contains(plain, []byte("=46rom the desk of Alice")) || !bytes.HasPrefix(plain, []byte("Content-Type: multipart/mixed")) {
			t.Errorf("%s: gpg plaintext is not our entity:\n%s", kind, plain)
		}
	}
}

// TestInteropWeVerifyGPGSignature: gpg signs our entity, we verify.
func TestInteropWeVerifyGPGSignature(t *testing.T) {
	for _, kind := range gpgKinds {
		g := newGPG(t)
		fpr := g.genKey("Alice <alice@example.com>", kind, "")
		alice := g.export(fpr, false, "")
		m := testMessage()
		ent, err := m.Entity()
		if err != nil {
			t.Fatal(err)
		}
		content := ent.Bytes()
		g.run(nil, "--armor", "--digest-algo", "SHA256", "--local-user", fpr,
			"--output", filepath.Join(g.dir, "sig.asc"), "--detach-sign", g.write("content", content))
		p, err := signedEntity(content, crlf(g.read("sig.asc")), "pgp-sha256")
		if err != nil {
			t.Fatal(err)
		}
		m.Body = p
		res, err := Verify(context.Background(), render(t, m), NewMemStore(alice))
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if res.Signature != SignatureValid || res.Signer.Fingerprint() != fpr || !bytes.Equal(res.Entity, content) {
			t.Errorf("%s: result = %v %v", kind, res.Signature, res.Signer)
		}
	}
}

// TestInteropWeDecryptGPGMessage: gpg signs, compresses and encrypts to a
// GnuPG-generated, passphrase-protected key; we unlock it and decrypt.
func TestInteropWeDecryptGPGMessage(t *testing.T) {
	for _, kind := range gpgKinds {
		g := newGPG(t)
		aliceFpr := g.genKey("Alice <alice@example.com>", kind, "")
		bobFpr := g.genKey("Bob <bob@example.com>", kind, "correct horse")
		alice := g.export(aliceFpr, false, "")
		bob := g.export(bobFpr, true, "correct horse")
		if !bob.Locked() {
			t.Fatal("exported secret key should be passphrase protected")
		}
		if err := bob.Unlock([]byte("correct horse")); err != nil {
			t.Fatal(err)
		}
		m := testMessage()
		ent, err := m.Entity()
		if err != nil {
			t.Fatal(err)
		}
		content := ent.Bytes()
		g.run(nil, "--armor", "--sign", "--encrypt", "--local-user", aliceFpr,
			"--recipient", bobFpr, "--output", filepath.Join(g.dir, "enc.asc"), g.write("content", content))
		p, err := encryptedEntity(crlf(g.read("enc.asc")))
		if err != nil {
			t.Fatal(err)
		}
		msg := email.Message{From: m.From, To: m.To, Subject: m.Subject, Body: p}
		res, err := Decrypt(context.Background(), render(t, msg), bob, NewMemStore(alice))
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if res.Signature != SignatureValid || res.Signer.Fingerprint() != aliceFpr || !bytes.Equal(res.Entity, content) {
			t.Errorf("%s: result = %v %v", kind, res.Signature, res.Signer)
		}
	}
}

// rsaKey returns a cached RSA-3072 private key for rita@example.com.
func rsaKey(t testing.TB) *Key {
	t.Helper()
	keyCacheMu.Lock()
	defer keyCacheMu.Unlock()
	if k, ok := keyCache["rsa"]; ok {
		return k
	}
	e, err := openpgp.NewEntity("Rita", "", "rita@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoRSA, RSABits: 3072})
	if err != nil {
		t.Fatal(err)
	}
	k := &Key{e: e}
	keyCache["rsa"] = k
	return k
}
