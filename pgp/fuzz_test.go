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
	"testing"
	"time"
)

// The fuzz targets cover every parser this package runs on untrusted
// input. Their seeds run in every "go test"; run one for longer with
// "go test -run '^$' -fuzz FuzzDecrypt -fuzztime 60s ./pgp/".

func FuzzReadArmoredKeys(f *testing.F) {
	armored, err := testKey(f, "Alice", "alice@example.com").ArmoredPublic()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(armored)
	f.Add([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n-----END PGP PUBLIC KEY BLOCK-----\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		keys, err := ReadArmoredKeys(bytes.NewReader(b))
		if err == nil && len(keys) == 0 {
			t.Fatal("no error and no keys")
		}
		for _, k := range keys {
			_ = k.Fingerprint()
			_ = k.Emails()
		}
		_, _ = ReadKeys(bytes.NewReader(b))
	})
}

// fuzzSeeds returns a signed message, an encrypted one, a signed and
// encrypted one, and a plain one.
func fuzzSeeds(f *testing.F) [][]byte {
	alice := testKey(f, "Alice", "alice@example.com")
	bob := testKey(f, "Bob", "bob@example.com")
	s, err := NewSigner(alice)
	if err != nil {
		f.Fatal(err)
	}
	signed := testMessage()
	if err := s.Sign(context.Background(), &signed); err != nil {
		f.Fatal(err)
	}
	mw, err := SignEncrypt(alice, NewMemStore(publicOnly(f, bob)))
	if err != nil {
		f.Fatal(err)
	}
	var out sink
	if err := mw(out.send)(context.Background(), new(testMessage())); err != nil {
		f.Fatal(err)
	}
	enc, _ := NewEncryptor(NewMemStore(publicOnly(f, bob)))
	encOnly := testMessage()
	if err := enc.Encrypt(context.Background(), &encOnly); err != nil {
		f.Fatal(err)
	}
	return [][]byte{render(f, signed), render(f, out.msgs[0]), render(f, encOnly), render(f, testMessage())}
}

// FuzzVerify checks that Verify never panics and only reports a valid
// signature when it has a signer.
func FuzzVerify(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		f.Add(s)
	}
	store := NewMemStore(publicOnly(f, testKey(f, "Alice", "alice@example.com")))
	f.Fuzz(func(t *testing.T, raw []byte) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, err := Verify(ctx, raw, store)
		if err == nil && (res == nil || res.Signer == nil || res.Signature != SignatureValid) {
			t.Fatalf("success without a valid signer: %+v", res)
		}
		if err != nil && res != nil {
			t.Fatal("result returned with an error")
		}
	})
}

// FuzzDecrypt checks that Decrypt never panics and never returns plaintext
// together with an error.
func FuzzDecrypt(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		f.Add(s)
	}
	bob := testKey(f, "Bob", "bob@example.com")
	store := NewMemStore(publicOnly(f, testKey(f, "Alice", "alice@example.com")))
	f.Fuzz(func(t *testing.T, raw []byte) {
		res, err := Decrypt(context.Background(), raw, bob, store, WithMaxSize(1<<20))
		if err != nil && res != nil {
			t.Fatal("result returned with an error")
		}
		if err == nil && (!res.Encrypted || res.Signature == SignatureValid && res.Signer == nil) {
			t.Fatalf("inconsistent result: %+v", res)
		}
	})
}
