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
	"fmt"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// KeyStore looks up candidate public keys for an email address. A store
// returns candidates only: the Encryptor and Verify check every key's
// validity, strength and user ID before using it, so a store never has to.
type KeyStore interface {
	// Keys returns the candidate keys for addr. addr may be a bare
	// address or a "Name <addr>" form; stores should match it
	// case-insensitively. No match is an empty result, not an error.
	Keys(ctx context.Context, addr string) ([]*Key, error)
}

// KeyStoreFunc adapts a function to a KeyStore.
type KeyStoreFunc func(ctx context.Context, addr string) ([]*Key, error)

// Keys implements KeyStore.
func (f KeyStoreFunc) Keys(ctx context.Context, addr string) ([]*Key, error) { return f(ctx, addr) }

// normalizeAddr returns the lower-cased bare address of addr, which may be
// in "Name <addr>" form. It returns "" when addr cannot be parsed.
func normalizeAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if a, err := mail.ParseAddress(addr); err == nil {
		return strings.ToLower(a.Address)
	}
	if strings.Count(addr, "@") == 1 && !strings.ContainsAny(addr, " <>\t\r\n") {
		return strings.ToLower(addr)
	}
	return ""
}

// MemStore is an in-memory KeyStore indexed by the keys' user ID emails.
// It is safe for concurrent use.
type MemStore struct {
	mu     sync.RWMutex
	byAddr map[string][]*Key
}

// NewMemStore returns a MemStore holding keys.
func NewMemStore(keys ...*Key) *MemStore {
	s := &MemStore{byAddr: map[string][]*Key{}}
	s.Add(keys...)
	return s
}

// Add indexes keys under each of their user ID emails. Adding a key whose
// fingerprint is already stored for an address is a no-op.
func (s *MemStore) Add(keys ...*Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range keys {
		if k == nil || k.e == nil {
			continue
		}
		fp := k.Fingerprint()
		for _, addr := range k.Emails() {
			if slices.ContainsFunc(s.byAddr[addr], func(o *Key) bool { return o.Fingerprint() == fp }) {
				continue
			}
			s.byAddr[addr] = append(s.byAddr[addr], k)
		}
	}
}

// Keys implements KeyStore.
func (s *MemStore) Keys(_ context.Context, addr string) ([]*Key, error) {
	a := normalizeAddr(addr)
	if a == "" {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.byAddr[a]), nil
}

// LoadDir reads every key file directly in dir into a new MemStore. Files
// ending in .asc, .gpg, .pgp or .key are read; armored and binary data are
// both accepted, whatever the extension. Other files and subdirectories
// are skipped. It fails, naming the file, on the first file that cannot be
// read or holds no key. The directory is read once and not watched.
func LoadDir(dir string) (*MemStore, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("pgp: reading key directory: %w", err)
	}
	s := NewMemStore()
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(ent.Name())) {
		case ".asc", ".gpg", ".pgp", ".key":
		default:
			continue
		}
		keys, err := readKeyFile(filepath.Join(dir, ent.Name()))
		if err != nil {
			return nil, fmt.Errorf("pgp: %s: %w", ent.Name(), err)
		}
		s.Add(keys...)
	}
	return s, nil
}

func readKeyFile(name string) ([]*Key, error) {
	f, err := os.Open(name) //nolint:gosec // the caller chose the directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxKeyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxKeyBytes {
		return nil, fmt.Errorf("key file larger than %d bytes", maxKeyBytes)
	}
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte("-----BEGIN ")) {
		return ReadArmoredKeys(bytes.NewReader(b))
	}
	return ReadKeys(bytes.NewReader(b))
}

// Chain returns a KeyStore that asks each store in order and returns the
// first non-empty result. A store error stops the lookup and is returned,
// so a failing store never silently falls through to a later one.
func Chain(stores ...KeyStore) KeyStore {
	return KeyStoreFunc(func(ctx context.Context, addr string) ([]*Key, error) {
		for i, s := range stores {
			if s == nil {
				continue
			}
			keys, err := s.Keys(ctx, addr)
			if err != nil {
				return nil, fmt.Errorf("pgp: key store %d: %w", i, err)
			}
			if len(keys) > 0 {
				return keys, nil
			}
		}
		return nil, nil
	})
}
