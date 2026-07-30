package email

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
	"context"
	"errors"
	"sync"
)

// ErrSuppressed is returned by the Suppress middleware when every recipient
// (To ∪ Cc ∪ Bcc) has been filtered out as suppressed, so there is no one
// left to send to. Suppress returns it in place of calling next, giving
// callers (e.g. SendBulk) a distinguishable, explicit outcome instead of
// having to infer a skip from an emptied recipient list.
var ErrSuppressed = errors.New("email: all recipients suppressed")

// Deduper decides whether a Message identified by an opaque dedup key has
// already been sent, and records that a key has now been sent. Consumers
// derive the key however they see fit (e.g. a template name plus recipient)
// and place it in Message.Meta["dedup_key"].
type Deduper interface {
	// Seen reports whether key has already been marked as sent.
	Seen(ctx context.Context, key string) (bool, error)
	// Mark records key as sent.
	Mark(ctx context.Context, key string) error
}

// Recorder observes the outcome of every send attempt, whether it succeeded
// or failed. It is typically used for audit trails or delivery logs.
type Recorder interface {
	Record(ctx context.Context, m *Message, sendErr error) error
}

// Suppressor decides whether a given address must never receive mail (e.g. a
// bounce or unsubscribe list).
type Suppressor interface {
	Suppressed(ctx context.Context, addr string) (bool, error)
}

// Signer applies a message signature (e.g. DKIM) to m before it is sent.
type Signer interface {
	Sign(ctx context.Context, m *Message) error
}

// Encryptor encrypts m (or parts of it) before it is sent.
type Encryptor interface {
	Encrypt(ctx context.Context, m *Message) error
}

// recorderFunc adapts a plain function to a Recorder, mirroring the
// http.HandlerFunc idiom so tests and simple callers can supply a Recorder
// without declaring a named type.
type recorderFunc func(ctx context.Context, m *Message, sendErr error) error

// Record implements Recorder.
func (f recorderFunc) Record(ctx context.Context, m *Message, sendErr error) error {
	return f(ctx, m, sendErr)
}

// suppressorFunc adapts a plain function to a Suppressor.
type suppressorFunc func(ctx context.Context, addr string) (bool, error)

// Suppressed implements Suppressor.
func (f suppressorFunc) Suppressed(ctx context.Context, addr string) (bool, error) {
	return f(ctx, addr)
}

// signerFunc adapts a plain function to a Signer.
type signerFunc func(ctx context.Context, m *Message) error

// Sign implements Signer.
func (f signerFunc) Sign(ctx context.Context, m *Message) error {
	return f(ctx, m)
}

// encryptorFunc adapts a plain function to an Encryptor.
type encryptorFunc func(ctx context.Context, m *Message) error

// Encrypt implements Encryptor.
func (f encryptorFunc) Encrypt(ctx context.Context, m *Message) error {
	return f(ctx, m)
}

// dedupKey reads the dedup key from m.Meta["dedup_key"], returning ok=false
// if it is absent or not a non-empty string. Messages without a dedup key
// are never deduplicated.
func dedupKey(m *Message) (string, bool) {
	if m == nil || m.Meta == nil {
		return "", false
	}
	key, ok := m.Meta["dedup_key"].(string)
	if !ok || key == "" {
		return "", false
	}
	return key, true
}

// isResend reports whether m.Meta requests a resend, bypassing dedupe.
func isResend(m *Message) bool {
	if m == nil || m.Meta == nil {
		return false
	}
	resend, _ := m.Meta["resend"].(bool)
	return resend
}

// Dedupe returns a Middleware that skips sending a Message whose
// Meta["dedup_key"] has already been marked as seen by d, unless
// Meta["resend"] is true. Messages without a dedup key always send. On a
// successful send, the key is marked so future attempts are deduplicated.
func Dedupe(d Deduper) Middleware {
	return func(next SendFunc) SendFunc {
		return func(ctx context.Context, m *Message) error {
			key, ok := dedupKey(m)
			if !ok {
				return next(ctx, m)
			}
			if !isResend(m) {
				seen, err := d.Seen(ctx, key)
				if err != nil {
					return err
				}
				if seen {
					return nil
				}
			}
			if err := next(ctx, m); err != nil {
				return err
			}
			return d.Mark(ctx, key)
		}
	}
}

// Record returns a Middleware that calls next and then reports the outcome
// (nil or non-nil) to r, including failures. The original send error (if
// any) is always returned to the caller, regardless of what r.Record
// returns.
func Record(r Recorder) Middleware {
	return func(next SendFunc) SendFunc {
		return func(ctx context.Context, m *Message) error {
			sendErr := next(ctx, m)
			_ = r.Record(ctx, m, sendErr)
			return sendErr
		}
	}
}

// Suppress returns a Middleware that removes addresses reported as
// suppressed by s from To, Cc, and Bcc before calling next. It is typically
// placed ahead of bulk sends to honor bounce or unsubscribe lists. If
// filtering leaves no recipient at all, it returns ErrSuppressed without
// calling next, rather than attempting a send with zero recipients.
func Suppress(s Suppressor) Middleware {
	filter := func(ctx context.Context, addrs []string) ([]string, error) {
		if len(addrs) == 0 {
			return addrs, nil
		}
		out := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			suppressed, err := s.Suppressed(ctx, addr)
			if err != nil {
				return nil, err
			}
			if !suppressed {
				out = append(out, addr)
			}
		}
		return out, nil
	}
	return func(next SendFunc) SendFunc {
		return func(ctx context.Context, m *Message) error {
			to, err := filter(ctx, m.To)
			if err != nil {
				return err
			}
			cc, err := filter(ctx, m.Cc)
			if err != nil {
				return err
			}
			bcc, err := filter(ctx, m.Bcc)
			if err != nil {
				return err
			}
			m.To, m.Cc, m.Bcc = to, cc, bcc
			if len(to)+len(cc)+len(bcc) == 0 {
				return ErrSuppressed
			}
			return next(ctx, m)
		}
	}
}

// Sign returns a Middleware that calls s.Sign on m before next. If s is nil,
// the returned Middleware is the identity: it calls next unchanged.
func Sign(s Signer) Middleware {
	return func(next SendFunc) SendFunc {
		return func(ctx context.Context, m *Message) error {
			if s == nil {
				return next(ctx, m)
			}
			if err := s.Sign(ctx, m); err != nil {
				return err
			}
			return next(ctx, m)
		}
	}
}

// Encrypt returns a Middleware that calls e.Encrypt on m before next. If e is
// nil, the returned Middleware is the identity: it calls next unchanged.
func Encrypt(e Encryptor) Middleware {
	return func(next SendFunc) SendFunc {
		return func(ctx context.Context, m *Message) error {
			if e == nil {
				return next(ctx, m)
			}
			if err := e.Encrypt(ctx, m); err != nil {
				return err
			}
			return next(ctx, m)
		}
	}
}

// NopDeduper is a Deduper that never remembers anything: every key is
// reported as unseen, and Mark is a no-op. It is the zero-value default for
// consumers that do not need deduplication.
type NopDeduper struct{}

// Seen always reports false.
func (NopDeduper) Seen(context.Context, string) (bool, error) { return false, nil }

// Mark is a no-op.
func (NopDeduper) Mark(context.Context, string) error { return nil }

// NopRecorder is a Recorder that discards every outcome. It is the zero-value
// default for consumers that do not need send auditing.
type NopRecorder struct{}

// Record is a no-op.
func (NopRecorder) Record(context.Context, *Message, error) error { return nil }

// NopSuppressor is a Suppressor that never suppresses any address. It is the
// zero-value default for consumers that do not maintain a suppression list.
type NopSuppressor struct{}

// Suppressed always reports false.
func (NopSuppressor) Suppressed(context.Context, string) (bool, error) { return false, nil }

// MemDeduper is an in-memory, mutex-guarded Deduper suitable for a single
// process or for tests. It does not persist across restarts and does not
// coordinate across processes; long-lived or multi-process deployments
// should supply their own Deduper backed by shared storage.
type MemDeduper struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

// NewMemDeduper returns a ready-to-use MemDeduper.
func NewMemDeduper() *MemDeduper {
	return &MemDeduper{seen: make(map[string]struct{})}
}

// Seen implements Deduper.
func (d *MemDeduper) Seen(_ context.Context, key string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.seen[key]
	return ok, nil
}

// Mark implements Deduper.
func (d *MemDeduper) Mark(_ context.Context, key string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen[key] = struct{}{}
	return nil
}
