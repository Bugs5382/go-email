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
	"fmt"
	"net/mail"
	"time"
)

// SendFunc sends a single Message. It is the terminal operation that a
// Middleware chain wraps: the innermost SendFunc typically delegates to a
// Transport, while each Middleware layer adds a cross-cutting concern
// (validation, retries, auditing, and so on) around it.
type SendFunc func(ctx context.Context, m *Message) error

// Middleware wraps a SendFunc with additional behavior, returning a new
// SendFunc that runs that behavior around a call to next.
type Middleware func(next SendFunc) SendFunc

// chain composes base with mws into a single SendFunc. mws are applied so
// that mws[0] is outermost: the returned SendFunc runs mws[0]'s logic first,
// which calls into mws[1], and so on, until base runs last.
func chain(base SendFunc, mws ...Middleware) SendFunc {
	send := base
	for i := len(mws) - 1; i >= 0; i-- {
		send = mws[i](send)
	}
	return send
}

// ErrValidation is returned (wrapped) by Validate when a Message fails
// envelope validation. Callers can test for it with errors.Is.
var ErrValidation = errors.New("email: message failed validation")

// TransientError marks an error as transient: safe to retry. Transports and
// other middleware should wrap retryable failures (e.g. temporary network or
// SMTP 4xx errors) in a TransientError so that Retry knows to act on them.
type TransientError struct {
	Err error
}

// Error implements the error interface.
func (e TransientError) Error() string {
	return e.Err.Error()
}

// Unwrap allows errors.Is/errors.As to see through to the wrapped error.
func (e TransientError) Unwrap() error {
	return e.Err
}

// Validate returns a Middleware that rejects a Message before it reaches the
// next stage unless: From is a syntactically valid address, there is at
// least one recipient (To ∪ Cc ∪ Bcc), and every recipient address is
// syntactically valid. Failures are reported as ErrValidation (wrapped with
// details via errors.Is-compatible wrapping).
func Validate() Middleware {
	return func(next SendFunc) SendFunc {
		return func(ctx context.Context, m *Message) error {
			if _, err := mail.ParseAddress(m.From); err != nil {
				return fmt.Errorf("%w: from %q: %v", ErrValidation, m.From, err)
			}
			recipients := m.Recipients()
			if len(recipients) == 0 {
				return fmt.Errorf("%w: no recipients", ErrValidation)
			}
			for _, addr := range recipients {
				if _, err := mail.ParseAddress(addr); err != nil {
					return fmt.Errorf("%w: recipient %q: %v", ErrValidation, addr, err)
				}
			}
			return next(ctx, m)
		}
	}
}

// Retry returns a Middleware that retries next up to attempts times when it
// fails with a TransientError, using exponential backoff starting at base
// (base, base*2, base*4, ...) between attempts. Non-transient errors are
// returned immediately without retrying. The wait between attempts honors
// ctx cancellation.
func Retry(attempts int, base time.Duration) Middleware {
	return func(next SendFunc) SendFunc {
		return func(ctx context.Context, m *Message) error {
			var err error
			for i := 0; i < attempts; i++ {
				err = next(ctx, m)
				if err == nil {
					return nil
				}
				var transient TransientError
				if !errors.As(err, &transient) {
					return err
				}
				if i == attempts-1 {
					break
				}
				wait := base * time.Duration(1<<uint(i))
				timer := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
			}
			return err
		}
	}
}
