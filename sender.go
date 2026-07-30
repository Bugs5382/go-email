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
)

// Sender is the top-level entry point for delivering mail: it runs a Message
// through the configured middleware chain to a Transport, optionally
// resolving its content from a named kind via a Renderer first.
type Sender interface {
	// Send runs m through the middleware chain and delivers it via the
	// underlying Transport.
	Send(ctx context.Context, m Message) error
	// SendKind resolves kind and data via the configured Renderer into a
	// Subject/HTML/Text body, applies it to a copy of m, and sends that
	// copy via Send.
	SendKind(ctx context.Context, kind string, m Message, data any) error
}

// Option configures a Sender built by New.
type Option func(*sender)

// WithMiddleware appends mws, in order, to the Sender's middleware chain.
// mws[0] runs outermost (first), mirroring chain's semantics.
func WithMiddleware(mws ...Middleware) Option {
	return func(s *sender) {
		s.mws = append(s.mws, mws...)
	}
}

// WithRenderer sets the Renderer that SendKind uses to resolve a kind and
// data into a Message body. Without it, SendKind returns an error.
func WithRenderer(r Renderer) Option {
	return func(s *sender) {
		s.renderer = r
	}
}

// sender is the default Sender implementation: a Transport wrapped by a
// middleware chain, plus an optional Renderer for SendKind.
type sender struct {
	transport Transport
	mws       []Middleware
	renderer  Renderer
	send      SendFunc
}

// New builds a Sender that delivers via t, running every Message through the
// middleware chain assembled from opts (outermost first) before t.Send sees
// it.
func New(t Transport, opts ...Option) Sender {
	s := &sender{transport: t}
	for _, opt := range opts {
		opt(s)
	}
	base := SendFunc(func(ctx context.Context, m *Message) error {
		return t.Send(ctx, *m)
	})
	s.send = chain(base, s.mws...)
	return s
}

// Send implements Sender.
func (s *sender) Send(ctx context.Context, m Message) error {
	return s.send(ctx, &m)
}

// ErrNoRenderer is returned by SendKind when the Sender was built without
// WithRenderer.
var ErrNoRenderer = errors.New("email: SendKind requires a Renderer (see WithRenderer)")

// SendKind implements Sender.
func (s *sender) SendKind(ctx context.Context, kind string, m Message, data any) error {
	if s.renderer == nil {
		return ErrNoRenderer
	}
	rendered, err := s.renderer.Render(ctx, kind, data)
	if err != nil {
		return err
	}
	out := m
	out.Subject = rendered.Subject
	out.HTML = rendered.HTML
	out.Text = rendered.Text
	return s.Send(ctx, out)
}
