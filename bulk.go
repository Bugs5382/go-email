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
	"time"
)

// Recipient is one target of a bulk send: an address plus the data a
// Renderer resolves into that recipient's Subject/HTML/Text body.
type Recipient struct {
	Address string
	Data    any
}

// BulkResult tallies the outcome of a SendBulk call: how many recipients
// were actually sent to, how many were skipped (e.g. suppressed), how many
// failed, and the per-address error for each failure.
type BulkResult struct {
	Sent, Skipped, Failed int
	Errors                map[string]error
}

// bulkConfig holds the settings assembled from a SendBulk call's BulkOptions.
type bulkConfig struct {
	throttle               time.Duration
	listUnsubscribe        string
	listUnsubscribePost    string
	setListUnsubscribe     bool
	setListUnsubscribePost bool
}

// BulkOption configures a SendBulk call.
type BulkOption func(*bulkConfig)

// WithThrottle paces a bulk send by waiting rate between each recipient's
// send. A non-positive rate disables throttling (the default).
func WithThrottle(rate time.Duration) BulkOption {
	return func(c *bulkConfig) {
		c.throttle = rate
	}
}

// WithListUnsubscribe sets the List-Unsubscribe and List-Unsubscribe-Post
// header values applied to every recipient's Message in a bulk send.
func WithListUnsubscribe(url, post string) BulkOption {
	return func(c *bulkConfig) {
		c.listUnsubscribe = url
		c.setListUnsubscribe = true
		c.listUnsubscribePost = post
		c.setListUnsubscribePost = true
	}
}

// SendBulk implements Sender: it renders kind and each recipient's Data into
// its own copy of base (To set to that single recipient), applies any
// List-Unsubscribe headers from opts, and sends it through the same
// middleware chain Send uses -- so Suppress, Dedupe, and Record all still
// apply per recipient. A failure or suppression on one recipient never
// aborts the rest of the batch.
func (s *sender) SendBulk(ctx context.Context, kind string, base Message, recipients []Recipient, opts ...BulkOption) (BulkResult, error) {
	if s.renderer == nil {
		return BulkResult{}, ErrNoRenderer
	}
	cfg := &bulkConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	result := BulkResult{Errors: make(map[string]error)}
	for i, rcpt := range recipients {
		rendered, err := s.renderer.Render(ctx, kind, rcpt.Data)
		if err != nil {
			result.Failed++
			result.Errors[rcpt.Address] = err
			continue
		}

		m := base
		m.To = []string{rcpt.Address}
		m.Subject, m.HTML, m.Text = rendered.Subject, rendered.HTML, rendered.Text
		if cfg.setListUnsubscribe {
			m.ListUnsubscribe = cfg.listUnsubscribe
		}
		if cfg.setListUnsubscribePost {
			m.ListUnsubscribePost = cfg.listUnsubscribePost
		}

		sendErr := s.send(ctx, &m)
		switch {
		case sendErr != nil:
			result.Failed++
			result.Errors[rcpt.Address] = sendErr
		case len(m.To) == 0:
			// A middleware (e.g. Suppress) removed the only recipient
			// before delivery: nothing was actually sent.
			result.Skipped++
		default:
			result.Sent++
		}

		if cfg.throttle > 0 && i < len(recipients)-1 {
			timer := time.NewTimer(cfg.throttle)
			select {
			case <-ctx.Done():
				timer.Stop()
				return result, ctx.Err()
			case <-timer.C:
			}
		}
	}
	return result, nil
}
