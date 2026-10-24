package smtp

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
	"net"
	"net/smtp"
	"sync"
	"time"

	email "github.com/Bugs5382/go-email"
)

// limit resolves a Config duration: zero means def, negative means no limit
// (returned as zero).
func limit(v, def time.Duration) time.Duration {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	}
	return v
}

// dial connects to addr within the DialTimeout and returns a client whose
// every read and write is bounded by Timeout and by ctx. A dial that times
// out on its own (not because ctx ended) is an email.TransientError: nothing
// reached the server, so a retry is safe.
func (t *SMTPTransport) dial(ctx context.Context, addr string) (*smtp.Client, error) {
	d := net.Dialer{Timeout: limit(t.cfg.DialTimeout, DefaultDialTimeout)}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctxErr := ended(ctx); ctxErr != nil {
			return nil, fmt.Errorf("%w: %w", ctxErr, err)
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, email.TransientError{Err: err}
		}
		return nil, err
	}

	conn := &deadlineConn{Conn: raw, ctx: ctx, timeout: limit(t.cfg.Timeout, DefaultTimeout)}
	conn.stop = context.AfterFunc(ctx, conn.cancel)

	client, err := smtp.NewClient(conn, t.cfg.Host)
	if err != nil {
		// NewClient closes conn when the greeting fails.
		return nil, err
	}
	return client, nil
}

// deadlineConn sets a fresh deadline before every Read and Write: Timeout
// from now, or ctx's deadline if that comes first. When ctx ends it pushes
// the deadline into the past, which unblocks any read or write in flight,
// and from then on every call fails with ctx's error.
type deadlineConn struct {
	net.Conn
	ctx     context.Context
	timeout time.Duration
	stop    func() bool

	mu        sync.Mutex
	cancelled bool
}

func (c *deadlineConn) cancel() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cancelled = true
	_ = c.SetDeadline(time.Now())
}

// arm sets the deadline for the next operation, or reports that ctx already
// ended. Holding mu while setting it means cancel can't be overwritten by a
// deadline set just after it ran.
func (c *deadlineConn) arm(set func(time.Time) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancelled {
		return c.ctx.Err()
	}
	var deadline time.Time
	if c.timeout > 0 {
		deadline = time.Now().Add(c.timeout)
	}
	if d, ok := c.ctx.Deadline(); ok && (deadline.IsZero() || d.Before(deadline)) {
		deadline = d
	}
	return set(deadline)
}

// wrap attaches ctx's error to a failure that happened once ctx had ended
// (cancelled, or its deadline used as the connection deadline), so callers
// can match it with errors.Is(err, context.Canceled) or
// context.DeadlineExceeded.
func (c *deadlineConn) wrap(err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ended(c.ctx); ctxErr != nil {
		return fmt.Errorf("%w: %w", ctxErr, err)
	}
	return err
}

// ended returns ctx's error once it is done, or context.DeadlineExceeded
// once its deadline has passed: a connection deadline taken from ctx can
// fire a moment before ctx's own timer marks it done.
func ended(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d, ok := ctx.Deadline(); ok && !time.Now().Before(d) {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *deadlineConn) Read(p []byte) (int, error) {
	if err := c.arm(c.SetReadDeadline); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	return n, c.wrap(err)
}

func (c *deadlineConn) Write(p []byte) (int, error) {
	if err := c.arm(c.SetWriteDeadline); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(p)
	return n, c.wrap(err)
}

// Close releases the ctx watcher along with the connection, so a long-lived
// ctx shared by many sends doesn't collect one watcher per send.
func (c *deadlineConn) Close() error {
	c.stop()
	return c.Conn.Close()
}
