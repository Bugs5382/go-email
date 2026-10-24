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
	"errors"
	"net/textproto"

	email "github.com/Bugs5382/go-email"
)

// acceptedError marks a failure that happened after the relay accepted the
// message (QUIT). The mail is already queued, so it is never treated as
// transient: a retry would deliver it twice.
type acceptedError struct {
	err error
}

func (e acceptedError) Error() string { return e.err.Error() }

func (e acceptedError) Unwrap() error { return e.err }

// classify wraps err in email.TransientError when the relay answered with a
// 4xx reply (RFC 5321 4.2.1: a transient negative completion, such as 421,
// 450, 451, 452 or 454), so email.Retry retries it. 5xx replies, local and
// network errors, and anything after the message was accepted are returned
// unchanged. The *textproto.Error stays reachable with errors.As either way.
func classify(err error) error {
	if err == nil {
		return nil
	}
	var accepted acceptedError
	if errors.As(err, &accepted) {
		return err
	}
	var reply *textproto.Error
	if errors.As(err, &reply) && reply.Code >= 400 && reply.Code < 500 {
		return email.TransientError{Err: err}
	}
	return err
}
