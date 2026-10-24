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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/textproto"
	"time"

	email "github.com/Bugs5382/go-email"
	log "github.com/Bugs5382/go-log"
)

// logKey keys the recipient hash. It is random per process, so a logged
// rcpt_id correlates lines within one run but cannot be looked up or
// brute-forced from the logs.
var logKey = func() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("smtp: reading random bytes: " + err.Error())
	}
	return k
}()

// rcptID returns an opaque ID for a recipient address, safe to log.
func rcptID(addr string) string {
	m := hmac.New(sha256.New, logKey)
	m.Write([]byte(addr))
	return hex.EncodeToString(m.Sum(nil)[:8])
}

// newSendID returns a random ID that ties together the lines of one send.
func newSendID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// logger returns the configured Logger, or a no-op one when it is nil.
func (t *SMTPTransport) logger() log.Logger {
	if t.cfg.Logger == nil {
		return log.Nop()
	}
	return t.cfg.Logger
}

// session tracks one send for logging: the stage it reached and the raw
// error that stage returned, before deliver wraps it. The wrapped error can
// carry a recipient address, so only the raw cause is ever logged.
type session struct {
	log    log.Logger
	stage  string
	cause  error
	rcptID string
}

// step runs fn as stage, tracing how long it took when it succeeds and
// recording the stage and its error when it fails.
func (s *session) step(stage string, fn func() error) error {
	s.stage = stage
	start := time.Now()
	if err := fn(); err != nil {
		s.cause = err
		return err
	}
	log.Trace(s.log, "smtp stage done", log.F("stage", stage), log.F("elapsed_ms", time.Since(start).Milliseconds()))
	return nil
}

// loggable returns an error safe to log for a failed send. A server reply is
// reduced to its code, because the reply text often echoes the address; any
// other failure is the stage's raw cause (a network, TLS or context error).
func (s *session) loggable(err error) error {
	var reply *textproto.Error
	if errors.As(err, &reply) {
		return fmt.Errorf("smtp %s: server replied %d", s.stage, reply.Code)
	}
	if s.cause != nil {
		return s.cause
	}
	return err
}

// finish logs the outcome of a send that started at start.
func (s *session) finish(ctx context.Context, err error, start time.Time) {
	took := log.F("duration_ms", time.Since(start).Milliseconds())
	if err == nil {
		s.log.Info("smtp send delivered", log.F("outcome", "delivered"), took)
		return
	}

	var transient email.TransientError
	fields := []log.Field{took, log.F("stage", s.stage), log.F("transient", errors.As(err, &transient))}
	var reply *textproto.Error
	if errors.As(err, &reply) {
		fields = append(fields, log.F("reply_code", reply.Code))
	}
	if s.rcptID != "" {
		fields = append(fields, log.F("rcpt_id", s.rcptID))
	}
	logged := s.loggable(err)

	var accepted acceptedError
	switch {
	case ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)):
		s.log.Warn("smtp send ended by context", append(fields, log.F("outcome", "cancelled"), log.F("error", logged.Error()))...)
	case errors.As(err, &accepted):
		s.log.Warn("smtp send accepted, quit failed", append(fields, log.F("outcome", "accepted"), log.F("error", logged.Error()))...)
	case errors.As(err, &transient):
		s.log.Warn("smtp send failed", append(fields, log.F("outcome", "transient"), log.F("error", logged.Error()))...)
	default:
		s.log.Error(logged, "smtp send failed", append(fields, log.F("outcome", "failed"))...)
	}
}
