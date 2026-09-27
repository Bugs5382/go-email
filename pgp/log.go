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
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	log "github.com/Bugs5382/go-log"
)

// nopLogger discards everything. It is the default, so the package is
// silent unless the caller passes WithLogger.
type nopLogger struct{}

func (nopLogger) Debug(string, ...log.Field)        {}
func (nopLogger) Info(string, ...log.Field)         {}
func (nopLogger) Warn(string, ...log.Field)         {}
func (nopLogger) Error(error, string, ...log.Field) {}
func (nopLogger) Fatal(error, string, ...log.Field) {}
func (n nopLogger) With(...log.Field) log.Logger    { return n }
func (n nopLogger) Ctx(context.Context) log.Logger  { return n }

// addrKey keys the address hash. It is random per process, so a logged
// address ID correlates lines within one run but cannot be looked up or
// brute-forced from the logs.
var addrKey = func() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("pgp: reading random bytes: " + err.Error())
	}
	return k
}()

// addrID returns an opaque ID for an email address, safe to log.
func addrID(addr string) string {
	m := hmac.New(sha256.New, addrKey)
	m.Write([]byte(addr))
	return hex.EncodeToString(m.Sum(nil)[:8])
}

// addrIDs maps addrID over addrs.
func addrIDs(addrs []string) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = addrID(a)
	}
	return out
}

// fingerprints returns the fingerprints of keys, for logging.
func fingerprints(keys []*Key) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.Fingerprint()
	}
	return out
}

// since returns the milliseconds elapsed since start, for a duration field.
func since(start time.Time) log.Field {
	return log.F("duration_ms", float64(time.Since(start).Microseconds())/1000)
}
