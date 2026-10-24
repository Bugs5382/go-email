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
	"os"
	"strconv"
	"time"
)

// Default limits applied when Config.DialTimeout or Config.Timeout is zero.
// DefaultTimeout follows the five-minute command timeout RFC 5321 4.5.3.2
// suggests for SMTP clients, so a slow but working relay is not cut off.
const (
	DefaultDialTimeout = 30 * time.Second
	DefaultTimeout     = 5 * time.Minute
)

// Config is the resolved SMTP configuration consumed by SMTPTransport. Build
// it with LoadConfig, which reads SMTP_* from the environment with
// maildev-friendly defaults, or construct it directly.
type Config struct {
	Host string // SMTP_HOST (default "localhost")
	Port int    // SMTP_PORT (default 1025)
	User string // SMTP_USER (default "" -- a local catcher like maildev needs no auth)
	Pass string // SMTP_PASS (default "")
	From string // SMTP_FROM (default "no-reply@example.com")
	TLS  bool   // SMTP_TLS (default false, matching a plaintext local catcher)
	// TLSInsecure skips STARTTLS certificate verification (SMTP_TLS_INSECURE,
	// default false). The connection is still encrypted, just not
	// cert-verified. Only set true for a trusted relay with a non-standard
	// certificate.
	TLSInsecure bool
	// DialTimeout bounds how long connecting to the server may take
	// (SMTP_DIAL_TIMEOUT, default DefaultDialTimeout). Zero means the
	// default; a negative value means no limit. A dial that times out is
	// returned as an email.TransientError, since nothing was sent.
	DialTimeout time.Duration
	// Timeout bounds how long any single read or write on the connection may
	// block, from the greeting through QUIT (SMTP_TIMEOUT, default
	// DefaultTimeout). It is an idle limit, not a limit on the whole send: a
	// large message keeps going as long as the server keeps reading. Zero
	// means the default; a negative value means no limit.
	Timeout time.Duration
}

// LoadConfig reads SMTP_* env vars with local-catcher (e.g. maildev) defaults:
// host localhost, port 1025, no user/pass, From no-reply@example.com, no TLS,
// and the DefaultDialTimeout and DefaultTimeout limits. SMTP_DIAL_TIMEOUT and
// SMTP_TIMEOUT take Go duration strings such as "10s" or "2m"; a value that
// does not parse falls back to the default.
func LoadConfig() Config {
	return Config{
		Host:        getOr("SMTP_HOST", "localhost"),
		Port:        getIntOr("SMTP_PORT", 1025),
		User:        os.Getenv("SMTP_USER"),
		Pass:        os.Getenv("SMTP_PASS"),
		From:        getOr("SMTP_FROM", "no-reply@example.com"),
		TLS:         getBoolOr("SMTP_TLS", false),
		TLSInsecure: getBoolOr("SMTP_TLS_INSECURE", false),
		DialTimeout: getDurationOr("SMTP_DIAL_TIMEOUT", DefaultDialTimeout),
		Timeout:     getDurationOr("SMTP_TIMEOUT", DefaultTimeout),
	}
}

func getOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func getIntOr(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

func getBoolOr(k string, d bool) bool {
	if v := os.Getenv(k); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return d
}

func getDurationOr(k string, d time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if dur, err := time.ParseDuration(v); err == nil {
			return dur
		}
	}
	return d
}
