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
	"os"
	"strconv"
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
}

// LoadConfig reads SMTP_* env vars with local-catcher (e.g. maildev) defaults:
// host localhost, port 1025, no user/pass, From no-reply@example.com, no TLS.
func LoadConfig() Config {
	return Config{
		Host:        getOr("SMTP_HOST", "localhost"),
		Port:        getIntOr("SMTP_PORT", 1025),
		User:        os.Getenv("SMTP_USER"),
		Pass:        os.Getenv("SMTP_PASS"),
		From:        getOr("SMTP_FROM", "no-reply@example.com"),
		TLS:         getBoolOr("SMTP_TLS", false),
		TLSInsecure: getBoolOr("SMTP_TLS_INSECURE", false),
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
