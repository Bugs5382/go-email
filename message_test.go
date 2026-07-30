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
	"fmt"
	"strings"
	"testing"
)

// headersString joins headerKV pairs as "K: V\n" lines for assertion in tests.
func headersString(kvs []headerKV) string {
	var b strings.Builder
	for _, kv := range kvs {
		fmt.Fprintf(&b, "%s: %s\n", kv.K, kv.V)
	}
	return b.String()
}

func TestHeaderMapping(t *testing.T) {
	t.Parallel()

	m := Message{
		From: "a@example.com", To: []string{"b@example.com"}, Cc: []string{"c@example.com"},
		Bcc: []string{"secret@example.com"}, ReplyTo: "r@example.com", Subject: "Hi",
		Priority: PriorityHigh, Sensitivity: SensitivityConfidential,
		ListUnsubscribe: "<mailto:u@example.com>", Headers: map[string]string{"X-Custom": "1"},
	}
	h := headersString(m.headerLines()) // test helper: join "K: V\n"
	want := []string{
		"From: a@example.com", "To: b@example.com", "Cc: c@example.com",
		"Reply-To: r@example.com", "Subject: Hi",
		"Importance: high", "X-Priority: 1", "Priority: urgent",
		"Sensitivity: Company-Confidential",
		"List-Unsubscribe: <mailto:u@example.com>", "X-Custom: 1",
	}
	for _, w := range want {
		if !strings.Contains(h, w) {
			t.Errorf("missing header %q in:\n%s", w, h)
		}
	}
	if strings.Contains(h, "secret@example.com") {
		t.Error("Bcc must not appear in headers")
	}
}

func TestRecipients(t *testing.T) {
	t.Parallel()

	m := Message{
		To:  []string{"b@example.com"},
		Cc:  []string{"c@example.com"},
		Bcc: []string{"secret@example.com"},
	}
	got := m.recipients()
	want := []string{"b@example.com", "c@example.com", "secret@example.com"}
	if len(got) != len(want) {
		t.Fatalf("recipients() = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("recipients()[%d] = %q, want %q", i, got[i], w)
		}
	}
}
