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

import "strings"

// Priority is the RFC 2076-family email priority hint (Importance/X-Priority/
// Priority headers). The zero value, PriorityNormal, emits no priority
// headers at all.
type Priority int

const (
	PriorityNormal Priority = iota
	PriorityHigh
	PriorityLow
)

// Sensitivity is the RFC 5322 Sensitivity header hint. The zero value,
// SensitivityNormal, emits no Sensitivity header.
type Sensitivity int

const (
	SensitivityNormal Sensitivity = iota
	SensitivityPersonal
	SensitivityPrivate
	SensitivityConfidential
)

// Attachment is a single file attached to, or inlined within, a Message.
// Inline attachments (Inline true) are referenced from HTML bodies via
// ContentID, e.g. `<img src="cid:ContentID">`.
type Attachment struct {
	Filename    string
	ContentType string
	Content     []byte
	Inline      bool
	ContentID   string
}

// Message is the neutral, transport-agnostic email envelope. It carries no
// dependency on any concrete transport (e.g. net/smtp) so callers can build
// and inspect a Message without pulling in an implementation.
type Message struct {
	From, EnvelopeFrom string

	To, Cc, Bcc []string

	ReplyTo, Subject, HTML, Text string

	Attachments []Attachment
	Headers     map[string]string

	Priority    Priority
	Sensitivity Sensitivity

	ListUnsubscribe, ListUnsubscribePost string

	Meta map[string]any
}

// Rendered is the resolved subject/HTML/text content produced by a Renderer,
// ready to be assembled into a Message body.
type Rendered struct {
	Subject, HTML, Text string
}

// headerKV is an ordered header key/value pair.
type headerKV struct{ K, V string }

// headerLines returns the ordered set of RFC 5322 header key/values derived
// from the Message's typed fields, for use by the MIME builder. Bcc is
// intentionally excluded: it is delivered via SMTP RCPT TO only and must
// never appear in the rendered headers.
func (m Message) headerLines() []headerKV {
	var h []headerKV
	add := func(k, v string) {
		if v != "" {
			h = append(h, headerKV{k, v})
		}
	}
	add("From", m.From)
	add("To", strings.Join(m.To, ", "))
	add("Cc", strings.Join(m.Cc, ", ")) // Bcc intentionally omitted from headers
	add("Reply-To", m.ReplyTo)
	add("Subject", m.Subject)
	switch m.Priority {
	case PriorityHigh:
		add("Importance", "high")
		add("X-Priority", "1")
		add("Priority", "urgent")
	case PriorityLow:
		add("Importance", "low")
		add("X-Priority", "5")
		add("Priority", "non-urgent")
	case PriorityNormal:
		// no priority headers
	}
	switch m.Sensitivity {
	case SensitivityPersonal:
		add("Sensitivity", "Personal")
	case SensitivityPrivate:
		add("Sensitivity", "Private")
	case SensitivityConfidential:
		add("Sensitivity", "Company-Confidential")
	case SensitivityNormal:
		// no sensitivity header
	}
	add("List-Unsubscribe", m.ListUnsubscribe)
	add("List-Unsubscribe-Post", m.ListUnsubscribePost)
	for k, v := range m.Headers {
		add(k, v) // custom headers last
	}
	return h
}

// Recipients returns the full SMTP RCPT TO set: To ∪ Cc ∪ Bcc.
func (m Message) Recipients() []string {
	out := make([]string, 0, len(m.To)+len(m.Cc)+len(m.Bcc))
	out = append(out, m.To...)
	out = append(out, m.Cc...)
	out = append(out, m.Bcc...)
	return out
}

// Bytes renders m into RFC 5322 message bytes (headers plus body), ready to
// be handed to a Transport for delivery. See buildMIME for the MIME
// structure it produces.
func (m Message) Bytes() ([]byte, error) {
	return buildMIME(m)
}
