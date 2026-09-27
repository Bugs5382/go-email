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
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	email "github.com/Bugs5382/go-email"
	"github.com/Bugs5382/go-email/internal/mimeparse"
	log "github.com/Bugs5382/go-log"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

// edConfig generates fast Ed25519/X25519 keys for tests.
var edConfig = &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}

var (
	keyCacheMu sync.Mutex
	keyCache   = map[string]*Key{}
)

// testKey returns a private key for addr, generated once per test binary so
// the suite stays fast. Callers must not Unlock/lock it.
func testKey(t testing.TB, name, addr string) *Key {
	t.Helper()
	keyCacheMu.Lock()
	defer keyCacheMu.Unlock()
	if k, ok := keyCache[addr]; ok {
		return k
	}
	e, err := openpgp.NewEntity(name, "", addr, edConfig)
	if err != nil {
		t.Fatal(err)
	}
	k := &Key{e: e}
	keyCache[addr] = k
	return k
}

// publicOnly re-reads k's public half, the way a recipient's key arrives.
func publicOnly(t testing.TB, k *Key) *Key {
	t.Helper()
	armored, err := k.ArmoredPublic()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ReadArmoredKeys(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	return keys[0]
}

// sink records every message that reaches the end of a middleware chain.
type sink struct {
	mu   sync.Mutex
	msgs []email.Message
}

func (s *sink) send(_ context.Context, m *email.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.msgs = append(s.msgs, *m)
	return nil
}

func render(t testing.TB, m email.Message) []byte {
	t.Helper()
	b, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testMessage() email.Message {
	return email.Message{
		From:    "Alice <alice@example.com>",
		To:      []string{"bob@example.com"},
		Subject: "Quarterly numbers",
		Text:    "From the desk of Alice:\nthe numbers are in.\n",
		HTML:    "<p>The numbers are in.</p>",
		Attachments: []email.Attachment{
			{Filename: "q3.csv", ContentType: "text/csv", Content: []byte("a,b\n1,2\n")},
		},
	}
}

// aeadConfig generates keys that advertise SEIPDv2 (AEAD) support, so
// messages to them use AEAD-encrypted data.
var aeadConfig = &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, AEADConfig: &packet.AEADConfig{}}

// testAEADKey returns a cached private key for addr that advertises AEAD.
func testAEADKey(t testing.TB, name, addr string) *Key {
	t.Helper()
	keyCacheMu.Lock()
	defer keyCacheMu.Unlock()
	if k, ok := keyCache["aead:"+addr]; ok {
		return k
	}
	e, err := openpgp.NewEntity(name, "", addr, aeadConfig)
	if err != nil {
		t.Fatal(err)
	}
	k := &Key{e: e}
	keyCache["aead:"+addr] = k
	return k
}

// recordingLogger is a go-log Logger that keeps every line, fields and
// error text included, so tests can check what would have been logged.
type recordingLogger struct {
	mu    sync.Mutex
	lines *[]string
	with  []log.Field
}

func (r *recordingLogger) add(level string, err error, msg string, fields []log.Field) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lines == nil {
		r.lines = new([]string)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", level, msg)
	if err != nil {
		fmt.Fprintf(&b, " err=%q", err.Error())
	}
	for _, f := range append(slices.Clone(r.with), fields...) {
		fmt.Fprintf(&b, " %s=%v", f.Key, f.Val)
	}
	*r.lines = append(*r.lines, b.String())
}

func (r *recordingLogger) Debug(msg string, f ...log.Field)            { r.add("debug", nil, msg, f) }
func (r *recordingLogger) Info(msg string, f ...log.Field)             { r.add("info", nil, msg, f) }
func (r *recordingLogger) Warn(msg string, f ...log.Field)             { r.add("warn", nil, msg, f) }
func (r *recordingLogger) Error(err error, msg string, f ...log.Field) { r.add("error", err, msg, f) }
func (r *recordingLogger) Fatal(err error, msg string, f ...log.Field) { r.add("fatal", err, msg, f) }
func (r *recordingLogger) Ctx(context.Context) log.Logger              { return r }

func (r *recordingLogger) With(f ...log.Field) log.Logger {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lines == nil {
		r.lines = new([]string)
	}
	return &recordingLogger{lines: r.lines, with: append(slices.Clone(r.with), f...)}
}

func (r *recordingLogger) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lines == nil {
		return ""
	}
	return strings.Join(*r.lines, "\n")
}

// splitTop returns the raw parts of raw's top-level multipart body.
func splitTop(t testing.TB, raw []byte) [][]byte {
	t.Helper()
	top, err := mimeparse.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, params, err := top.MediaType()
	if err != nil {
		t.Fatal(err)
	}
	parts, err := mimeparse.SplitMultipart(top.Body, params["boundary"])
	if err != nil {
		t.Fatal(err)
	}
	return parts
}

// rebuildWithParts keeps raw's header block, boundary included, and
// replaces its multipart body with parts.
func rebuildWithParts(t testing.TB, raw []byte, parts ...[]byte) []byte {
	t.Helper()
	top, err := mimeparse.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, params, err := top.MediaType()
	if err != nil {
		t.Fatal(err)
	}
	body, err := mimeparse.Join(params["boundary"], parts...)
	if err != nil {
		t.Fatal(err)
	}
	head := raw[:len(raw)-len(top.Body)]
	return append(slices.Clone(head), body...)
}

// ciphertextOf returns the binary OpenPGP message inside a PGP/MIME
// multipart/encrypted message.
func ciphertextOf(t testing.TB, raw []byte) []byte {
	t.Helper()
	parts := splitTop(t, raw)
	if len(parts) != 2 {
		t.Fatalf("got %d parts", len(parts))
	}
	data, err := mimeparse.Parse(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	block, err := armor.Decode(bytes.NewReader(data.Body))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(block.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rebuildEncrypted wraps binary OpenPGP data in a fresh PGP/MIME
// multipart/encrypted message.
func rebuildEncrypted(t testing.TB, ct []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.MessageType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(ct); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := encryptedEntity(crlf(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return render(t, email.Message{From: "alice@example.com", To: []string{"bob@example.com"}, Subject: "x", Body: p})
}

// packetHeader is one top-level OpenPGP packet: where its header byte is
// and its tag. Only new-format headers are handled, which is what
// go-crypto writes.
type packetHeader struct {
	off int
	tag byte
}

// packets walks the top-level packets of ct, following partial body
// lengths (RFC 9580 section 4.2.1).
func packets(t testing.TB, ct []byte) []packetHeader {
	t.Helper()
	var out []packetHeader
	for i := 0; i < len(ct); {
		if ct[i]&0xC0 != 0xC0 {
			t.Fatalf("old-format packet header at %d", i)
		}
		out = append(out, packetHeader{off: i, tag: ct[i] & 0x3F})
		i++
		for {
			l := int(ct[i])
			switch {
			case l < 192:
				i += 1 + l
			case l < 224:
				i += 2 + (l-192)<<8 + int(ct[i+1]) + 192
			case l == 255:
				i += 5 + (int(ct[i+1])<<24 | int(ct[i+2])<<16 | int(ct[i+3])<<8 | int(ct[i+4]))
			default: // partial body length: another length follows
				i += 1 + 1<<(l&0x1F)
				continue
			}
			break
		}
	}
	return out
}

// seipdVersion returns the version byte of ct's encrypted data packet.
func seipdVersion(t testing.TB, ct []byte) byte {
	t.Helper()
	for _, p := range packets(t, ct) {
		if p.tag == 18 {
			i := p.off + 1
			switch l := int(ct[i]); {
			case l < 192 || l >= 224 && l != 255:
				return ct[i+1]
			case l < 224:
				return ct[i+2]
			default:
				return ct[i+5]
			}
		}
	}
	t.Fatal("no SEIPD packet")
	return 0
}

// downgradeToSED rewrites the Symmetrically Encrypted Integrity Protected
// Data packet (tag 18) of ct as a legacy Symmetrically Encrypted Data
// packet (tag 9), which carries no MDC.
func downgradeToSED(t testing.TB, ct []byte) []byte {
	t.Helper()
	out := slices.Clone(ct)
	for _, p := range packets(t, ct) {
		if p.tag == 18 {
			out[p.off] = 0xC0 | 9
			return out
		}
	}
	t.Fatal("no SEIPD packet")
	return nil
}
