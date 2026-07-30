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
	"errors"
	"testing"
)

func TestDedupeSkipsWhenSeen(t *testing.T) {
	d := NewMemDeduper()
	_ = d.Mark(context.Background(), "welcome:u1")
	calls := 0
	base := SendFunc(func(context.Context, *Message) error { calls++; return nil })
	m := &Message{Meta: map[string]any{"dedup_key": "welcome:u1"}}
	if err := chain(base, Dedupe(d))(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Error("must skip a seen message")
	}
}

func TestDedupeResendBypass(t *testing.T) {
	d := NewMemDeduper()
	_ = d.Mark(context.Background(), "welcome:u1")
	calls := 0
	base := SendFunc(func(context.Context, *Message) error { calls++; return nil })
	m := &Message{Meta: map[string]any{"dedup_key": "welcome:u1", "resend": true}}
	_ = chain(base, Dedupe(d))(context.Background(), m)
	if calls != 1 {
		t.Error("resend must bypass dedupe")
	}
}

func TestDedupeMarksAfterSuccess(t *testing.T) {
	d := NewMemDeduper()
	base := SendFunc(func(context.Context, *Message) error { return nil })
	m := &Message{Meta: map[string]any{"dedup_key": "welcome:u2"}}
	_ = chain(base, Dedupe(d))(context.Background(), m)
	seen, err := d.Seen(context.Background(), "welcome:u2")
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Error("must mark key as seen after a successful send")
	}
}

func TestDedupeNoKeyAlwaysSends(t *testing.T) {
	d := NewMemDeduper()
	calls := 0
	base := SendFunc(func(context.Context, *Message) error { calls++; return nil })
	_ = chain(base, Dedupe(d))(context.Background(), &Message{})
	if calls != 1 {
		t.Error("messages without a dedup key must always send")
	}
}

func TestRecordCapturesOutcome(t *testing.T) {
	var got error
	var recorded bool
	r := recorderFunc(func(_ context.Context, _ *Message, e error) error { recorded = true; got = e; return nil })
	base := SendFunc(func(context.Context, *Message) error { return errors.New("boom") })
	_ = chain(base, Record(r))(context.Background(), &Message{})
	if !recorded || got == nil {
		t.Error("Record must see the send error")
	}
}

func TestRecordReturnsOriginalSendError(t *testing.T) {
	sendErr := errors.New("boom")
	r := recorderFunc(func(context.Context, *Message, error) error { return nil })
	base := SendFunc(func(context.Context, *Message) error { return sendErr })
	err := chain(base, Record(r))(context.Background(), &Message{})
	if !errors.Is(err, sendErr) {
		t.Errorf("want original send error, got %v", err)
	}
}

func TestRecordCapturesSuccess(t *testing.T) {
	var got error
	var recorded bool
	r := recorderFunc(func(_ context.Context, _ *Message, e error) error { recorded = true; got = e; return nil })
	base := SendFunc(func(context.Context, *Message) error { return nil })
	if err := chain(base, Record(r))(context.Background(), &Message{}); err != nil {
		t.Fatal(err)
	}
	if !recorded || got != nil {
		t.Error("Record must see a nil error on success")
	}
}

func TestSuppressDropsSuppressedAddresses(t *testing.T) {
	s := suppressorFunc(func(_ context.Context, addr string) (bool, error) {
		return addr == "blocked@example.com", nil
	})
	var seen *Message
	base := SendFunc(func(_ context.Context, m *Message) error { seen = m; return nil })
	m := &Message{
		To:  []string{"a@example.com", "blocked@example.com"},
		Cc:  []string{"blocked@example.com"},
		Bcc: []string{"b@example.com", "blocked@example.com"},
	}
	if err := chain(base, Suppress(s))(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if len(seen.To) != 1 || seen.To[0] != "a@example.com" {
		t.Errorf("To = %v", seen.To)
	}
	if len(seen.Cc) != 0 {
		t.Errorf("Cc = %v", seen.Cc)
	}
	if len(seen.Bcc) != 1 || seen.Bcc[0] != "b@example.com" {
		t.Errorf("Bcc = %v", seen.Bcc)
	}
}

func TestSignNilIsIdentity(t *testing.T) {
	calls := 0
	base := SendFunc(func(context.Context, *Message) error { calls++; return nil })
	if err := chain(base, Sign(nil))(context.Background(), &Message{}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Error("nil Signer must be identity")
	}
}

func TestSignCallsHook(t *testing.T) {
	signed := false
	s := signerFunc(func(context.Context, *Message) error { signed = true; return nil })
	base := SendFunc(func(context.Context, *Message) error { return nil })
	if err := chain(base, Sign(s))(context.Background(), &Message{}); err != nil {
		t.Fatal(err)
	}
	if !signed {
		t.Error("Sign must invoke the Signer")
	}
}

func TestEncryptNilIsIdentity(t *testing.T) {
	calls := 0
	base := SendFunc(func(context.Context, *Message) error { calls++; return nil })
	if err := chain(base, Encrypt(nil))(context.Background(), &Message{}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Error("nil Encryptor must be identity")
	}
}

func TestEncryptCallsHook(t *testing.T) {
	encrypted := false
	e := encryptorFunc(func(context.Context, *Message) error { encrypted = true; return nil })
	base := SendFunc(func(context.Context, *Message) error { return nil })
	if err := chain(base, Encrypt(e))(context.Background(), &Message{}); err != nil {
		t.Fatal(err)
	}
	if !encrypted {
		t.Error("Encrypt must invoke the Encryptor")
	}
}

func TestNopDefaults(t *testing.T) {
	ctx := context.Background()
	if seen, err := (NopDeduper{}).Seen(ctx, "k"); err != nil || seen {
		t.Errorf("NopDeduper.Seen = %v, %v", seen, err)
	}
	if err := (NopDeduper{}).Mark(ctx, "k"); err != nil {
		t.Errorf("NopDeduper.Mark = %v", err)
	}
	if err := (NopRecorder{}).Record(ctx, &Message{}, nil); err != nil {
		t.Errorf("NopRecorder.Record = %v", err)
	}
	if suppressed, err := (NopSuppressor{}).Suppressed(ctx, "a@example.com"); err != nil || suppressed {
		t.Errorf("NopSuppressor.Suppressed = %v, %v", suppressed, err)
	}
}
