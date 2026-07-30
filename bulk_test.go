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
	"sort"
	"testing"
	"time"
)

// assertSameSet fails the test unless got and want contain the same elements,
// ignoring order.
func assertSameSet(t *testing.T, got, want []string) {
	t.Helper()
	gotSorted := append([]string(nil), got...)
	wantSorted := append([]string(nil), want...)
	sort.Strings(gotSorted)
	sort.Strings(wantSorted)
	if len(gotSorted) != len(wantSorted) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range gotSorted {
		if gotSorted[i] != wantSorted[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestSendBulkPerRecipient(t *testing.T) {
	var tos []string
	tr := transportFunc(func(_ context.Context, m Message) error { tos = append(tos, m.To[0]); return nil })
	r := newFakeRenderer()
	if err := r.register("promo", "Hi {{.Name}}", "", "Hi {{.Name}}"); err != nil {
		t.Fatal(err)
	}
	s := New(tr, WithRenderer(r))
	res, err := s.SendBulk(context.Background(), "promo", Message{From: "a@example.com"},
		[]Recipient{{Address: "b@example.com", Data: map[string]any{"Name": "B"}}, {Address: "c@example.com", Data: map[string]any{"Name": "C"}}},
		WithListUnsubscribe("<mailto:u@example.com>", "List-Unsubscribe=One-Click"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent != 2 {
		t.Errorf("sent = %d", res.Sent)
	}
	assertSameSet(t, tos, []string{"b@example.com", "c@example.com"})
}

func TestSendBulkAppliesListUnsubscribe(t *testing.T) {
	var got []Message
	tr := transportFunc(func(_ context.Context, m Message) error { got = append(got, m); return nil })
	r := newFakeRenderer()
	if err := r.register("promo", "Hi {{.Name}}", "", "Hi {{.Name}}"); err != nil {
		t.Fatal(err)
	}
	s := New(tr, WithRenderer(r))
	_, err := s.SendBulk(context.Background(), "promo", Message{From: "a@example.com"},
		[]Recipient{{Address: "b@example.com", Data: map[string]any{"Name": "B"}}},
		WithListUnsubscribe("<mailto:u@example.com>", "List-Unsubscribe=One-Click"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 send, got %d", len(got))
	}
	if got[0].ListUnsubscribe != "<mailto:u@example.com>" || got[0].ListUnsubscribePost != "List-Unsubscribe=One-Click" {
		t.Errorf("List-Unsubscribe not applied: %+v", got[0])
	}
}

func TestSendBulkSuppressedRecipientCountsSkipped(t *testing.T) {
	var tos []string
	tr := transportFunc(func(_ context.Context, m Message) error { tos = append(tos, m.To[0]); return nil })
	r := newFakeRenderer()
	if err := r.register("promo", "Hi {{.Name}}", "", "Hi {{.Name}}"); err != nil {
		t.Fatal(err)
	}
	suppressed := suppressorFunc(func(_ context.Context, addr string) (bool, error) {
		return addr == "blocked@example.com", nil
	})
	s := New(tr, WithRenderer(r), WithMiddleware(Suppress(suppressed)))
	res, err := s.SendBulk(context.Background(), "promo", Message{From: "a@example.com"},
		[]Recipient{
			{Address: "blocked@example.com", Data: map[string]any{"Name": "Blocked"}},
			{Address: "ok@example.com", Data: map[string]any{"Name": "Ok"}},
		})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent != 1 {
		t.Errorf("sent = %d, want 1", res.Sent)
	}
	if res.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", res.Skipped)
	}
	if res.Failed != 0 || len(res.Errors) != 0 {
		t.Errorf("a suppressed recipient must count as Skipped, not Failed: failed=%d errors=%v", res.Failed, res.Errors)
	}
	assertSameSet(t, tos, []string{"ok@example.com"})
}

func TestSendBulkRecipientFailureDoesNotAbortBatch(t *testing.T) {
	var tos []string
	tr := transportFunc(func(_ context.Context, m Message) error {
		if m.To[0] == "bad@example.com" {
			return errors.New("boom")
		}
		tos = append(tos, m.To[0])
		return nil
	})
	r := newFakeRenderer()
	if err := r.register("promo", "Hi {{.Name}}", "", "Hi {{.Name}}"); err != nil {
		t.Fatal(err)
	}
	s := New(tr, WithRenderer(r))
	res, err := s.SendBulk(context.Background(), "promo", Message{From: "a@example.com"},
		[]Recipient{
			{Address: "bad@example.com", Data: map[string]any{"Name": "Bad"}},
			{Address: "good@example.com", Data: map[string]any{"Name": "Good"}},
		})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent != 1 || res.Failed != 1 {
		t.Errorf("got sent=%d failed=%d, want sent=1 failed=1", res.Sent, res.Failed)
	}
	if res.Errors["bad@example.com"] == nil {
		t.Errorf("expected error recorded for bad@example.com")
	}
	assertSameSet(t, tos, []string{"good@example.com"})
}

func TestSendBulkThrottle(t *testing.T) {
	tr := transportFunc(func(_ context.Context, m Message) error { return nil })
	r := newFakeRenderer()
	if err := r.register("promo", "Hi {{.Name}}", "", "Hi {{.Name}}"); err != nil {
		t.Fatal(err)
	}
	s := New(tr, WithRenderer(r))
	start := time.Now()
	_, err := s.SendBulk(context.Background(), "promo", Message{From: "a@example.com"},
		[]Recipient{
			{Address: "b@example.com", Data: map[string]any{"Name": "B"}},
			{Address: "c@example.com", Data: map[string]any{"Name": "C"}},
		},
		WithThrottle(20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Errorf("expected throttle delay, elapsed = %v", elapsed)
	}
}
