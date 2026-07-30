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
	"strings"
	"testing"
	"time"
)

// okBase is a base SendFunc that always succeeds, for tests that only care
// about middleware behavior and not the terminal send outcome.
var okBase = SendFunc(func(context.Context, *Message) error { return nil })

func TestChainOrder(t *testing.T) {
	var log []string
	mk := func(name string) Middleware {
		return func(n SendFunc) SendFunc {
			return func(c context.Context, m *Message) error { log = append(log, name); return n(c, m) }
		}
	}
	base := SendFunc(func(context.Context, *Message) error { log = append(log, "base"); return nil })
	_ = chain(base, mk("a"), mk("b"))(context.Background(), &Message{})
	if strings.Join(log, ",") != "a,b,base" {
		t.Errorf("order = %v", log)
	}
}

func TestValidateRejectsNoRecipients(t *testing.T) {
	err := chain(okBase, Validate())(context.Background(), &Message{From: "a@example.com"})
	if !errors.Is(err, ErrValidation) {
		t.Errorf("want ErrValidation, got %v", err)
	}
}

func TestValidateRejectsBadAddress(t *testing.T) {
	err := chain(okBase, Validate())(context.Background(), &Message{From: "a@example.com", To: []string{"not-an-email"}})
	if !errors.Is(err, ErrValidation) {
		t.Error("want ErrValidation")
	}
}

func TestRetryTransientThenSucceed(t *testing.T) {
	n := 0
	base := SendFunc(func(context.Context, *Message) error {
		n++
		if n < 3 {
			return TransientError{errors.New("x")}
		}
		return nil
	})
	if err := chain(base, Retry(3, time.Millisecond))(context.Background(), &Message{}); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("attempts = %d", n)
	}
}

func TestRetryNotOnValidation(t *testing.T) {
	n := 0
	base := SendFunc(func(context.Context, *Message) error { n++; return ErrValidation })
	_ = chain(base, Retry(3, time.Millisecond))(context.Background(), &Message{})
	if n != 1 {
		t.Errorf("must not retry non-transient; attempts = %d", n)
	}
}
