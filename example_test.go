package email_test

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
	"fmt"
	"time"

	email "github.com/Bugs5382/go-email"
	"github.com/Bugs5382/go-email/smtp"
	"github.com/Bugs5382/go-email/template"
)

// Example shows the common wiring: an SMTP transport, a Validate+Retry
// middleware chain, and a template.Renderer, composed into a Sender that
// delivers a templated message by kind.
//
// It has no "Output:" comment, so `go test` compiles it but does not run it
// -- SendKind below would otherwise dial the SMTP host from smtp.LoadConfig
// (a local catcher such as maildev by default), which this package's test
// suite must not depend on.
func Example() {
	renderer := template.New()
	if err := renderer.Register(
		"welcome",
		"Welcome, {{.Name}}!",
		"<p>Hi {{.Name}}, welcome aboard.</p>",
		"Hi {{.Name}}, welcome aboard.",
	); err != nil {
		fmt.Println(err)
		return
	}

	sender := email.New(
		smtp.NewSMTPTransport(smtp.LoadConfig()),
		email.WithMiddleware(email.Validate(), email.Retry(3, time.Second)),
		email.WithRenderer(renderer),
	)

	ctx := context.Background()
	msg := email.Message{
		From: "no-reply@example.com",
		To:   []string{"user@example.com"},
	}

	if err := sender.SendKind(ctx, "welcome", msg, map[string]any{"Name": "Ada"}); err != nil {
		fmt.Println(err)
	}
}
