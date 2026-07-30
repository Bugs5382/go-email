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
	"bytes"
	"context"
	"fmt"
	htmltemplate "html/template"
	"testing"
	texttemplate "text/template"
)

// transportFunc adapts a plain function to the Transport interface, for use
// as a test double: it lets a test observe the Message a Sender hands to its
// Transport without standing up a real one.
type transportFunc func(ctx context.Context, m Message) error

// Send implements Transport.
func (f transportFunc) Send(ctx context.Context, m Message) error { return f(ctx, m) }

// kindTemplates holds the compiled subject/HTML/text templates for one kind,
// used by fakeRenderer below.
type kindTemplates struct {
	subject *texttemplate.Template
	html    *htmltemplate.Template
	text    *texttemplate.Template
}

// fakeRenderer is a minimal Renderer test double: it compiles and executes
// real subject/HTML/text templates per kind, without depending on the
// template subpackage (which the root package must not import).
type fakeRenderer struct {
	templates map[string]kindTemplates
}

func newFakeRenderer() *fakeRenderer {
	return &fakeRenderer{templates: make(map[string]kindTemplates)}
}

func (f *fakeRenderer) register(kind, subjectTmpl, htmlTmpl, textTmpl string) error {
	subject, err := texttemplate.New(kind + "-subject").Parse(subjectTmpl)
	if err != nil {
		return err
	}
	html, err := htmltemplate.New(kind + "-html").Parse(htmlTmpl)
	if err != nil {
		return err
	}
	text, err := texttemplate.New(kind + "-text").Parse(textTmpl)
	if err != nil {
		return err
	}
	f.templates[kind] = kindTemplates{subject: subject, html: html, text: text}
	return nil
}

func (f *fakeRenderer) Render(_ context.Context, kind string, data any) (Rendered, error) {
	kt, ok := f.templates[kind]
	if !ok {
		return Rendered{}, fmt.Errorf("email_test: unknown kind %q", kind)
	}
	var subjectBuf, htmlBuf, textBuf bytes.Buffer
	if err := kt.subject.Execute(&subjectBuf, data); err != nil {
		return Rendered{}, err
	}
	if err := kt.html.Execute(&htmlBuf, data); err != nil {
		return Rendered{}, err
	}
	if err := kt.text.Execute(&textBuf, data); err != nil {
		return Rendered{}, err
	}
	return Rendered{Subject: subjectBuf.String(), HTML: htmlBuf.String(), Text: textBuf.String()}, nil
}

func TestSenderSendKindRendersThenSends(t *testing.T) {
	var sent Message
	tr := transportFunc(func(_ context.Context, m Message) error { sent = m; return nil })
	r := newFakeRenderer()
	if err := r.register("welcome", "Welcome {{.Name}}", "<b>{{.Name}}</b>", "{{.Name}}"); err != nil {
		t.Fatal(err)
	}
	s := New(tr, WithRenderer(r))
	if err := s.SendKind(context.Background(), "welcome", Message{To: []string{"b@example.com"}, From: "a@example.com"}, map[string]any{"Name": "Ada"}); err != nil {
		t.Fatal(err)
	}
	if sent.Subject != "Welcome Ada" || sent.Text != "Ada" {
		t.Errorf("not rendered: %+v", sent)
	}
}
