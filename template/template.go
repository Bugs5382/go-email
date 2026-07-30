// Package template provides a TemplateRenderer, a concrete email.Renderer
// backed by the standard library's text/template and html/template packages.
package template

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
	"sync"
	texttemplate "text/template"

	email "github.com/Bugs5382/go-email"
)

// templateSet is the compiled subject/HTML/text templates registered for a
// single kind.
type templateSet struct {
	subject *texttemplate.Template
	html    *htmltemplate.Template
	text    *texttemplate.Template
}

// TemplateRenderer is a concrete email.Renderer that resolves subject and
// text bodies with text/template and HTML bodies with html/template (which
// auto-escapes template data). Register a kind before rendering it; Render
// returns an error for any kind that has not been registered.
type TemplateRenderer struct {
	mu   sync.RWMutex
	sets map[string]*templateSet
}

// New returns an empty TemplateRenderer. Register kinds with Register before
// calling Render.
func New() *TemplateRenderer {
	return &TemplateRenderer{sets: make(map[string]*templateSet)}
}

// Register parses the subject, HTML, and text templates for kind and stores
// them for later use by Render. It returns an error if any template fails to
// parse.
func (r *TemplateRenderer) Register(kind, subjectTmpl, htmlTmpl, textTmpl string) error {
	subject, err := texttemplate.New(kind + ".subject").Parse(subjectTmpl)
	if err != nil {
		return fmt.Errorf("template: parse subject for kind %q: %w", kind, err)
	}
	html, err := htmltemplate.New(kind + ".html").Parse(htmlTmpl)
	if err != nil {
		return fmt.Errorf("template: parse html for kind %q: %w", kind, err)
	}
	text, err := texttemplate.New(kind + ".text").Parse(textTmpl)
	if err != nil {
		return fmt.Errorf("template: parse text for kind %q: %w", kind, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.sets[kind] = &templateSet{subject: subject, html: html, text: text}
	return nil
}

// Render executes the templates registered for kind against data, returning
// the resolved subject, HTML, and text bodies. It returns an error if kind
// has not been registered or if any template fails to execute.
func (r *TemplateRenderer) Render(ctx context.Context, kind string, data any) (email.Rendered, error) {
	select {
	case <-ctx.Done():
		return email.Rendered{}, ctx.Err()
	default:
	}

	r.mu.RLock()
	set, ok := r.sets[kind]
	r.mu.RUnlock()
	if !ok {
		return email.Rendered{}, fmt.Errorf("template: unknown kind %q", kind)
	}

	var subjectBuf, htmlBuf, textBuf bytes.Buffer
	if err := set.subject.Execute(&subjectBuf, data); err != nil {
		return email.Rendered{}, fmt.Errorf("template: execute subject for kind %q: %w", kind, err)
	}
	if err := set.html.Execute(&htmlBuf, data); err != nil {
		return email.Rendered{}, fmt.Errorf("template: execute html for kind %q: %w", kind, err)
	}
	if err := set.text.Execute(&textBuf, data); err != nil {
		return email.Rendered{}, fmt.Errorf("template: execute text for kind %q: %w", kind, err)
	}

	return email.Rendered{
		Subject: subjectBuf.String(),
		HTML:    htmlBuf.String(),
		Text:    textBuf.String(),
	}, nil
}

var _ email.Renderer = (*TemplateRenderer)(nil)
