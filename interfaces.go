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

import "context"

// Transport delivers a Message. It is the neutral seam between the
// envelope/rendering layer and the wire protocol: no concrete implementation
// (e.g. net/smtp) type appears in this interface, so callers can depend on
// Transport without pulling in one.
type Transport interface {
	Send(ctx context.Context, m Message) error
}

// Renderer resolves a subject/HTML/text body for a named kind of content
// (e.g. a template name) and arbitrary data, returning it ready to be
// assembled into a Message. No concrete implementation (e.g. html/template)
// appears in this interface, so callers can depend on Renderer without
// pulling in one.
type Renderer interface {
	Render(ctx context.Context, kind string, data any) (Rendered, error)
}
