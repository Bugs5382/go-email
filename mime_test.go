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
	"strings"
	"testing"
)

func TestBuildMIME_Alternative(t *testing.T) {
	b, err := buildMIME(Message{From: "a@example.com", To: []string{"b@example.com"}, Subject: "S", HTML: "<p>hi</p>", Text: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "Content-Type: multipart/alternative") {
		t.Error("want multipart/alternative")
	}
	if !strings.Contains(s, "text/plain") || !strings.Contains(s, "text/html") {
		t.Error("want both parts")
	}
	if !strings.Contains(s, "\r\n") {
		t.Error("want CRLF")
	}
}

func TestBuildMIME_SingleText(t *testing.T) {
	b, _ := buildMIME(Message{From: "a@example.com", To: []string{"b@example.com"}, Subject: "S", Text: "hi"})
	if strings.Contains(string(b), "multipart") {
		t.Error("text-only must be single part")
	}
}

func TestBuildMIME_MixedWithAttachment(t *testing.T) {
	b, _ := buildMIME(Message{From: "a@example.com", To: []string{"b@example.com"}, Subject: "S", Text: "hi",
		Attachments: []Attachment{{Filename: "r.pdf", ContentType: "application/pdf", Content: []byte("%PDF")}}})
	s := string(b)
	if !strings.Contains(s, "multipart/mixed") {
		t.Error("want multipart/mixed")
	}
	if !strings.Contains(s, `filename="r.pdf"`) {
		t.Error("want attachment filename")
	}
}

func TestBuildMIME_InlineRelated(t *testing.T) {
	b, _ := buildMIME(Message{From: "a@example.com", To: []string{"b@example.com"}, Subject: "S", HTML: `<img src="cid:logo">`,
		Attachments: []Attachment{{Filename: "logo.png", ContentType: "image/png", Content: []byte("PNG"), Inline: true, ContentID: "logo"}}})
	if !strings.Contains(string(b), "multipart/related") {
		t.Error("want multipart/related for inline CID")
	}
}
