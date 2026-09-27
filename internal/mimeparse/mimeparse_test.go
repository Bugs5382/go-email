package mimeparse

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
	"errors"
	"strings"
	"testing"
)

func TestCanonical(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"a\nb\n":     "a\r\nb\r\n",
		"a\r\nb\r\n": "a\r\nb\r\n",
		"a\rb\n":     "a\rb\r\n",
		"\n\n":       "\r\n\r\n",
		"":           "",
		"x\r\r\n":    "x\r\r\n",
	} {
		if got := string(Canonical([]byte(in))); got != want {
			t.Errorf("Canonical(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParse(t *testing.T) {
	t.Parallel()

	raw := []byte("Content-Type: text/plain; charset=utf-8\r\nX-A: 1\r\n\r\nhello\r\nworld")
	e, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e.Header.Get("X-A") != "1" || string(e.Body) != "hello\r\nworld" {
		t.Errorf("got header %v body %q", e.Header, e.Body)
	}
	mt, params, err := e.MediaType()
	if err != nil || mt != "text/plain" || params["charset"] != "utf-8" {
		t.Errorf("MediaType = %q %v %v", mt, params, err)
	}

	e, err = Parse([]byte("\r\nbody only"))
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Header) != 0 || string(e.Body) != "body only" {
		t.Errorf("headerless: %v %q", e.Header, e.Body)
	}
	if mt, _, _ := e.MediaType(); mt != "text/plain" {
		t.Errorf("default media type = %q", mt)
	}
	if _, err := Parse([]byte("no separator here")); !errors.Is(err, ErrMalformed) {
		t.Errorf("missing separator: err = %v", err)
	}
}

func TestSplitMultipart(t *testing.T) {
	t.Parallel()

	body := "preamble\r\n--b\r\nContent-Type: text/plain\r\n\r\none\r\n--b  \r\n\r\ntwo\r\n\r\n--b--\r\nepilogue"
	parts, err := SplitMultipart([]byte(body), "b")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Content-Type: text/plain\r\n\r\none", "\r\ntwo\r\n"}
	if len(parts) != len(want) {
		t.Fatalf("got %d parts: %q", len(parts), parts)
	}
	for i := range want {
		if string(parts[i]) != want[i] {
			t.Errorf("part %d = %q, want %q", i, parts[i], want[i])
		}
	}
}

func TestSplitMultipartIgnoresLookalikeBoundaries(t *testing.T) {
	t.Parallel()

	body := "--b\r\n\r\nx\r\n--bb\r\nnot a delimiter\r\n --b\r\n--b--"
	parts, err := SplitMultipart([]byte(body), "b")
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 || string(parts[0]) != "\r\nx\r\n--bb\r\nnot a delimiter\r\n --b" {
		t.Errorf("parts = %q", parts)
	}
}

func TestSplitMultipartErrors(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct{ body, boundary string }{
		"no close":       {"--b\r\n\r\nx\r\n", "b"},
		"no delimiter":   {"just text", "b"},
		"empty boundary": {"--\r\n\r\nx\r\n----", ""},
		"long boundary":  {"x", strings.Repeat("a", 71)},
		"bad tail":       {"--bx\r\n\r\nx\r\n--b--", "b"},
	} {
		if _, err := SplitMultipart([]byte(tc.body), tc.boundary); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

func TestJoinRoundTrip(t *testing.T) {
	t.Parallel()

	a := []byte("Content-Type: text/plain\r\n\r\nhello")
	b := []byte("Content-Type: application/octet-stream\r\n\r\nAAAA\r\n")
	boundary, err := NewBoundary()
	if err != nil {
		t.Fatal(err)
	}
	body, err := Join(boundary, a, b)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := SplitMultipart(body, boundary)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 || !bytes.Equal(parts[0], a) || !bytes.Equal(parts[1], b) {
		t.Errorf("round trip parts = %q", parts)
	}
	if _, err := Join(boundary, []byte("x\r\n--"+boundary+"\r\n")); !errors.Is(err, ErrMalformed) {
		t.Errorf("Join must refuse a part containing the delimiter, err = %v", err)
	}
}

func FuzzSplitMultipart(f *testing.F) {
	f.Add([]byte("--b\r\n\r\none\r\n--b\r\n\r\ntwo\r\n--b--\r\n"), "b")
	f.Add([]byte("x\r\n--b\r\n--b--"), "b")
	f.Add([]byte("--b\r\n\r\n--b--"), "b")
	f.Fuzz(func(t *testing.T, body []byte, boundary string) {
		parts, err := SplitMultipart(body, boundary)
		if err != nil {
			return
		}
		for _, p := range parts {
			if !bytes.Contains(body, p) {
				t.Fatalf("part %q is not a slice of the body", p)
			}
		}
		// Anything that split cleanly must re-join and split to the same parts.
		joined, err := Join(boundary, parts...)
		if err != nil {
			return // a part legitimately contains a lookalike delimiter
		}
		again, err := SplitMultipart(joined, boundary)
		if err != nil || len(again) != len(parts) {
			t.Fatalf("re-split of %q: %d parts, err %v", joined, len(again), err)
		}
		for i := range parts {
			if !bytes.Equal(parts[i], again[i]) {
				t.Fatalf("part %d changed: %q -> %q", i, parts[i], again[i])
			}
		}
	})
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("Content-Type: text/plain\r\n\r\nhi"))
	f.Add([]byte("\r\n"))
	f.Add([]byte("A: b\r\n c\r\n\r\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := Parse(raw)
		if err != nil {
			return
		}
		if !bytes.HasSuffix(raw, e.Body) {
			t.Fatalf("body %q is not the tail of the input", e.Body)
		}
		_, _, _ = e.MediaType()
	})
}
