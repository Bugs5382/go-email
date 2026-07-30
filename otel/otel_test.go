package otel

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

	email "github.com/Bugs5382/go-email"

	"go.opentelemetry.io/otel/codes"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// newTestTracer returns a tracer backed by an in-memory span recorder, so
// tests can assert on the spans a Send produces without any network export.
func newTestTracer(t *testing.T) (trace.Tracer, *tracetest.SpanRecorder) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
	})
	return tp.Tracer("otel_test"), recorder
}

func TestMiddleware_RecordsSpanOnSuccess(t *testing.T) {
	tracer, recorder := newTestTracer(t)
	meter := noopmetric.NewMeterProvider().Meter("otel_test")

	send := Middleware(tracer, meter)(func(_ context.Context, _ *email.Message) error {
		return nil
	})

	msg := &email.Message{
		From: "sender@example.com",
		To:   []string{"a@example.com", "b@example.com"},
		Meta: map[string]any{"kind": "welcome"},
	}

	if err := send(context.Background(), msg); err != nil {
		t.Fatalf("send: unexpected error: %v", err)
	}

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected exactly 1 span, got %d", len(spans))
	}
	if got := spans[0].Name(); got != "email.send" {
		t.Fatalf("expected span name %q, got %q", "email.send", got)
	}
	if got := spans[0].Status().Code; got != codes.Unset {
		t.Fatalf("expected unset status on success, got %v", got)
	}
}

func TestMiddleware_RecordsErrorStatus(t *testing.T) {
	tracer, recorder := newTestTracer(t)
	meter := noopmetric.NewMeterProvider().Meter("otel_test")

	wantErr := errors.New("smtp: connection refused")
	send := Middleware(tracer, meter)(func(_ context.Context, _ *email.Message) error {
		return wantErr
	})

	msg := &email.Message{
		From: "sender@example.com",
		To:   []string{"a@example.com"},
	}

	if err := send(context.Background(), msg); !errors.Is(err, wantErr) {
		t.Fatalf("expected send to propagate the underlying error, got %v", err)
	}

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected exactly 1 span, got %d", len(spans))
	}
	if got := spans[0].Name(); got != "email.send" {
		t.Fatalf("expected span name %q, got %q", "email.send", got)
	}
	if got := spans[0].Status().Code; got != codes.Error {
		t.Fatalf("expected status Error, got %v", got)
	}
}
