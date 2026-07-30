// Package otel provides an OpenTelemetry email.Middleware: it wraps a Send
// call in a span plus send counter and duration metrics. It is the only
// package in this module that imports go.opentelemetry.io/otel -- the core
// email package stays telemetry-free.
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
	"time"

	email "github.com/Bugs5382/go-email"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// spanName is the span emitted around every wrapped Send call.
const spanName = "email.send"

// Middleware returns an email.Middleware that records, around every Send
// call:
//
//   - a span named "email.send" carrying the recipient count (To ∪ Cc ∪ Bcc)
//     and, when present, the "kind" entry from Message.Meta as attributes.
//     A failed send records the error onto the span and sets its status to
//     codes.Error.
//   - an "email.send.count" counter and an "email.send.duration" histogram
//     (seconds), both tagged with a "status" attribute of "ok" or "error".
//
// tracer and meter are typically obtained from an
// go.opentelemetry.io/otel.TracerProvider / MeterProvider configured by the
// caller; passing noop implementations disables telemetry without changing
// call sites.
func Middleware(tracer trace.Tracer, meter metric.Meter) email.Middleware {
	// The error is intentionally ignored: per the OTel-go contract, a usable
	// no-op instrument is returned even when construction fails, so counter
	// and duration are always safe to call below.
	counter, _ := meter.Int64Counter(
		"email.send.count",
		metric.WithDescription("Number of email send attempts, by status."),
	)
	duration, _ := meter.Float64Histogram(
		"email.send.duration",
		metric.WithDescription("Duration of email send attempts, in seconds."),
		metric.WithUnit("s"),
	)

	return func(next email.SendFunc) email.SendFunc {
		return func(ctx context.Context, m *email.Message) error {
			attrs := []attribute.KeyValue{
				attribute.Int("email.recipient_count", len(m.Recipients())),
			}
			if kind, ok := m.Meta["kind"].(string); ok && kind != "" {
				attrs = append(attrs, attribute.String("email.kind", kind))
			}

			ctx, span := tracer.Start(ctx, spanName, trace.WithAttributes(attrs...))
			defer span.End()
			start := time.Now()

			err := next(ctx, m)

			status := "ok"
			if err != nil {
				status = "error"
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
			}

			statusAttr := attribute.String("status", status)
			counter.Add(ctx, 1, metric.WithAttributes(statusAttr))
			duration.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(statusAttr))

			return err
		}
	}
}
