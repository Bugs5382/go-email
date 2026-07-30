# go-email ✉️

> A small, dependency-light email client for Go: a full RFC 5322 envelope,
> multipart (`alternative`/`mixed`/`related`) rendering, and an ordered
> middleware chain around a pluggable `Transport`.

The exported surface is a set of neutral interfaces (`Transport`, `Renderer`,
`Sender`), so a caller never has to import `net/smtp` or `mime/multipart`
directly. The core package stays dependency-free and telemetry-free; SMTP
delivery, templated rendering, and OpenTelemetry instrumentation each live in
their own subpackage.

## 📦 Install

```bash
go get github.com/Bugs5382/go-email
```

## 🚀 Usage

```go
renderer := template.New()
renderer.Register(
	"welcome",
	"Welcome, {{.Name}}!",
	"<p>Hi {{.Name}}, welcome aboard.</p>",
	"Hi {{.Name}}, welcome aboard.",
)

sender := email.New(
	smtp.NewSMTPTransport(smtp.LoadConfig()),
	email.WithMiddleware(email.Validate(), email.Retry(3, time.Second)),
	email.WithRenderer(renderer),
)

err := sender.SendKind(ctx, "welcome", email.Message{
	From: "no-reply@example.com",
	To:   []string{"user@example.com"},
}, map[string]any{"Name": "Ada"})
```

`smtp.LoadConfig` reads `SMTP_*` environment variables with defaults suited
to a local mail catcher (host `localhost`, port `1025`, no auth, no TLS) --
point it at a real relay by setting `SMTP_HOST`/`SMTP_PORT`/`SMTP_USER`/
`SMTP_PASS`/`SMTP_TLS` in production. See [`example_test.go`](example_test.go)
for a complete, compilable example.

## 📨 Envelope

`Message` is the neutral, transport-agnostic envelope: `From`/`To`/`Cc`/`Bcc`,
`ReplyTo`, `Subject`/`HTML`/`Text`, `Attachments` (including inline
attachments referenced via `cid:`), arbitrary `Headers`, `Priority` and
`Sensitivity` hints, `List-Unsubscribe`/`List-Unsubscribe-Post`, and a
`Meta` map for middleware/subpackage use (e.g. tracing attributes).

- When both `HTML` and `Text` are set, the message renders as
  `multipart/alternative` -- the plaintext body is a first-class fallback,
  not an afterthought.
- `Bcc` recipients are only ever passed to the transport's envelope (SMTP
  `RCPT TO`); they are never written into a message header.

## 🪝 Middleware and hooks

`Sender` runs every `Message` through an ordered middleware chain before
handing it to the `Transport`:

- `Validate()` -- rejects a `Message` missing a `From` or any recipient.
- `Retry(attempts, base)` -- retries a failed `Send` with exponential
  backoff.
- `Dedupe(Deduper)` -- skips a `Message` already seen by a caller-supplied
  `Deduper` (an in-memory `MemDeduper` is included).
- `Record(Recorder)` -- reports every send attempt, success or failure, to a
  caller-supplied `Recorder`.
- `Suppress(Suppressor)` -- skips recipients on a caller-supplied suppression
  list, returning `ErrSuppressed` when every recipient is suppressed.
- `Sign(Signer)` / `Encrypt(Encryptor)` -- hook seams for a caller-supplied
  S/MIME, PGP, or other signing/encryption implementation.

`SendBulk` sends one rendered `Message` per recipient through the same
middleware chain, with per-recipient throttling and a `BulkResult` tally
instead of aborting the batch on the first failure.

## 🧩 Subpackages

- [`smtp`](smtp) -- `Config`/`LoadConfig` and an `SMTPTransport` speaking
  `net/smtp`, with a plaintext no-auth path for local catchers (e.g.
  `maildev`) and an optional STARTTLS+auth relay path.
- [`template`](template) -- a `TemplateRenderer` backed by the standard
  library's `text/template` (subject, plaintext) and `html/template` (HTML,
  auto-escaped) packages.
- [`otel`](otel) -- an `email.Middleware` that wraps every `Send` in an
  OpenTelemetry span plus send-count and duration metrics. It is the only
  package in this module that imports `go.opentelemetry.io/otel`; the core
  package stays telemetry-free.

## 🛠 Develop

```bash
task build    # go build ./...
task test     # go test ./...
task lint     # gofmt check + golangci-lint + yamllint
task ci       # build + vet + lint
task license  # verify every source file carries the MIT header
```

## ⚖️ License

MIT © 2026 Shane
