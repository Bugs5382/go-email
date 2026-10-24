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

⏱️ Every SMTP send is time-bounded. `Config.DialTimeout` (`SMTP_DIAL_TIMEOUT`,
default `30s`) caps the connect, and `Config.Timeout` (`SMTP_TIMEOUT`,
default `5m`, the command timeout RFC 5321 suggests) caps how long any single
read or write may wait on the server, so a relay that hangs can't block a
send forever. Both take Go duration strings; zero means the default and a
negative value turns the limit off. Cancelling the `ctx` passed to `Send`, or
reaching its deadline, also ends a send that is waiting on the server. A dial
that times out comes back as an `email.TransientError`, since nothing was
sent.

🪵 Set `Config.Logger` to a [go-log](https://github.com/Bugs5382/go-log)
`Logger` to see what the transport does. It's nil by default, which logs
nothing. With a logger set, each send writes a debug line when it starts
(relay, recipient count, message size, TLS mode, whether it authenticates),
a trace line per SMTP stage with its timing, and one outcome line: info when
the relay accepted the message, warn for a 4xx reply, a context that ended
or a failed QUIT after the message was accepted, and error for anything
permanent. The outcome line names the failing stage and the server's reply
code, and every line from one send shares a random `send_id`.

```go
cfg := smtp.LoadConfig()
cfg.Logger = log.NewLogger("billing")
transport := smtp.NewSMTPTransport(cfg)
```

The logs never carry credentials, addresses, the subject or the body. The
server's reply text is dropped too, since relays often echo the address in
it; a rejected recipient shows up as `rcpt_id`, a keyed hash that's random per
process.

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
- `Retry(attempts, base)` -- retries a `Send` that failed with an
  `email.TransientError`, with exponential backoff. Anything else fails
  straight away.
- `Dedupe(Deduper)` -- skips a `Message` already seen by a caller-supplied
  `Deduper` (an in-memory `MemDeduper` is included).
- `Record(Recorder)` -- reports every send attempt, success or failure, to a
  caller-supplied `Recorder`.
- `Suppress(Suppressor)` -- skips recipients on a caller-supplied suppression
  list, returning `ErrSuppressed` when every recipient is suppressed.
- `Sign(Signer)` / `Encrypt(Encryptor)` -- hook seams for signing and
  encryption, such as the [`pgp`](pgp) subpackage or your own S/MIME
  implementation.

`SendBulk` sends one rendered `Message` per recipient through the same
middleware chain, with per-recipient throttling and a `BulkResult` tally
instead of aborting the batch on the first failure.

## 🧩 Subpackages

- [`smtp`](smtp) -- `Config`/`LoadConfig` and an `SMTPTransport` speaking
  `net/smtp`, with a plaintext no-auth path for local catchers (e.g.
  `maildev`) and an optional STARTTLS+auth relay path. A 4xx reply from the
  server (421, 450, 451, 452, 454 and the like) comes back as an
  `email.TransientError`, so `Retry` retries it; a 5xx reply is permanent,
  and a failed `QUIT` after the server accepted the message is never
  retried. The server's `*textproto.Error` is still there for `errors.As`.
- [`template`](template) -- a `TemplateRenderer` backed by the standard
  library's `text/template` (subject, plaintext) and `html/template` (HTML,
  auto-escaped) packages.
- [`otel`](otel) -- an `email.Middleware` that wraps every `Send` in an
  OpenTelemetry span plus send-count and duration metrics. It is the only
  package in this module that imports `go.opentelemetry.io/otel`; the core
  package stays telemetry-free.
- [`pgp`](pgp) -- PGP/MIME (RFC 3156): a `Signer`, an `Encryptor`, and a
  `SignEncrypt` middleware that signs, encrypts, and gives each Bcc
  recipient its own copy, plus `Verify` and `Decrypt` for inbound mail.
  Decryption fails closed on any integrity error. Built on
  `ProtonMail/go-crypto`; logs through `go-log` and is silent by default.

## 🛠 Develop

```bash
task build    # go build ./...
task test     # go test ./...
task lint     # gofmt check + golangci-lint + yamllint
task ci       # build + vet + lint
task license  # verify every source file carries the MIT header
task interop  # round-trip PGP/MIME through a local gpg
```

## ⚖️ License

MIT © 2026 Shane
