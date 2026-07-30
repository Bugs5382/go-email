# go-email 📧

> A small, dependency-light email client for Go: a full RFC 5322 envelope, multipart (alternative/mixed/related) rendering, and a middleware hook chain around a pluggable `Transport`.

## 📦 Install

```bash
go get github.com/Bugs5382/go-email
```

## 🚀 Usage

`go-email` is under active development. The package exposes neutral interfaces
(`Transport`, `Renderer`, `Sender`) so a consumer never has to import `net/smtp`
or `mime/multipart` directly: it depends on the interface, and the default
`SMTPTransport` speaks `net/smtp` with an optional STARTTLS+auth relay path or
a plaintext no-auth path for local catchers (for example a `maildev`-style
container on `localhost:1025`).

When both an HTML and a plaintext body are set, the message renders as
`multipart/alternative` -- the plaintext body is a first-class fallback, not
an afterthought. `Bcc` recipients are only ever passed to the transport's
envelope (SMTP `RCPT TO`); they are never written into a message header.

Usage examples land alongside the exported surface as it is built out.

## 🛠 Develop

```bash
task build    # go build ./...
task test     # go test ./...
task lint     # gofmt check + golangci-lint + yamllint
task license  # inject MIT headers (golic)
```

## ⚖️ License

MIT © 2026 Shane
