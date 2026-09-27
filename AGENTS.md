# AGENTS.md - go-email

Guide for AI agents working in this repository. Pair with `CLAUDE.md` (the working agreement and
hook-enforced rules). Keep this file current when the build, layout, or public API changes.

## What this is

A small, dependency-light email client for Go: a full RFC 5322 envelope, multipart
(alternative/mixed/related) rendering, and a middleware hook chain around a pluggable `Transport`.
The package exposes neutral interfaces (`Transport`, `Renderer`, `Sender`) so a consumer never
imports `net/smtp` or `mime/multipart` directly. The default `SMTPTransport` speaks `net/smtp` with
an optional STARTTLS+auth relay path and a plaintext no-auth path for local catchers.

## Using go-email

- Depend on the neutral interfaces (`Transport`, `Renderer`, `Sender`), never on a concrete
  implementation type; no `net/smtp` (or other transport-library) type appears in the exported
  surface.
- `Bcc` recipients are envelope-only (SMTP `RCPT TO`) and must never be written to a message header.
- When both `HTML` and `Text` are set on a message, it renders as `multipart/alternative`: the
  plaintext body is a first-class fallback, not an afterthought.
- `Message.Bytes` rejects a CR or LF in any header value, attachment filename, content type, or
  Content-ID with `ErrInvalidHeader` (and `Validate` reports it too), so header injection is
  impossible. Non-ASCII Subject text and display names are RFC 2047 encoded, non-ASCII filenames
  use RFC 2231 plus an RFC 2047 fallback, custom headers render in sorted order, and `Date` and
  `Message-ID` are generated unless set in `Headers`. `Content-Type`,
  `Content-Transfer-Encoding` and `MIME-Version` cannot be set through `Headers`.
- `Message.Entity()` returns the body as one encoded `Part`; `Part.Bytes()` is its canonical
  form, and every nested part is written with it, so a signature over it survives rendering. When
  `Message.Body` is set it replaces HTML/Text/Attachments. Text parts use our own QP encoder
  (`encodeQP` in `part.go`), which also escapes `From ` at the start of a line.
- `Sign` and `Encrypt` hand the hook a deep-enough copy (`Message.clone`) and pass that copy on,
  so the caller's message and any outer middleware (Retry, Record) never see the hook's changes.
- `SplitBcc` sends one copy to To+Cc and one per Bcc address, using `Message.EnvelopeTo` to limit
  RCPT TO while keeping the To/Cc headers. Put it outside `Encrypt` and put `Retry` inside it.
- The core package stays telemetry-free; OpenTelemetry integration lives only in an `email/otel`
  subpackage, imported separately.
- `pgp` is PGP/MIME (RFC 3156) on `github.com/ProtonMail/go-crypto/openpgp/v2`. Never import
  `golang.org/x/crypto/openpgp` (deprecated, unsafe); a depguard rule in `.golangci.yml` blocks
  it. No go-crypto type appears in the exported API: keys are the opaque `*pgp.Key`, and a `Key`
  formats and logs as its fingerprint only. The rules it enforces: sign before encrypt
  (`ErrAlreadyEncrypted`), the signing key must own the From address, a missing recipient key
  fails closed (`MissingKeyError`) unless `MissingKeyPlaintext` is set, `SignEncrypt` gives each
  Bcc recipient a separate copy and a bare `Encryptor` refuses a shared Bcc copy, and RSA under
  2048 bits, DSA and ElGamal are refused. `Verify` and `Decrypt` only trust a signature by a key
  bound to the single From address; `Decrypt` only opens a top-level two-part
  `multipart/encrypted`, reads the whole message before trusting it, and on any MDC, AEAD,
  truncation or signature failure returns an error and no plaintext.
- `pgp` logs through the `go-log` `Logger` passed with `WithLogger` (silent by default): key
  fingerprints, counts, sizes and durations only. Addresses are logged as `addr_id`, a keyed hash
  that is random per process. Never log message content, passphrases, key material or addresses.
- `internal/mimeparse` is the strict raw-MIME reader behind `Verify`/`Decrypt`: it keeps each
  part's exact bytes (what a detached signature covers) and fails closed on ambiguous structure.

## Layout

- `doc.go` - package documentation and the MIT license header.
- `doc_test.go` - a trivial compile-check test; replaced/extended as the real surface lands.
- `pgp/` - PGP/MIME: `key.go` (the `Key` wrapper and strength checks), `store.go` (`KeyStore`,
  `MemStore`, `LoadDir`, `Chain`), `sign.go`, `encrypt.go` (`Encryptor`, `SignEncrypt`),
  `verify.go` (`Verify`, `Decrypt`), `mime.go` (RFC 3156 framing), `options.go`, `log.go`.
  `interop_test.go` (build tag `interop`) runs against gpg; `fuzz_test.go` fuzzes every parser.
- `internal/mimeparse/` - the raw-MIME reader used by `pgp` for inbound mail.

This section grows as the envelope, renderer, transport, and middleware chain are implemented in
later tasks; update it alongside each new file.

## Build, test, lint

- Build: `task build` (`go build ./...`)
- Test: `task test` (`go test ./...`); no external service/fixture required.
- Lint: `task lint` (gofmt check + `golangci-lint run` + `yamllint .`)
- GnuPG interop: `task interop` (`go test -tags interop -run Interop ./pgp/`); needs `gpg` on
  PATH and runs in CI. Keys GnuPG must hold secretly are generated by gpg itself in the test.
- Full local gate: `task ci` (build + `go vet` + test + lint)
- License headers: `task license` (check) / `task license:fix` (inject)

## Conventions and gotchas

- See `CLAUDE.md` for the branch/commit/PR rules; they are enforced by the git hooks in
  `.claude/hooks` (run `bash .claude/hooks/install.sh` once per clone).
- This is a **public** repository: never introduce internal hostnames, service names, or
  organization-specific identifiers. Use generic placeholders (`localhost:1025`,
  `no-reply@example.com`, a `smtp`/`mailhog`-style catcher host) in code, tests, and docs.
- Any change to an exported interface is a public-API change: keep it additive (non-breaking)
  unless the change is explicitly scoped as a major version bump, and update this file plus the
  README when the surface changes.
