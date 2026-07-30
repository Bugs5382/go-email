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
- The core package stays telemetry-free; OpenTelemetry integration lives only in an `email/otel`
  subpackage, imported separately.

## Layout

- `doc.go` - package documentation and the MIT license header.
- `doc_test.go` - a trivial compile-check test; replaced/extended as the real surface lands.

This section grows as the envelope, renderer, transport, and middleware chain are implemented in
later tasks; update it alongside each new file.

## Build, test, lint

- Build: `task build` (`go build ./...`)
- Test: `task test` (`go test ./...`); no external service/fixture required.
- Lint: `task lint` (gofmt check + `golangci-lint run` + `yamllint .`)
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
