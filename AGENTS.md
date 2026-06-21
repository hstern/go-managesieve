# Contributing to go-managesieve

`go-managesieve` is a Go implementation of [RFC 5804 — A Protocol for
Remotely Managing Sieve Scripts (ManageSieve)](https://www.rfc-editor.org/rfc/rfc5804.html),
providing both a client and a server role over a shared wire core.

## Ground rules

- **Standard library only at runtime** (see Dependencies below).
- **Wire fidelity over ergonomics.** Where the spec says X, the library
  round-trips X verbatim. Script bodies are opaque UTF-8 octets and must
  survive a `PutScript` → `GetScript` cycle byte-for-byte.
- **Lenient on the wire, strict on our own output.** Parse defensively
  (tolerate unknown capabilities and response codes); reject our own
  malformed arguments early.
- Every Go source file (including tests) starts with the two-line
  header:

  ```go
  // Copyright 2026 The go-managesieve Authors
  // SPDX-License-Identifier: Apache-2.0
  ```

## Building and testing

```sh
go build ./...
go test -race ./...
go vet ./...
gofmt -l .          # must print nothing
```

CI runs three required checks on every PR: `static`, `test`, `lint`.

## Dependencies

- **Runtime: standard library only, with one exception class.**
  A non-stdlib runtime dependency is acceptable only when (a) it
  implements a validator no reasonable hand-coding could match
  (libphonenumber-class data: country code numbering plan,
  per-country length rules, IDN normalization tables); (b) it is
  well-maintained and widely used in the Go ecosystem; and
  (c) the alternative is the library quietly accepting input the
  spec rejects. Any other runtime dep needs a discussion and a
  justification in the PR description. Default answer is still
  "no" — the bar is "the spec demands data we cannot reasonably
  ship ourselves."
- **Tests: standard library only by default.** Test-only deps
  still need a one-line justification.
- **Build-time tooling: unconstrained.** Generators, linters,
  release tooling, and similar live under `tools/` (separate
  `go.mod`) or are invoked via `go run` with a pinned version;
  they never end up in library users' `go.sum`.
- **`go.mod`**: keep the `module` path stable at
  `github.com/hstern/go-managesieve` (no `/vN` suffix for v0.x/v1.x —
  Go SemVer rule). Major-version bumps follow the `go-jose` branch
  pattern.
