# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Shared wire core: CRLF framing, quoted strings, `{n+}`/`{n}` literals,
  a typed `OK`/`NO`/`BYE` response model with structured `ResponseCode`s,
  and `ServerError` / `ReferralError`.
- Client: `Dial`, `DialTLS`, `NewClient`, in-place `StartTLS` with
  capability re-negotiation, SASL `Authenticate` (pluggable `SASLClient`,
  built-in `PlainAuth`), and the full command set (`PutScript`,
  `GetScript`, `ListScripts`, `SetActive`, `DeleteScript`,
  `RenameScript`, `CheckScript`, `HaveSpace`, `Noop`, `Logout`).
- Server: `Server`/`Serve` with a consumer-implemented `Backend` /
  `Session` (and `UnimplementedSession`), STARTTLS, the server-side SASL
  exchange (`SASLServer`, built-in `PlainServer`), pre-/post-auth gating,
  and `ENCRYPT-NEEDED` enforcement.
- Conformance tests against the RFC 5804 §2 examples, a client⇄server
  loopback suite, and a build-tagged live-server integration test.
- `Server.ReadTimeout` / `Server.WriteTimeout` for per-command deadlines.
- `SASLFinalReceiver`, an optional `SASLClient` interface that receives
  the server's final `(SASL ...)` data (e.g. for mutual-auth mechanisms);
  the server emits it from a `SASLServer` that returns final data on
  completion.
