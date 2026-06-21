# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-21

### Added

- The client re-reads capabilities after a successful `Authenticate`, so
  post-authentication additions such as the `OWNER` capability appear in
  `Capabilities()`. The server advertises `OWNER` when its `Session`
  implements the optional `SessionOwner` interface.
- `Client.RenameScriptFallback`, an opt-in copy-based rename for servers
  that predate RFC 5804 and lack the `RENAMESCRIPT` command.
- `Connect` with `WithStartTLS` / `WithAuth` / `WithMaxReferrals`: dials,
  optionally upgrades TLS and authenticates, and transparently follows
  `REFERRAL` redirects to the referred server (capped). `ReferralError`
  gains `Addr()` to parse the `sieve://` target into a dialable host:port.
- Built-in SASL client mechanisms beyond PLAIN: `External` (EXTERNAL),
  `OAuthBearer` (OAUTHBEARER, RFC 7628), and `ScramSHA256` (SCRAM-SHA-256,
  RFC 7677, with mutual server-signature verification) — all standard
  library only.
- `Pool`: a concurrency-safe connection pool over `Connect`, with
  `Get`/`Put`, a `Do` helper that auto-reconnects on transport errors
  (but not on protocol errors), NOOP health checks, and a bounded idle
  set.

## [0.1.0] - 2026-06-21

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
- `Server.ReadTimeout` / `Server.WriteTimeout` for per-command deadlines.
- `SASLFinalReceiver`, an optional `SASLClient` interface that receives
  the server's final `(SASL ...)` data (e.g. for mutual-auth mechanisms);
  the server emits it from a `SASLServer` that returns final data on
  completion.
- Conformance tests against the RFC 5804 §2 examples, a client⇄server
  loopback suite, and a build-tagged live-server integration test.

[Unreleased]: https://github.com/hstern/go-managesieve/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/hstern/go-managesieve/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hstern/go-managesieve/releases/tag/v0.1.0
