# go-managesieve

[![Go Reference](https://pkg.go.dev/badge/github.com/hstern/go-managesieve.svg)](https://pkg.go.dev/github.com/hstern/go-managesieve)

A Go client for **[RFC 5804](https://www.rfc-editor.org/rfc/rfc5804.html)
— A Protocol for Remotely Managing Sieve Scripts (ManageSieve)**.

ManageSieve is a small, line-oriented protocol for managing the Sieve
scripts a mail server runs on delivery (Dovecot Pigeonhole, Cyrus, …):
upload, download, list, activate, delete, rename, and remotely check
scripts. This library implements **both roles** — a **client** and a
**server** (the server's logic behind a small `Backend`/`Session`
interface, in the `emersion/go-smtp` style). It treats script bodies as
opaque UTF-8 blobs — it does not parse, validate, or evaluate Sieve
itself (that is the server backend's job, via `CHECKSCRIPT`).

> Status: pre-publication. The API may change until `v1.0.0`.

## Install

```sh
go get github.com/hstern/go-managesieve
```

## Quick start

```go
ctx := context.Background()

c, err := managesieve.Dial(ctx, "mail.example.com")
if err != nil {
	log.Fatal(err)
}
defer c.Logout()

// Upgrade to TLS and re-read capabilities, then authenticate.
if err := c.StartTLS(&tls.Config{ServerName: "mail.example.com"}); err != nil {
	log.Fatal(err)
}
if err := c.Authenticate(managesieve.PlainAuth("", "user", "secret")); err != nil {
	log.Fatal(err)
}

// Upload a script and make it active.
if err := c.PutScript("main", "require \"fileinto\";\nfileinto \"INBOX\";\n"); err != nil {
	log.Fatal(err)
}
if err := c.SetActive("main"); err != nil {
	log.Fatal(err)
}
```

## Scope

**In:** a shared wire core (CRLF framing, `{n+}`/`{n}` literals, a typed
`OK`/`NO`/`BYE` response model with structured response codes); a
**client** (connect, STARTTLS with capability re-negotiation, SASL
`AUTHENTICATE`, the full command set — `PUTSCRIPT`, `GETSCRIPT`,
`LISTSCRIPTS`, `SETACTIVE`, `DELETESCRIPT`, `RENAMESCRIPT`,
`CHECKSCRIPT`, `HAVESPACE`, `NOOP`, `LOGOUT`); and a **server**
(`Serve(net.Listener)` + a consumer-implemented `Backend`/`Session`
that owns script storage and credential checks). SASL is pluggable on
both ends, with a built-in `PLAIN`.

**Out:** executing or validating Sieve locally, and generating Sieve
from a rule model — both are RFC 5228, owned by the sibling
[`go-sieve`](https://github.com/hstern/go-sieve). The server transports
opaque script blobs and delegates validation to its backend.

## License

[Apache-2.0](LICENSE).
