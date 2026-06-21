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

// Upload a script and make it active. PutScript also returns any
// non-fatal compiler warnings the server reported.
if _, err := c.PutScript("main", "require \"fileinto\";\nfileinto \"INBOX\";\n"); err != nil {
	log.Fatal(err)
}
if err := c.SetActive("main"); err != nil {
	log.Fatal(err)
}
```

## Serving

Implement `Backend` and `Session` (embed `UnimplementedSession` to supply
only the commands you support) and hand them to a `Server`:

```go
type backend struct{ /* your script store */ }

func (b *backend) NewSession(*managesieve.ServerConn) (managesieve.Session, error) {
	return &session{}, nil
}

type session struct {
	managesieve.UnimplementedSession // "not implemented" defaults
}

func (*session) AuthMechanisms() []string { return []string{"PLAIN"} }

func (*session) Authenticate(mech string) (managesieve.SASLServer, error) {
	return managesieve.PlainServer(func(_, user, pass string) error {
		// check user/pass against your store; return an error to reject
		return nil
	}), nil
}

// ...implement ListScripts / GetScript / PutScript / SetActive / ...

func main() {
	l, _ := net.Listen("tcp", ":4190")
	srv := managesieve.NewServer(&backend{})
	srv.SieveExtensions = []string{"fileinto", "vacation"}
	// srv.TLSConfig = ... // advertise STARTTLS and require TLS for auth
	log.Fatal(srv.Serve(l))
}
```

The server owns the wire protocol and session state machine (greeting,
STARTTLS, the SASL exchange, command parsing, response framing); your
`Session` owns script storage and credential checks. Return a
`*managesieve.ServerError` from a `Session` method to control the
response code (e.g. `NONEXISTENT`, a `QUOTA` code).

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
