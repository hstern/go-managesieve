// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

// Package managesieve implements a client for the ManageSieve protocol
// (RFC 5804 — A Protocol for Remotely Managing Sieve Scripts).
//
// ManageSieve is a line-oriented, IMAP-flavoured protocol for managing
// the Sieve scripts a mail server runs on delivery: uploading,
// downloading, listing, activating, deleting, renaming, and remotely
// checking them. This package speaks the protocol as a client; it treats
// script bodies as opaque UTF-8 blobs and never parses, validates, or
// evaluates Sieve itself (the server does that, via CHECKSCRIPT).
//
// A typical session:
//
//	c, err := managesieve.Dial(ctx, "mail.example.com")
//	if err != nil { /* ... */ }
//	defer c.Logout()
//	if err := c.StartTLS(tlsConfig); err != nil { /* ... */ }
//	if err := c.Authenticate(managesieve.PlainAuth("", "user", "pass")); err != nil { /* ... */ }
//	if err := c.PutScript("main", scriptBody); err != nil { /* ... */ }
//	if err := c.SetActive("main"); err != nil { /* ... */ }
//
// The package targets RFC 5804 and is verified against Dovecot
// Pigeonhole.
package managesieve

// SpecVersion is the ManageSieve specification this build implements.
const SpecVersion = "RFC 5804"
