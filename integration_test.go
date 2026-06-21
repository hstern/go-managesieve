// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

//go:build managesieve_integration

// Integration tests against a live ManageSieve server (e.g. Dovecot
// Pigeonhole). They are excluded from the default build and run only with
//
//	go test -tags managesieve_integration
//
// configured via environment:
//
//	MANAGESIEVE_ADDR  host[:port] of the server (default port 4190)
//	MANAGESIEVE_USER  username for PLAIN authentication
//	MANAGESIEVE_PASS  password for PLAIN authentication
//	MANAGESIEVE_TLS   "starttls" (default), "implicit", or "none"
//	MANAGESIEVE_INSECURE  "1" to skip TLS certificate verification
package managesieve

import (
	"context"
	"crypto/tls"
	"os"
	"testing"
	"time"
)

func liveClient(t *testing.T) *Client {
	t.Helper()
	addr := os.Getenv("MANAGESIEVE_ADDR")
	if addr == "" {
		t.Skip("MANAGESIEVE_ADDR not set; skipping integration test")
	}
	user, pass := os.Getenv("MANAGESIEVE_USER"), os.Getenv("MANAGESIEVE_PASS")
	mode := os.Getenv("MANAGESIEVE_TLS")
	if mode == "" {
		mode = "starttls"
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: os.Getenv("MANAGESIEVE_INSECURE") == "1"}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var c *Client
	var err error
	if mode == "implicit" {
		c, err = DialTLS(ctx, addr, tlsCfg)
	} else {
		c, err = Dial(ctx, addr)
	}
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if mode == "starttls" {
		if err := c.StartTLS(tlsCfg); err != nil {
			t.Fatalf("StartTLS: %v", err)
		}
	}
	if user != "" {
		if err := c.Authenticate(PlainAuth("", user, pass)); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	}
	return c
}

func TestIntegrationLifecycle(t *testing.T) {
	c := liveClient(t)
	defer c.Logout()

	const name = "go_managesieve_itest"
	const body = "require [\"fileinto\"];\r\nfileinto \"INBOX\";\r\n"

	if _, err := c.CheckScript(body); err != nil {
		t.Fatalf("CheckScript: %v", err)
	}
	if _, err := c.PutScript(name, body); err != nil {
		t.Fatalf("PutScript: %v", err)
	}
	t.Cleanup(func() {
		_ = c.SetActive("")
		_ = c.DeleteScript(name)
	})

	got, err := c.GetScript(name)
	if err != nil {
		t.Fatalf("GetScript: %v", err)
	}
	if got != body {
		t.Fatalf("GetScript not byte-exact:\n got %q\nwant %q", got, body)
	}
	if err := c.SetActive(name); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	scripts, err := c.ListScripts()
	if err != nil {
		t.Fatalf("ListScripts: %v", err)
	}
	var sawActive bool
	for _, s := range scripts {
		if s.Name == name && s.Active {
			sawActive = true
		}
	}
	if !sawActive {
		t.Fatalf("uploaded script not active in listing: %+v", scripts)
	}
}
