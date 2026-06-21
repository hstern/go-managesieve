// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve_test

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"

	"github.com/hstern/go-managesieve"
)

// Example shows the common client flow: connect, upgrade to TLS,
// authenticate, then upload and activate a script.
func Example() {
	ctx := context.Background()

	c, err := managesieve.Dial(ctx, "mail.example.com")
	if err != nil {
		log.Print(err)
		return
	}
	defer func() { _ = c.Logout() }()

	if err := c.StartTLS(&tls.Config{ServerName: "mail.example.com"}); err != nil {
		log.Print(err)
		return
	}
	if err := c.Authenticate(managesieve.PlainAuth("", "user", "secret")); err != nil {
		log.Print(err)
		return
	}

	const script = "require [\"fileinto\"];\nfileinto \"INBOX\";\n"
	if warnings, err := c.PutScript("main", script); err != nil {
		log.Print(err)
		return
	} else if warnings != "" {
		log.Printf("script stored with warnings: %s", warnings)
	}
	if err := c.SetActive("main"); err != nil {
		log.Print(err)
		return
	}
}

// ExampleClient_ListScripts lists scripts and reports which is active.
func ExampleClient_ListScripts() {
	var c *managesieve.Client // obtained via Dial + Authenticate

	scripts, err := c.ListScripts()
	if err != nil {
		log.Fatal(err)
	}
	for _, s := range scripts {
		if s.Active {
			log.Printf("%s (active)", s.Name)
		} else {
			log.Printf("%s", s.Name)
		}
	}
}

// fileStore is a minimal Backend that keeps scripts in memory. A real
// backend would persist them and check credentials against a user store.
type fileStore struct{}

func (fileStore) NewSession(*managesieve.ServerConn) (managesieve.Session, error) {
	return &fileSession{}, nil
}

type fileSession struct {
	managesieve.UnimplementedSession
}

func (*fileSession) AuthMechanisms() []string { return []string{"PLAIN"} }

func (*fileSession) Authenticate(mech string) (managesieve.SASLServer, error) {
	if mech != "PLAIN" {
		return nil, errors.New("unsupported mechanism")
	}
	return managesieve.PlainServer(func(_, username, password string) error {
		// Replace with a real credential check against your user store.
		if username == "" || password == "" {
			return errors.New("invalid credentials")
		}
		return nil
	}), nil
}

// Example_server stands up a ManageSieve server backed by a custom store.
func Example_server() {
	l, err := net.Listen("tcp", ":4190")
	if err != nil {
		log.Fatal(err)
	}
	srv := managesieve.NewServer(fileStore{})
	srv.SieveExtensions = []string{"fileinto", "vacation"}
	// srv.TLSConfig = ... // set to advertise STARTTLS and require TLS for auth
	log.Fatal(srv.Serve(l))
}
