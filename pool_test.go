// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"context"
	"errors"
	"net"
	"testing"
)

// tcpServer starts a real TCP ManageSieve server backed by an in-memory
// store and returns its address plus a stop function.
func tcpServer(t *testing.T) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(newMemBackend())
	go func() { _ = srv.Serve(l) }()
	return l.Addr().String(), func() { _ = l.Close() }
}

func plainPool(t *testing.T, maxIdle int) (*Pool, func()) {
	t.Helper()
	addr, stop := tcpServer(t)
	p := NewPool(addr, maxIdle, WithAuth(func() SASLClient {
		return PlainAuth("", "alice", "secret")
	}))
	return p, func() { _ = p.Close(); stop() }
}

func TestPoolReusesIdleConnection(t *testing.T) {
	p, cleanup := plainPool(t, 2)
	defer cleanup()
	ctx := context.Background()

	c1, err := p.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := c1.PutScript("s", "stop;\r\n"); err != nil {
		t.Fatalf("PutScript: %v", err)
	}
	p.Put(c1)

	c2, err := p.Get(ctx)
	if err != nil {
		t.Fatalf("Get (2): %v", err)
	}
	if c1 != c2 {
		t.Fatal("expected the idle connection to be reused")
	}
	p.Put(c2)
}

func TestPoolReplacesStaleConnection(t *testing.T) {
	p, cleanup := plainPool(t, 2)
	defer cleanup()
	ctx := context.Background()

	c, err := p.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.Put(c)
	_ = c.Close() // kill the idle connection underneath the pool

	c2, err := p.Get(ctx)
	if err != nil {
		t.Fatalf("Get after stale: %v", err)
	}
	if c2 == c {
		t.Fatal("expected a fresh connection, got the dead one")
	}
	if _, err := c2.ListScripts(); err != nil {
		t.Fatalf("fresh connection unusable: %v", err)
	}
	p.Put(c2)
}

func TestPoolDoSuccessAndProtocolError(t *testing.T) {
	p, cleanup := plainPool(t, 2)
	defer cleanup()
	ctx := context.Background()

	if err := p.Do(ctx, func(c *Client) error {
		_, err := c.PutScript("s", "stop;\r\n")
		return err
	}); err != nil {
		t.Fatalf("Do success: %v", err)
	}

	// A protocol error propagates and is not retried away.
	err := p.Do(ctx, func(c *Client) error { return c.DeleteScript("nope") })
	var se *ServerError
	if !errors.As(err, &se) || se.CodeName() != CodeNonexistent {
		t.Fatalf("Do protocol error = %v, want NONEXISTENT", err)
	}
}

func TestPoolClosed(t *testing.T) {
	p, cleanup := plainPool(t, 1)
	cleanup() // closes the pool
	if _, err := p.Get(context.Background()); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("Get on closed pool = %v, want ErrPoolClosed", err)
	}
}
