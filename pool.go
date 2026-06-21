// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"context"
	"errors"
	"sync"
)

// ErrPoolClosed is returned by a closed Pool's Get and Do.
var ErrPoolClosed = errors.New("managesieve: pool is closed")

// Pool maintains a bounded set of reusable, already-established Client
// connections to a single server, recreating them on demand. A single
// Client is not safe for concurrent use; a Pool hands a Client to one
// caller at a time (via Get/Put or Do) and is itself safe for concurrent
// use by multiple goroutines.
//
// Connections are made with Connect, so a Pool inherits transparent
// STARTTLS, authentication, and REFERRAL following from its options.
type Pool struct {
	addr    string
	opts    []ConnectOption
	maxIdle int

	mu     sync.Mutex
	idle   []*Client
	closed bool
}

// NewPool returns a Pool that dials addr (keeping at most maxIdle idle
// connections) using the given Connect options — typically WithStartTLS
// and WithAuth so pooled connections are ready to use.
func NewPool(addr string, maxIdle int, opts ...ConnectOption) *Pool {
	if maxIdle < 1 {
		maxIdle = 1
	}
	return &Pool{addr: addr, opts: opts, maxIdle: maxIdle}
}

// Get returns a ready Client, reusing an idle connection when one is
// healthy (verified with NOOP) or establishing a new one otherwise. The
// caller must return it with Put when done.
func (p *Pool) Get(ctx context.Context) (*Client, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, ErrPoolClosed
		}
		var c *Client
		if n := len(p.idle); n > 0 {
			c = p.idle[n-1]
			p.idle = p.idle[:n-1]
		}
		p.mu.Unlock()

		if c == nil {
			break
		}
		if err := c.Noop(""); err == nil {
			return c, nil // healthy: reuse
		}
		_ = c.Close() // stale: drop and try the next idle / a fresh dial
	}
	return Connect(ctx, p.addr, p.opts...)
}

// Put returns a Client to the pool. A Client beyond the idle cap, or one
// returned to a closed pool, is logged out instead of retained.
func (p *Pool) Put(c *Client) {
	if c == nil {
		return
	}
	p.mu.Lock()
	if p.closed || len(p.idle) >= p.maxIdle {
		p.mu.Unlock()
		_ = c.Logout()
		return
	}
	p.idle = append(p.idle, c)
	p.mu.Unlock()
}

// Do runs fn with a pooled Client, returning the Client afterward. If fn
// fails with a transport error (not a *ServerError or *ReferralError,
// which are protocol-level), the connection is discarded and fn is
// retried once on a fresh connection — transparent auto-reconnect.
func (p *Pool) Do(ctx context.Context, fn func(*Client) error) error {
	var lastErr error
	for range 2 {
		c, err := p.Get(ctx)
		if err != nil {
			return err
		}
		err = fn(c)
		if err == nil {
			p.Put(c)
			return nil
		}
		var se *ServerError
		var re *ReferralError
		if errors.As(err, &se) || errors.As(err, &re) {
			p.Put(c) // protocol error: connection is still usable
			return err
		}
		_ = c.Close() // transport error: discard and retry
		lastErr = err
	}
	return lastErr
}

// Close logs out and discards all idle connections. Connections currently
// checked out are unaffected; returning them via Put will log them out.
func (p *Pool) Close() error {
	p.mu.Lock()
	p.closed = true
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()

	var firstErr error
	for _, c := range idle {
		if err := c.Logout(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
