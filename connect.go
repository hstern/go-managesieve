// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"context"
	"crypto/tls"
	"errors"
)

// connectConfig holds the options applied by Connect.
type connectConfig struct {
	useTLS       bool
	tlsConfig    *tls.Config
	newAuth      func() SASLClient
	maxReferrals int
}

// ConnectOption configures Connect.
type ConnectOption func(*connectConfig)

// WithStartTLS makes Connect upgrade the connection with STARTTLS (using
// cfg, which may be nil for defaults) before authenticating.
func WithStartTLS(cfg *tls.Config) ConnectOption {
	return func(c *connectConfig) {
		c.useTLS = true
		c.tlsConfig = cfg
	}
}

// WithAuth makes Connect authenticate after connecting. newMech is called
// once per connection attempt to obtain a fresh SASL mechanism, so a
// referral that forces a reconnect re-runs authentication cleanly.
func WithAuth(newMech func() SASLClient) ConnectOption {
	return func(c *connectConfig) { c.newAuth = newMech }
}

// WithMaxReferrals caps how many REFERRAL redirects Connect will follow
// before giving up (default 5). A value < 0 disables following.
func WithMaxReferrals(n int) ConnectOption {
	return func(c *connectConfig) { c.maxReferrals = n }
}

// Connect dials a ManageSieve server and optionally upgrades to TLS and
// authenticates, transparently following REFERRAL responses (RFC 5804
// §1.3) to the referred server up to the configured hop limit. It returns
// a ready-to-use Client.
//
// Referrals are followed for failures surfaced as *ReferralError at any
// of the connect, STARTTLS, or authentication steps. Each redirect dials
// the new target with the same options.
func Connect(ctx context.Context, addr string, opts ...ConnectOption) (*Client, error) {
	cfg := connectConfig{maxReferrals: 5}
	for _, o := range opts {
		o(&cfg)
	}

	hops := 0
	for {
		c, err := connectOnce(ctx, addr, &cfg)
		if err == nil {
			return c, nil
		}
		var ref *ReferralError
		if errors.As(err, &ref) && cfg.maxReferrals >= 0 && hops < cfg.maxReferrals {
			hops++
			addr = ref.Addr()
			continue
		}
		return nil, err
	}
}

// connectOnce performs a single dial + optional STARTTLS + optional auth,
// closing the connection if a later step fails.
func connectOnce(ctx context.Context, addr string, cfg *connectConfig) (*Client, error) {
	c, err := Dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	if cfg.useTLS {
		if err := c.StartTLS(cfg.tlsConfig); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	if cfg.newAuth != nil {
		if err := c.Authenticate(cfg.newAuth()); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	return c, nil
}
