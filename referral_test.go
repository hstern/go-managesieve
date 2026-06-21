// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"context"
	"net"
	"testing"
)

func TestReferralErrorAddr(t *testing.T) {
	cases := []struct{ url, want string }{
		{"sieve://mail.example.com", "mail.example.com:4190"},
		{"sieve://mail.example.com:5190", "mail.example.com:5190"},
		{"sieve://user@mail.example.com", "mail.example.com:4190"},
		{"sieve://[2001:db8::1]:4190", "[2001:db8::1]:4190"},
	}
	for _, tc := range cases {
		got := (&ReferralError{URL: tc.url}).Addr()
		if got != tc.want {
			t.Errorf("Addr(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

// referralListener accepts one connection, writes a BYE REFERRAL to the
// given target, and closes — emulating a server that redirects clients.
func referralListener(t *testing.T, target string) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("BYE (REFERRAL \"sieve://" + target + "\") \"Try elsewhere\"\r\n"))
			_ = conn.Close()
		}
	}()
	return l
}

func TestConnectFollowsReferral(t *testing.T) {
	// Real server B on a TCP listener.
	lb, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lb.Close() }()
	srv := NewServer(newMemBackend())
	go func() { _ = srv.Serve(lb) }()

	// Referring server A points at B.
	la := referralListener(t, lb.Addr().String())
	defer func() { _ = la.Close() }()

	c, err := Connect(context.Background(), la.Addr().String(),
		WithAuth(func() SASLClient { return PlainAuth("", "alice", "secret") }))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = c.Logout() }()

	// We landed on B (authenticated) and can drive commands.
	if _, err := c.PutScript("s", "stop;\r\n"); err != nil {
		t.Fatalf("PutScript after referral: %v", err)
	}
}

func TestConnectReferralLoopCapped(t *testing.T) {
	// A server that always refers to itself; Connect must give up.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	self := l.Addr().String()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("BYE (REFERRAL \"sieve://" + self + "\") \"loop\"\r\n"))
			_ = conn.Close()
		}
	}()

	_, err = Connect(context.Background(), self, WithMaxReferrals(3))
	var ref *ReferralError
	if !asReferralError(err, &ref) {
		t.Fatalf("want *ReferralError after exhausting hops, got %v", err)
	}
}
