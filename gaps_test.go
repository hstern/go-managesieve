// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// recordConn wraps a net.Conn and counts deadline calls, so a test can
// assert the server applies its configured timeouts without relying on
// wall-clock timing.
type recordConn struct {
	net.Conn
	mu     sync.Mutex
	reads  int
	writes int
}

func (r *recordConn) SetReadDeadline(t time.Time) error {
	r.mu.Lock()
	r.reads++
	r.mu.Unlock()
	return r.Conn.SetReadDeadline(t)
}

func (r *recordConn) SetWriteDeadline(t time.Time) error {
	r.mu.Lock()
	r.writes++
	r.mu.Unlock()
	return r.Conn.SetWriteDeadline(t)
}

func (r *recordConn) counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reads, r.writes
}

func TestServerAppliesDeadlines(t *testing.T) {
	srv := NewServer(newMemBackend())
	srv.ReadTimeout = time.Minute
	srv.WriteTimeout = time.Minute

	cconn, sconn := net.Pipe()
	rec := &recordConn{Conn: sconn}
	go srv.serveConn(rec)

	c, err := NewClient(cconn)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Authenticate(PlainAuth("", "alice", "secret")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, err := c.ListScripts(); err != nil {
		t.Fatalf("ListScripts: %v", err)
	}
	reads, writes := rec.counts()
	if reads == 0 || writes == 0 {
		t.Fatalf("expected read and write deadlines to be applied, got reads=%d writes=%d", reads, writes)
	}
}

func TestServerNoDeadlinesByDefault(t *testing.T) {
	// With zero timeouts, the server must not touch deadlines at all.
	srv := NewServer(newMemBackend())
	cconn, sconn := net.Pipe()
	rec := &recordConn{Conn: sconn}
	go srv.serveConn(rec)

	c, err := NewClient(cconn)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Authenticate(PlainAuth("", "alice", "secret")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if reads, writes := rec.counts(); reads != 0 || writes != 0 {
		t.Fatalf("expected no deadline calls, got reads=%d writes=%d", reads, writes)
	}
}

// --- toy mutual-auth mechanism exercising the SASL-final path ---

const echoMech = "X-ECHO"

type echoClient struct {
	token  string
	final  []byte
	called bool
}

func (e *echoClient) Start() (string, []byte, error) { return echoMech, []byte(e.token), nil }
func (e *echoClient) Next([]byte) ([]byte, error) {
	return nil, errors.New("X-ECHO expects no challenge")
}

func (e *echoClient) SASLFinal(data []byte) error {
	e.called = true
	e.final = data
	if string(data) != "ack:"+e.token {
		return errors.New("bad server-final signature")
	}
	return nil
}

type echoServer struct{}

func (echoServer) Next(response []byte) ([]byte, bool, error) {
	if response == nil {
		return []byte{}, false, nil
	}
	// Accept and return a server-final acknowledgement.
	return append([]byte("ack:"), response...), true, nil
}

// echoBackend is a memBackend that also offers the X-ECHO mechanism.
type echoBackend struct{ *memBackend }

func (b echoBackend) NewSession(*ServerConn) (Session, error) {
	return &echoSession{memSession{be: b.memBackend}}, nil
}

type echoSession struct{ memSession }

func (echoSession) AuthMechanisms() []string { return []string{"PLAIN", echoMech} }
func (s echoSession) Authenticate(mech string) (SASLServer, error) {
	if mech == echoMech {
		return echoServer{}, nil
	}
	return s.memSession.Authenticate(mech)
}

func TestSASLFinalDelivered(t *testing.T) {
	srv := NewServer(echoBackend{newMemBackend()})
	c := dialLoopback(t, srv)
	defer func() { _ = c.Close() }()

	mech := &echoClient{token: "hello"}
	if err := c.Authenticate(mech); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !mech.called {
		t.Fatal("SASLFinal was not called")
	}
	if string(mech.final) != "ack:hello" {
		t.Fatalf("final = %q, want ack:hello", mech.final)
	}
}

func TestSASLFinalRejectedByMechanism(t *testing.T) {
	// If the mechanism rejects the server-final, Authenticate fails even
	// though the server itself accepted the credentials.
	srv := NewServer(echoBackend{newMemBackend()})
	c := dialLoopback(t, srv)
	defer func() { _ = c.Close() }()

	if err := c.Authenticate(mismatchEcho{}); err == nil {
		t.Fatal("expected Authenticate to fail on bad server-final")
	}
}

// mismatchEcho sends "a" but verifies the server-final against "ack:b",
// which the echo server will never produce.
type mismatchEcho struct{}

func (mismatchEcho) Start() (string, []byte, error) { return echoMech, []byte("a"), nil }
func (mismatchEcho) Next([]byte) ([]byte, error)    { return nil, errors.New("no challenge") }
func (mismatchEcho) SASLFinal(data []byte) error {
	if string(data) != "ack:b" {
		return errors.New("server-final mismatch")
	}
	return nil
}
