// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- in-memory backend used by the loopback tests ---

type memStore struct {
	mu      sync.Mutex
	scripts map[string]string
	active  string
	maxSize int64
}

type memBackend struct {
	creds map[string]string // username -> password
	store *memStore
}

func newMemBackend() *memBackend {
	return &memBackend{
		creds: map[string]string{"alice": "secret"},
		store: &memStore{scripts: map[string]string{}, maxSize: 1 << 20},
	}
}

func (b *memBackend) NewSession(_ *ServerConn) (Session, error) {
	return &memSession{be: b}, nil
}

type memSession struct {
	UnimplementedSession
	be   *memBackend
	user string
}

func (s *memSession) AuthMechanisms() []string { return []string{"PLAIN"} }

func (s *memSession) Authenticate(mech string) (SASLServer, error) {
	if mech != "PLAIN" {
		return nil, &ServerError{Status: statusNO, Text: "unsupported mechanism"}
	}
	return PlainServer(func(_, user, pass string) error {
		if want, ok := s.be.creds[user]; ok && want == pass {
			s.user = user
			return nil
		}
		return &ServerError{Status: statusNO, Text: "invalid credentials"}
	}), nil
}

// Owner implements the optional SessionOwner interface so the server
// advertises OWNER after authentication.
func (s *memSession) Owner() string { return s.user }

func (s *memSession) ListScripts() ([]ScriptInfo, error) {
	st := s.be.store
	st.mu.Lock()
	defer st.mu.Unlock()
	names := make([]string, 0, len(st.scripts))
	for n := range st.scripts {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]ScriptInfo, 0, len(names))
	for _, n := range names {
		out = append(out, ScriptInfo{Name: n, Active: n == st.active})
	}
	return out, nil
}

func (s *memSession) GetScript(name string) (string, error) {
	st := s.be.store
	st.mu.Lock()
	defer st.mu.Unlock()
	body, ok := st.scripts[name]
	if !ok {
		return "", &ServerError{Status: statusNO, Code: &ResponseCode{Name: CodeNonexistent}, Text: "no such script"}
	}
	return body, nil
}

func (s *memSession) PutScript(name, body string) (string, error) {
	st := s.be.store
	st.mu.Lock()
	defer st.mu.Unlock()
	st.scripts[name] = body
	if strings.Contains(body, "WARNME") {
		return "test warning: deprecated action", nil
	}
	return "", nil
}

func (s *memSession) CheckScript(body string) (string, error) {
	if strings.Contains(body, "INVALID") {
		return "", &ServerError{Status: statusNO, Text: "syntax error"}
	}
	if strings.Contains(body, "WARNME") {
		return "test warning", nil
	}
	return "", nil
}

func (s *memSession) SetActive(name string) error {
	st := s.be.store
	st.mu.Lock()
	defer st.mu.Unlock()
	if name == "" {
		st.active = ""
		return nil
	}
	if _, ok := st.scripts[name]; !ok {
		return &ServerError{Status: statusNO, Code: &ResponseCode{Name: CodeNonexistent}, Text: "no such script"}
	}
	st.active = name
	return nil
}

func (s *memSession) DeleteScript(name string) error {
	st := s.be.store
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.scripts[name]; !ok {
		return &ServerError{Status: statusNO, Code: &ResponseCode{Name: CodeNonexistent}, Text: "no such script"}
	}
	if name == st.active {
		return &ServerError{Status: statusNO, Code: &ResponseCode{Name: CodeActive}, Text: "script is active"}
	}
	delete(st.scripts, name)
	return nil
}

func (s *memSession) RenameScript(oldName, newName string) error {
	st := s.be.store
	st.mu.Lock()
	defer st.mu.Unlock()
	body, ok := st.scripts[oldName]
	if !ok {
		return &ServerError{Status: statusNO, Code: &ResponseCode{Name: CodeNonexistent}, Text: "no such script"}
	}
	if _, exists := st.scripts[newName]; exists {
		return &ServerError{Status: statusNO, Code: &ResponseCode{Name: CodeAlreadyExists}, Text: "target exists"}
	}
	delete(st.scripts, oldName)
	st.scripts[newName] = body
	if st.active == oldName {
		st.active = newName
	}
	return nil
}

func (s *memSession) HaveSpace(_ string, size int64) error {
	if size > s.be.store.maxSize {
		return &ServerError{Status: statusNO, Code: &ResponseCode{Name: CodeQuota, Subcode: "maxsize"}, Text: "too large"}
	}
	return nil
}

// --- harness ---

// dialLoopback starts srv on one end of a net.Pipe and returns a Client
// connected to the other end (greeting already read).
func dialLoopback(t *testing.T, srv *Server) *Client {
	t.Helper()
	cconn, sconn := net.Pipe()
	go srv.serveConn(sconn)
	c, err := NewClient(cconn)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func authedClient(t *testing.T) (*Client, *memBackend) {
	t.Helper()
	be := newMemBackend()
	c := dialLoopback(t, NewServer(be))
	if err := c.Authenticate(PlainAuth("", "alice", "secret")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	return c, be
}

func TestGreetingCapabilities(t *testing.T) {
	srv := NewServer(newMemBackend())
	srv.SieveExtensions = []string{"fileinto", "vacation"}
	c := dialLoopback(t, srv)
	defer func() { _ = c.Close() }()
	caps := c.Capabilities()
	if caps.Implementation != "go-managesieve" {
		t.Errorf("implementation = %q", caps.Implementation)
	}
	if len(caps.SASL) != 1 || caps.SASL[0] != "PLAIN" {
		t.Errorf("sasl = %v", caps.SASL)
	}
	if len(caps.Sieve) != 2 {
		t.Errorf("sieve = %v", caps.Sieve)
	}
	if caps.Version != "1.0" {
		t.Errorf("version = %q", caps.Version)
	}
}

func TestAuthPlainSuccessAndFailure(t *testing.T) {
	be := newMemBackend()
	c := dialLoopback(t, NewServer(be))
	defer func() { _ = c.Close() }()
	if err := c.Authenticate(PlainAuth("", "alice", "wrong")); err == nil {
		t.Fatal("expected auth failure")
	}
	// A fresh connection authenticates successfully.
	c2 := dialLoopback(t, NewServer(be))
	defer func() { _ = c2.Close() }()
	if err := c2.Authenticate(PlainAuth("", "alice", "secret")); err != nil {
		t.Fatalf("auth: %v", err)
	}
}

func TestCommandsRequireAuth(t *testing.T) {
	c := dialLoopback(t, NewServer(newMemBackend()))
	defer func() { _ = c.Close() }()
	_, err := c.ListScripts()
	var se *ServerError
	if !errors.As(err, &se) {
		t.Fatalf("want ServerError, got %v", err)
	}
}

func TestScriptLifecycleByteExact(t *testing.T) {
	c, _ := authedClient(t)
	defer func() { _ = c.Close() }()

	// A body with embedded CRLFs and a multibyte rune; must round-trip exactly.
	body := "require [\"fileinto\"];\r\n# café rules\r\nfileinto \"INBOX\";\r\n"

	if _, err := c.PutScript("main", body); err != nil {
		t.Fatalf("PutScript: %v", err)
	}
	scripts, err := c.ListScripts()
	if err != nil {
		t.Fatalf("ListScripts: %v", err)
	}
	if len(scripts) != 1 || scripts[0].Name != "main" || scripts[0].Active {
		t.Fatalf("ListScripts = %+v", scripts)
	}
	if err := c.SetActive("main"); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	scripts, _ = c.ListScripts()
	if !scripts[0].Active {
		t.Fatalf("script not active after SetActive: %+v", scripts)
	}
	got, err := c.GetScript("main")
	if err != nil {
		t.Fatalf("GetScript: %v", err)
	}
	if got != body {
		t.Fatalf("GetScript not byte-exact:\n got %q\nwant %q", got, body)
	}
}

func TestOwnerCapabilityAfterAuth(t *testing.T) {
	c, _ := authedClient(t)
	defer func() { _ = c.Close() }()
	// The client re-reads capabilities after authenticating; the server
	// advertises OWNER for the authenticated user.
	if got := c.Capabilities().Owner; got != "alice" {
		t.Fatalf("Owner = %q, want alice", got)
	}
}

func TestSetActiveEmptyDeactivates(t *testing.T) {
	c, _ := authedClient(t)
	defer func() { _ = c.Close() }()
	if _, err := c.PutScript("s1", "stop;\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetActive("s1"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetActive(""); err != nil {
		t.Fatalf("SetActive(\"\"): %v", err)
	}
	scripts, _ := c.ListScripts()
	if scripts[0].Active {
		t.Fatal("expected no active script after SetActive(\"\")")
	}
}

func TestFailureCodes(t *testing.T) {
	c, _ := authedClient(t)
	defer func() { _ = c.Close() }()

	assertCode := func(err error, code string) {
		t.Helper()
		var se *ServerError
		if !errors.As(err, &se) {
			t.Fatalf("want *ServerError, got %v", err)
		}
		if se.CodeName() != code {
			t.Fatalf("code = %q, want %q (%v)", se.CodeName(), code, se)
		}
	}

	_, err := c.GetScript("nope")
	assertCode(err, CodeNonexistent)

	assertCode(c.SetActive("nope"), CodeNonexistent)

	if _, err := c.PutScript("act", "keep;\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetActive("act"); err != nil {
		t.Fatal(err)
	}
	assertCode(c.DeleteScript("act"), CodeActive)

	if _, err := c.PutScript("a", "keep;\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutScript("b", "keep;\r\n"); err != nil {
		t.Fatal(err)
	}
	assertCode(c.RenameScript("a", "b"), CodeAlreadyExists)

	assertCode(c.HaveSpace("big", 1<<40), CodeQuota)
}

func TestWarningsSurfaced(t *testing.T) {
	c, _ := authedClient(t)
	defer func() { _ = c.Close() }()
	warn, err := c.PutScript("w", "WARNME;\r\n")
	if err != nil {
		t.Fatalf("PutScript: %v", err)
	}
	if warn == "" {
		t.Fatal("expected warnings to be surfaced")
	}
	cw, err := c.CheckScript("WARNME;\r\n")
	if err != nil || cw == "" {
		t.Fatalf("CheckScript warnings: warn=%q err=%v", cw, err)
	}
	if _, err := c.CheckScript("INVALID"); err == nil {
		t.Fatal("expected CheckScript to reject invalid script")
	}
}

func TestRenameAndHaveSpaceOK(t *testing.T) {
	c, _ := authedClient(t)
	defer func() { _ = c.Close() }()
	if _, err := c.PutScript("old", "keep;\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := c.RenameScript("old", "new"); err != nil {
		t.Fatalf("RenameScript: %v", err)
	}
	if err := c.HaveSpace("x", 1024); err != nil {
		t.Fatalf("HaveSpace: %v", err)
	}
	if _, err := c.GetScript("new"); err != nil {
		t.Fatalf("renamed script missing: %v", err)
	}
}

func TestNoop(t *testing.T) {
	c, _ := authedClient(t)
	defer func() { _ = c.Close() }()
	if err := c.Noop(""); err != nil {
		t.Fatalf("Noop: %v", err)
	}
	if err := c.Noop("tag123"); err != nil {
		t.Fatalf("Noop(tag): %v", err)
	}
}

func TestStartTLSRoundTrip(t *testing.T) {
	be := newMemBackend()
	srv := NewServer(be)
	srv.TLSConfig = testTLSConfig(t)

	cconn, sconn := net.Pipe()
	go srv.serveConn(sconn)
	c, err := NewClient(cconn)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	// Before TLS, STARTTLS is advertised.
	if !c.Capabilities().StartTLS {
		t.Fatal("STARTTLS not advertised pre-upgrade")
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("StartTLS: %v", err)
	}
	// After TLS, capabilities are re-read and STARTTLS is gone.
	if c.Capabilities().StartTLS {
		t.Fatal("STARTTLS still advertised after upgrade")
	}
	if err := c.Authenticate(PlainAuth("", "alice", "secret")); err != nil {
		t.Fatalf("Authenticate over TLS: %v", err)
	}
	if _, err := c.PutScript("s", "keep;\r\n"); err != nil {
		t.Fatalf("PutScript over TLS: %v", err)
	}
}

func TestEncryptNeeded(t *testing.T) {
	be := newMemBackend()
	srv := NewServer(be)
	srv.TLSConfig = testTLSConfig(t)
	c := dialLoopback(t, srv)
	defer func() { _ = c.Close() }()
	// Auth before STARTTLS must be refused with ENCRYPT-NEEDED.
	err := c.Authenticate(PlainAuth("", "alice", "secret"))
	var se *ServerError
	if !errors.As(err, &se) || se.CodeName() != CodeEncryptNeeded {
		t.Fatalf("want ENCRYPT-NEEDED, got %v", err)
	}
}

func TestDialContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Dial(ctx, "203.0.113.1:4190")
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

// testTLSConfig builds a throwaway self-signed server TLS config.
func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31-1, 0),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
}
