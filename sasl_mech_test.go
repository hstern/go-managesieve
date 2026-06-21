// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"testing"
)

func TestExternalMechanism(t *testing.T) {
	mech, ir, err := External("alice").Start()
	if err != nil || mech != "EXTERNAL" || string(ir) != "alice" {
		t.Fatalf("External: mech=%q ir=%q err=%v", mech, ir, err)
	}
	mech, ir, _ = External("").Start()
	if mech != "EXTERNAL" || len(ir) != 0 {
		t.Fatalf("External(\"\"): mech=%q ir=%q", mech, ir)
	}
}

func TestOAuthBearerMechanism(t *testing.T) {
	_, ir, err := OAuthBearer("alice", "tok123").Start()
	if err != nil {
		t.Fatal(err)
	}
	want := "n,a=alice,\x01auth=Bearer tok123\x01\x01"
	if string(ir) != want {
		t.Fatalf("OAUTHBEARER ir = %q, want %q", ir, want)
	}
	// No authzid -> "n,,".
	_, ir, _ = OAuthBearer("", "tok123").Start()
	if string(ir) != "n,,\x01auth=Bearer tok123\x01\x01" {
		t.Fatalf("OAUTHBEARER (no authzid) ir = %q", ir)
	}
	// On an error challenge the client acknowledges with %x01.
	resp, err := OAuthBearer("a", "t").Next([]byte(`{"status":"invalid_token"}`))
	if err != nil || len(resp) != 1 || resp[0] != 0x01 {
		t.Fatalf("OAUTHBEARER Next = %v, %v", resp, err)
	}
}

// TestScramSHA256RFC7677 checks the full client computation against the
// worked example in RFC 7677 §3 (fixed client nonce).
func TestScramSHA256RFC7677(t *testing.T) {
	s := &scramClient{
		username: "user",
		password: "pencil",
		nonce:    "rOprNGfwEbeRWgbNEkqO",
	}

	mech, ir, err := s.Start()
	if err != nil {
		t.Fatal(err)
	}
	if mech != "SCRAM-SHA-256" {
		t.Fatalf("mech = %q", mech)
	}
	if string(ir) != "n,,n=user,r=rOprNGfwEbeRWgbNEkqO" {
		t.Fatalf("client-first = %q", ir)
	}

	serverFirst := "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," +
		"s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
	resp, err := s.Next([]byte(serverFirst))
	if err != nil {
		t.Fatal(err)
	}
	wantFinal := "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," +
		"p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
	if string(resp) != wantFinal {
		t.Fatalf("client-final =\n %q\nwant\n %q", resp, wantFinal)
	}

	// Server signature from the RFC; SASLFinal must accept it.
	if err := s.SASLFinal([]byte("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")); err != nil {
		t.Fatalf("SASLFinal (valid server sig): %v", err)
	}
}

func TestScramSHA256RejectsBadServerSig(t *testing.T) {
	s := &scramClient{username: "user", password: "pencil", nonce: "rOprNGfwEbeRWgbNEkqO"}
	_, _, _ = s.Start()
	serverFirst := "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," +
		"s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
	if _, err := s.Next([]byte(serverFirst)); err != nil {
		t.Fatal(err)
	}
	if err := s.SASLFinal([]byte("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")); err == nil {
		t.Fatal("expected server signature mismatch to be rejected")
	}
}

func TestScramServerNonceMustExtendClient(t *testing.T) {
	s := &scramClient{username: "user", password: "pencil", nonce: "abc"}
	_, _, _ = s.Start()
	// Server nonce that does not start with the client nonce -> reject.
	if _, err := s.Next([]byte("r=zzz,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")); err == nil {
		t.Fatal("expected rejection when server nonce does not extend client nonce")
	}
}

// --- end-to-end: EXTERNAL over the loopback server ---

type externalBackend struct{ *memBackend }

func (b externalBackend) NewSession(*ServerConn) (Session, error) {
	return &externalSession{memSession{be: b.memBackend}}, nil
}

type externalSession struct{ memSession }

func (externalSession) AuthMechanisms() []string { return []string{"EXTERNAL"} }
func (s *externalSession) Authenticate(mech string) (SASLServer, error) {
	if mech != "EXTERNAL" {
		return nil, &ServerError{Status: statusNO, Text: "unsupported mechanism"}
	}
	return &externalServer{s: s}, nil
}

// externalServer accepts any authorization identity (test only).
type externalServer struct{ s *externalSession }

func (e *externalServer) Next(response []byte) ([]byte, bool, error) {
	e.s.user = string(response)
	return nil, true, nil
}

func TestExternalEndToEnd(t *testing.T) {
	c := dialLoopback(t, NewServer(externalBackend{newMemBackend()}))
	defer func() { _ = c.Close() }()
	if err := c.Authenticate(External("alice")); err != nil {
		t.Fatalf("EXTERNAL auth: %v", err)
	}
	if _, err := c.PutScript("s", "stop;\r\n"); err != nil {
		t.Fatalf("PutScript after EXTERNAL: %v", err)
	}
}
