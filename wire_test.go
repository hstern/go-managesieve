// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"bufio"
	"reflect"
	"strings"
	"testing"
)

func tokenize(t *testing.T, s string) []token {
	t.Helper()
	r := &reader{bufio.NewReader(strings.NewReader(s))}
	toks, err := r.readLine()
	if err != nil {
		t.Fatalf("readLine(%q): %v", s, err)
	}
	return toks
}

func TestReadLineAtomsAndStrings(t *testing.T) {
	toks := tokenize(t, "OK \"all good\"\r\n")
	want := []token{{tokAtom, "OK"}, {tokString, "all good"}}
	if !reflect.DeepEqual(toks, want) {
		t.Fatalf("got %#v, want %#v", toks, want)
	}
}

func TestReadLineQuotedEscapes(t *testing.T) {
	toks := tokenize(t, `"a\"b\\c"`+"\r\n")
	if len(toks) != 1 || toks[0].val != `a"b\c` {
		t.Fatalf("got %#v", toks)
	}
}

func TestReadLineParenResponseCode(t *testing.T) {
	toks := tokenize(t, "NO (QUOTA/maxscripts) \"too many\"\r\n")
	want := []token{{tokAtom, "NO"}, {tokParen, "QUOTA/maxscripts"}, {tokString, "too many"}}
	if !reflect.DeepEqual(toks, want) {
		t.Fatalf("got %#v, want %#v", toks, want)
	}
}

func TestReadLineParenWithQuotedArg(t *testing.T) {
	toks := tokenize(t, `BYE (REFERRAL "sieve://other.example.com") "go away"`+"\r\n")
	if len(toks) != 3 || toks[1].kind != tokParen {
		t.Fatalf("got %#v", toks)
	}
	if toks[1].val != `REFERRAL "sieve://other.example.com"` {
		t.Fatalf("paren body = %q", toks[1].val)
	}
}

func TestReadServerLiteral(t *testing.T) {
	// {n} (server-to-client) literal containing embedded CRLF.
	body := "line one\r\nline two\r\n"
	in := "{20}\r\n" + body
	r := &reader{bufio.NewReader(strings.NewReader(in + "\r\nOK\r\n"))}
	toks, err := r.readLine()
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 1 || toks[0].kind != tokLiteral {
		t.Fatalf("got %#v", toks)
	}
	if toks[0].val != body {
		t.Fatalf("literal = %q, want %q", toks[0].val, body)
	}
	next, err := r.readLine()
	if err != nil {
		t.Fatal(err)
	}
	if len(next) != 1 || next[0].val != "OK" {
		t.Fatalf("trailing line = %#v", next)
	}
}

func TestReadClientLiteralPlusAccepted(t *testing.T) {
	// {n+} (client-to-server, non-synchronising) read by the server side.
	body := "require \"fileinto\";\n"
	in := "PUTSCRIPT \"x\" {" + itoa(len(body)) + "+}\r\n" + body + "\r\n"
	r := &reader{bufio.NewReader(strings.NewReader(in))}
	toks, err := r.readLine()
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 3 || toks[2].kind != tokLiteral || toks[2].val != body {
		t.Fatalf("got %#v", toks)
	}
}

func TestReadLiteralMultibyte(t *testing.T) {
	// Octet count, not rune count: "héllo" is 6 bytes.
	body := "héllo"
	if len(body) != 6 {
		t.Fatalf("precondition: len=%d", len(body))
	}
	in := "{6}\r\n" + body + "\r\n"
	r := &reader{bufio.NewReader(strings.NewReader(in))}
	toks, err := r.readLine()
	if err != nil {
		t.Fatal(err)
	}
	if toks[0].val != body {
		t.Fatalf("got %q", toks[0].val)
	}
}

func TestQuoteRoundTrip(t *testing.T) {
	for _, s := range []string{"", "simple", `with "quotes"`, `back\slash`, "spaces here"} {
		q := quote(s)
		r := &reader{bufio.NewReader(strings.NewReader(q + "\r\n"))}
		toks, err := r.readLine()
		if err != nil {
			t.Fatalf("quote(%q)=%q: %v", s, q, err)
		}
		if len(toks) != 1 || toks[0].val != s {
			t.Fatalf("round-trip of %q via %q got %#v", s, q, toks)
		}
	}
}

func TestParseResponseCode(t *testing.T) {
	cases := []struct {
		in   string
		name string
		sub  string
		arg  string
	}{
		{"NONEXISTENT", "NONEXISTENT", "", ""},
		{"QUOTA/maxscripts", "QUOTA", "maxscripts", ""},
		{`REFERRAL "sieve://h.example"`, "REFERRAL", "", "sieve://h.example"},
		{`TAG "abc"`, "TAG", "", "abc"},
		{"WARNINGS", "WARNINGS", "", ""},
	}
	for _, tc := range cases {
		rc := parseResponseCode(tc.in)
		if rc.Name != tc.name || rc.Subcode != tc.sub || rc.Arg != tc.arg {
			t.Errorf("parseResponseCode(%q) = %+v", tc.in, rc)
		}
	}
}

func TestCapabilitiesParseAndRoundTrip(t *testing.T) {
	lines := [][]token{
		{{tokString, "IMPLEMENTATION"}, {tokString, "Example v1"}},
		{{tokString, "SASL"}, {tokString, "PLAIN SCRAM-SHA-1"}},
		{{tokString, "SIEVE"}, {tokString, "fileinto vacation"}},
		{{tokAtom, "STARTTLS"}},
		{{tokString, "MAXREDIRECTS"}, {tokString, "5"}},
		{{tokString, "VERSION"}, {tokString, "1.0"}},
		{{tokString, "X-CUSTOM"}, {tokString, "value"}},
	}
	caps := parseCapabilities(lines)
	if caps.Implementation != "Example v1" {
		t.Errorf("implementation = %q", caps.Implementation)
	}
	if len(caps.SASL) != 2 || caps.SASL[0] != "PLAIN" {
		t.Errorf("sasl = %v", caps.SASL)
	}
	if !caps.StartTLS {
		t.Error("starttls not set")
	}
	if caps.MaxRedirects != 5 {
		t.Errorf("maxredirects = %d", caps.MaxRedirects)
	}
	if caps.Extra["X-CUSTOM"] != "value" {
		t.Errorf("extra = %v", caps.Extra)
	}

	// Re-encoding then re-parsing must preserve the typed fields.
	var data [][]token
	for _, l := range caps.lines() {
		data = append(data, tokenize(t, l+"\r\n"))
	}
	caps2 := parseCapabilities(data)
	if caps2.Implementation != caps.Implementation ||
		!reflect.DeepEqual(caps2.SASL, caps.SASL) ||
		!reflect.DeepEqual(caps2.Sieve, caps.Sieve) ||
		caps2.StartTLS != caps.StartTLS ||
		caps2.MaxRedirects != caps.MaxRedirects ||
		caps2.Version != caps.Version ||
		caps2.Extra["X-CUSTOM"] != "value" {
		t.Errorf("round-trip mismatch:\n %+v\n %+v", caps, caps2)
	}
}

// itoa avoids importing strconv just for the test literals above.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
