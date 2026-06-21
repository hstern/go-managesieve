// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"bufio"
	"strings"
	"testing"
)

// readAll tokenises every line of a server response transcript until a
// status line is reached, returning the data lines and the status.
func readAll(t *testing.T, transcript string) ([][]token, *response) {
	t.Helper()
	r := &reader{bufio.NewReader(strings.NewReader(transcript))}
	var data [][]token
	for {
		toks, err := r.readLine()
		if err != nil {
			t.Fatalf("readLine: %v (data so far: %#v)", err, data)
		}
		if st, ok := parseStatus(toks); ok {
			return data, st
		}
		data = append(data, toks)
	}
}

// TestRFCCapabilityExample parses the CAPABILITY listing from RFC 5804
// §2.4.
func TestRFCCapabilityExample(t *testing.T) {
	transcript := "\"IMPLEMENTATION\" \"Example1 ManageSieved v001\"\r\n" +
		"\"SASL\" \"PLAIN SCRAM-SHA-1 GSSAPI\"\r\n" +
		"\"SIEVE\" \"fileinto vacation\"\r\n" +
		"\"STARTTLS\"\r\n" +
		"\"VERSION\" \"1.0\"\r\n" +
		"OK\r\n"
	data, st := readAll(t, transcript)
	if st.status != statusOK {
		t.Fatalf("status = %q", st.status)
	}
	caps := parseCapabilities(data)
	if caps.Implementation != "Example1 ManageSieved v001" {
		t.Errorf("implementation = %q", caps.Implementation)
	}
	if len(caps.SASL) != 3 || caps.SASL[2] != "GSSAPI" {
		t.Errorf("sasl = %v", caps.SASL)
	}
	if !caps.StartTLS || caps.Version != "1.0" {
		t.Errorf("starttls=%v version=%q", caps.StartTLS, caps.Version)
	}
}

// TestRFCPutScriptError parses the PUTSCRIPT failure from RFC 5804 §2.6.
func TestRFCPutScriptError(t *testing.T) {
	_, st := readAll(t, "NO \"line 2: Syntax error\"\r\n")
	err := st.err()
	var se *ServerError
	if !asServerError(err, &se) {
		t.Fatalf("want *ServerError, got %v", err)
	}
	if se.Text != "line 2: Syntax error" {
		t.Errorf("text = %q", se.Text)
	}
}

// TestRFCGetScriptExample parses the GETSCRIPT response from RFC 5804
// §2.9, including the {n} literal whose octet count includes the script's
// own CRLFs.
func TestRFCGetScriptExample(t *testing.T) {
	body := "#this is my wonderful script\r\nreject \"I reject you\";\r\n"
	if len(body) != 54 {
		t.Fatalf("precondition: body is %d octets, want 54", len(body))
	}
	transcript := "{54}\r\n" + body + "\r\nOK\r\n"
	data, st := readAll(t, transcript)
	if st.status != statusOK {
		t.Fatalf("status = %q", st.status)
	}
	if len(data) != 1 || data[0][0].val != body {
		t.Fatalf("script body not parsed exactly: %#v", data)
	}
}

// TestRFCListScriptsActiveMarker parses the LISTSCRIPTS response from RFC
// 5804 §2.7 with the trailing ACTIVE marker.
func TestRFCListScriptsActiveMarker(t *testing.T) {
	transcript := "\"summer_script\"\r\n" +
		"\"vacation_script\"\r\n" +
		"\"main_script\" ACTIVE\r\n" +
		"OK\r\n"
	data, st := readAll(t, transcript)
	if st.status != statusOK {
		t.Fatalf("status = %q", st.status)
	}
	var active string
	names := make([]string, 0, len(data))
	for _, line := range data {
		names = append(names, line[0].val)
		for _, tk := range line[1:] {
			if tk.kind == tokAtom && tk.val == "ACTIVE" {
				active = line[0].val
			}
		}
	}
	if len(names) != 3 {
		t.Fatalf("names = %v", names)
	}
	if active != "main_script" {
		t.Errorf("active = %q, want main_script", active)
	}
}

// TestRFCReferral parses a BYE referral (RFC 5804 §1.3) into a
// ReferralError.
func TestRFCReferral(t *testing.T) {
	_, st := readAll(t, "BYE (REFERRAL \"sieve://other.example.com\") \"Try Remote.\"\r\n")
	err := st.err()
	var re *ReferralError
	if !asReferralError(err, &re) {
		t.Fatalf("want *ReferralError, got %v", err)
	}
	if re.URL != "sieve://other.example.com" {
		t.Errorf("url = %q", re.URL)
	}
}

// asServerError / asReferralError are tiny errors.As wrappers kept local
// to avoid importing errors just for these assertions.
func asServerError(err error, target **ServerError) bool {
	se, ok := err.(*ServerError)
	if ok {
		*target = se
	}
	return ok
}

func asReferralError(err error, target **ReferralError) bool {
	re, ok := err.(*ReferralError)
	if ok {
		*target = re
	}
	return ok
}
