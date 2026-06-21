// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"strings"
)

// Response-code names carried in the "(...)" atom of an OK/NO/BYE
// response (RFC 5804 §1.3). Callers branch on these rather than parsing
// the human-readable text, which is localised.
const (
	CodeAuthTooWeak      = "AUTH-TOO-WEAK"
	CodeEncryptNeeded    = "ENCRYPT-NEEDED"
	CodeQuota            = "QUOTA"
	CodeSASL             = "SASL"
	CodeReferral         = "REFERRAL"
	CodeTransitionNeeded = "TRANSITION-NEEDED"
	CodeTryLater         = "TRYLATER"
	CodeActive           = "ACTIVE"
	CodeNonexistent      = "NONEXISTENT"
	CodeAlreadyExists    = "ALREADYEXISTS"
	CodeWarnings         = "WARNINGS"
	CodeTag              = "TAG"
)

// Status is a response type: "OK", "NO", or "BYE".
const (
	statusOK  = "OK"
	statusNO  = "NO"
	statusBYE = "BYE"
)

// ResponseCode is the structured "(...)" atom of a response. Name is the
// upper-cased code (e.g. "QUOTA"); Subcode is the part after a '/' (e.g.
// "maxscripts" in "QUOTA/maxscripts"); Arg is a single quoted argument
// where the code carries one (REFERRAL, TAG, SASL).
type ResponseCode struct {
	Name    string
	Subcode string
	Arg     string
}

// String renders the code back to its wire form (without the
// surrounding parentheses).
func (rc *ResponseCode) String() string {
	if rc == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(rc.Name)
	if rc.Subcode != "" {
		sb.WriteByte('/')
		sb.WriteString(rc.Subcode)
	}
	if rc.Arg != "" {
		sb.WriteByte(' ')
		sb.WriteString(quote(rc.Arg))
	}
	return sb.String()
}

// parseResponseCode parses the raw inner text of a "(...)" group.
func parseResponseCode(inner string) *ResponseCode {
	inner = strings.TrimSpace(inner)
	if inner == "" {
		return nil
	}
	name, rest := inner, ""
	if i := strings.IndexAny(inner, " \t"); i >= 0 {
		name, rest = inner[:i], strings.TrimSpace(inner[i+1:])
	}
	rc := &ResponseCode{}
	if base, sub, found := strings.Cut(name, "/"); found {
		rc.Name, rc.Subcode = strings.ToUpper(base), sub
	} else {
		rc.Name = strings.ToUpper(name)
	}
	rc.Arg = unquote(rest)
	return rc
}

// unquote strips one layer of surrounding double quotes (with backslash
// unescaping) if present; otherwise returns s unchanged.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '"' {
		return s
	}
	var sb strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i++
			sb.WriteByte(s[i])
			continue
		}
		if c == '"' {
			break
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

// response is a parsed OK/NO/BYE status line.
type response struct {
	status string
	code   *ResponseCode
	text   string
}

// parseStatus interprets a tokenised line as a status response. The
// second return is false when the line is not a status line (i.e. it is
// data preceding the status, such as a capability or LISTSCRIPTS line).
func parseStatus(toks []token) (*response, bool) {
	if len(toks) == 0 || toks[0].kind != tokAtom {
		return nil, false
	}
	s := strings.ToUpper(toks[0].val)
	if s != statusOK && s != statusNO && s != statusBYE {
		return nil, false
	}
	resp := &response{status: s}
	i := 1
	if i < len(toks) && toks[i].kind == tokParen {
		resp.code = parseResponseCode(toks[i].val)
		i++
	}
	if i < len(toks) {
		resp.text = toks[i].val
	}
	return resp, true
}

// warnings returns the warning text if this OK response carries the
// WARNINGS code, else "".
func (r *response) warnings() string {
	if r.code != nil && r.code.Name == CodeWarnings {
		return r.text
	}
	return ""
}

// err converts a non-OK response to a typed error (nil for OK). A BYE or
// NO carrying REFERRAL becomes a *ReferralError; anything else becomes a
// *ServerError.
func (r *response) err() error {
	if r.status == statusOK {
		return nil
	}
	if r.code != nil && r.code.Name == CodeReferral {
		return &ReferralError{URL: r.code.Arg, Text: r.text}
	}
	return &ServerError{Status: r.status, Code: r.code, Text: r.text}
}

// ServerError is a typed NO or BYE response from the peer. Inspect Code
// to branch on the machine-readable reason.
type ServerError struct {
	Status string // "NO" or "BYE"
	Code   *ResponseCode
	Text   string
}

func (e *ServerError) Error() string {
	var sb strings.Builder
	sb.WriteString("managesieve: ")
	sb.WriteString(e.Status)
	if e.Code != nil {
		sb.WriteString(" (")
		sb.WriteString(e.Code.String())
		sb.WriteByte(')')
	}
	if e.Text != "" {
		sb.WriteString(" ")
		sb.WriteString(e.Text)
	}
	return sb.String()
}

// CodeName returns the response code's name (e.g. "NONEXISTENT"), or ""
// if the error carried no code.
func (e *ServerError) CodeName() string {
	if e.Code == nil {
		return ""
	}
	return e.Code.Name
}

// ReferralError reports that the server redirected the client to another
// server via a REFERRAL response code (RFC 5804 §1.3). The library does
// not follow referrals automatically.
type ReferralError struct {
	URL  string // sieve://host[:port]
	Text string
}

func (e *ReferralError) Error() string {
	return "managesieve: referral to " + e.URL
}
