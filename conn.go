// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// DefaultPort is the IANA-registered TCP port for ManageSieve.
const DefaultPort = "4190"

// tokKind classifies one lexical token on a ManageSieve line.
type tokKind int

const (
	tokAtom    tokKind = iota // bare word: OK, NO, BYE, ACTIVE, a number, …
	tokString                 // a "quoted string"
	tokLiteral                // a {n} / {n+} octet literal
	tokParen                  // a (response code) group, captured raw
)

// token is one lexical token. For every kind, val holds the decoded
// content (quotes removed, literal octets as a string, paren body raw).
type token struct {
	kind tokKind
	val  string
}

// reader tokenises the ManageSieve wire format off a buffered stream.
type reader struct {
	br *bufio.Reader
}

// readLine reads and tokenises one logical line. A line ends at the
// first CRLF that is not inside a literal's octet payload. It is lenient
// about a bare LF line terminator.
func (r *reader) readLine() ([]token, error) {
	var toks []token
	for {
		b, err := r.br.ReadByte()
		if err != nil {
			return nil, err
		}
		switch b {
		case '\r':
			nb, err := r.br.ReadByte()
			if err != nil {
				return nil, err
			}
			if nb != '\n' {
				return nil, fmt.Errorf("managesieve: expected LF after CR")
			}
			return toks, nil
		case '\n':
			return toks, nil // lenient: accept a bare LF
		case ' ', '\t':
			continue
		case '"':
			s, err := r.readQuoted()
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{tokString, s})
		case '{':
			s, err := r.readLiteral()
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{tokLiteral, s})
		case '(':
			s, err := r.readParen()
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{tokParen, s})
		default:
			if err := r.br.UnreadByte(); err != nil {
				return nil, err
			}
			s, err := r.readAtom()
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{tokAtom, s})
		}
	}
}

func (r *reader) readQuoted() (string, error) {
	var sb strings.Builder
	for {
		b, err := r.br.ReadByte()
		if err != nil {
			return "", err
		}
		switch b {
		case '\\':
			nb, err := r.br.ReadByte()
			if err != nil {
				return "", err
			}
			sb.WriteByte(nb)
		case '"':
			return sb.String(), nil
		default:
			sb.WriteByte(b)
		}
	}
}

// readLiteral parses an octet count (the leading '{' already consumed),
// the CRLF after the '}', and exactly that many octets. The
// non-synchronising '+' marker is accepted and ignored on read.
func (r *reader) readLiteral() (string, error) {
	var num strings.Builder
	for {
		b, err := r.br.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '+' {
			continue
		}
		if b == '}' {
			break
		}
		if b < '0' || b > '9' {
			return "", fmt.Errorf("managesieve: malformed literal length")
		}
		num.WriteByte(b)
	}
	n, err := strconv.Atoi(num.String())
	if err != nil {
		return "", fmt.Errorf("managesieve: bad literal length: %w", err)
	}
	if err := r.expectCRLF(); err != nil {
		return "", err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r.br, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func (r *reader) readParen() (string, error) {
	var sb strings.Builder
	inQuote := false
	for {
		b, err := r.br.ReadByte()
		if err != nil {
			return "", err
		}
		switch {
		case b == '"':
			inQuote = !inQuote
			sb.WriteByte(b)
		case b == '\\' && inQuote:
			nb, err := r.br.ReadByte()
			if err != nil {
				return "", err
			}
			sb.WriteByte(b)
			sb.WriteByte(nb)
		case b == ')' && !inQuote:
			return sb.String(), nil
		default:
			sb.WriteByte(b)
		}
	}
}

func (r *reader) readAtom() (string, error) {
	var sb strings.Builder
	for {
		b, err := r.br.ReadByte()
		if err != nil {
			if err == io.EOF && sb.Len() > 0 {
				return sb.String(), nil
			}
			return "", err
		}
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '(' || b == ')' {
			if err := r.br.UnreadByte(); err != nil {
				return "", err
			}
			return sb.String(), nil
		}
		sb.WriteByte(b)
	}
}

func (r *reader) expectCRLF() error {
	b, err := r.br.ReadByte()
	if err != nil {
		return err
	}
	switch b {
	case '\n':
		return nil
	case '\r':
		b2, err := r.br.ReadByte()
		if err != nil {
			return err
		}
		if b2 != '\n' {
			return fmt.Errorf("managesieve: expected LF after CR")
		}
		return nil
	default:
		return fmt.Errorf("managesieve: expected CRLF")
	}
}

// conn is the shared, role-neutral wire connection used by both the
// client and the server. Write methods return an error; literal
// direction is the only asymmetry between the two roles (see §4 of the
// design notes): the client emits non-synchronising {n+} bodies, the
// server emits {n} bodies.
type conn struct {
	nc net.Conn
	r  *reader
	w  *bufio.Writer
}

func newConn(nc net.Conn) *conn {
	return &conn{
		nc: nc,
		r:  &reader{bufio.NewReader(nc)},
		w:  bufio.NewWriter(nc),
	}
}

// upgrade swaps the underlying connection (after a STARTTLS handshake)
// and resets the buffered reader/writer over the new transport.
func (c *conn) upgrade(nc net.Conn) {
	c.nc = nc
	c.r = &reader{bufio.NewReader(nc)}
	c.w = bufio.NewWriter(nc)
}

// writeLine writes s followed by CRLF and flushes.
func (c *conn) writeLine(s string) error {
	if _, err := c.w.WriteString(s); err != nil {
		return err
	}
	if _, err := c.w.WriteString("\r\n"); err != nil {
		return err
	}
	return c.w.Flush()
}

// writeClientLiteral writes "head {n+}CRLF<body>CRLF" and flushes — the
// client-to-server, non-synchronising literal form.
func (c *conn) writeClientLiteral(head string, body []byte) error {
	if _, err := fmt.Fprintf(c.w, "%s {%d+}\r\n", head, len(body)); err != nil {
		return err
	}
	if _, err := c.w.Write(body); err != nil {
		return err
	}
	if _, err := c.w.WriteString("\r\n"); err != nil {
		return err
	}
	return c.w.Flush()
}

// quote renders s as a ManageSieve quoted string, escaping '\' and '"'.
// Callers must not pass values containing CR or LF (use a literal for
// those); script names and short atoms never do.
func quote(s string) string {
	var sb strings.Builder
	sb.Grow(len(s) + 2)
	sb.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '"' || c == '\\' {
			sb.WriteByte('\\')
		}
		sb.WriteByte(s[i])
	}
	sb.WriteByte('"')
	return sb.String()
}
