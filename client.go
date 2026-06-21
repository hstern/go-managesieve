// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"time"
)

// Client is a ManageSieve client bound to a single connection. It is not
// safe for concurrent use by multiple goroutines: the protocol is a
// strictly ordered request/response conversation per connection.
type Client struct {
	conn       *conn
	caps       Capabilities
	serverName string // for TLS SNI / certificate verification
}

// Dial connects to a ManageSieve server over plaintext TCP and reads the
// initial capability listing. addr may be "host" (the default port 4190
// is appended) or "host:port". Use StartTLS before authenticating, or
// DialTLS for an implicit-TLS endpoint.
func Dial(ctx context.Context, addr string) (*Client, error) {
	addr = ensurePort(addr)
	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return newClient(nc, hostOnly(addr))
}

// DialTLS connects to a ManageSieve server over implicit TLS and reads
// the initial capability listing. If cfg is nil a default is used; its
// ServerName defaults to the dialed host.
func DialTLS(ctx context.Context, addr string, cfg *tls.Config) (*Client, error) {
	addr = ensurePort(addr)
	host := hostOnly(addr)
	cfg = tlsConfigFor(cfg, host)
	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(nc, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = nc.Close()
		return nil, err
	}
	return newClient(tc, host)
}

// NewClient wraps an already-established connection (for example a proxied
// or test connection) and reads the initial capability listing. The
// server name, used for a later StartTLS, is taken from the connection's
// remote address.
func NewClient(nc net.Conn) (*Client, error) {
	host := ""
	if a := nc.RemoteAddr(); a != nil {
		host = hostOnly(a.String())
	}
	return newClient(nc, host)
}

func newClient(nc net.Conn, serverName string) (*Client, error) {
	c := &Client{conn: newConn(nc), serverName: serverName}
	if err := c.readCapabilities(); err != nil {
		_ = nc.Close()
		return nil, err
	}
	return c, nil
}

// Capabilities returns the most recently read server capabilities.
func (c *Client) Capabilities() Capabilities { return c.caps }

// SetDeadline sets the read/write deadline on the underlying connection.
func (c *Client) SetDeadline(t time.Time) error { return c.conn.nc.SetDeadline(t) }

// Close closes the underlying connection without sending LOGOUT.
func (c *Client) Close() error { return c.conn.nc.Close() }

// StartTLS upgrades the connection to TLS in place and re-reads the
// capability listing, discarding the pre-TLS capabilities (RFC 5804
// §2.2). If cfg is nil a default is used; its ServerName defaults to the
// host this client dialed.
func (c *Client) StartTLS(cfg *tls.Config) error {
	if err := c.execOK("STARTTLS"); err != nil {
		return err
	}
	tc := tls.Client(c.conn.nc, tlsConfigFor(cfg, c.serverName))
	if err := tc.Handshake(); err != nil {
		return err
	}
	c.conn.upgrade(tc)
	return c.readCapabilities()
}

// Capability re-requests the capability listing from the server.
func (c *Client) Capability() error {
	if err := c.conn.writeLine("CAPABILITY"); err != nil {
		return err
	}
	return c.readCapabilities()
}

// Noop sends a NOOP. If tag is non-empty the server echoes it in a TAG
// response code (RFC 5804 §2.13).
func (c *Client) Noop(tag string) error {
	if tag == "" {
		return c.execOK("NOOP")
	}
	return c.execOK("NOOP " + quote(tag))
}

// Logout sends LOGOUT and closes the connection.
func (c *Client) Logout() error {
	err := c.execOK("LOGOUT")
	closeErr := c.conn.nc.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// Authenticate performs SASL authentication using the supplied mechanism
// (RFC 5804 §2.1). PlainAuth provides the built-in PLAIN mechanism.
func (c *Client) Authenticate(m SASLClient) error {
	mech, ir, err := m.Start()
	if err != nil {
		return err
	}
	line := "AUTHENTICATE " + quote(mech)
	if ir != nil {
		line += " " + quote(base64.StdEncoding.EncodeToString(ir))
	}
	if err := c.conn.writeLine(line); err != nil {
		return err
	}
	for {
		toks, err := c.conn.r.readLine()
		if err != nil {
			return err
		}
		if st, ok := parseStatus(toks); ok {
			if st.status == statusOK {
				if err := deliverSASLFinal(m, st); err != nil {
					return err
				}
			}
			return st.err()
		}
		challenge, err := decodeChallenge(toks)
		if err != nil {
			return err
		}
		resp, err := m.Next(challenge)
		if err != nil {
			_ = c.conn.writeLine(quote("*"))
			_, _, _ = c.readResponse()
			return err
		}
		if err := c.conn.writeLine(quote(base64.StdEncoding.EncodeToString(resp))); err != nil {
			return err
		}
	}
}

// deliverSASLFinal hands the server's final "(SASL ...)" data to the
// mechanism if it implements SASLFinalReceiver. A no-op otherwise.
func deliverSASLFinal(m SASLClient, st *response) error {
	if st.code == nil || st.code.Name != CodeSASL || st.code.Arg == "" {
		return nil
	}
	f, ok := m.(SASLFinalReceiver)
	if !ok {
		return nil
	}
	data, err := base64.StdEncoding.DecodeString(st.code.Arg)
	if err != nil {
		return fmt.Errorf("managesieve: invalid final SASL data: %w", err)
	}
	return f.SASLFinal(data)
}

func decodeChallenge(toks []token) ([]byte, error) {
	for _, t := range toks {
		if t.kind == tokString || t.kind == tokLiteral {
			b, err := base64.StdEncoding.DecodeString(t.val)
			if err != nil {
				return nil, fmt.Errorf("managesieve: invalid SASL challenge: %w", err)
			}
			return b, nil
		}
	}
	return nil, nil
}

// readResponse reads data lines until a status line, returning the data
// lines and the parsed status.
func (c *Client) readResponse() (data [][]token, resp *response, err error) {
	for {
		toks, err := c.conn.r.readLine()
		if err != nil {
			return nil, nil, err
		}
		if st, ok := parseStatus(toks); ok {
			return data, st, nil
		}
		data = append(data, toks)
	}
}

// readCapabilities reads a capability listing terminated by OK.
func (c *Client) readCapabilities() error {
	data, resp, err := c.readResponse()
	if err != nil {
		return err
	}
	if err := resp.err(); err != nil {
		return err
	}
	c.caps = parseCapabilities(data)
	return nil
}

// execOK sends a one-line command and returns the error from its status.
func (c *Client) execOK(cmd string) error {
	if err := c.conn.writeLine(cmd); err != nil {
		return err
	}
	_, resp, err := c.readResponse()
	if err != nil {
		return err
	}
	return resp.err()
}

func ensurePort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, DefaultPort)
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func tlsConfigFor(cfg *tls.Config, serverName string) *tls.Config {
	if cfg == nil {
		cfg = &tls.Config{}
	}
	if cfg.ServerName == "" && serverName != "" {
		cfg = cfg.Clone()
		cfg.ServerName = serverName
	}
	return cfg
}
