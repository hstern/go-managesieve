// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"bytes"
	"errors"
)

// SASLClient drives the client side of a SASL exchange for
// AUTHENTICATE. Start returns the mechanism name and an optional initial
// response; Next is called for each server challenge until the server
// completes the exchange.
type SASLClient interface {
	Start() (mech string, ir []byte, err error)
	Next(challenge []byte) (response []byte, err error)
}

// SASLServer drives the server side of a SASL exchange. Next is called
// with each client response (nil on the first call when the client sent
// no initial response). It returns a challenge to send and done=false to
// continue, or done=true to accept the authentication; a non-nil error
// rejects it. When done is true, a non-empty challenge is sent to the
// client as the final SASL data in the success response (e.g. a
// mutual-authentication signature).
type SASLServer interface {
	Next(response []byte) (challenge []byte, done bool, err error)
}

// SASLFinalReceiver is an optional interface a SASLClient may implement
// to receive the server's final SASL data carried in a successful
// "OK (SASL ...)" response — for example to verify a server signature in
// a mutual-authentication mechanism. Mechanisms without a server-final
// step (such as PLAIN) need not implement it.
type SASLFinalReceiver interface {
	SASLFinal(data []byte) error
}

// ErrSASLAborted is returned by the server-side AUTHENTICATE handling
// when the client aborts the exchange with "*".
var ErrSASLAborted = errors.New("managesieve: SASL exchange aborted by client")

// PlainAuth returns a SASLClient implementing the SASL PLAIN mechanism
// (RFC 4616). identity is the authorization identity (usually ""),
// username the authentication identity, and password the secret. PLAIN
// transmits the password in the clear; use it only over a TLS channel
// (after StartTLS or DialTLS).
func PlainAuth(identity, username, password string) SASLClient {
	return &plainClient{identity: identity, username: username, password: password}
}

type plainClient struct {
	identity, username, password string
}

func (p *plainClient) Start() (string, []byte, error) {
	ir := []byte(p.identity + "\x00" + p.username + "\x00" + p.password)
	return "PLAIN", ir, nil
}

func (p *plainClient) Next([]byte) ([]byte, error) {
	return nil, errors.New("managesieve: PLAIN does not expect a server challenge")
}

// PlainServer returns a SASLServer implementing SASL PLAIN. check is
// called with the decoded authorization identity, authentication
// identity, and password; returning a non-nil error rejects the login.
func PlainServer(check func(identity, username, password string) error) SASLServer {
	return &plainServer{check: check}
}

type plainServer struct {
	check func(identity, username, password string) error
}

func (p *plainServer) Next(response []byte) ([]byte, bool, error) {
	if response == nil {
		// No initial response: prompt the client with an empty challenge.
		return []byte{}, false, nil
	}
	parts := bytes.SplitN(response, []byte{0}, 3)
	if len(parts) != 3 {
		return nil, false, errors.New("managesieve: malformed PLAIN response")
	}
	if err := p.check(string(parts[0]), string(parts[1]), string(parts[2])); err != nil {
		return nil, false, err
	}
	return nil, true, nil
}
