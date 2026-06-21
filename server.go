// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"crypto/tls"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"time"
)

// Backend builds a Session for each accepted connection. It is the entry
// point a consumer implements to serve ManageSieve.
type Backend interface {
	NewSession(*ServerConn) (Session, error)
}

// Session is the consumer's per-connection handler. The server owns the
// wire protocol and session state machine and calls these methods to
// carry out commands. Embed UnimplementedSession to stay
// forward-compatible and to get "not implemented" defaults for commands
// a backend does not support.
//
// A method may return a *ServerError to control the response code sent
// to the client (for example NONEXISTENT or a QUOTA code); any other
// error becomes a generic NO.
type Session interface {
	// AuthMechanisms returns the SASL mechanism names to advertise.
	AuthMechanisms() []string
	// Authenticate begins a SASL exchange for the named mechanism,
	// returning the server-side driver. Return an error for an
	// unsupported mechanism.
	Authenticate(mech string) (SASLServer, error)

	ListScripts() ([]ScriptInfo, error)
	GetScript(name string) (body string, err error)
	PutScript(name, body string) (warnings string, err error)
	CheckScript(body string) (warnings string, err error)
	SetActive(name string) error // "" deactivates all scripts
	DeleteScript(name string) error
	RenameScript(oldName, newName string) error
	HaveSpace(name string, size int64) error

	// Logout is called when the connection ends (LOGOUT or disconnect).
	Logout() error
}

// ServerConn exposes per-connection details to a Backend.
type ServerConn struct {
	conn net.Conn
	tls  bool
}

// RemoteAddr returns the client's network address.
func (sc *ServerConn) RemoteAddr() net.Addr { return sc.conn.RemoteAddr() }

// TLS reports whether the connection has been upgraded to TLS.
func (sc *ServerConn) TLS() bool { return sc.tls }

// Server serves the ManageSieve protocol, delegating all script logic to
// a Backend.
type Server struct {
	// Backend builds a Session per connection. Required.
	Backend Backend
	// TLSConfig, if set, enables the advertised STARTTLS upgrade and
	// causes the server to require TLS before AUTHENTICATE.
	TLSConfig *tls.Config
	// Implementation is advertised in the IMPLEMENTATION capability.
	Implementation string
	// SieveExtensions is advertised in the SIEVE capability.
	SieveExtensions []string
	// ReadTimeout, if non-zero, bounds how long the server waits for each
	// client command before closing the connection.
	ReadTimeout time.Duration
	// WriteTimeout, if non-zero, bounds how long the server may take to
	// write each response.
	WriteTimeout time.Duration
}

// NewServer returns a Server using b, with a default IMPLEMENTATION
// string.
func NewServer(b Backend) *Server {
	return &Server{Backend: b, Implementation: "go-managesieve"}
}

// Serve accepts connections on l and serves each in its own goroutine
// until l.Accept returns an error (e.g. the listener is closed).
func (s *Server) Serve(l net.Listener) error {
	for {
		nc, err := l.Accept()
		if err != nil {
			return err
		}
		go s.serveConn(nc)
	}
}

func (s *Server) serveConn(nc net.Conn) {
	defer func() { _ = nc.Close() }()
	sc := &ServerConn{conn: nc}
	sess, err := s.Backend.NewSession(sc)
	if err != nil {
		c := newConn(nc)
		_ = c.writeLine(statusBYE + " " + quote("Service unavailable"))
		return
	}
	h := &serverHandler{s: s, c: newConn(nc), sc: sc, sess: sess}
	h.run()
}

// serverHandler holds the per-connection state machine. Write errors are
// sticky (stored in err); the run loop exits when one occurs.
type serverHandler struct {
	s      *Server
	c      *conn
	sc     *ServerConn
	sess   Session
	authed bool
	err    error
}

func (h *serverHandler) run() {
	h.applyDeadlines()
	h.greet()
	for h.err == nil {
		h.applyDeadlines()
		toks, err := h.c.r.readLine()
		if err != nil {
			break
		}
		if len(toks) == 0 || toks[0].kind != tokAtom {
			h.reply(statusNO, nil, "Expected a command")
			continue
		}
		cmd := strings.ToUpper(toks[0].val)
		args := toks[1:]
		if cmd == "LOGOUT" {
			h.reply(statusOK, nil, "Logout complete")
			_ = h.sess.Logout()
			return
		}
		h.dispatch(cmd, args)
	}
	_ = h.sess.Logout()
}

func (h *serverHandler) dispatch(cmd string, args []token) {
	switch cmd {
	case "CAPABILITY":
		h.greet()
	case "NOOP":
		h.noop(args)
	case "STARTTLS":
		h.startTLS()
	case "AUTHENTICATE":
		h.authenticate(args)
	case "LISTSCRIPTS", "GETSCRIPT", "PUTSCRIPT", "CHECKSCRIPT", "SETACTIVE",
		"DELETESCRIPT", "RENAMESCRIPT", "HAVESPACE":
		if !h.authed {
			h.reply(statusNO, nil, "Authenticate first")
			return
		}
		h.command(cmd, args)
	default:
		h.reply(statusNO, nil, "Unknown command")
	}
}

func (h *serverHandler) command(cmd string, args []token) {
	switch cmd {
	case "LISTSCRIPTS":
		list, err := h.sess.ListScripts()
		if err != nil {
			h.replyErr(err)
			return
		}
		for _, si := range list {
			line := quote(si.Name)
			if si.Active {
				line += " ACTIVE"
			}
			h.write(line + "\r\n")
		}
		h.reply(statusOK, nil, "")
	case "GETSCRIPT":
		if len(args) < 1 {
			h.reply(statusNO, nil, "GETSCRIPT requires a name")
			return
		}
		body, err := h.sess.GetScript(args[0].val)
		if err != nil {
			h.replyErr(err)
			return
		}
		h.writeServerLiteral([]byte(body))
		h.reply(statusOK, nil, "")
	case "PUTSCRIPT":
		if len(args) < 2 {
			h.reply(statusNO, nil, "PUTSCRIPT requires a name and a script")
			return
		}
		warn, err := h.sess.PutScript(args[0].val, args[1].val)
		h.replyWarn(warn, err)
	case "CHECKSCRIPT":
		if len(args) < 1 {
			h.reply(statusNO, nil, "CHECKSCRIPT requires a script")
			return
		}
		warn, err := h.sess.CheckScript(args[0].val)
		h.replyWarn(warn, err)
	case "SETACTIVE":
		if len(args) < 1 {
			h.reply(statusNO, nil, "SETACTIVE requires a name")
			return
		}
		h.replyResult(h.sess.SetActive(args[0].val))
	case "DELETESCRIPT":
		if len(args) < 1 {
			h.reply(statusNO, nil, "DELETESCRIPT requires a name")
			return
		}
		h.replyResult(h.sess.DeleteScript(args[0].val))
	case "RENAMESCRIPT":
		if len(args) < 2 {
			h.reply(statusNO, nil, "RENAMESCRIPT requires two names")
			return
		}
		h.replyResult(h.sess.RenameScript(args[0].val, args[1].val))
	case "HAVESPACE":
		if len(args) < 2 {
			h.reply(statusNO, nil, "HAVESPACE requires a name and a size")
			return
		}
		size, perr := strconv.ParseInt(args[1].val, 10, 64)
		if perr != nil {
			h.reply(statusNO, nil, "Invalid size")
			return
		}
		h.replyResult(h.sess.HaveSpace(args[0].val, size))
	}
}

func (h *serverHandler) noop(args []token) {
	if len(args) >= 1 {
		h.reply(statusOK, &ResponseCode{Name: CodeTag, Arg: args[0].val}, "Done")
		return
	}
	h.reply(statusOK, nil, "")
}

func (h *serverHandler) startTLS() {
	if h.s.TLSConfig == nil {
		h.reply(statusNO, nil, "TLS not available")
		return
	}
	if h.sc.tls {
		h.reply(statusNO, nil, "Already using TLS")
		return
	}
	h.reply(statusOK, nil, "Begin TLS negotiation now")
	if h.err != nil {
		return
	}
	tc := tls.Server(h.c.nc, h.s.TLSConfig)
	if err := tc.Handshake(); err != nil {
		h.err = err
		return
	}
	h.c.upgrade(tc)
	h.sc.conn = tc
	h.sc.tls = true
	h.greet() // re-advertise capabilities over TLS
}

func (h *serverHandler) authenticate(args []token) {
	if h.authed {
		h.reply(statusNO, nil, "Already authenticated")
		return
	}
	if h.s.TLSConfig != nil && !h.sc.tls {
		h.reply(statusNO, &ResponseCode{Name: CodeEncryptNeeded}, "TLS required before authentication")
		return
	}
	if len(args) < 1 {
		h.reply(statusNO, nil, "AUTHENTICATE requires a mechanism")
		return
	}
	mech := strings.ToUpper(args[0].val)
	ss, err := h.sess.Authenticate(mech)
	if err != nil {
		h.replyErr(err)
		return
	}
	var resp []byte
	if len(args) >= 2 {
		ir, derr := base64.StdEncoding.DecodeString(args[1].val)
		if derr != nil {
			h.reply(statusNO, nil, "Invalid base64 initial response")
			return
		}
		resp = ir
	}
	for h.err == nil {
		challenge, done, aerr := ss.Next(resp)
		if aerr != nil {
			h.replyErr(aerr)
			return
		}
		if done {
			h.authed = true
			if len(challenge) > 0 {
				// Server-final data (e.g. mutual-auth signature) travels
				// in the SASL response code of the success line.
				final := base64.StdEncoding.EncodeToString(challenge)
				h.reply(statusOK, &ResponseCode{Name: CodeSASL, Arg: final}, "Authentication successful")
			} else {
				h.reply(statusOK, nil, "Authentication successful")
			}
			return
		}
		h.write(quote(base64.StdEncoding.EncodeToString(challenge)) + "\r\n")
		h.flush()
		h.applyDeadlines()
		toks, rerr := h.c.r.readLine()
		if rerr != nil {
			h.err = rerr
			return
		}
		if len(toks) == 1 && toks[0].kind == tokString && toks[0].val == "*" {
			h.reply(statusNO, nil, "Authentication aborted")
			return
		}
		resp = nil
		for _, t := range toks {
			if t.kind == tokString || t.kind == tokLiteral {
				d, derr := base64.StdEncoding.DecodeString(t.val)
				if derr != nil {
					h.reply(statusNO, nil, "Invalid base64 response")
					return
				}
				resp = d
				break
			}
		}
	}
}

// greet writes the capability listing followed by OK.
func (h *serverHandler) greet() {
	for _, line := range h.serverCaps().lines() {
		h.write(line + "\r\n")
	}
	h.reply(statusOK, nil, "")
}

func (h *serverHandler) serverCaps() Capabilities {
	caps := Capabilities{
		Implementation: h.s.Implementation,
		Sieve:          h.s.SieveExtensions,
		Version:        "1.0",
		Extra:          map[string]string{},
	}
	if !h.sc.tls && h.s.TLSConfig != nil {
		caps.StartTLS = true
	}
	if mechs := h.sess.AuthMechanisms(); len(mechs) > 0 {
		caps.SASL = mechs
	}
	if h.authed {
		if o, ok := h.sess.(SessionOwner); ok {
			caps.Owner = o.Owner()
		}
	}
	return caps
}

// SessionOwner is an optional interface a Session may implement so the
// server advertises the OWNER capability — the authenticated user — in
// the capability listing it sends after a successful AUTHENTICATE.
type SessionOwner interface {
	Owner() string
}

// --- write helpers (sticky error) ---

func (h *serverHandler) write(s string) {
	if h.err != nil {
		return
	}
	_, h.err = h.c.w.WriteString(s)
}

func (h *serverHandler) flush() {
	if h.err != nil {
		return
	}
	h.err = h.c.w.Flush()
}

// applyDeadlines sets per-command read/write deadlines from the Server's
// configured timeouts. A zero timeout leaves the corresponding deadline
// untouched (no limit).
func (h *serverHandler) applyDeadlines() {
	now := time.Now()
	if h.s.ReadTimeout > 0 {
		_ = h.c.nc.SetReadDeadline(now.Add(h.s.ReadTimeout))
	}
	if h.s.WriteTimeout > 0 {
		_ = h.c.nc.SetWriteDeadline(now.Add(h.s.WriteTimeout))
	}
}

func (h *serverHandler) writeServerLiteral(body []byte) {
	if h.err != nil {
		return
	}
	h.write("{" + strconv.Itoa(len(body)) + "}\r\n")
	if h.err != nil {
		return
	}
	_, h.err = h.c.w.Write(body)
	h.write("\r\n")
}

// reply writes a status line (and flushes).
func (h *serverHandler) reply(status string, code *ResponseCode, text string) {
	if h.err != nil {
		return
	}
	var sb strings.Builder
	sb.WriteString(status)
	if code != nil {
		sb.WriteString(" (")
		sb.WriteString(code.String())
		sb.WriteByte(')')
	}
	if text != "" {
		sb.WriteByte(' ')
		sb.WriteString(quote(text))
	}
	h.write(sb.String() + "\r\n")
	h.flush()
}

// replyResult maps a Session method result to OK or an error response.
func (h *serverHandler) replyResult(err error) {
	if err != nil {
		h.replyErr(err)
		return
	}
	h.reply(statusOK, nil, "")
}

// replyWarn maps a (warnings, err) result: an error response, an OK with
// a WARNINGS code, or a plain OK.
func (h *serverHandler) replyWarn(warnings string, err error) {
	if err != nil {
		h.replyErr(err)
		return
	}
	if warnings != "" {
		h.reply(statusOK, &ResponseCode{Name: CodeWarnings}, warnings)
		return
	}
	h.reply(statusOK, nil, "")
}

// replyErr maps an error to a NO response, preserving a *ServerError's
// status, code, and text.
func (h *serverHandler) replyErr(err error) {
	var se *ServerError
	if as, ok := err.(*ServerError); ok {
		se = as
	}
	if se != nil {
		status := se.Status
		if status == "" {
			status = statusNO
		}
		h.reply(status, se.Code, se.Text)
		return
	}
	h.reply(statusNO, nil, err.Error())
}

// UnimplementedSession provides "not implemented" defaults for every
// Session method. Embed it in a backend session to implement only the
// commands you support and to remain forward-compatible if the interface
// grows.
type UnimplementedSession struct{}

// AuthMechanisms advertises no SASL mechanisms by default.
func (UnimplementedSession) AuthMechanisms() []string { return nil }

// Authenticate rejects every mechanism by default.
func (UnimplementedSession) Authenticate(string) (SASLServer, error) {
	return nil, errNotImplemented
}

// ListScripts is not implemented by default.
func (UnimplementedSession) ListScripts() ([]ScriptInfo, error) { return nil, errNotImplemented }

// GetScript is not implemented by default.
func (UnimplementedSession) GetScript(string) (string, error) { return "", errNotImplemented }

// PutScript is not implemented by default.
func (UnimplementedSession) PutScript(string, string) (string, error) {
	return "", errNotImplemented
}

// CheckScript is not implemented by default.
func (UnimplementedSession) CheckScript(string) (string, error) { return "", errNotImplemented }

// SetActive is not implemented by default.
func (UnimplementedSession) SetActive(string) error { return errNotImplemented }

// DeleteScript is not implemented by default.
func (UnimplementedSession) DeleteScript(string) error { return errNotImplemented }

// RenameScript is not implemented by default.
func (UnimplementedSession) RenameScript(string, string) error { return errNotImplemented }

// HaveSpace is not implemented by default.
func (UnimplementedSession) HaveSpace(string, int64) error { return errNotImplemented }

// Logout does nothing by default.
func (UnimplementedSession) Logout() error { return nil }

var errNotImplemented = &ServerError{Status: statusNO, Text: "Command not implemented"}
