// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"fmt"
	"strings"
)

// ListScripts returns the scripts stored for the authenticated user; the
// active script (if any) has Active set (RFC 5804 §2.7).
func (c *Client) ListScripts() ([]ScriptInfo, error) {
	if err := c.conn.writeLine("LISTSCRIPTS"); err != nil {
		return nil, err
	}
	data, resp, err := c.readResponse()
	if err != nil {
		return nil, err
	}
	if err := resp.err(); err != nil {
		return nil, err
	}
	out := make([]ScriptInfo, 0, len(data))
	for _, line := range data {
		if len(line) == 0 {
			continue
		}
		si := ScriptInfo{Name: line[0].val}
		for _, t := range line[1:] {
			if t.kind == tokAtom && strings.EqualFold(t.val, "ACTIVE") {
				si.Active = true
			}
		}
		out = append(out, si)
	}
	return out, nil
}

// GetScript fetches the body of the named script (RFC 5804 §2.9). A
// missing script yields a *ServerError whose CodeName is NONEXISTENT.
func (c *Client) GetScript(name string) (string, error) {
	if err := c.conn.writeLine("GETSCRIPT " + quote(name)); err != nil {
		return "", err
	}
	data, resp, err := c.readResponse()
	if err != nil {
		return "", err
	}
	if err := resp.err(); err != nil {
		return "", err
	}
	for _, line := range data {
		for _, t := range line {
			if t.kind == tokLiteral || t.kind == tokString {
				return t.val, nil
			}
		}
	}
	return "", nil
}

// PutScript uploads (or replaces) a script (RFC 5804 §2.6). On success
// the server may still return non-fatal compiler warnings, returned as
// the warnings string with a nil error. An invalid script yields a
// *ServerError.
func (c *Client) PutScript(name, body string) (warnings string, err error) {
	if err := c.conn.writeClientLiteral("PUTSCRIPT "+quote(name), []byte(body)); err != nil {
		return "", err
	}
	_, resp, err := c.readResponse()
	if err != nil {
		return "", err
	}
	if err := resp.err(); err != nil {
		return "", err
	}
	return resp.warnings(), nil
}

// CheckScript asks the server to validate a script without storing it
// (RFC 5804 §2.12). Non-fatal warnings are returned with a nil error; an
// invalid script yields a *ServerError.
func (c *Client) CheckScript(body string) (warnings string, err error) {
	if err := c.conn.writeClientLiteral("CHECKSCRIPT", []byte(body)); err != nil {
		return "", err
	}
	_, resp, err := c.readResponse()
	if err != nil {
		return "", err
	}
	if err := resp.err(); err != nil {
		return "", err
	}
	return resp.warnings(), nil
}

// SetActive marks the named script active, replacing any currently
// active script (RFC 5804 §2.8). An empty name deactivates all scripts.
func (c *Client) SetActive(name string) error {
	return c.execOK("SETACTIVE " + quote(name))
}

// DeleteScript removes the named script (RFC 5804 §2.10). Deleting the
// active script yields a *ServerError whose CodeName is ACTIVE.
func (c *Client) DeleteScript(name string) error {
	return c.execOK("DELETESCRIPT " + quote(name))
}

// RenameScript renames a script (RFC 5804 §2.11). Not every server
// implements this; an unsupported server returns a *ServerError, in
// which case fall back to GetScript+PutScript+SetActive+DeleteScript. A
// name collision yields CodeName ALREADYEXISTS.
func (c *Client) RenameScript(oldName, newName string) error {
	return c.execOK("RENAMESCRIPT " + quote(oldName) + " " + quote(newName))
}

// HaveSpace asks whether a script of the given byte size could be stored
// under name (RFC 5804 §2.5). It returns nil if there is room, or a
// *ServerError with a QUOTA code (possibly QUOTA/maxscripts or
// QUOTA/maxsize) if not.
func (c *Client) HaveSpace(name string, size int64) error {
	return c.execOK(fmt.Sprintf("HAVESPACE %s %d", quote(name), size))
}
