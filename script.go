// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

// ScriptInfo names a script stored on the server and reports whether it
// is the active script (the one the server runs on delivery). At most
// one script is active at a time.
type ScriptInfo struct {
	Name   string
	Active bool
}
