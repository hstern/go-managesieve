// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"sort"
	"strconv"
	"strings"
)

// Capabilities is the set of capabilities a server advertises in its
// CAPABILITY listing (RFC 5804 §1.7, §2.4). Known capabilities have
// typed fields; any unrecognised capability line is preserved verbatim
// in Extra so callers and the registry (§6.3) can evolve independently.
type Capabilities struct {
	Implementation string            // IMPLEMENTATION — server name and version
	SASL           []string          // SASL — usable SASL mechanism names
	Sieve          []string          // SIEVE — supported Sieve extensions
	StartTLS       bool              // STARTTLS — TLS upgrade is offered
	MaxRedirects   int               // MAXREDIRECTS — max redirects a script may use
	Notify         []string          // NOTIFY — notification URI schemes
	Language       string            // LANGUAGE — RFC 5646 tag of response text
	Owner          string            // OWNER — authenticated owner (post-auth)
	Version        string            // VERSION — "1.0" indicates RFC 5804 compliance
	Extra          map[string]string // any unrecognised capability, by upper-cased name
}

// parseCapabilities builds Capabilities from the data lines of a
// CAPABILITY listing. A value that fails to parse into its typed field
// (e.g. a non-numeric MAXREDIRECTS) is preserved raw in Extra rather
// than failing the whole listing.
func parseCapabilities(data [][]token) Capabilities {
	caps := Capabilities{Extra: map[string]string{}}
	for _, line := range data {
		if len(line) == 0 {
			continue
		}
		name := strings.ToUpper(line[0].val)
		val := ""
		if len(line) >= 2 {
			val = line[1].val
		}
		switch name {
		case "IMPLEMENTATION":
			caps.Implementation = val
		case "SASL":
			caps.SASL = strings.Fields(val)
		case "SIEVE":
			caps.Sieve = strings.Fields(val)
		case "STARTTLS":
			caps.StartTLS = true
		case "MAXREDIRECTS":
			if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
				caps.MaxRedirects = n
			} else {
				caps.Extra[name] = val
			}
		case "NOTIFY":
			caps.Notify = strings.Fields(val)
		case "LANGUAGE":
			caps.Language = val
		case "OWNER":
			caps.Owner = val
		case "VERSION":
			caps.Version = val
		default:
			caps.Extra[name] = val
		}
	}
	return caps
}

// lines renders the capabilities as the wire lines of a listing (without
// the trailing OK). Extra entries are emitted in sorted order so the
// output is deterministic.
func (c Capabilities) lines() []string {
	var out []string
	if c.Implementation != "" {
		out = append(out, quote("IMPLEMENTATION")+" "+quote(c.Implementation))
	}
	if len(c.SASL) > 0 {
		out = append(out, quote("SASL")+" "+quote(strings.Join(c.SASL, " ")))
	}
	if len(c.Sieve) > 0 {
		out = append(out, quote("SIEVE")+" "+quote(strings.Join(c.Sieve, " ")))
	}
	if c.StartTLS {
		out = append(out, quote("STARTTLS"))
	}
	if c.MaxRedirects > 0 {
		out = append(out, quote("MAXREDIRECTS")+" "+quote(strconv.Itoa(c.MaxRedirects)))
	}
	if len(c.Notify) > 0 {
		out = append(out, quote("NOTIFY")+" "+quote(strings.Join(c.Notify, " ")))
	}
	if c.Language != "" {
		out = append(out, quote("LANGUAGE")+" "+quote(c.Language))
	}
	if c.Owner != "" {
		out = append(out, quote("OWNER")+" "+quote(c.Owner))
	}
	if c.Version != "" {
		out = append(out, quote("VERSION")+" "+quote(c.Version))
	}
	keys := make([]string, 0, len(c.Extra))
	for k := range c.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v := c.Extra[k]; v != "" {
			out = append(out, quote(k)+" "+quote(v))
		} else {
			out = append(out, quote(k))
		}
	}
	return out
}
