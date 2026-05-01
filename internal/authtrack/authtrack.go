// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authtrack snoops the IMAP authentication exchange to learn the
// authenticated username, without ever inspecting or storing the password
// or bearer token. It supports the four mechanisms in use here: LOGIN,
// AUTHENTICATE PLAIN, AUTHENTICATE XOAUTH2, AUTHENTICATE OAUTHBEARER —
// in both SASL-IR (RFC 4959) and multi-line forms.
//
// The Tracker is fed every framed line in both directions by the session
// loop. It stays out of the way for any line it doesn't recognise.
package authtrack

import (
	"bytes"
	"strings"

	"github.com/benalbrecht/imap-shadow/internal/sasl"
)

// Tracker is a stateful, NOT goroutine-safe state machine. The session
// owns one per connection and serialises calls.
type Tracker struct {
	// pending* describe an in-flight auth attempt: a tag has been sent but
	// the server hasn't tagged-OK'd it yet.
	pendingTag  string
	pendingUser string

	// expectAuthPayload is set when the client sent AUTHENTICATE without an
	// initial response and we're waiting for the server '+' continuation
	// followed by the client's payload line.
	expectAuthPayload bool
	pendingMech       string // "PLAIN" / "XOAUTH2" / "OAUTHBEARER"

	user string // committed
}

// User returns the authenticated username, or "" if not yet authenticated.
func (t *Tracker) User() string { return t.user }

// HandleClientLine inspects line travelling client → server.
func (t *Tracker) HandleClientLine(line []byte) {
	// Client cancellation of a SASL exchange.
	if t.expectAuthPayload && bytes.HasPrefix(line, []byte("*")) {
		t.expectAuthPayload = false
		t.pendingMech = ""
		t.pendingTag = ""
		t.pendingUser = ""
		return
	}

	// If we were waiting for the SASL payload, this line IS the payload
	// (already-base64).
	if t.expectAuthPayload {
		t.expectAuthPayload = false
		t.pendingUser = extractByMech(t.pendingMech, trimCRLF(dup(line)))
		return
	}

	// Parse a normal command line: "<tag> <CMD> <args>".
	tag, cmd, rest, ok := splitTagCommand(line)
	if !ok {
		return
	}
	switch strings.ToUpper(cmd) {
	case "LOGIN":
		args := dup(trimCRLF(rest))
		user, err := sasl.UsernameFromLogin(args)
		if err != nil {
			return
		}
		t.pendingTag = tag
		t.pendingUser = user
	case "AUTHENTICATE":
		mech, ir := splitMechIR(trimCRLF(rest))
		mech = strings.ToUpper(mech)
		if !isSupportedMech(mech) {
			return
		}
		t.pendingTag = tag
		t.pendingMech = mech
		if ir != "" {
			t.pendingUser = extractByMech(mech, dup([]byte(ir)))
		} else {
			t.expectAuthPayload = true
		}
	}
}

// HandleServerLine inspects line travelling server → client. Returns true
// when this line caused the username to be committed.
func (t *Tracker) HandleServerLine(line []byte) bool {
	// Server '+' continuation does not affect commit state by itself.
	if len(line) > 0 && line[0] == '+' {
		return false
	}
	tag, status, _, ok := splitTagStatus(line)
	if !ok || t.pendingTag == "" || tag != t.pendingTag {
		return false
	}
	defer t.resetPending()
	switch strings.ToUpper(status) {
	case "OK":
		if t.pendingUser != "" {
			t.user = t.pendingUser
			return true
		}
	}
	return false
}

func (t *Tracker) resetPending() {
	t.pendingTag = ""
	t.pendingUser = ""
	t.pendingMech = ""
	t.expectAuthPayload = false
}

func isSupportedMech(m string) bool {
	switch m {
	case "PLAIN", "XOAUTH2", "OAUTHBEARER":
		return true
	}
	return false
}

func extractByMech(mech string, payload []byte) string {
	switch strings.ToUpper(mech) {
	case "PLAIN":
		u, err := sasl.UsernameFromPlain(payload)
		if err != nil {
			return ""
		}
		return u
	case "XOAUTH2", "OAUTHBEARER":
		u, err := sasl.UsernameFromBearer(payload)
		if err != nil {
			return ""
		}
		return u
	}
	return ""
}

// splitTagCommand parses "<tag> <CMD> <rest>". rest may be empty. The CRLF
// (if any) is preserved in rest.
func splitTagCommand(line []byte) (tag, cmd string, rest []byte, ok bool) {
	sp1 := bytes.IndexByte(line, ' ')
	if sp1 <= 0 {
		return "", "", nil, false
	}
	tag = string(line[:sp1])
	after := line[sp1+1:]
	sp2 := bytes.IndexByte(after, ' ')
	if sp2 < 0 {
		// command without args, e.g. "t1 NOOP\r\n"
		cmd = string(trimCRLF(after))
		return tag, cmd, nil, true
	}
	cmd = string(after[:sp2])
	rest = after[sp2+1:]
	return tag, cmd, rest, true
}

// splitTagStatus parses "<tag> <STATUS> <rest>" used for OK/NO/BAD.
func splitTagStatus(line []byte) (tag, status, rest string, ok bool) {
	t, c, r, k := splitTagCommand(line)
	if !k {
		return "", "", "", false
	}
	return t, c, string(r), true
}

// splitMechIR splits "MECH" or "MECH <base64-IR>".
func splitMechIR(rest []byte) (mech, ir string) {
	rest = trimCRLF(rest)
	sp := bytes.IndexByte(rest, ' ')
	if sp < 0 {
		return string(rest), ""
	}
	return string(rest[:sp]), string(rest[sp+1:])
}

func trimCRLF(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\r' || b[len(b)-1] == '\n') {
		b = b[:len(b)-1]
	}
	return b
}

// dup returns a fresh copy so the SASL package can safely zero it.
func dup(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
